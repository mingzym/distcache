/* distcache, Distributed Session Caching technology
 * Copyright (C) 2000-2002  Geoff Thorpe, and Cryptographic Appliances, Inc.
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; using version 2.1 of the License. The copyright holders
 * may elect to allow the application of later versions of the License to this
 * software, please contact the author (geoff@distcache.org) if you wish us to
 * review any later version released by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <libnal/common.h>
#include <libnal/nal.h>
#include <distcache/dc_server.h>
#include <distcache/dc_enc.h>

/* The starting size of the array of *pointers* to client items */
#define DC_SERVER_START_SIZE		256
/* The starting size for a client's "store" when first allocated */
#define DC_CLIENT_STORE_START_SIZE	DC_MSG_MAX_DATA
/* The starting size for a client's "response" when first allocated */
#define DC_CLIENT_RESPONSE_START_SIZE	DC_MSG_MAX_DATA

/* Our only global - the cache "implementation" we create new 'DC_SERVER'
 * structures with. */
static const DC_CACHE_cb *default_cache_implementation = NULL;

/******************************************/
/* The "DC_SERVER" structure details */

struct st_DC_SERVER {
	/* The implementation used corresponding to this server structure */
	const DC_CACHE_cb *vt;
	/* The (resizable array of) clients */
	DC_CLIENT **clients;
	unsigned int clients_used, clients_size;
	/* The session storage */
	DC_CACHE *cache;
	/* The counter of cache operations */
	unsigned long ops;
};

struct st_DC_CLIENT {
	/* A pointer back to the server */
	DC_SERVER *server;
	/* The plug for this client */
	DC_PLUG *plug;
	/* Our flags */
	unsigned int flags;
	/* Storage for received data (from the plug) */
	unsigned char read_data[DC_MAX_TOTAL_DATA];
	unsigned int read_data_len;
	/* Storage for sent data (to go to the plug) */
	unsigned char send_data[DC_MAX_TOTAL_DATA];
	unsigned int send_data_len;
};

/****************************************************/
/* Internal functions to manage clients in a server */

static void int_server_del_client(DC_SERVER *ctx, unsigned int idx)
{
	DC_CLIENT *clnt = ctx->clients[idx];
	/* Clean up the client */
	DC_PLUG_free(clnt->plug);
	SYS_free(DC_CLIENT, clnt);
	/* Unlink the client from the server's array */
	if(idx + 1 < ctx->clients_used)
		SYS_memmove_n(DC_CLIENT *, ctx->clients + idx,
			(const DC_CLIENT **)ctx->clients + (idx + 1),
			ctx->clients_used - (idx + 1));
	ctx->clients_used--;
}

/*********************************************************************/
/* Internal functions to perform specific session caching operations */

static void int_response_1byte(DC_CLIENT *clnt, unsigned char val)
{
	clnt->send_data[0] = val;
	clnt->send_data_len = 1;
}

static int int_do_op_add(DC_CLIENT *clnt, const struct timeval *now)
{
	int res;
	unsigned long msecs, id_len, data_len;
	unsigned char *p = clnt->read_data;
	unsigned int p_len = clnt->read_data_len;

	/* We encode "add"s as;
	 *   4 bytes            (timeout)
	 *   4 bytes            (id_len)
	 *   'id_len' bytes     (id_data)
	 *   'sess_len' bytes   (sess_data) */
	if(!NAL_decode_uint32((const unsigned char **)&p, &p_len, &msecs) ||
			!NAL_decode_uint32((const unsigned char **)&p,
				&p_len, &id_len))
		return 0;
	assert((p_len + 8) == clnt->read_data_len);
	assert(p == (clnt->read_data + 8));
	if(msecs > DC_MAX_EXPIRY) {
		int_response_1byte(clnt, DC_ADD_ERR_TIMEOUT_RANGE);
		return 1;
	}
	if(id_len >= p_len) {
		int_response_1byte(clnt, DC_ADD_ERR_CORRUPT);
		return 1;
	}
	if(!id_len || (id_len > DC_MAX_ID_LEN)) {
		int_response_1byte(clnt, DC_ADD_ERR_ID_RANGE);
		return 1;
	}
	data_len = p_len - id_len;
	if(!data_len || (data_len > DC_MAX_DATA_LEN)) {
		int_response_1byte(clnt, DC_ADD_ERR_DATA_RANGE);
		return 1;
	}
	res = clnt->server->vt->cache_add(clnt->server->cache, now, msecs,
			p, id_len, p + id_len, data_len);
	if(res)
		int_response_1byte(clnt, DC_ERR_OK);
	else
		int_response_1byte(clnt, DC_ADD_ERR_MATCHING_SESSION);
	return 1;
}

static int int_do_op_get(DC_CLIENT *clnt, const struct timeval *now)
{
	unsigned int len;
	len = clnt->server->vt->cache_get(clnt->server->cache, now,
			clnt->read_data, clnt->read_data_len, NULL, 0);
	if(!len) {
		int_response_1byte(clnt, DC_ERR_NOTOK);
		return 1;
	}
	/* Make sure we have enough allocated room for the response */
	if(len > DC_MAX_TOTAL_DATA)
		return 0;
	/* NB: It's ok to pass in the session id again like this - the cache
	 * implementation automatically caches the lookup from the first call,
	 * so this one will not actually involve any searching. */
	len = clnt->server->vt->cache_get(clnt->server->cache, now,
				clnt->read_data, clnt->read_data_len,
				clnt->send_data, DC_MAX_TOTAL_DATA);
	assert(len && (len <= DC_MAX_TOTAL_DATA));
	if(!len)
		/* shouldn't happen, equals "bug" */
		return 0;
	clnt->send_data_len = len;
	return 1;
}

static int int_do_op_remove(DC_CLIENT *clnt, const struct timeval *now)
{
	if(clnt->server->vt->cache_remove(clnt->server->cache, now,
				clnt->read_data, clnt->read_data_len))
		int_response_1byte(clnt, DC_ERR_OK);
	else
		int_response_1byte(clnt, DC_ERR_NOTOK);
	return 1;

}

static int int_do_op_have(DC_CLIENT *clnt, const struct timeval *now)
{
	if(clnt->server->vt->cache_have(clnt->server->cache, now,
				clnt->read_data, clnt->read_data_len))
		int_response_1byte(clnt, DC_ERR_OK);
	else
		int_response_1byte(clnt, DC_ERR_NOTOK);
	return 1;

}

static int int_do_operation(DC_CLIENT *clnt, const struct timeval *now)
{
	int toret = 1, plug_read = 1, plug_write = 0;
	unsigned long request_uid;
	DC_CMD cmd;
	const unsigned char *payload_data;
	unsigned int payload_len;

	/* Try a read on the plug. We resume because this function is only
	 * called if the top-level function detected a request using "read". */
	if(!DC_PLUG_read(clnt->plug, 1, &request_uid, &cmd,
				&payload_data, &payload_len))
		goto err;
	/* Make sure we don't forget to consume this request */
	plug_read = 1;
	/* Try and prepare writing of the response */
	if(!DC_PLUG_write(clnt->plug, 0, request_uid, cmd, NULL, 0))
		goto err;
	/* Make sure we don't forget to commit this response */
	plug_write = 1;
	/* Now duplicate the payload into our clnt buffer */
	assert(payload_len <= DC_MAX_TOTAL_DATA);
	if(payload_len)
		SYS_memcpy_n(unsigned char, clnt->read_data,
				payload_data, payload_len);
	clnt->read_data_len = payload_len;
	/* Switch on the command type */
	switch(cmd) {
	case DC_CMD_ADD:
		toret = int_do_op_add(clnt, now);
		break;
	case DC_CMD_GET:
		toret = int_do_op_get(clnt, now);
		break;
	case DC_CMD_REMOVE:
		toret = int_do_op_remove(clnt, now);
		break;
	case DC_CMD_HAVE:
		toret = int_do_op_have(clnt, now);
		break;
	default:
		goto err;
	}
	if(!toret)
		goto err;
	if(!DC_PLUG_write_more(clnt->plug, clnt->send_data,
				clnt->send_data_len) ||
			!DC_PLUG_commit(clnt->plug))
		goto err;
	plug_write = 0;
	if(!DC_PLUG_consume(clnt->plug))
		goto err;
	/* Operation done */
	clnt->server->ops++;
	return toret;
err:
	if(plug_read)
		DC_PLUG_consume(clnt->plug);
	if(plug_write)
		DC_PLUG_rollback(clnt->plug);
	return 0;
}

/***************************/
/* API (exposed) functions */

int DC_SERVER_set_cache(const DC_CACHE_cb *impl)
{
	if(!impl || !impl->cache_new || !impl->cache_free ||
			!impl->cache_add || !impl->cache_get ||
			!impl->cache_remove || !impl->cache_have ||
			!impl->cache_num_items)
		return 0;
	default_cache_implementation = impl;
	return 1;
}

DC_SERVER *DC_SERVER_new(unsigned int max_sessions)
{
	DC_SERVER *toret;
	if(!default_cache_implementation)
		/* A cache implementation must be set before we can create
		 * server structures. */
		return NULL;
	toret = SYS_malloc(DC_SERVER, 1);
	if(!toret)
		return NULL;
	toret->clients = SYS_malloc(DC_CLIENT *,
				DC_SERVER_START_SIZE);
	if(!toret->clients) {
		SYS_free(DC_SERVER, toret);
		return NULL;
	}
	toret->vt = default_cache_implementation;
	toret->cache = toret->vt->cache_new(max_sessions);
	if(!toret->cache) {
		SYS_free(DC_CLIENT *, toret->clients);
		SYS_free(DC_SERVER, toret);
		return NULL;
	}
	toret->clients_used = 0;
	toret->clients_size = DC_SERVER_START_SIZE;
	toret->ops = 0;
	return toret;
}

void DC_SERVER_free(DC_SERVER *ctx)
{
	DC_CLIENT *client;
	unsigned int idx = ctx->clients_used;
	/* Clean up existing session items */
	ctx->vt->cache_free(ctx->cache);
	/* Clean up dependant clients */
	while(idx-- > 0) {
		client = ctx->clients[idx];
		if(client->flags & DC_CLIENT_FLAG_IN_SERVER)
			int_server_del_client(ctx, idx);
	};
	/* So any clients left are ones "leaked" by the application */
	assert(ctx->clients_used == 0);
	SYS_free(DC_CLIENT *, ctx->clients);
	SYS_free(DC_SERVER, ctx);
}

unsigned int DC_SERVER_items_stored(DC_SERVER *ctx,
			const struct timeval *now)
{
	return ctx->vt->cache_num_items(ctx->cache, now);
}

void DC_SERVER_reset_operations(DC_SERVER *ctx)
{
	ctx->ops = 0;
}

unsigned long DC_SERVER_num_operations(DC_SERVER *ctx)
{
	return ctx->ops;
}

DC_CLIENT *DC_SERVER_new_client(DC_SERVER *ctx,
			NAL_CONNECTION *conn, unsigned int flags)
{
	DC_CLIENT *c;
	DC_PLUG *plug;
	unsigned int plug_flags = 0;
	if(ctx->clients_used == ctx->clients_size) {
		DC_CLIENT **newitems;
		unsigned int newsize = ctx->clients_size * 3 / 2;
		newitems = SYS_malloc(DC_CLIENT *, newsize);
		if(!newitems)
			return NULL;
		/* client_used will always be non-zero at this point */
		SYS_memcpy_n(DC_CLIENT *, newitems,
				(const DC_CLIENT **)ctx->clients,
				ctx->clients_used);
		SYS_free(DC_CLIENT *, ctx->clients);
		ctx->clients = newitems;
		ctx->clients_size = newsize;
	}
	/* Create the plug */
	if(flags & DC_CLIENT_FLAG_NOFREE_CONN)
		plug_flags |= DC_PLUG_FLAG_NOFREE_CONN;
	if((plug = DC_PLUG_new(conn, plug_flags)) == NULL)
		return NULL;
	c = SYS_malloc(DC_CLIENT, 1);
	if(!c) {
		DC_PLUG_free(plug);
		return NULL;
	}
	c->server = ctx;
	c->plug = plug;
	c->flags = flags;
	c->read_data_len = c->send_data_len = 0;
	ctx->clients[ctx->clients_used++] = c;
	return c;
}

int DC_SERVER_del_client(DC_CLIENT *clnt)
{
	DC_SERVER *ctx = clnt->server;
	unsigned int idx = 0;
	/* Find the client in the server */
	while((idx < ctx->clients_used) && (ctx->clients[idx] != clnt))
		idx++;
	if(idx >= ctx->clients_used)
		/* not found! */
		return 0;
	int_server_del_client(ctx, idx);
	return 1;
}

int DC_SERVER_process_client(DC_CLIENT *clnt,
			const struct timeval *now)
{
	unsigned long request_uid;
	DC_CMD cmd;
	const unsigned char *payload_data;
	unsigned int payload_len;
	if(!DC_PLUG_read(clnt->plug, 0, &request_uid, &cmd,
				&payload_data, &payload_len))
		/* No request to read */
		return 1;
	return int_do_operation(clnt, now);
}

/*****************************************************************************/
/* Network functions for clients with the DC_CLIENT_FLAG_IN_SERVER flag */

int DC_SERVER_clients_to_sel(DC_SERVER *ctx, NAL_SELECTOR *sel)
{
	unsigned int idx = 0;
	DC_CLIENT *client;
	while(idx < ctx->clients_used) {
		client = ctx->clients[idx];
		if(client->flags & DC_CLIENT_FLAG_IN_SERVER)
			DC_PLUG_to_select(client->plug, sel);
		idx++;
	}
	return 1;
}

int DC_SERVER_clients_io(DC_SERVER *ctx, NAL_SELECTOR *sel,
				const struct timeval *now)
{
	unsigned int idx = 0;
	DC_CLIENT *client;
	while(idx < ctx->clients_used) {
		client = ctx->clients[idx];
		if((client->flags & DC_CLIENT_FLAG_IN_SERVER) &&
				(!DC_PLUG_io(client->plug, sel) ||
				!DC_SERVER_process_client(client, now)))
			int_server_del_client(ctx, idx);
		else
			idx++;
	}
	return 1;
}
