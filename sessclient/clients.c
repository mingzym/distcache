/* distcache, Distributed Session Caching technology
 * Copyright (C) 2000-2003  Geoff Thorpe, and Cryptographic Appliances, Inc.
 * Copyright (C) 2004       The Distcache.org project
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

#include "private.h"

/* The maximum number of client connections we can serve at a time */
#define CLIENTS_MAX_ITEMS	1024
/* The maximum number of times to retry a request if it deserves retries */
#define CLIENTS_MAX_RETRIES	5

typedef struct st_client_ctx {
	/* A unique id (within each 'clients_t' structure) for this client */
	unsigned long uid;
	/* The "plug" communicating with the client */
	DC_PLUG *plug;
	/* If this value is non-zero, the plug has an in-"read" request (that can
	 * be resumed) that has not been consumed yet. */
	int request_open;
	/* If "request_open", these are the values; */
	unsigned long request_uid;
	DC_CMD request_cmd;
	const unsigned char *request_data;
	unsigned int request_len;
	/* If this value is non-zero, the plug has had its response written but
	 * not yet committed or rollbacked. */
	int response_done;
	/* The multiplex 'id' of the current request, zero if the current
	 * request is not currently forwarded (ie. it's not referred to in the
	 * multiplexer table) */
	unsigned long multiplex_id;
	/* The last time the current request was forwarded, used for
	 * determining if a server has not responded in a suitable timeframe.
	 * Only used if 'multiplexer_id' is non-zero. */
	struct timeval timestamp;
} client_ctx;

struct st_clients_t {
	/* The arry of pointers to client_ctx items */
	client_ctx *items[CLIENTS_MAX_ITEMS];
	/* The number of client_ctx items currently used */
	unsigned int used;
	/* Used to generate 'uid' values for new client_ctx items */
	unsigned long uid_seed;
	/* Used to handle scheduling of the array of clients */
	unsigned int priorities[CLIENTS_MAX_ITEMS];
};

/************************************************/
/* Functions operating on the 'client_ctx' type */

/* This internal logic ensures that, if possible, a request is pulled out of the
 * plug if one hasn't already been. It also handles, if 'response' is non-zero,
 * what to do about committing responses or unwriting them and having them
 * reforwarded. */
static void client_ctx_flush(client_ctx *ctx)
{
	assert(ctx->plug != NULL);
restart:
	if(!ctx->request_open) {
		/* We don't currently have a request to work on */
		ctx->request_open = DC_PLUG_read(ctx->plug, 0,
				&ctx->request_uid,
				&ctx->request_cmd,
				&ctx->request_data,
				&ctx->request_len);
		if(!ctx->request_open)
			return;
		ctx->multiplex_id = 0;
		ctx->response_done = 0;
		if(!DC_PLUG_write(ctx->plug, 0, ctx->request_uid,
					ctx->request_cmd, NULL, 0)) {
			assert(NULL == "shouldn't happen");
			DC_PLUG_consume(ctx->plug);
			ctx->request_open = 0;
		}
		return;
	}
	/* We already had a request ... has it been answered? */
	if(!ctx->response_done)
		/* nope */
		return;
	if(!DC_PLUG_commit(ctx->plug))
		/* Can't commit it at this point */
		return;
	/* Consume the request and go back to the beginning */
	if(!DC_PLUG_consume(ctx->plug)) {
		assert(NULL == "shouldn't happen");
		return;
	}
	ctx->response_done = 0;
	ctx->request_open = 0;
	goto restart;
}

static client_ctx *client_ctx_new(unsigned long uid, NAL_CONNECTION *conn,
				const struct timeval *now)
{
	client_ctx *c = SYS_malloc(client_ctx, 1);
	if(!c)
		return NULL;
	c->uid = uid;
	c->request_open = 0;
	c->response_done = 0;
	c->multiplex_id = 0;
	SYS_timecpy(&c->timestamp, now);
	c->plug = DC_PLUG_new(conn, 0);
	if(!c->plug) {
		SYS_free(client_ctx, c);
		return NULL;
	}
	return c;
}

static void client_ctx_free(client_ctx *c)
{
	DC_PLUG_free(c->plug);
	SYS_free(client_ctx, c);
}

static int client_ctx_io(client_ctx *c)
{
	assert(c->plug != NULL);
	if(!DC_PLUG_io(c->plug))
		return 0;
	client_ctx_flush(c);
	return 1;
}

static void client_ctx_digest_response(client_ctx *ctx,
			DC_CMD cmd,
			const unsigned char *data,
			unsigned int data_len)
{
	assert(ctx->response_done == 0);
	assert(ctx->request_open != 0);
	assert(ctx->plug != NULL);
	assert(ctx->request_cmd == cmd);
	/* Add the data in. NB: Even if the write_more doesn't work, we still
	 * need to unblock the current situation and return *something* (let the
	 * client worry about it!). */
	if(data_len)
		DC_PLUG_write_more(ctx->plug, data, data_len);
	ctx->response_done = 1;
	client_ctx_flush(ctx);
}

static int client_ctx_should_timeout(client_ctx *c, unsigned long idle_timeout,
			const struct timeval *now)
{
	/* If we have a request (whether forwarded or not), don't "idle-timeout"
	 * this client connection. */
	if(c->request_open)
		return 0;
	/* Check the time-interval */
	return SYS_expirycheck(&c->timestamp, idle_timeout, now);
}

/*************************************************************************/
/* Functions operation in the 'priorities' array of the 'clients_t' type */

static void priority_removed(clients_t *c, unsigned int idx)
{
	unsigned int *p_iterate = c->priorities;
	unsigned int iterate = 0;
	int convertedfound = 0;
	unsigned int converted = c->priorities[idx];

	assert(c->used >= idx);
	while(iterate < c->used) {
		/* If convertedfound is non-zero, we move priorities[x+1] to
		 * priorities[x] with a decrement if the value exceeds
		 * converted. If convertedfound is zero, we either decrement
		 * priorities[x] (if the value exceeds converted), leave
		 * priorities[x] alone (if the value is less than converted), or
		 * set convertedfound. */
		if(convertedfound) {
just_found:
			p_iterate[0] = p_iterate[1];
			assert(p_iterate[0] != converted);
			if(p_iterate[0] > converted)
				p_iterate[0]--;
		} else {
			if(p_iterate[0] == converted) {
				convertedfound = 1;
				goto just_found;
			} else if(p_iterate[0] > converted)
				p_iterate[0]--;
		}
		iterate++;
		p_iterate++;
	}
	/* Either 'converted' was found, or it was already the last entry in the
	 * array and therefore wasn't touched */
	assert(convertedfound || (*p_iterate == converted));
}

static void priority_totail(clients_t *c, unsigned int pre_index)
{
	if(pre_index + 1 < c->used) {
		/* The item wasn't already at the end of the priority array, so
		 * store it, scroll everything else, then dump it at the tail */
		unsigned int tmp = c->priorities[pre_index];
		SYS_memmove_n(unsigned int, c->priorities + pre_index,
				c->priorities + (pre_index + 1),
				c->used - (pre_index + 1));
		c->priorities[c->used - 1] = tmp;
	}
}

/***********************************************/
/* Functions operating on the 'clients_t' type */

static int int_find(clients_t *c, unsigned long client_uid, unsigned int *pos)
{
	unsigned int idx = 0;
	client_ctx **item = c->items;
	while(idx < c->used) {
		if((*item)->uid == client_uid) {
			*pos = idx;
			return 1;
		}
		if((*item)->uid > client_uid)
			return 0;
		idx++;
		item++;
	}
	return 0;
}

clients_t *clients_new(void)
{
	clients_t *c = SYS_malloc(clients_t, 1);
	if(!c)
		return NULL;
	c->used = 0;
	c->uid_seed = 1;
	return c;
}

void clients_free(clients_t *c)
{
	while(c->used > 0)
		client_ctx_free(c->items[--c->used]);
	SYS_free(clients_t, c);
}

int clients_empty(const clients_t *c)
{
	return !c->used;
}

static void clients_delete(clients_t *c, unsigned int idx, multiplexer_t *m)
{
	client_ctx **ctx = c->items + idx;

#ifdef CLIENTS_PRINT_CONNECTS
	SYS_fprintf(SYS_stderr, "Info: dead client connection (%u)\n", idx);
#endif
	/* Notify the multiplexer */
	multiplexer_mark_dead_client(m, (*ctx)->uid);
	/* Clean up the client_ctx */
	client_ctx_free(*ctx);
	/* adjust the array */
	if(idx + 1 < c->used)
		SYS_memmove_n(client_ctx *, ctx, (const client_ctx **)ctx + 1,
				c->used - (idx + 1));
	c->used--;
	/* correct the priority array */
	priority_removed(c, idx);
}

int clients_io(clients_t *c, multiplexer_t *m, const struct timeval *now,
			unsigned long idle_timeout)
{
	unsigned int pos = 0;
	while(pos < c->used) {
		if(!client_ctx_io(c->items[pos]) || (idle_timeout &&
				client_ctx_should_timeout(c->items[pos],
					idle_timeout, now)))
			clients_delete(c, pos, m);
		else
			pos++;
	}
	return 1;
}

int clients_new_client(clients_t *c, NAL_CONNECTION *conn,
			const struct timeval *now)
{
	client_ctx **item = c->items + c->used;

	if(c->used >= CLIENTS_MAX_ITEMS) {
		SYS_fprintf(SYS_stderr, "Error, rejected new client connection "
				"already at maximum (%u)\n", CLIENTS_MAX_ITEMS);
		return 0;
	}
	*item = client_ctx_new(c->uid_seed, conn, now);
	if(*item == NULL) {
		SYS_fprintf(SYS_stderr, "Error, initialisation of new client "
				"connection failed\n");
		return 0;
	}
	c->uid_seed++;
	if(c->uid_seed == 0)
		/* eek! Just do the best we can */
		c->uid_seed = 1;
	/* Get this client into the priority table */
	c->priorities[c->used] = c->used;
	c->used++;
#ifdef CLIENTS_PRINT_CONNECTS
	SYS_fprintf(SYS_stderr, "Info: new client connection (%u)\n", c->used);
#endif
	return 1;
}

int clients_to_server(clients_t *c, server_t *s, multiplexer_t *m,
			const struct timeval *now)
{
	/* The sliding window has this left edge of the priorities array that
	 * lies after high-priority clients that can't provide any more
	 * requests. */
	unsigned int edge_l = 0;
	while(edge_l < c->used) {
		unsigned long m_uid;
		unsigned int client_idx;
		client_ctx *ctx;
restart_loop:
		client_idx = c->priorities[edge_l];
		ctx = c->items[client_idx];
		/* If the multiplex table won't take another request, we can
		 * abandon now */
		if(!multiplexer_has_space(m))
			return 1;
		/* If this context has no request or its request is already
		 * in-progress, skip it and don't come back */
		if(!ctx->request_open || ctx->multiplex_id)
			goto skip;
		if(!server_is_active(s)) {
			/* doomed */
			client_ctx_digest_response(ctx, ctx->request_cmd, NULL, 0);
			goto responded_locally;
		}
		m_uid = multiplexer_add(m, ctx->uid, server_get_uid(s));
		if(!server_place_request(s, m_uid, ctx->request_cmd,
				ctx->request_data, ctx->request_len)) {
			/* There wasn't room so the server won't take this or
			 * any other request. */
			multiplexer_delete_item(m, m_uid);
			return 1;
		}
		ctx->multiplex_id = m_uid;
		SYS_timecpy(&ctx->timestamp, now);
responded_locally:
		/* Adjust priorities and continue */
		priority_totail(c, edge_l);
		goto restart_loop;
skip:
		/* Skip this context and ensure we don't revisit it */
		edge_l++;
	}
	return 1;
}

void clients_digest_response(clients_t *c, unsigned long client_uid,
				DC_CMD cmd,
				const unsigned char *data,
				unsigned int data_len)
{
	unsigned int idx;
	if(!int_find(c, client_uid, &idx)) {
		assert(NULL == "shouldn't happen!");
		return;
	}
	client_ctx_digest_response(c->items[idx], cmd, data, data_len);
}

void clients_digest_error(clients_t *c, unsigned long client_uid)
{
	static const unsigned char errbyte = DC_ERR_DISCONNECTED;
	client_ctx *ctx;
	unsigned int idx;
	if(!int_find(c, client_uid, &idx)) {
		assert(NULL == "shouldn't happen!");
		return;
	}
	ctx = c->items[idx];
	client_ctx_digest_response(ctx, ctx->request_cmd, &errbyte, 1);
}
