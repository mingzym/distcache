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
#include <libdistcache/dc_client.h>
#include <libdistcache/dc_enc.h>

/* How big connection's buffers should be */
#define DC_CTX_BUFFER_SIZE		4096
/* When parsing a series of (framed) responses, we concatenate payload into an
 * expanding array - it starts at this size then grows 50% each time. */
#define DC_RET_START_SIZE		2048

/***************************************/
/* The "DC_CTX" structure details */

struct st_DC_CTX {
	NAL_ADDRESS *address;
	DC_PLUG *plug;
	unsigned int flags;
	pid_t current_pid;
	/* State for the DC_CTX_reget_session() handling */
	unsigned int last_op_was_get;
	unsigned char last_get_id[DC_MAX_ID_LEN];
	unsigned int last_get_id_len;
	/* Storage for received data (from the plug) */
	unsigned char read_data[DC_MAX_TOTAL_DATA];
	unsigned int read_data_len;
	/* Storage for sent data (to go to the plug) */
	unsigned char send_data[DC_MAX_TOTAL_DATA];
	unsigned int send_data_len;
};

/****************************************/
/* Internal networking helper functions */

static DC_PLUG *int_temp_connect(DC_CTX *ctx)
{
	NAL_CONNECTION *conn;
	DC_PLUG *plug;
	if(((conn = NAL_CONNECTION_malloc()) != NULL) &&
			NAL_CONNECTION_create(conn, ctx->address) &&
			((plug = DC_PLUG_new(conn,
				DC_PLUG_FLAG_TO_SERVER)) != NULL))
		return plug;
	if(conn)
		NAL_CONNECTION_free(conn);
	return NULL;
}

static int int_connect(DC_CTX *ctx)
{
	/* Cleanup any previous connection */
	if(ctx->plug) {
		DC_PLUG_free(ctx->plug);
		ctx->plug = NULL;
	}
	if((ctx->plug = int_temp_connect(ctx)) == NULL)
		return 0;
	return 1;
}

static int int_netloop(DC_PLUG *plug, NAL_SELECTOR *sel)
{
	int ret;
	if(!DC_PLUG_to_select(plug, sel))
		return 0;
reselect:
	ret = NAL_SELECTOR_select(sel, 0, 0);
	if((ret < 0) && (errno != EINTR))
		return 0;
	if(ret <= 0)
		goto reselect;
	if(!DC_PLUG_io(plug, sel))
		return 0;
	return 1;
}

/**************************************************************************
 * The core "operation" function. Takes a command type and input data and *
 * generates return data. Handles generating request frames, interpreting *
 * response frames, and all network logic.                                */
static unsigned long global_uid = 1;

static int int_transact(DC_CTX *ctx, DC_CMD cmd)
{
	DC_PLUG *plug;
	NAL_SELECTOR *sel;
	DC_CMD check_cmd;
	const unsigned char *ret_data;
	unsigned int ret_len;
	pid_t pid;
	int toreturn = 0;
	int retried = 0;
	/* The request_uid for this transaction */
	unsigned long check_uid, request_uid = global_uid++;

	/* This is the point where if the previous operation was a "get" but
	 * this one is not, we will cancel our "last_get" state. This means that
	 * even if something fails here, a "reget" call to followup on the last
	 * "get" will fail. If that's a problem - don't try and do failed
	 * (non-get) operations inbetween "get" and "reget" and wonder why it
	 * doesn't work! :-) */
	if(cmd != DC_CMD_GET)
		ctx->last_op_was_get = 0;
	/* Reset our buffer for incoming data */
	ctx->read_data_len = 0;
	/* Handle connection logic based on flags */
	if(ctx->flags & DC_CTX_FLAG_PERSISTENT) {
		/* (re)connect due to 'pid' or 'late' checks? */
		if(((ctx->flags & DC_CTX_FLAG_PERSISTENT_PIDCHECK) &&
				((pid = NAL_getpid()) != ctx->current_pid)) ||
				((ctx->flags & DC_CTX_FLAG_PERSISTENT_LATE)
					&& !ctx->plug)) {
			if(!int_connect(ctx))
				return 0;
		}
		plug = ctx->plug;
	} else {
		/* Get a temporary connection */
		if((plug = int_temp_connect(ctx)) == NULL)
			return 0;
	}
	/* Get our selector ready */
	if((sel = NAL_SELECTOR_malloc()) == NULL)
		goto err;
	/* Do the network loop. This writes "send_data" into the
	 * plug and hopes for a response until either;
	 *  - I/O fails,
	 *  - we receive a "complete" response (if this happens before the
	 *    request is fully sent, it's an error anyway), or
	 *  - we have decoding failures (eg. mismatched request_uids, corrupt
	 *    line-data, etc).
	 */
restart_after_net_err:
	/* Write the request into the plug */
	if(ctx->send_data_len && (!DC_PLUG_write(plug, 0, request_uid, cmd,
				ctx->send_data, ctx->send_data_len) ||
			!DC_PLUG_commit(plug)))
		goto err;
reselect:
	if(!int_netloop(plug, sel))
		goto net_err;
	if(!DC_PLUG_read(plug, 0, &check_uid, &check_cmd,
				&ret_data, &ret_len))
		goto reselect;
	if((check_uid != request_uid) || (check_cmd != cmd) || !ret_data ||
			!ret_len || (ret_len > DC_MAX_TOTAL_DATA))
		goto err;
	ctx->read_data_len = ret_len;
	NAL_memcpy_n(unsigned char, ctx->read_data, ret_data, ret_len);
	/* Success */
	DC_PLUG_consume(plug);
	toreturn = 1;
err:
	/* Data sent (or the whole operation blew up), so reset this */
	ctx->send_data_len = 0;
	/* Cleanup */
	if(sel)
		NAL_SELECTOR_free(sel);
	if(!(ctx->flags & DC_CTX_FLAG_PERSISTENT) && plug)
		DC_PLUG_free(plug);
	return toreturn;
net_err:
	if(retried || !(ctx->flags & DC_CTX_FLAG_PERSISTENT) ||
			!(ctx->flags & DC_CTX_FLAG_PERSISTENT_RETRY))
		goto err;
	/* retry */
	retried = 1;
	if(!int_connect(ctx))
		goto err;
	plug = ctx->plug;
	goto restart_after_net_err;
}

/***************************/
/* Exposed (API) functions */

DC_CTX *DC_CTX_new(const char *target, unsigned int flags)
{
	DC_CTX *ctx = NAL_malloc(DC_CTX, 1);
	if(!ctx)
		goto err;
	ctx->flags = flags;
	ctx->current_pid = NAL_getpid();
	ctx->plug = NULL;
	ctx->last_op_was_get = ctx->last_get_id_len = 0;
	ctx->read_data_len = ctx->send_data_len = 0;
	/* Construct the target address */
	if(((ctx->address = NAL_ADDRESS_malloc()) == NULL) ||
			!NAL_ADDRESS_create(ctx->address, target,
				DC_CTX_BUFFER_SIZE) ||
			!NAL_ADDRESS_can_connect(ctx->address))
		goto err;
	/* Only connect if "PERSISTENT" and not "PERSISTENT_LATE" */
	if(((flags & DC_CTX_FLAG_PERSISTENT) &&
			!(flags & DC_CTX_FLAG_PERSISTENT_LATE)) &&
			!int_connect(ctx))
		goto err;
	/* Success */
	return ctx;
err:
	if(ctx) {
		if(ctx->address)
			NAL_ADDRESS_free(ctx->address);
		if(ctx->plug)
			DC_PLUG_free(ctx->plug);
		NAL_free(DC_CTX, ctx);
	}
	return NULL;
}

void DC_CTX_free(DC_CTX *ctx)
{
	if(ctx->plug)
		DC_PLUG_free(ctx->plug);
	NAL_ADDRESS_free(ctx->address);
	NAL_free(DC_CTX, ctx);
}

int DC_CTX_add_session(DC_CTX *ctx,
			const unsigned char *id_data,
			unsigned int id_len,
			const unsigned char *sess_data,
			unsigned int sess_len,
			unsigned long timeout_msecs)
{
	unsigned char *ptr;
	unsigned int check;
	/* Make sure the input is sensible */
	assert(id_data && sess_data && id_len && sess_len &&
			(id_len <= DC_MAX_TOTAL_DATA) &&
			(timeout_msecs > DC_MIN_TIMEOUT));
	/* We encode "add"s as;
	 *   4 bytes            (timeout)
	 *   4 bytes            (id_len)
	 *   'id_len' bytes     (id_data)
	 *   'sess_len' bytes   (sess_data) */
	ctx->send_data_len = id_len + sess_len + 8;
	/* Check this isn't too big */
	if(ctx->send_data_len > DC_MAX_TOTAL_DATA)
		return 0;
	ptr = ctx->send_data;
	check = ctx->send_data_len;
	if(!NAL_encode_uint32(&ptr, &check, timeout_msecs) ||
			!NAL_encode_uint32(&ptr, &check, id_len))
		return 0;
	assert((check + 8) == ctx->send_data_len);
	assert((ctx->send_data + 8) == ptr);
	/* Copy in the session-id and the session data */
	NAL_memcpy_n(unsigned char, ptr, id_data, id_len);
	ptr += id_len;
	NAL_memcpy_n(unsigned char, ptr, sess_data, sess_len);
	/* Do the network operation */
	if(!int_transact(ctx, DC_CMD_ADD))
		/* The transaction itself failed. */
		return 0;
	/* Does the response look unusual or is it well-formed but indicating an
	 * error? */
	if((ctx->read_data_len != 1) || (ctx->read_data[0] !=
					DC_ERR_OK))
		return 0;
	/* Success! */
	return 1;
}

int DC_CTX_remove_session(DC_CTX *ctx,
			const unsigned char *id_data,
			unsigned int id_len)
{
	/* Check this isn't too big */
	assert(id_data && id_len && (id_len <= DC_MAX_TOTAL_DATA));
	ctx->send_data_len = id_len;
	NAL_memcpy_n(unsigned char, ctx->send_data, id_data, id_len);
	if(!int_transact(ctx, DC_CMD_REMOVE))
		/* The transaction itself failed. */
		return 0;
	/* Does the response look unusual or is it well-formed but indicating an
	 * error? */
	if((ctx->read_data_len != 1) || (ctx->read_data[0] !=
					DC_ERR_OK))
		return 0;
	/* Success! */
	return 1;
}

/* this function saves duplication in "get" and "reget" */
static void get_helper(DC_CTX *ctx, unsigned char *result_storage,
			unsigned int result_size,
			unsigned int *result_used)
{
	/* Even if result_storage==NULL *or* result_size is too small, we will
	 * still populate (*result_used) with the session length so the caller
	 * can make sense of a "short read" if it occurs. */
	*result_used = ctx->read_data_len;
	if(result_storage) {
		unsigned int tocopy = ctx->read_data_len;
		if(tocopy > result_size)
			tocopy = result_size;
		/* Check, in case result_size is zero (should perhaps make that
		 * an error condition ...) */
		if(tocopy)
			NAL_memcpy_n(unsigned char, result_storage,
					ctx->read_data, tocopy);
	}
}

int DC_CTX_get_session(DC_CTX *ctx,
			const unsigned char *id_data,
			unsigned int id_len,
			unsigned char *result_storage,
			unsigned int result_size,
			unsigned int *result_used)
{
	/* Check this isn't too big */
	assert(id_data && id_len && (id_len <= DC_MAX_TOTAL_DATA));
	ctx->send_data_len = id_len;
	NAL_memcpy_n(unsigned char, ctx->send_data, id_data, id_len);
	if(!int_transact(ctx, DC_CMD_GET))
		/* The transaction itself failed. */
		return 0;
	/* Does the response look unusual or is it well-formed but indicating an
	 * error? */
	if(ctx->read_data_len < 5)
		return 0;
	/* Before worrying about whether we return the session (in part or full)
	 * in the caller-provided buffer, cache this operation. That way, the
	 * caller can always come back with a larger buffer in "reget" and we
	 * will not have to touch the network. */
	ctx->last_op_was_get = 1;
	ctx->last_get_id_len = id_len;
	NAL_memcpy_n(unsigned char, ctx->last_get_id, id_data, id_len);
	get_helper(ctx, result_storage, result_size, result_used);
	return 1;
}

int DC_CTX_reget_session(DC_CTX *ctx,
			const unsigned char *id_data,
			unsigned int id_len,
			unsigned char *result_storage,
			unsigned int result_size,
			unsigned int *result_used)
{
	if(!ctx->last_op_was_get)
		/* We don't have a "get" to "reget" */
		return 0;
	if((ctx->last_get_id_len != id_len) ||
			(memcmp(ctx->last_get_id, id_data, id_len) != 0))
		/* The "reget" is for a different session id */
		return 0;
	/* Fine, "ctx->incoming" should still contain the response from the
	 * matching "get" operation. */
	get_helper(ctx, result_storage, result_size, result_used);
	return 1;
}

int DC_CTX_has_session(DC_CTX *ctx,
			const unsigned char *id_data,
			unsigned int id_len)
{
	/* Check this isn't too big */
	assert(id_data && id_len && (id_len <= DC_MAX_TOTAL_DATA));
	ctx->send_data_len = id_len;
	NAL_memcpy_n(unsigned char, ctx->send_data, id_data, id_len);
	if(!int_transact(ctx, DC_CMD_HAVE))
		/* The transaction itself failed. */
		return -1;
	/* Does the response look unusual */
	if(ctx->read_data_len != 1)
		return 0;
	switch(ctx->read_data[0]) {
	case DC_ERR_OK:
		return 1;
	case DC_ERR_NOTOK:
		return 0;
	default:
		break;
	}
	return -1;
}
