/* distcache, Distributed Session Caching technology
 * Copyright (C) 2000-2003  Geoff Thorpe, and Cryptographic Appliances, Inc.
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
#include <libdistcache/dc_enc.h>

/* We can't handle proxying of more than this many connections at a time */
#define SNOOP_MAX_ITEMS		10

/* Our NAL_CONNECTIONs are created with buffers of this size */
#define SNOOP_BUF_SIZE		(3*DC_MSG_MAX_DATA)
/* A connection's send buffer must have at least this much space free before its
 * peer connection will be allowed to select for readability. */
#define SNOOP_BUF_WINDOW	DC_MSG_MAX_DATA

/* When parsing messages, we won't tolerate anything with a 'data_len' greater
 * than this threadhold. */
#define SNOOP_MAX_MSG_DATA	DC_MSG_MAX_DATA

/********************/
/* Debugging macros */
/********************/

#define SNOOP_DBG_SELECT
#define SNOOP_DBG_CONNS

/* snoop_data_arriving will use this as a return type */
typedef enum {
	SNOOP_PARSE_ERR,
	SNOOP_PARSE_INCOMPLETE,
	SNOOP_PARSE_COMPLETE
} snoop_parse_t;

typedef struct st_snoop_item {
	/* Our traffic proxying is always direct between these two */
	NAL_CONNECTION *client;
	NAL_CONNECTION *server;
	/* Before client->server traffic forwarding, we supplement this buffer
	 * for tracing. */
	unsigned char buf_client[DC_MSG_MAX_DATA];
	unsigned int buf_client_used;
	/* Before server->client forwarding, we supplement this one. */
	unsigned char buf_server[DC_MSG_MAX_DATA];
	unsigned int buf_server_used;
} snoop_item;

typedef struct st_snoop_ctx {
	/* Our listener */
	NAL_LISTENER *list;
	/* Our destination proxy address */
	NAL_ADDRESS *addr;
	/* Our selector */
	NAL_SELECTOR *sel;
	/* An array of snoop-items */
	snoop_item items[SNOOP_MAX_ITEMS];
	unsigned int items_used;
	/* Our flags */
	unsigned int flags;
	/* A temporary connection for accepting incoming connections */
	NAL_CONNECTION *newclient;
} snoop_ctx;

/* Flags to control output */
#define SNOOP_FLAG_IO		(unsigned int)0x0001	/* Dump read/write counts */
#define SNOOP_FLAG_MSG		(unsigned int)0x0002	/* Note completed messages */
#define SNOOP_FLAG_MSG_DETAIL	(unsigned int)0x0004	/* Dump complete messages */

static const char *def_listen = NULL;
static const char *def_connect = NULL;
static const unsigned int def_flags = 0;

/* Avoid the dreaded "greater than the length `509' ISO C89 compilers are
 * required to support" warning by splitting this into an array of strings. */
static const char *usage_msg[] = {
"",
"Usage: dc_snoop [options]     where 'options' are from;",
"  -listen <addr>   (accept incoming connections on address 'addr')",
"  -connect <addr>  (proxy incoming connections to server at address 'addr')",
"  -<h|help|?>      (display this usage message)",
"", NULL};

/* Prototypes */
static int do_snoop(const char *addr_connect, const char *addr_listen,
			unsigned int flags);

static int usage(void)
{
	const char **u = usage_msg;
	while(*u)
		NAL_fprintf(NAL_stderr(), "%s\n", *(u++));
	/* Return 0 because main() can use this is as a help
	 * screen which shouldn't return an "error" */
	return 0;
}
static const char *CMD_HELP1 = "-h";
static const char *CMD_HELP2 = "-help";
static const char *CMD_HELP3 = "-?";
static const char *CMD_LISTEN = "-listen";
static const char *CMD_CONNECT = "-connect";

static int err_noarg(const char *arg)
{
	NAL_fprintf(NAL_stderr(), "Error, -%s requires an argument\n", arg);
	usage();
	return 1;
}
#if 0
static int err_badrange(const char *arg)
{
	NAL_fprintf(NAL_stderr(), "Error, -%s given an invalid argument\n", arg);
	usage();
	return 1;
}
#endif
static int err_badswitch(const char *arg)
{
	NAL_fprintf(NAL_stderr(), "Error, \"%s\" not recognised\n", arg);
	usage();
	return 1;
}

/*****************/
/* MAIN FUNCTION */
/*****************/

#define ARG_INC {argc--;argv++;}
#define ARG_CHECK(a) \
	if(argc < 2) \
		return err_noarg(a); \
	ARG_INC

int main(int argc, char *argv[])
{
	/* Overridables */
	const char *addr_listen = def_listen;
	const char *addr_connect = def_connect;
	unsigned int flags = def_flags;

	ARG_INC;
	while(argc > 0) {
		if((strcmp(*argv, CMD_HELP1) == 0) ||
				(strcmp(*argv, CMD_HELP2) == 0) ||
				(strcmp(*argv, CMD_HELP3) == 0))
			return usage();
		else if(strcmp(*argv, CMD_CONNECT) == 0) {
			ARG_CHECK(CMD_CONNECT);
			addr_connect = *argv;
		} else if(strcmp(*argv, CMD_LISTEN) == 0) {
			ARG_CHECK(CMD_LISTEN);
			addr_listen = *argv;
		} else
			return err_badswitch(*argv);
		ARG_INC;
	}

	/* Scrutinise the settings */
	if(!addr_connect || !addr_listen) {
		NAL_fprintf(NAL_stderr(), "Error, must provide -connect and -listen\n");
		return 1;
	}

	if(!NAL_sigpipe_ignore()) {
#if NAL_DEBUG_LEVEL > 0
		NAL_fprintf(NAL_stderr(), "Error, couldn't ignore SIGPIPE\n");
#endif
		return 1;
	}

	return do_snoop(addr_connect, addr_listen, flags);
}

/************************/
/* snoop_item functions */
/************************/

static int snoop_item_init(snoop_item *item, NAL_CONNECTION *accepted,
			const NAL_ADDRESS *addr_connect)
{
	int ret = 0;
	if((item->server = NAL_CONNECTION_malloc()) == NULL) goto err;
	if(!NAL_CONNECTION_create(item->server, addr_connect)) goto err;
	/* Success */
	item->client = accepted;
	item->buf_client_used = item->buf_server_used = 0;
	ret = 1;
err:
	if(!ret) {
		if(item->server) NAL_CONNECTION_free(item->server);
	}
	return ret;
}

static void snoop_item_finish(snoop_item *item)
{
	NAL_CONNECTION_free(item->client);
	NAL_CONNECTION_free(item->server);
}

static int snoop_item_to_sel(snoop_item *item, NAL_SELECTOR *sel)
{
	/* Check 'server' has space in its send buffer before we allow 'client'
	 * to do any reading. */
	if((NAL_BUFFER_unused(NAL_CONNECTION_get_send(item->server)) >=
							SNOOP_BUF_WINDOW) &&
			!NAL_SELECTOR_add_conn(sel, item->client))
		return 0;
	/* Ditto the other way around */
	if((NAL_BUFFER_unused(NAL_CONNECTION_get_send(item->client)) >=
							SNOOP_BUF_WINDOW) &&
			!NAL_SELECTOR_add_conn(sel, item->server))
		return 0;
	return 1;
}

/*
 * unsigned long (4-bytes)              proto_level
 * unsigned char (1-byte)               is_response
 * unsigned long (4-bytes)              request_uid
 * unsigned char (1-byte)               op_class
 * unsigned char (1-byte)               operation
 * unsigned char (1-byte)               complete
 * unsigned int (2-bytes)               data_len    (max: 1024)
 * unsigned char[] ('data_len' bytes)   data
 */
#define BUF_HEADER_SIZE		(4+1+4+1+1+1+2)
#define BUF_HEADER_COMPLETE(n)	((n) < BUF_HEADER_SIZE)

static snoop_parse_t snoop_data_arriving(NAL_CONNECTION *src, NAL_CONNECTION *dest,
			unsigned char *buf, unsigned int *buf_used)
{
	NAL_BUFFER *buf_in = NAL_CONNECTION_get_read(src);
	NAL_BUFFER *buf_out = NAL_CONNECTION_get_send(dest);
	while((NAL_BUFFER_unused(buf_out) >= SNOOP_BUF_WINDOW) &&
			NAL_BUFFER_notempty(buf_in)) {
		unsigned int moved;
		/* This shouldn't happen as we keep our "state-machine"
		 * advanced as far as possible and our SNOOP_BUF_WINDOW logic
		 * should prevent anything jamming here. The testing lower down
		 * should also catch jamming from corrupt wire-data, so this
		 * assert should only catch bugs in snoop code. */
		assert(*buf_used < DC_MSG_MAX_DATA);
		moved = NAL_BUFFER_takedata(buf_in, buf + *buf_used,
					DC_MSG_MAX_DATA - *buf_used);
		assert(moved > 0);
		*buf_used += moved;
		/* This is the single place where we catch the arrival of
		 * *more* data, so it's the single place where we should check
		 * if we can parse a message from the buffer at 'buf'. If we
		 * can, we deal with it and immediately forward it to 'dest'. */
		if(*buf_used < BUF_HEADER_SIZE)
			/* We don't have enough data to parse the header */
			return SNOOP_PARSE_INCOMPLETE;
		{
		/* Use the NAL serialisation code to pull out the data_len
		 * element of the header in network-byte-order. */
		const unsigned char *foop = buf + (BUF_HEADER_SIZE - 2);
		const unsigned char **fooptr = &foop;
		unsigned int foolen = 2;
		unsigned int fooval;
		moved = NAL_decode_uint16(fooptr, &foolen, &fooval);
		assert(moved && (foolen == 0));
		moved = (unsigned int)fooval;
		}
		if(moved > SNOOP_MAX_MSG_DATA) {
			NAL_fprintf(NAL_stderr(), "[TODO: change me] bad message,"
					" data_len=%d\n", moved);
			return SNOOP_PARSE_ERR;
		}
		/* Make moved the length of the whole message, header included */
		moved += BUF_HEADER_SIZE;
		if(*buf_used < moved)
			/* everything seems ok but the data hasn't finished
			 * arriving. */
			return SNOOP_PARSE_INCOMPLETE;
		/* YES, a message! */
		NAL_fprintf(NAL_stdout(), "[TODO: change me] complete message!\n");
		/* Forward the data to 'dest' before pulling it out of 'buf' */
		{
		unsigned int foo = NAL_BUFFER_write(buf_out, buf, moved);
		assert(foo == moved);
		}
		*buf_used -= moved;
		if(*buf_used)
			/* Shift the remaining data left */
			NAL_memcpy_n(unsigned char, buf, buf + moved, *buf_used);
		return SNOOP_PARSE_COMPLETE;
	}
	return SNOOP_PARSE_INCOMPLETE;
}

static int snoop_item_io(snoop_item *item, NAL_SELECTOR *sel)
{
	snoop_parse_t res;
	if(!NAL_CONNECTION_io(item->client, sel) ||
			!NAL_CONNECTION_io(item->server, sel))
		return 0;
	/* Handle client data arriving */
	do {
		res = snoop_data_arriving(item->client, item->server, item->buf_client,
				&item->buf_client_used);
		if(res == SNOOP_PARSE_ERR) {
			NAL_fprintf(NAL_stderr(), "[TODO: change me] client->server error\n");
			return 0;
		}
	} while(res == SNOOP_PARSE_COMPLETE);
	/* And server data arriving */
	do {
		res = snoop_data_arriving(item->server, item->client, item->buf_server,
				&item->buf_server_used);
		if(res == SNOOP_PARSE_ERR) {
			NAL_fprintf(NAL_stderr(), "[TODO: change me] server->client error\n");
			return 0;
		}
	} while(res == SNOOP_PARSE_COMPLETE);
	return 1;
}

/***********************/
/* snoop_ctx functions */
/***********************/

static int snoop_ctx_init(snoop_ctx *ctx, const char *addr_listen,
			const char *addr_connect, unsigned int flags)
{
	int ret = 0;
	NAL_ADDRESS *a;
	ctx->list = NULL;
	ctx->addr = NULL;
	ctx->sel = NULL;
	ctx->newclient = NULL;
	ctx->items_used = 0;
	ctx->flags = flags;
	if((a = NAL_ADDRESS_malloc()) == NULL) goto err;
	if(!NAL_ADDRESS_create(a, addr_listen, SNOOP_BUF_SIZE)) goto err;
	if(!NAL_ADDRESS_can_listen(a)) goto err;
	if((ctx->addr = NAL_ADDRESS_malloc()) == NULL) goto err;
	if(!NAL_ADDRESS_create(ctx->addr, addr_connect, SNOOP_BUF_SIZE)) goto err;
	if(!NAL_ADDRESS_can_connect(ctx->addr)) goto err;
	if((ctx->list = NAL_LISTENER_malloc()) == NULL) goto err;
	if(!NAL_LISTENER_create(ctx->list, a)) goto err;
	if((ctx->sel = NAL_SELECTOR_malloc()) == NULL) goto err;
	if((ctx->newclient = NAL_CONNECTION_malloc()) == NULL) goto err;

	/* Success */
	ret = 1;
err:
	if(a) NAL_ADDRESS_free(a);
	if(!ret) {
		if(ctx->list) NAL_LISTENER_free(ctx->list);
		if(ctx->addr) NAL_ADDRESS_free(ctx->addr);
		if(ctx->sel) NAL_SELECTOR_free(ctx->sel);
		if(ctx->newclient) NAL_CONNECTION_free(ctx->newclient);
	}
	return ret;
}

static void snoop_ctx_finish(snoop_ctx *ctx)
{
#if 0
	exit(0);
#else
	unsigned int loop = 0;
	snoop_item *i = ctx->items;
	NAL_LISTENER_free(ctx->list);
	while(loop++ < ctx->items_used)
		snoop_item_finish(i++);
#endif
}

static int snoop_ctx_to_sel(snoop_ctx *ctx)
{
	unsigned int loop = 0;
	snoop_item *i = ctx->items;
	if((ctx->items_used < SNOOP_MAX_ITEMS) && !NAL_SELECTOR_add_listener(
			ctx->sel, ctx->list))
		return 0;
	while(loop++ < ctx->items_used)
		if(!snoop_item_to_sel(i++, ctx->sel))
			return 0;
	return 1;
}

static int snoop_ctx_io(snoop_ctx *ctx)
{
	unsigned int loop = 0;
	snoop_item *i = ctx->items;
	if(NAL_LISTENER_accept(ctx->list, ctx->sel, ctx->newclient)) {
#ifdef SNOOP_DBG_CONNS
		NAL_fprintf(NAL_stdout(), "SNOOP_DBG_CONNS: connection accepted\n");
#endif
		/* This assert is justified by the fact we don't add the
		 * listener to the selector unless this is already true. */
		assert(ctx->items_used < SNOOP_MAX_ITEMS);
		if(!snoop_item_init(ctx->items + ctx->items_used,
				ctx->newclient, ctx->addr))
			/* The error could be an inability to connect to the
			 * backend server, so we just destroy the
			 * "can't-help-you-right-now" connection and hope for
			 * better luck next time. */
			NAL_CONNECTION_free(ctx->newclient);
		else
			ctx->items_used++;
		ctx->newclient = NAL_CONNECTION_malloc();
		if(!ctx->newclient)
			/* The failure here is malloc and not anything network
			 * related, however this breaks our logic and will
			 * segfault when the next connection arrives, so it's
			 * better to blow up here where the error happened and
			 * not later where the bug will be less obvious. */
			return 0;
	}
	while(loop < ctx->items_used) {
		if(!snoop_item_io(i, ctx->sel)) {
#ifdef SNOOP_DBG_CONNS
			NAL_fprintf(NAL_stdout(), "SNOOP_DBG_CONNS: connection dropped\n");
#endif
			snoop_item_finish(i);
			if(loop + 1 < ctx->items_used)
				NAL_memmove_n(snoop_item, i, i + 1,
						ctx->items_used - (loop + 1));
			ctx->items_used--;
		} else {
			loop++;
			i++;
		}
	}
	return 1;
}

static int snoop_ctx_loop(snoop_ctx *ctx)
{
	int sel_res;
	if(!snoop_ctx_to_sel(ctx)) return 0;
#ifdef SNOOP_DBG_SELECT
	NAL_fprintf(NAL_stdout(), "SNOOP_DBG_SELECT: selecting ...");
	fflush(NAL_stdout());
#endif
	sel_res = NAL_SELECTOR_select(ctx->sel, 0, 0);
#ifdef SNOOP_DBG_SELECT
	NAL_fprintf(NAL_stdout(), "returned %d\n", sel_res);
#endif
	if(sel_res < 0) {
		switch(errno) {
		case EINTR:
			/* hmm, whatever - do nothing */
			return 1;
		case EBADF:
			NAL_fprintf(NAL_stderr(), "Error: EBADF from select()\n");
			break;
		case ENOMEM:
			NAL_fprintf(NAL_stderr(), "Error: ENOMEM from select()\n");
			break;
		default:
			NAL_fprintf(NAL_stderr(), "Error: unknown problem in select()\n");
			break;
		}
		return 0;
	}
	if(sel_res == 0) {
		NAL_fprintf(NAL_stderr(), "Error, select() returned zero?\n");
		return 0;
	}
	return snoop_ctx_io(ctx);
}

/************/
/* do_snoop */
/************/

static int do_snoop(const char *addr_connect, const char *addr_listen,
			unsigned int flags)
{
	snoop_ctx ctx;
	if(!snoop_ctx_init(&ctx, addr_listen, addr_connect, flags))
		return 0;
	while(snoop_ctx_loop(&ctx))
		;
	snoop_ctx_finish(&ctx);
	return 1;
}

