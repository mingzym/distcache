/* distcache, Distributed Session Caching technology
 * Copyright (C) 2000-2004  Geoff Thorpe, and Cryptographic Appliances, Inc.
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

#define SYS_GENERATING_LIB

#include <libsys/pre.h>
#include <libnal/nal.h>
#include "nal_internal.h"
#include "ctrl_fd.h"
#include <libsys/post.h>

/**************************/
/* predeclare our vtables */
/**************************/

/* Predeclare the address functions */
static int addr_on_create(NAL_ADDRESS *addr);
static void addr_on_destroy(NAL_ADDRESS *addr);
static int addr_parse(NAL_ADDRESS *addr, const char *addr_string);
static int addr_can_connect(const NAL_ADDRESS *addr);
static int addr_can_listen(const NAL_ADDRESS *addr);
static const NAL_LISTENER_vtable *addr_create_listener(const NAL_ADDRESS *addr);
static const NAL_CONNECTION_vtable *addr_create_connection(const NAL_ADDRESS *addr);
static const char *addr_prefixes[] = {"FD:", NULL};
typedef struct st_addr_ctx {
	int fd_read;
	int fd_send;
} addr_ctx;
extern NAL_ADDRESS_vtable builtin_fd_addr_vtable;
NAL_ADDRESS_vtable builtin_fd_addr_vtable = {
	"proto_fd",
	sizeof(addr_ctx),
	addr_prefixes,
	addr_on_create,
	addr_on_destroy,
	addr_on_destroy, /* destroy==reset */
	NULL, /* pre_close */
	addr_parse,
	addr_can_connect,
	addr_can_listen,
	addr_create_listener,
	addr_create_connection,
	NULL
};

/* Predeclare the listener functions */
static int list_on_create(NAL_LISTENER *l);
static void list_on_destroy(NAL_LISTENER *l);
static int list_listen(NAL_LISTENER *l, const NAL_ADDRESS *addr);
static const NAL_CONNECTION_vtable *list_pre_accept(NAL_LISTENER *l);
static int list_finished(const NAL_LISTENER *l);
static int list_pre_selector_add(NAL_LISTENER *, NAL_SELECTOR *);
static void list_post_selector_del(NAL_LISTENER *, NAL_SELECTOR *);
static void list_pre_select(NAL_LISTENER *, NAL_SELECTOR *, NAL_SELECTOR_TOKEN);
static void list_post_select(NAL_LISTENER *, NAL_SELECTOR *, NAL_SELECTOR_TOKEN);
/* This is the type we attach to our listeners */
typedef struct st_list_ctx {
	/* We accept only once */
	int accepted;
	int fd_read;
	int fd_send;
} list_ctx;
static const NAL_LISTENER_vtable list_vtable = {
	sizeof(list_ctx),
	list_on_create,
	list_on_destroy,
	list_on_destroy, /* reset==destroy */
	NULL, /* pre_close */
	list_listen,
	list_pre_accept,
	list_finished,
	list_pre_selector_add,
	NULL, /* post_selector_add */
	NULL, /* pre_selector_del */
	list_post_selector_del,
	list_pre_select,
	list_post_select,
	NULL, /* set_fs_owner */
	NULL  /* set_fs_perms */
};

/* Predeclare the connection functions */
static int conn_on_create(NAL_CONNECTION *conn);
static void conn_on_destroy(NAL_CONNECTION *conn);
static void conn_on_reset(NAL_CONNECTION *conn);
static int conn_connect(NAL_CONNECTION *conn, const NAL_ADDRESS *addr);
static int conn_accept(NAL_CONNECTION *conn, const NAL_LISTENER *l);
static int conn_set_size(NAL_CONNECTION *conn, unsigned int size);
static NAL_BUFFER *conn_get_read(const NAL_CONNECTION *conn);
static NAL_BUFFER *conn_get_send(const NAL_CONNECTION *conn);
static int conn_is_established(const NAL_CONNECTION *conn);
static int conn_pre_selector_add(NAL_CONNECTION *, NAL_SELECTOR *);
static void conn_post_selector_del(NAL_CONNECTION *, NAL_SELECTOR *);
static void conn_pre_select(NAL_CONNECTION *, NAL_SELECTOR *, NAL_SELECTOR_TOKEN);
static void conn_post_select(NAL_CONNECTION *, NAL_SELECTOR *, NAL_SELECTOR_TOKEN);
static int conn_do_io(NAL_CONNECTION *);
/* This is the type we attach to our connections */
typedef struct st_conn_ctx {
	int fd_read;
	int fd_send;
	unsigned char flags;
	NAL_BUFFER *b_read;
	NAL_BUFFER *b_send;
} conn_ctx;
static const NAL_CONNECTION_vtable conn_vtable = {
	sizeof(conn_ctx),
	conn_on_create,
	conn_on_destroy,
	conn_on_reset,
	NULL, /* pre_close */
	conn_connect,
	conn_accept,
	conn_set_size,
	conn_get_read,
	conn_get_send,
	conn_is_established,
	conn_pre_selector_add,
	NULL, /* post_selector_add */
	NULL, /* pre_selector_del */
	conn_post_selector_del,
	conn_pre_select,
	conn_post_select,
	conn_do_io
};

/**************************************/
/* Implementation of address handlers */
/**************************************/

static int addr_on_create(NAL_ADDRESS *addr)
{
	addr_ctx *ctx = nal_address_get_vtdata(addr);
	ctx->fd_read = ctx->fd_send = -1;
	return 1;
}

static void addr_on_destroy(NAL_ADDRESS *addr)
{
	addr_ctx *ctx = nal_address_get_vtdata(addr);
	ctx->fd_read = ctx->fd_send = -1;
}

static int addr_parse(NAL_ADDRESS *addr, const char *addr_string)
{
	char *tmp_ptr;
	addr_ctx *ctx;
	long conv_val;

	/* The addresses we support all start with a protocol followed by a
	 * colon. */
	tmp_ptr = strchr(addr_string, ':');
	if(!tmp_ptr) return 0;
	/* Retrieve the context we keep attached to NAL_ADDRESS */
	ctx = nal_address_get_vtdata(addr);
	/* Point to what remains after the ':' */
	addr_string = tmp_ptr + 1;
	conv_val = strtol(addr_string, &tmp_ptr, 10);
	if(!tmp_ptr || (tmp_ptr == addr_string)) return 0;
	if(((conv_val == LONG_MIN) || (conv_val == LONG_MAX)) &&
			(errno == ERANGE)) return 0;
	if((conv_val < -1) && (errno == EINVAL)) return 0;
	if(conv_val > 65535) return 0;
	switch(*tmp_ptr) {
	case '\0':
		/* we can't use -1 for both directions. */
		if(conv_val < 0) return 0;
		ctx->fd_read = ctx->fd_send = (int)conv_val;
		return 1;
	case ':':
		ctx->fd_read = (int)conv_val;
		break;
	default:
		return 0;
	}
	/* Repeat the above for the second fd */
	addr_string = tmp_ptr + 1;
	conv_val = strtol(addr_string, &tmp_ptr, 10);
	if(!tmp_ptr || (tmp_ptr == addr_string)) return 0;
	if(((conv_val == LONG_MIN) || (conv_val == LONG_MAX)) &&
			(errno == ERANGE)) return 0;
	if((conv_val < -1) && (errno == EINVAL)) return 0;
	if(conv_val > 65535) return 0;
	if(*tmp_ptr != '\0') return 0;
	/* we can't use -1 for both directions. */
	if((ctx->fd_read < 0) && (conv_val < 0)) return 0;
	ctx->fd_send = (int)conv_val;
	/* Success */
	return 1;
}

static int addr_can_connect(const NAL_ADDRESS *addr)
{
	return 1;
}

static int addr_can_listen(const NAL_ADDRESS *addr)
{
	return 1;
}

static const NAL_LISTENER_vtable *addr_create_listener(const NAL_ADDRESS *addr)
{
	return &list_vtable;
}

static const NAL_CONNECTION_vtable *addr_create_connection(const NAL_ADDRESS *addr)
{
	return &conn_vtable;
}

/******************************************/
/* Implementation of list_vtable handlers */
/******************************************/

static int list_on_create(NAL_LISTENER *l)
{
	list_ctx *ctx = nal_listener_get_vtdata(l);
	ctx->fd_read = ctx->fd_send = -1;
	return 1;
}

static void list_on_destroy(NAL_LISTENER *l)
{
	list_ctx *ctx = nal_listener_get_vtdata(l);
	ctx->fd_read = ctx->fd_send = -1;
}

static int list_listen(NAL_LISTENER *l, const NAL_ADDRESS *addr)
{
	addr_ctx *ctx_addr = nal_address_get_vtdata(addr);
	list_ctx *ctx_list = nal_listener_get_vtdata(l);
	ctx_list->fd_read = ctx_addr->fd_read;
	ctx_list->fd_send = ctx_addr->fd_send;
	ctx_list->accepted = 0;
	return 1;
}

static const NAL_CONNECTION_vtable *list_pre_accept(NAL_LISTENER *l)
{
	list_ctx *ctx = nal_listener_get_vtdata(l);
	if(ctx->accepted == 1) {
		ctx->accepted = 2;
		return &conn_vtable;
	}
	return NULL;
}

static int list_finished(const NAL_LISTENER *l)
{
	list_ctx *ctx = nal_listener_get_vtdata(l);
	return ctx->accepted;
}

static int list_pre_selector_add(NAL_LISTENER *l, NAL_SELECTOR *sel)
{
	switch(nal_selector_get_type(sel)) {
	case NAL_SELECTOR_TYPE_FDSELECT:
	case NAL_SELECTOR_TYPE_FDPOLL:
		return 1;
	case NAL_SELECTOR_TYPE_DYNAMIC:
		return nal_selector_dynamic_set(sel, NAL_SELECTOR_VT_DEFAULT());
	default:
		break;
	}
	return 0;
}

static void list_post_selector_del(NAL_LISTENER *l, NAL_SELECTOR *sel)
{
	/* nop */
}

static void list_pre_select(NAL_LISTENER *l, NAL_SELECTOR *sel,
			NAL_SELECTOR_TOKEN tok)
{
	list_ctx *ctx = nal_listener_get_vtdata(l);
	/* We fake things out by selecting for readability on the read socket
	 * if we haven't yet accepted. That way, it will appear that we receive
	 * "the connection" when the first data arrives. (Not perfect, but
	 * better than deadlocking.) */
	if(!ctx->accepted)
		nal_selector_fd_set(sel, tok, ctx->fd_read, SELECTOR_FLAG_READ);
}

static void list_post_select(NAL_LISTENER *l, NAL_SELECTOR *sel,
			NAL_SELECTOR_TOKEN tok)
{
	unsigned char flags;
	list_ctx *ctx = nal_listener_get_vtdata(l);
	if(ctx->accepted) return;
	nal_selector_fd_test(&flags, sel, tok, ctx->fd_read);
	if(flags & SELECTOR_FLAG_READ) ctx->accepted = 1;
}

/******************************************/
/* Implementation of conn_vtable handlers */
/******************************************/

/* internal function shared by conn_connect and conn_accept */
static int conn_ctx_setup(conn_ctx *ctx_conn, int fd_read, int fd_send,
				unsigned int buf_size)
{
	if((fd_read != -1) && !NAL_BUFFER_set_size(ctx_conn->b_read, buf_size))
		return 0;
	if((fd_send != -1) && !NAL_BUFFER_set_size(ctx_conn->b_send, buf_size))
		return 0;
	ctx_conn->fd_read = fd_read;
	ctx_conn->fd_send = fd_send;
	return 1;
}

static int conn_on_create(NAL_CONNECTION *conn)
{
	conn_ctx *ctx = nal_connection_get_vtdata(conn);
	if(!ctx->b_read) ctx->b_read = NAL_BUFFER_new();
	if(!ctx->b_send) ctx->b_send = NAL_BUFFER_new();
	if(!ctx->b_read || !ctx->b_send) return 0;
	ctx->fd_read = -1;
	ctx->fd_send = -1;
	return 1;
}

static void conn_on_destroy(NAL_CONNECTION *conn)
{
	conn_ctx *ctx = nal_connection_get_vtdata(conn);
	nal_fd_close(&ctx->fd_read);
	nal_fd_close(&ctx->fd_send);
	NAL_BUFFER_free(ctx->b_read);
	NAL_BUFFER_free(ctx->b_send);
}

static void conn_on_reset(NAL_CONNECTION *conn)
{
	conn_ctx *ctx = nal_connection_get_vtdata(conn);
	nal_fd_close(&ctx->fd_read);
	nal_fd_close(&ctx->fd_send);
	NAL_BUFFER_reset(ctx->b_read);
	NAL_BUFFER_reset(ctx->b_send);
	ctx->flags = 0;
}

static int conn_connect(NAL_CONNECTION *conn, const NAL_ADDRESS *addr)
{
	const addr_ctx *ctx_addr = nal_address_get_vtdata(addr);
	conn_ctx *ctx_conn = nal_connection_get_vtdata(conn);
	if((ctx_addr->fd_read != -1) && !nal_fd_make_non_blocking(ctx_addr->fd_read, 1))
		return 0;
	if((ctx_addr->fd_send != -1) && !nal_fd_make_non_blocking(ctx_addr->fd_send, 1))
		return 0;
	if(!conn_ctx_setup(ctx_conn, ctx_addr->fd_read, ctx_addr->fd_send,
				NAL_ADDRESS_get_def_buffer_size(addr)))
		return 0;
	return 1;
}

static int conn_accept(NAL_CONNECTION *conn, const NAL_LISTENER *l)
{
	list_ctx *ctx_list = nal_listener_get_vtdata(l);
	conn_ctx *ctx_conn = nal_connection_get_vtdata(conn);
	if(ctx_list->accepted != 2)
		return 0;
	if((ctx_list->fd_read != -1) && !nal_fd_make_non_blocking(ctx_list->fd_read, 1))
		return 0;
	if((ctx_list->fd_send != -1) && !nal_fd_make_non_blocking(ctx_list->fd_send, 1))
		return 0;
	if(!conn_ctx_setup(ctx_conn, ctx_list->fd_read, ctx_list->fd_send,
				nal_listener_get_def_buffer_size(l)))
		return 0;
	ctx_list->accepted = 2;
	return 1;
}

static int conn_set_size(NAL_CONNECTION *conn, unsigned int size)
{
	conn_ctx *ctx_conn = nal_connection_get_vtdata(conn);
	if((ctx_conn->fd_read != -1) && !NAL_BUFFER_set_size(ctx_conn->b_read, size))
		return 0;
	if((ctx_conn->fd_send != -1) && !NAL_BUFFER_set_size(ctx_conn->b_send, size))
		return 0;
	return 1;
}

static NAL_BUFFER *conn_get_read(const NAL_CONNECTION *conn)
{
	conn_ctx *ctx_conn = nal_connection_get_vtdata(conn);
	return ctx_conn->b_read;
}

static NAL_BUFFER *conn_get_send(const NAL_CONNECTION *conn)
{
	conn_ctx *ctx_conn = nal_connection_get_vtdata(conn);
	return ctx_conn->b_send;
}

static int conn_is_established(const NAL_CONNECTION *conn)
{
	return 1;
}

static int conn_pre_selector_add(NAL_CONNECTION *conn, NAL_SELECTOR *sel)
{
	switch(nal_selector_get_type(sel)) {
	case NAL_SELECTOR_TYPE_FDSELECT:
	case NAL_SELECTOR_TYPE_FDPOLL:
		return 1;
	case NAL_SELECTOR_TYPE_DYNAMIC:
		return nal_selector_dynamic_set(sel, NAL_SELECTOR_VT_DEFAULT());
	default:
		break;
	}
	return 0;
}

static void conn_post_selector_del(NAL_CONNECTION *conn, NAL_SELECTOR *sel)
{
	conn_ctx *ctx = nal_connection_get_vtdata(conn);
	ctx->flags = 0;
}

static void conn_pre_select(NAL_CONNECTION *conn, NAL_SELECTOR *sel,
			NAL_SELECTOR_TOKEN token)
{
	conn_ctx *ctx = nal_connection_get_vtdata(conn);
	unsigned char rflag =
		(NAL_BUFFER_notfull(ctx->b_read) ?  SELECTOR_FLAG_READ : 0);
	unsigned char sflag =
		(NAL_BUFFER_notempty(ctx->b_send) ?  SELECTOR_FLAG_SEND : 0);
	if(ctx->fd_read == ctx->fd_send) {
		if(ctx->fd_read != -1)
			nal_selector_fd_set(sel, token, ctx->fd_read,
					rflag | sflag | SELECTOR_FLAG_EXCEPT);
	} else {
		if(ctx->fd_read != -1)
			nal_selector_fd_set(sel, token, ctx->fd_read,
					rflag | SELECTOR_FLAG_EXCEPT);
		if(ctx->fd_send != -1)
			nal_selector_fd_set(sel, token, ctx->fd_send,
					sflag | SELECTOR_FLAG_EXCEPT);
	}
}

static void conn_post_select(NAL_CONNECTION *conn, NAL_SELECTOR *sel,
			NAL_SELECTOR_TOKEN token)
{
	conn_ctx *ctx = nal_connection_get_vtdata(conn);
	if(ctx->fd_read == ctx->fd_send) {
		if(ctx->fd_read != -1)
			nal_selector_fd_test(&ctx->flags, sel, token, ctx->fd_read);
	} else {
		ctx->flags = 0;
		if(ctx->fd_read != -1)
			nal_selector_fd_test(&ctx->flags, sel, token, ctx->fd_read);
		if(ctx->fd_send != -1)
			nal_selector_fd_test(&ctx->flags, sel, token, ctx->fd_send);
	}
}

static int conn_do_io(NAL_CONNECTION *conn)
{
	conn_ctx *ctx = nal_connection_get_vtdata(conn);
	if(ctx->flags & SELECTOR_FLAG_EXCEPT) return 0;
	if(ctx->flags & SELECTOR_FLAG_READ) {
		int io_ret = nal_fd_buffer_from_fd(ctx->b_read, ctx->fd_read, 0);
		/* zero shouldn't happen if we're readable, and negative is err */
		if(io_ret <= 0)
			return 0;
	}
	if(ctx->flags & SELECTOR_FLAG_SEND) {
		int io_ret = nal_fd_buffer_to_fd(ctx->b_send, ctx->fd_send, 0);
		if(io_ret <= 0)
			return 0;
	}
	return 1;
}

