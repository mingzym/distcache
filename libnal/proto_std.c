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

#define SYS_GENERATING_LIB

#include <libsys/pre.h>
#include <libnal/nal.h>
#include "nal_internal.h"
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
static const char *addr_prefixes[] = {"IP:", "IPv4:", "UNIX:", NULL};
extern NAL_ADDRESS_vtable builtin_sock_addr_vtable;
extern NAL_ADDRESS_vtable builtin_fd_addr_vtable;
NAL_ADDRESS_vtable builtin_sock_addr_vtable = {
	"proto_std",
	sizeof(nal_sockaddr),
	addr_prefixes,
	addr_on_create,
	addr_on_destroy,
	addr_on_destroy, /* destroy==reset */
	addr_parse,
	addr_can_connect,
	addr_can_listen,
	addr_create_listener,
	addr_create_connection,
	&builtin_fd_addr_vtable
};

/* Predeclare the listener functions */
static int list_on_create(NAL_LISTENER *l);
static void list_on_destroy(NAL_LISTENER *l);
static int list_listen(NAL_LISTENER *l, const NAL_ADDRESS *addr);
static const NAL_CONNECTION_vtable *list_pre_accept(NAL_LISTENER *l,
						NAL_SELECTOR *sel);
static void list_selector_add(const NAL_LISTENER *l, NAL_SELECTOR *sel);
static void list_selector_del(const NAL_LISTENER *l, NAL_SELECTOR *sel);
static int list_finished(const NAL_LISTENER *l);
static int list_set_fs_owner(NAL_LISTENER *l, const char *ownername,
				const char *groupname);
static int list_set_fs_perms(NAL_LISTENER *l, const char *octal_string);
/* This is the type we attach to our listeners */
typedef struct st_list_ctx {
	int fd;
	nal_sockaddr_type type;
} list_ctx;
static const NAL_LISTENER_vtable list_vtable = {
	sizeof(list_ctx),
	list_on_create,
	list_on_destroy,
	list_on_destroy, /* destroy==reset */
	list_listen,
	list_pre_accept,
	list_selector_add,
	list_selector_del,
	list_finished,
	list_set_fs_owner,
	list_set_fs_perms
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
static int conn_do_io(NAL_CONNECTION *conn, NAL_SELECTOR *sel,
		unsigned int max_read, unsigned int max_send);
static void conn_selector_add(const NAL_CONNECTION *conn, NAL_SELECTOR *sel,
		unsigned int flags);
static void conn_selector_del(const NAL_CONNECTION *conn, NAL_SELECTOR *sel);
/* This is the type we attach to our connections */
typedef struct st_conn_ctx {
	int fd, established;
	NAL_BUFFER *b_read;
	NAL_BUFFER *b_send;
} conn_ctx;
static const NAL_CONNECTION_vtable conn_vtable = {
	sizeof(conn_ctx),
	conn_on_create,
	conn_on_destroy,
	conn_on_reset,
	conn_connect,
	conn_accept,
	conn_set_size,
	conn_get_read,
	conn_get_send,
	conn_is_established,
	conn_do_io,
	conn_selector_add,
	conn_selector_del
};

/***********/
/* globals */
/***********/

/* This flag, if set to zero, will cause new ipv4 connections to have the Nagle
 * algorithm turned off (by setting TCP_NODELAY). */
static int gb_use_nagle = 1;

/*****************/
/* API functions */
/*****************/

void NAL_config_set_nagle(int enabled)
{
	gb_use_nagle = enabled;
}

int NAL_CONNECTION_create_pair(NAL_CONNECTION *conn1,
				NAL_CONNECTION *conn2,
				unsigned int def_buffer_size)
{
	int fds[2];
	conn_ctx *ctx1, *ctx2;
	if(nal_connection_get_vtable(conn1) || nal_connection_get_vtable(conn2))
		return 0;
	if(!nal_connection_set_vtable(conn1, &conn_vtable) ||
			!nal_connection_set_vtable(conn2, &conn_vtable))
		return 0;
	if(!NAL_CONNECTION_set_size(conn1, def_buffer_size) ||
			!NAL_CONNECTION_set_size(conn2, def_buffer_size))
		return 0;
	if(!nal_sock_create_unix_pair(fds))
		return 0;
	if(!nal_fd_make_non_blocking(fds[0], 1) ||
			!nal_fd_make_non_blocking(fds[1], 1) ||
			!nal_sock_set_nagle(fds[0], gb_use_nagle, nal_sockaddr_type_unix) ||
			!nal_sock_set_nagle(fds[1], gb_use_nagle, nal_sockaddr_type_unix)) {
		nal_fd_close(fds);
		nal_fd_close(fds + 1);
		return 0;
	}
	ctx1 = nal_connection_get_vtdata(conn1);
	ctx2 = nal_connection_get_vtdata(conn2);
	ctx1->fd = fds[0];
	ctx2->fd = fds[1];
	ctx1->established = 1;
	ctx2->established = 1;
	return 1;
}

/**************************************/
/* Implementation of address handlers */
/**************************************/

static int addr_on_create(NAL_ADDRESS *addr)
{
	return 1;
}

static void addr_on_destroy(NAL_ADDRESS *addr)
{
}

static int addr_parse(NAL_ADDRESS *addr, const char *addr_string)
{
	char *tmp_ptr;
	nal_sockaddr *ctx;
	int len;

	/* The addresses we support all start with a protocol followed by a
	 * colon. */
	tmp_ptr = strchr(addr_string, ':');
	if(!tmp_ptr) return 0;
	/* How long is the prefix to the ':'? */
	len = (tmp_ptr - addr_string);
	if(len < 1) return 0;
	/* Make 'tmp_ptr' point to what remains after the ':' */
	tmp_ptr++;
	/* Retrieve the context we keep attached to NAL_ADDRESS */
	ctx = nal_address_get_vtdata(addr);
	/* Parse the string */
	if(((len == 4) && (strncmp(addr_string, "IPv4", 4) == 0)) ||
			((len == 2) && (strncmp(addr_string, "IP", 2) == 0))) {
		if(!nal_sock_sockaddr_from_ipv4(ctx, tmp_ptr))
			return 0;
	} else if((len == 4) && (strncmp(addr_string, "UNIX", 4) == 0)) {
		if(!nal_sock_sockaddr_from_unix(ctx, tmp_ptr))
			return 0;
	} else
		/* Unknown prefix */
		return 0;
	/* Success */
	return 1;
}

static int addr_can_connect(const NAL_ADDRESS *addr)
{
	nal_sockaddr *ctx = nal_address_get_vtdata(addr);
	return ((ctx->caps & NAL_ADDRESS_CAN_CONNECT) ? 1 : 0);
}

static int addr_can_listen(const NAL_ADDRESS *addr)
{
	nal_sockaddr *ctx = nal_address_get_vtdata(addr);
	return ((ctx->caps & NAL_ADDRESS_CAN_LISTEN) ? 1 : 0);
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
	return 1;
}

static void list_on_destroy(NAL_LISTENER *l)
{
	list_ctx *ctx = nal_listener_get_vtdata(l);
	nal_fd_close(&ctx->fd);
}

static int list_listen(NAL_LISTENER *l, const NAL_ADDRESS *addr)
{
	nal_sockaddr *ctx_addr = nal_address_get_vtdata(addr);
	list_ctx *ctx_listener = nal_listener_get_vtdata(l);
	ctx_listener->fd = -1;
	if(!nal_sock_create_socket(&ctx_listener->fd, ctx_addr) ||
			!nal_sock_listen(ctx_listener->fd, ctx_addr)) {
		nal_fd_close(&ctx_listener->fd);
		return 0;
	}
	ctx_listener->type = ctx_addr->type;
	return 1;
}

static const NAL_CONNECTION_vtable *list_pre_accept(NAL_LISTENER *l,
						NAL_SELECTOR *sel)
{
	list_ctx *ctx = nal_listener_get_vtdata(l);
	unsigned char flags = nal_selector_fd_test(sel, ctx->fd);
	if(flags & SELECTOR_FLAG_READ)
		return &conn_vtable;
	return NULL;
}

static void list_selector_add(const NAL_LISTENER *l, NAL_SELECTOR *sel)
{
	list_ctx *ctx = nal_listener_get_vtdata(l);
	nal_selector_fd_set(sel, ctx->fd, SELECTOR_FLAG_READ);
}

static void list_selector_del(const NAL_LISTENER *l, NAL_SELECTOR *sel)
{
	list_ctx *ctx = nal_listener_get_vtdata(l);
	nal_selector_fd_unset(sel, ctx->fd);
}

static int list_finished(const NAL_LISTENER *l)
{
	return 0;
}

static int list_set_fs_owner(NAL_LISTENER *l, const char *ownername,
				const char *groupname)
{
	nal_sockaddr sa;
	list_ctx *ctx = nal_listener_get_vtdata(l);
	if(ctx->type != nal_sockaddr_type_unix) return 0;
	if(!nal_sockaddr_get(&sa, ctx->fd)) return 0;
	return nal_sockaddr_chown(&sa, ownername, groupname);
}

static int list_set_fs_perms(NAL_LISTENER *l, const char *octal_string)
{
	nal_sockaddr sa;
	list_ctx *ctx = nal_listener_get_vtdata(l);
	if(ctx->type != nal_sockaddr_type_unix) return 0;
	if(!nal_sockaddr_get(&sa, ctx->fd)) return 0;
	return nal_sockaddr_chmod(&sa, octal_string);
}

/******************************************/
/* Implementation of conn_vtable handlers */
/******************************************/

/* internal function shared by conn_connect and conn_accept */
static int conn_ctx_setup(conn_ctx *ctx_conn, int fd, int established,
				unsigned int buf_size)
{
	if(!NAL_BUFFER_set_size(ctx_conn->b_read, buf_size) ||
			!NAL_BUFFER_set_size(ctx_conn->b_send, buf_size))
		return 0;
	ctx_conn->fd = fd;
	ctx_conn->established = established;
	return 1;
}

static int conn_on_create(NAL_CONNECTION *conn)
{
	conn_ctx *ctx = nal_connection_get_vtdata(conn);
	if(!ctx->b_read) ctx->b_read = NAL_BUFFER_new();
	if(!ctx->b_send) ctx->b_send = NAL_BUFFER_new();
	if(!ctx->b_read || !ctx->b_send) return 0;
	return 1;
}

static void conn_on_destroy(NAL_CONNECTION *conn)
{
	conn_ctx *ctx = nal_connection_get_vtdata(conn);
	nal_fd_close(&ctx->fd);
	NAL_BUFFER_free(ctx->b_read);
	NAL_BUFFER_free(ctx->b_send);
}

static void conn_on_reset(NAL_CONNECTION *conn)
{
	conn_ctx *ctx = nal_connection_get_vtdata(conn);
	nal_fd_close(&ctx->fd);
	NAL_BUFFER_reset(ctx->b_read);
	NAL_BUFFER_reset(ctx->b_send);
}

static int conn_connect(NAL_CONNECTION *conn, const NAL_ADDRESS *addr)
{
	int fd = -1, established;
	const nal_sockaddr *ctx_addr = nal_address_get_vtdata(addr);
	conn_ctx *ctx_conn = nal_connection_get_vtdata(conn);
	if(!nal_sock_create_socket(&fd, ctx_addr) ||
			!nal_fd_make_non_blocking(fd, 1) ||
			!nal_sock_connect(fd, ctx_addr, &established) ||
			!nal_sock_set_nagle(fd, gb_use_nagle, ctx_addr->type) ||
			!conn_ctx_setup(ctx_conn, fd, established,
				NAL_ADDRESS_get_def_buffer_size(addr)))
		goto err;
	return 1;
err:
	nal_fd_close(&fd);
	return 0;
}

static int conn_accept(NAL_CONNECTION *conn, const NAL_LISTENER *l)
{
	int fd = -1;
	list_ctx *ctx_list = nal_listener_get_vtdata(l);
	conn_ctx *ctx_conn = nal_connection_get_vtdata(conn);
	if(!nal_sock_accept(ctx_list->fd, &fd) ||
			!nal_fd_make_non_blocking(fd, 1) ||
			!nal_sock_set_nagle(fd, gb_use_nagle, ctx_list->type) ||
			!conn_ctx_setup(ctx_conn, fd, 1,
				nal_listener_get_def_buffer_size(l)))
		goto err;
	return 1;
err:
	nal_fd_close(&fd);
	return 0;
}

static int conn_set_size(NAL_CONNECTION *conn, unsigned int size)
{
	conn_ctx *ctx_conn = nal_connection_get_vtdata(conn);
	if(!NAL_BUFFER_set_size(ctx_conn->b_read, size) ||
			!NAL_BUFFER_set_size(ctx_conn->b_send, size))
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
	conn_ctx *ctx_conn = nal_connection_get_vtdata(conn);
	return ctx_conn->established;
}

static int conn_do_io(NAL_CONNECTION *conn, NAL_SELECTOR *sel,
		unsigned int max_read, unsigned int max_send)
{
	int nb = 0;
	conn_ctx *ctx = nal_connection_get_vtdata(conn);
	unsigned char flags = nal_selector_fd_test(sel, ctx->fd);
	if(flags & SELECTOR_FLAG_EXCEPT) return 0;
	/* If we're waiting on a non-blocking connect, hook the test here */
	if(!ctx->established) {
		/* We need to be sendable after a non-blocking connect */
		if(!(flags & SELECTOR_FLAG_SEND))
			return 1;
		/* Connect or error? */
		if(!nal_sock_is_connected(ctx->fd))
			return 0;
		ctx->established = 1;
		/* this is the case where sendability is OK when there's
		 * nothing to send */
		nb = 1;
	}
	if(flags & SELECTOR_FLAG_READ) {
		int io_ret = nal_fd_buffer_from_fd(ctx->b_read, ctx->fd, max_read);
		/* zero shouldn't happen if we're readable, and negative is err */
		if(io_ret <= 0)
			return 0;
	}
	if(flags & SELECTOR_FLAG_SEND) {
		int io_ret = nal_fd_buffer_to_fd(ctx->b_send, ctx->fd, max_send);
		if((io_ret < 0) || (!io_ret && !nb))
			return 0;
	}
	nal_selector_fd_clear(sel, ctx->fd);
	return 1;
}

static void conn_selector_add(const NAL_CONNECTION *conn, NAL_SELECTOR *sel,
		unsigned int flags)
{
	conn_ctx *ctx = nal_connection_get_vtdata(conn);
	nal_selector_fd_set(sel, ctx->fd,
		/* Do we select for readability? Only if connection is complete
		 * and there is space in the buffer. */
		(ctx->established &&
		(flags & NAL_SELECT_FLAG_READ) && NAL_BUFFER_notfull(ctx->b_read) ?
			SELECTOR_FLAG_READ : 0) |
		/* Do we select for writability? We do if the connection isn't
		 * complete or there is data in the buffer to be sent. */
		(!ctx->established ||
		((flags & NAL_SELECT_FLAG_SEND) && NAL_BUFFER_notempty(ctx->b_send)) ?
			SELECTOR_FLAG_SEND : 0) |
		SELECTOR_FLAG_EXCEPT);
}

static void conn_selector_del(const NAL_CONNECTION *conn, NAL_SELECTOR *sel)
{
	conn_ctx *ctx = nal_connection_get_vtdata(conn);
	nal_selector_fd_unset(sel, ctx->fd);
}

