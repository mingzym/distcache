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

/***********/
/* globals */
/***********/

/* This flag, if set to zero, will cause new ipv4 connections to have the Nagle
 * algorithm turned off (by setting TCP_NODELAY). */
static int gb_use_nagle = 1;

/* These functions used to be exposed but for encapsulation reasons have been
 * made private. Pre-declaring them here makes the order of function
 * implementations less restrictive. */
static void nal_address_init(NAL_ADDRESS *addr);
static int nal_address_close(NAL_ADDRESS *addr);

/*********************/
/* ADDRESS FUNCTIONS */
/*********************/

static void nal_address_init(NAL_ADDRESS *addr)
{
	/* Fortunately, zero is fine for this structure! */
	SYS_zero(NAL_ADDRESS, addr);
}

static int nal_address_close(NAL_ADDRESS *addr)
{
	/* So far "address" is completely static, so there's no real cleanup
	 * required, just reinitialisation. */
	return 1;
}

NAL_ADDRESS *NAL_ADDRESS_new(void)
{
	NAL_ADDRESS *a = SYS_malloc(NAL_ADDRESS, 1);
	if(a)
		nal_address_init(a);
	return a;
}

void NAL_ADDRESS_free(NAL_ADDRESS *a)
{
	nal_address_close(a);
	SYS_free(NAL_ADDRESS, a);
}

int NAL_ADDRESS_set_def_buffer_size(NAL_ADDRESS *addr,
		unsigned int def_buffer_size)
{
	if(!nal_check_buffer_size(def_buffer_size))
		return 0;
	addr->def_buffer_size = def_buffer_size;
	return 1;
}

int NAL_ADDRESS_create(NAL_ADDRESS *addr, const char *addr_string,
			unsigned int def_buffer_size)
{
	int len;
	const char *start_ptr;

	/* Try to catch any cases of being called with a used 'addr' */
	assert(addr->family == NAL_ADDRESS_TYPE_NULL);
	if(addr->family != NAL_ADDRESS_TYPE_NULL)
		goto err;
	/* Ensure the buffer size is acceptable */
	if(!nal_check_buffer_size(def_buffer_size))
		goto err;
	/* Before we get into specifics, do the easy bits... :-) */
	addr->def_buffer_size = def_buffer_size;
	len = strlen(addr_string);
	/* Minimum and maximums enforced */
	if((len < 4) || (len > NAL_ADDRESS_MAX_STR_LEN))
		goto err;
	/* Stick the "parsed" string straight in now rather than doing it at
	 * all the "success" exit points. The "err:" label takes care of
	 * blanking out any stuff in the event we discovered problems. */
	strcpy(addr->str_form, addr_string);
	/* Check for the "<protocol>:" header in order of increasing string
	 * length. */
	if(strncmp(addr_string, "IP:", 3) == 0) {
		start_ptr = addr_string + 3;
		goto do_ipv4;
	}
	/* We move onto IPv4 */
	if(len < 6)
		goto err;
	if(strncmp(addr_string, "IPv4:", 5) == 0) {
		start_ptr = addr_string + 5;
		goto do_ipv4;
	}
#ifndef WIN32
	/* Try UNIX */
	if(strncmp(addr_string, "UNIX:", 5) == 0) {
		start_ptr = addr_string + 5;
		goto do_unix;
	}
#endif
	/* It hasn't matched anything! Bail out */
	goto err;

do_ipv4:
	if((addr->caps = nal_sock_sockaddr_from_ipv4(&addr->addr, start_ptr)) == 0)
		goto err;
	addr->family = NAL_ADDRESS_TYPE_IP;
	return 1;

#ifndef WIN32
do_unix:
	/* We're a domain socket address, and start_ptr points to the first
	 * character of the address part */
	len = strlen(start_ptr);
	if(len < 1)
		goto err;
	if(len >= UNIX_PATH_MAX)
		goto err;
	/* Plonk the path into the sockaddr structure */
	nal_sock_sockaddr_from_unix(&addr->addr, start_ptr);
	addr->caps = NAL_ADDRESS_CAN_LISTEN | NAL_ADDRESS_CAN_CONNECT;
	addr->family = NAL_ADDRESS_TYPE_UNIX;
	return 1;
#endif

err:
#if SYS_DEBUG_LEVEL > 1
	SYS_fprintf(SYS_stderr, "Error, '%s' is an invalid address\n\n",
			addr_string);
#endif
	/* Reverse any progress made up until the point of failure */
	nal_address_close(addr);
	return 0;
}

int NAL_ADDRESS_can_connect(NAL_ADDRESS *addr)
{
	return (addr->caps & NAL_ADDRESS_CAN_CONNECT);
}

int NAL_ADDRESS_can_listen(NAL_ADDRESS *addr)
{
	return (addr->caps & NAL_ADDRESS_CAN_LISTEN);
}

const char *NAL_ADDRESS_source_string(NAL_ADDRESS *addr)
{
	return addr->str_form;
}

/**********************/
/* LISTENER FUNCTIONS */
/**********************/

NAL_LISTENER *NAL_LISTENER_new(void)
{
	NAL_LISTENER *l = SYS_malloc(NAL_LISTENER, 1);
	if(l) {
		nal_address_init(&l->addr);
		l->fd = -1;
	}
	return l;
}

void NAL_LISTENER_free(NAL_LISTENER *list)
{
	nal_fd_close(&list->fd);
	nal_address_close(&list->addr);
	SYS_free(NAL_LISTENER, list);
}

int NAL_LISTENER_create(NAL_LISTENER *list, const NAL_ADDRESS *addr)
{
	int listen_fd = -1;

	if(addr->family == NAL_ADDRESS_TYPE_NULL)
		/* also should never happen */
		abort();
	/* Try to catch any cases of being called with a used 'list' */
	assert(list->addr.family == NAL_ADDRESS_TYPE_NULL);
	if(list->addr.family != NAL_ADDRESS_TYPE_NULL)
		goto err;
	if((addr->caps & NAL_ADDRESS_CAN_LISTEN) == 0) {
		/* Perhaps the string for the address was invalid? */
#if SYS_DEBUG_LEVEL > 1
		SYS_fprintf(SYS_stderr, "Error, '%s' can't listen\n", addr->str_form);
#endif
		goto err;
	}
#ifndef WIN32
	if(addr->family == NAL_ADDRESS_TYPE_UNIX)
		/* Stevens' book says do it, so I do. Unfortunately - this
		 * actually needs additional file-locking to prevent one
		 * application stealing another's listener (without him
		 * noticing it's gone even!). */
		unlink(addr->addr.val_un.sun_path);
#endif
	if(!nal_sock_create_socket(&listen_fd, addr->family))
		goto err;
	if((addr->family == NAL_ADDRESS_TYPE_IP) &&
			!nal_sock_set_reuse(listen_fd))
		goto err;
	if(!nal_sock_bind(listen_fd, &addr->addr, addr->family) ||
			!nal_sock_listen(listen_fd))
		goto err;
	/* Success! */
	SYS_memcpy(NAL_ADDRESS, &(list->addr), addr);
	list->fd = listen_fd;
	return 1;
err:
	nal_fd_close(&listen_fd);
	return 0;
}

int NAL_LISTENER_accept_block(const NAL_LISTENER *list, NAL_CONNECTION *conn)
{
	int conn_fd = -1;

	/* Try to catch any cases of being called with a used 'conn' */
	assert((conn->addr.family == NAL_ADDRESS_TYPE_NULL) &&
			(conn->fd == -1));
	if((conn->addr.family != NAL_ADDRESS_TYPE_NULL) || (conn->fd != -1))
		goto err;
	/* Do the accept */
	if(!nal_sock_accept(list->fd, &conn_fd) ||
			!nal_fd_make_non_blocking(conn_fd, 1))
		goto err;
	/* If appropriate, apply "nagle" setting */
	if((list->addr.family == NAL_ADDRESS_TYPE_IPv4) &&
			!nal_sock_set_nagle(conn_fd, gb_use_nagle))
		goto err;
	if(!NAL_CONNECTION_set_size(conn, list->addr.def_buffer_size))
		goto err;
	/* Success! */
	SYS_memcpy(NAL_ADDRESS, &(conn->addr), &(list->addr));
	conn->fd = conn_fd;
	conn->established = 1;
	return 1;
err:
	nal_fd_close(&conn_fd);
	return 0;
}

int NAL_LISTENER_accept(const NAL_LISTENER *list, NAL_SELECTOR *sel,
			NAL_CONNECTION *conn)
{
	unsigned char flags;
	int conn_fd = -1;

	/* Try to catch any cases of being called with a used 'conn' */
	assert((conn->addr.family == NAL_ADDRESS_TYPE_NULL) &&
			(conn->fd == -1));
	if((conn->addr.family != NAL_ADDRESS_TYPE_NULL) || (conn->fd != -1))
		goto err;
	flags = nal_selector_fd_test(sel, list->fd);
	if(flags & SELECTOR_FLAG_EXCEPT) {
#if SYS_DEBUG_LEVEL > 1
		SYS_fprintf(SYS_stderr, "Warn, listener has exception flag set\n\n");
#endif
		goto err;
	}
	if(!(flags & SELECTOR_FLAG_READ))
		/* No incoming connections */
		return 0;
	/* Do the accept */
	if(!nal_sock_accept(list->fd, &conn_fd) ||
			!nal_fd_make_non_blocking(conn_fd, 1))
		goto err;
	/* If appropriate, apply "nagle" setting */
	if((list->addr.family == NAL_ADDRESS_TYPE_IPv4) &&
			!nal_sock_set_nagle(conn_fd, gb_use_nagle))
		goto err;
	if(!NAL_CONNECTION_set_size(conn, list->addr.def_buffer_size))
		goto err;
	SYS_memcpy(NAL_ADDRESS, &(conn->addr), &(list->addr));
	conn->fd = conn_fd;
	conn->established = 1;
	nal_selector_fd_clear(sel, list->fd);
	return 1;
err:
	nal_fd_close(&conn_fd);
	return 0;
}

void NAL_LISTENER_add_to_selector(const NAL_LISTENER *list,
				NAL_SELECTOR *sel)
{
	nal_selector_fd_set(sel, list->fd, SELECTOR_FLAG_READ);
}

void NAL_LISTENER_del_from_selector(const NAL_LISTENER *list,
				NAL_SELECTOR *sel)
{
	nal_selector_fd_unset(sel, list->fd);
}

/************************/
/* CONNECTION FUNCTIONS */
/************************/

NAL_CONNECTION *NAL_CONNECTION_new(void)
{
	NAL_CONNECTION *conn = SYS_malloc(NAL_CONNECTION, 1);
	if(!conn) return NULL;
	conn->read = NAL_BUFFER_new();
	conn->send = NAL_BUFFER_new();
	if(!conn->read || !conn->send) {
		if(conn->read) NAL_BUFFER_free(conn->read);
		if(conn->send) NAL_BUFFER_free(conn->send);
		SYS_free(NAL_CONNECTION, conn);
		return NULL;
	}
	if(conn) {
		nal_address_init(&conn->addr);
		conn->fd = -1;
		conn->established = 0;
	}
	return conn;
}

void NAL_CONNECTION_free(NAL_CONNECTION *conn)
{
	nal_fd_close(&conn->fd);
	/* destroy the buffers */
	NAL_BUFFER_free(conn->read);
	NAL_BUFFER_free(conn->send);
	/* good (unnecessary) aggregation programming practice. :-) */
	nal_address_close(&conn->addr);
	SYS_free(NAL_CONNECTION, conn);
}

int NAL_CONNECTION_create(NAL_CONNECTION *conn, const NAL_ADDRESS *addr)
{
	int established;
	int fd = -1;

	/* Try to catch any cases of being called with a used 'conn' */
	assert((conn->addr.family == NAL_ADDRESS_TYPE_NULL) && (conn->fd == -1));
	if((conn->addr.family != NAL_ADDRESS_TYPE_NULL) || (conn->fd != -1))
		goto err;
	if(addr->family == NAL_ADDRESS_TYPE_NULL)
		/* also should never happen */
		abort();
	if((addr->caps & NAL_ADDRESS_CAN_CONNECT) == 0) {
		/* Perhaps the string for the address was invalid? */
#if SYS_DEBUG_LEVEL > 1
		SYS_fprintf(SYS_stderr, "Error, '%s' can't connect\n", addr->str_form);
#endif
		goto err;
	}
	if(!nal_sock_create_socket(&fd, addr->family) ||
			!nal_fd_make_non_blocking(fd, 1) ||
			!nal_sock_connect(fd, &addr->addr, addr->family, &established))
		goto err;
	/* If appropriate, apply "nagle" setting */
	if((addr->family == NAL_ADDRESS_TYPE_IPv4) &&
			!nal_sock_set_nagle(fd, gb_use_nagle))
		goto err;
	if(!NAL_CONNECTION_set_size(conn, addr->def_buffer_size))
		goto err;
	/* Success! */
	SYS_memcpy(NAL_ADDRESS, &(conn->addr), addr);
	conn->fd = fd;
	conn->established = established;
	return 1;
err:
	nal_fd_close(&fd);
	return 0;
}

/* This function never works on WIN32 */
int NAL_CONNECTION_create_pair(NAL_CONNECTION *conn1, NAL_CONNECTION *conn2,
			unsigned int def_buffer_size)
{
#ifndef WIN32
	int sv[2] = {-1,-1};

	if(!nal_check_buffer_size(def_buffer_size))
		return 0;
	/* Try to catch any cases of being called with used 'conns' */
	assert((conn1->addr.family == NAL_ADDRESS_TYPE_NULL) && (conn1->fd == -1));
	assert((conn2->addr.family == NAL_ADDRESS_TYPE_NULL) && (conn2->fd == -1));
	if((conn1->addr.family != NAL_ADDRESS_TYPE_NULL) || (conn1->fd != -1))
		goto err;
	if((conn2->addr.family != NAL_ADDRESS_TYPE_NULL) || (conn2->fd != -1))
		goto err;
	if(!nal_sock_create_unix_pair(sv) ||
			!nal_fd_make_non_blocking(sv[0], 1) ||
			!nal_fd_make_non_blocking(sv[1], 1) ||
			!NAL_CONNECTION_set_size(conn1, def_buffer_size) ||
			!NAL_CONNECTION_set_size(conn2, def_buffer_size))
		goto err;
	/* Success, populate */
	conn1->fd = sv[0];
	conn2->fd = sv[1];
	/* socketpair()s are automatically "established" */
	conn1->established = conn2->established = 1;
	/* The address type should be set though */
	conn1->addr.family = conn2->addr.family = NAL_ADDRESS_TYPE_PAIR;
	return 1;
err:
	nal_fd_close(sv);
	nal_fd_close(sv + 1);
#endif
	return 0;
}

int NAL_CONNECTION_create_dummy(NAL_CONNECTION *conn,
			unsigned int def_buffer_size)
{
	if(!nal_check_buffer_size(def_buffer_size))
		return 0;
	/* Try to catch any cases of being called with used a 'conn' */
	assert((conn->addr.family == NAL_ADDRESS_TYPE_NULL) && (conn->fd == -1));
	if((conn->addr.family != NAL_ADDRESS_TYPE_NULL) || (conn->fd != -1))
		return 0;
	/* We only use one buffer, so only expand one */
	if(!NAL_BUFFER_set_size(conn->read, def_buffer_size))
		return 0;
	/* Mark ourselves with that *special something* that is a dummy
	 * connection. Basically, you read and write into the same buffer, there
	 * *is no file-descriptor*, and selectors and I/O are 'nop's. */
	conn->fd = -2;
	conn->addr.family = NAL_ADDRESS_TYPE_DUMMY;
	/* The "dummy" is pretty much automatically established! */
	conn->established = 1;
	return 1;
}

int NAL_CONNECTION_set_size(NAL_CONNECTION *conn, unsigned int size)
{
	if(!nal_check_buffer_size(size))
		return 0;
	if(!NAL_BUFFER_set_size(conn->read, size) ||
			((conn->addr.family != NAL_ADDRESS_TYPE_DUMMY) &&
				!NAL_BUFFER_set_size(conn->send, size))) {
#if SYS_DEBUG_LEVEL > 1
		SYS_fprintf(SYS_stderr, "Error, couldn't set buffer sizes\n");
#endif
		return 0;
	}
	return 1;
}

NAL_BUFFER *NAL_CONNECTION_get_read(NAL_CONNECTION *conn)
{
	return conn->read;
}

NAL_BUFFER *NAL_CONNECTION_get_send(NAL_CONNECTION *conn)
{
	/* A "dummy" connection reads and writes into the same buffer, so handle
	 * this special case. */
	if(conn->fd == -2)
		return conn->read;
	return conn->send;
}

/* "const" versions of the above */
const NAL_BUFFER *NAL_CONNECTION_get_read_c(const NAL_CONNECTION *conn)
{
	return conn->read;
}

const NAL_BUFFER *NAL_CONNECTION_get_send_c(const NAL_CONNECTION *conn)
{
	/* A "dummy" connection reads and writes into the same buffer, so handle
	 * this special case. */
	if(conn->fd == -2)
		return conn->read;
	return conn->send;
}

/* If this function returns zero (failure), then it is a bad thing and means
 * the connection should be closed by the caller. */
int NAL_CONNECTION_io_cap(NAL_CONNECTION *conn, NAL_SELECTOR *sel,
			unsigned int max_read, unsigned int max_send)
{
	unsigned char flags;
	int io_ret, nb = 0;

	if((conn == NULL) || (sel == NULL))
		return 0;
	/* If we're a dummy connection, "io" has no useful meaning */
	if(conn->fd == -2)
		return 1;
	flags = nal_selector_fd_test(sel, conn->fd);
	if(flags & SELECTOR_FLAG_EXCEPT) {
#if SYS_DEBUG_LEVEL > 1
		SYS_fprintf(SYS_stderr, "Warn, connection has exception flag set\n\n");
#endif
		goto closing;
	}
#if SYS_DEBUG_LEVEL > 1
	/* We shouldn't have selected on readability if there's no space to
	 * read into. */
	if((flags & SELECTOR_FLAG_READ) && NAL_BUFFER_full(conn->read))
		abort();
#endif
	/* If we're waiting on a non-blocking connect, hook the test here */
	if(!conn->established) {
		int t;
		socklen_t t_len = sizeof(t);
		/* We wait until we're sendable when in a non-blocking connect */
		if(!(flags & SELECTOR_FLAG_SEND))
			goto ok;
		/* Check getsockopt() to check whether the connect succeeded.
		 * Note, the ugly cast is necessary with my system headers to
		 * avoid warnings, but there's probably a reason and/or
		 * autoconf things to do with this. */
		if(getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &t,
					(unsigned int *)&t_len) != 0)
			/* This should only happen if our code (or the calling
			 * application) is buggy. Any network error should pop
			 * out of the following (t!=0) check. */
			goto closing;
		if(t != 0)
			/* The non-blocking connected failed. Note, if we ever
			 * want to know about what kind of errors there are -
			 * 't' will equal the same value that errno would
			 * normally be set to if connect() failed immediately
			 * for the same reason. */
			goto closing;
		conn->established = 1;
		/* This allows the send logic further down to handle the fact
		 * we're sendable yet have nothing to send. This only happens
		 * in the nb-connect case because sendability is used to
		 * indicated connectedness. */
		nb = 1;
	}
#if SYS_DEBUG_LEVEL > 1
	else {
		/* If we weren't waiting a non-blocking connect, then
		 * sendability should only happen when there's data to send. */
		if((flags & SELECTOR_FLAG_SEND) && NAL_BUFFER_empty(conn->send))
			abort();
	}
#endif
	if(flags & SELECTOR_FLAG_READ) {
		io_ret = nal_fd_buffer_from_fd(conn->read, conn->fd, max_read);
		if(io_ret <= 0)
			/* (<0) --> error, (==0) --> clean disconnect */
			goto closing;
	}
	if(flags & SELECTOR_FLAG_SEND) {
		io_ret = nal_fd_buffer_to_fd(conn->send, conn->fd, max_send);
		if(io_ret < 0)
			/* error */
			goto closing;
		if(!io_ret && !nb)
			/*  clean disconnect */
			goto closing;
	}
ok:
	/* Remove this connection from the select sets so a redundant call does
	 * nothing. */
	nal_selector_fd_clear(sel, conn->fd);
	/* Success! */
	return 1;
closing:
#if SYS_DEBUG_LEVEL > 2
	if(NAL_BUFFER_notempty(conn->send))
		SYS_fprintf(SYS_stderr, "Warn, connection closing with unsent data\n");
	else if(NAL_BUFFER_notempty(conn->read))
		SYS_fprintf(SYS_stderr, "Warn, connection closing with received data\n");
	else
		SYS_fprintf(SYS_stderr, "Info, connection with empty buffers will close\n");
#endif
	return 0;
}

int NAL_CONNECTION_io(NAL_CONNECTION *conn, NAL_SELECTOR *sel)
{
	return NAL_CONNECTION_io_cap(conn, sel, 0, 0);
}

int NAL_CONNECTION_is_established(const NAL_CONNECTION *conn)
{
	return conn->established;
}

void NAL_CONNECTION_add_to_selector(const NAL_CONNECTION *conn,
				NAL_SELECTOR *sel)
{
	if(conn->fd < 0) return;
	nal_selector_fd_set(sel, conn->fd,
		(NAL_BUFFER_notfull(conn->read) ? SELECTOR_FLAG_READ : 0) |
		(NAL_BUFFER_notempty(conn->send) ? SELECTOR_FLAG_SEND : 0) |
		SELECTOR_FLAG_EXCEPT);
}

void NAL_CONNECTION_del_from_selector(const NAL_CONNECTION *conn,
				NAL_SELECTOR *sel)
{
	if(conn->fd < 0) return;
	nal_selector_fd_unset(sel, conn->fd);
}

int NAL_stdin_set_non_blocking(int non_blocking)
{
	return nal_fd_make_non_blocking(fileno(SYS_stdin), non_blocking);
}

/* This special sets our global flag that controls whether new ipv4 connections
 * (explicitly connected or via an accept()) have nagle turned off or not. */
int NAL_config_set_nagle(int enabled)
{
	gb_use_nagle = (enabled ? 1 : 0);
	return 1;
}

