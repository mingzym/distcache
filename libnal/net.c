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
#include <libnal/nal_internal.h>

/* Noone outside this file should need to know about these defines, so I'm
 * scoping them down here where noone else *can*. */
#define SELECTOR_FLAG_READ	0x01
#define SELECTOR_FLAG_SEND	0x02
#define SELECTOR_FLAG_EXCEPT	0x04

/* This global flag, if set to zero, will cause new ipv4 connections to have the
 * Nagle algorithm turned off (by setting TCP_NODELAY). */
static int int_use_nagle = 1;
static int int_always_one = 1; /* used in setsockopt() */

/* Solaris (among possibly many platforms) doesn't know what SOL_TCP is, we need
 * to use getprotobyname() to find it. The result is stored here. */
static int sol_tcp = -1;

/* Some platforms don't get socklen_t ... use int */
#ifndef socklen_t
#define socklen_t int
#endif

/**************************************/
/* Internal network utility functions */
/**************************************/

/* Functions I've decided not to expose any further so they're static now and
 * I'm predeclaring them here. Eg. a call to NAL_CONNECTION_io(conn,sel) would
 * call this itself. */
static void int_selector_get_conn(const NAL_SELECTOR *sel,
			const NAL_CONNECTION *conn,
			unsigned char *flags);
static void int_selector_get_list(const NAL_SELECTOR *sel,
			const NAL_LISTENER *list,
			unsigned char *flags);
/* Also used by NAL_CONNECTION_io() - used to unset read/write flags once a
 * NAL_CONNECTION has already been processed. NB: Does not unset exception
 * flags, a redundant call to NAL_CONNECTION_io() should still notice
 * exceptions, it just shouldn't be retrying reads and sends that already
 * succeeded (otherwise it'll wrongly diagnose them as clean disconnects by the
 * peer). */
static void int_selector_conn_done(NAL_SELECTOR *sel,
			const NAL_CONNECTION *conn);
static void int_selector_list_done(NAL_SELECTOR *sel,
			const NAL_LISTENER *listener);

static int int_make_non_blocking(int fd, int non_blocking)
{
#ifdef WIN32
	u_long dummy = 1;
	if(ioctlsocket(fd, FIONBIO, &dummy) != 0)
		return 0;
	return 1;
#else
	int flags;

	if(((flags = fcntl(fd, F_GETFL, 0)) < 0) ||
			(fcntl(fd, F_SETFL, (non_blocking ?
			(flags | O_NONBLOCK) : (flags & ~O_NONBLOCK))) < 0)) {
#if NAL_DEBUG_LEVEL > 1
		NAL_fprintf(NAL_stderr(), "Error, couldn't make socket non-blocking.\n");
#endif
		return 0;
	}
	return 1;
#endif
}

static int int_set_nagle(int fd)
{
#ifndef WIN32
	if(int_use_nagle)
		return 1;

	if(sol_tcp == -1) {
		struct protoent *p = getprotobyname("tcp");
		if(!p) {
#if NAL_DEBUG_LEVEL > 1
			NAL_fprintf(NAL_stderr(), "Error, couldn't obtain SOL_TCP\n");
#endif
			return 0;
		}
		sol_tcp = p->p_proto;
	}

	if(setsockopt(fd, sol_tcp, TCP_NODELAY, &int_always_one,
			sizeof(int_always_one)) != 0) {
#if NAL_DEBUG_LEVEL > 1
		NAL_fprintf(NAL_stderr(), "Error, couldn't disable Nagle algorithm\n");
#endif
		return 0;
	}
#endif
	return 1;
}

/* These two functions are static, so we shouldn't have flow errors - so we only
 * check in debugging mode, and in those cases abort(). */
static int int_buffer_to_fd(NAL_BUFFER *buf, int fd, unsigned int max_send)
{
	ssize_t ret;

#if NAL_DEBUG_LEVEL > 3
	if(NAL_BUFFER_empty(buf))
		abort();
#endif
	/* Decide the maximum we should send */
	if((max_send == 0) || (max_send > NAL_BUFFER_used(buf)))
		max_send = NAL_BUFFER_used(buf);
#ifdef WIN32
	ret = send(fd, NAL_BUFFER_data(buf), max_send, 0);
#elif !defined(MSG_DONTWAIT) || !defined(MSG_NOSIGNAL)
	ret = write(fd, NAL_BUFFER_data(buf), max_send);
#else
	ret = send(fd, NAL_BUFFER_data(buf), max_send,
		MSG_DONTWAIT | MSG_NOSIGNAL);
#endif
	/* There's a couple of "soft errors" we don't consider fatal */
	if(ret < 0) {
		switch(errno) {
		case EAGAIN:
		case EINTR:
			return 0;
		default:
			break;
		}
		return -1;
	}
	if(ret > 0) {
		unsigned int uret = (unsigned int)ret;
		/* Scroll the buffer forward */
		NAL_BUFFER_takedata(buf, NULL, uret);
#if NAL_DEBUG_LEVEL > 1
		NAL_fprintf(NAL_stdout(), "Debug: net.c (fd=%d) sent %lu bytes\n",
			fd, (unsigned long)uret);
#endif
	}
	return ret;
}

static int int_buffer_from_fd(NAL_BUFFER *buf, int fd, unsigned int max_read)
{
	ssize_t ret;

#if NAL_DEBUG_LEVEL > 3
	if(NAL_BUFFER_full(buf))
		abort();
#endif
	/* Decide the maximum we should read */
	if((max_read == 0) || (max_read > NAL_BUFFER_unused(buf)))
		max_read = NAL_BUFFER_unused(buf);
#ifdef WIN32
	ret = recv(fd, NAL_BUFFER_write_ptr(buf), max_read, 0);
#elif !defined(MSG_NOSIGNAL)
	ret = read(fd, NAL_BUFFER_write_ptr(buf), max_read);
#else
	ret = recv(fd, NAL_BUFFER_write_ptr(buf), max_read, MSG_NOSIGNAL);
#endif
	/* There's a couple of "soft errors" we don't consider fatal */
	if(ret < 0) {
		switch(errno) {
		case EINTR:
		case EAGAIN:
			return 0;
		default:
			break;
		}
		return -1;
	}
	if(ret > 0) {
		unsigned int uret = (unsigned int)ret;
		NAL_BUFFER_wrote(buf, uret);
#if NAL_DEBUG_LEVEL > 1
		NAL_fprintf(NAL_stdout(), "Debug: net.c (fd=%d) received %lu bytes\n",
			fd, (unsigned long)uret);
#endif
	}
	return ret;
}

static void int_sockaddr_from_ipv4(sockaddr_safe *addr, unsigned char *ip,
				unsigned short port)
{
	struct sockaddr_in in_addr;

	in_addr.sin_family = AF_INET;
	if(ip == NULL)
		in_addr.sin_addr.s_addr = INADDR_ANY;
	else
		memcpy(&in_addr.sin_addr.s_addr, ip, 4);
	in_addr.sin_port = htons(port);
	/* Now sandblast the sockaddr_in structure onto the sockaddr structure
	 * (which one hopes is greater than or equal to it in size :-). */
	NAL_zero(sockaddr_safe, addr);
	NAL_memcpy(struct sockaddr_in, &addr->val_in, &in_addr);
}

#ifndef WIN32
static void int_sockaddr_from_unix(sockaddr_safe *addr, const char *start_ptr)
{
	struct sockaddr_un un_addr;

	un_addr.sun_family = AF_UNIX;
	strncpy(un_addr.sun_path, start_ptr, UNIX_PATH_MAX);
	/* Now sandblast the sockaddr_un structure onto the sockaddr structure
	 * (which one hopes is greater than or equal to it in size :-). */
	NAL_zero(sockaddr_safe, addr);
	NAL_memcpy(struct sockaddr_un, &addr->val_un, &un_addr);
}
#endif

/* Rather than doing this more than once and repeating error output code,
 * I've suctioned it into a function. */
static int int_create_socket(int *fd, int type)
{
	switch(type) {
	case NAL_ADDRESS_TYPE_IP:
		*fd = socket(PF_INET, SOCK_STREAM, 0);
		break;
#ifndef WIN32
	case NAL_ADDRESS_TYPE_UNIX:
		*fd = socket(PF_UNIX, SOCK_STREAM, 0);
		break;
#endif
	default:
		/* Should never happen */
		abort();
	}
	if(*fd  == -1) {
#if NAL_DEBUG_LEVEL > 1
		NAL_fprintf(NAL_stderr(), "Error, can't create socket\n\n");
#endif
		return 0;
	}
	return 1;
}

#ifndef WIN32
static int int_create_unix_pair(int sv[2])
{
	if(socketpair(PF_UNIX, SOCK_STREAM, 0, sv) != 0) {
#if NAL_DEBUG_LEVEL > 1
		NAL_fprintf(NAL_stderr(), "Error, can't create socketpair\n\n");
#endif
		return 0;
	}
	return 1;
}
#endif

static int int_set_reuse(int fd)
{
	int reuseVal = 1;

	if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
			(char *)(&reuseVal), sizeof(reuseVal)) != 0) {
#if NAL_DEBUG_LEVEL > 1
		NAL_fprintf(NAL_stderr(), "Error, couldn't set SO_REUSEADDR\n\n");
#endif
		return 0;
	}
	return 1;
}

/* An internal function only used by other internal functions! */
static int int_int_sockaddr_size(int address_type)
{
	switch(address_type) {
	case NAL_ADDRESS_TYPE_IP:
		return sizeof(struct sockaddr_in);
#ifndef WIN32
	case NAL_ADDRESS_TYPE_UNIX:
		return sizeof(struct sockaddr_un);
#endif
	default:
		break;
	}
	/* for now at least, should *never* happen */
	abort();
	/* return 0; */
}

static int int_bind(int fd, const sockaddr_safe *addr, int address_type)
{
	socklen_t addr_size = int_int_sockaddr_size(address_type);
	sockaddr_safe tmp;

	NAL_memcpy(sockaddr_safe, &tmp, addr);
	if(bind(fd, (struct sockaddr *)&tmp, addr_size) != 0) {
#if NAL_DEBUG_LEVEL > 1
		NAL_fprintf(NAL_stderr(), "Error, couldn't bind to the IP/Port\n\n");
#endif
		return 0;
	}
	return 1;
}

static int int_connect(int fd, const sockaddr_safe *addr, int address_type,
			int *established)
{
	socklen_t addr_size = int_int_sockaddr_size(address_type);
	sockaddr_safe tmp;

	NAL_memcpy(sockaddr_safe, &tmp, addr);
	if(connect(fd, (struct sockaddr *)&tmp, addr_size) != 0) {
#ifdef WIN32
		if(WSAGetLastError() != WSAEWOULDBLOCK)
#else
		if(errno != EINPROGRESS)
#endif
		{
#if NAL_DEBUG_LEVEL > 1
			NAL_fprintf(NAL_stderr(), "Error, couldn't connect\n\n");
#endif
			return 0;
		}
		/* non-blocking connect ... connect() succeeded, but it may yet
		 * fail without a single byte going anywhere. */
		*established = 0;
	} else
		*established = 1;
	return 1;
}

static int int_listen(int fd)
{
	if(listen(fd, NAL_LISTENER_BACKLOG) != 0) {
#if NAL_DEBUG_LEVEL > 1
		NAL_fprintf(NAL_stderr(), "Error, couldn't listen on that IP/Port\n\n");
#endif
		return 0;
        }
	return 1;
}

static int int_accept(int listen_fd, int *conn)
{
	if((*conn = accept(listen_fd, NULL, NULL)) == -1) {
#if NAL_DEBUG_LEVEL > 1
		NAL_fprintf(NAL_stderr(), "Error, accept failed\n\n");
#endif
		return 0;
	}
	return 1;
}

/* A handy little simple function that removes loads of lines of code from
 * elsewhere. */
static void int_close(int *fd)
{
	if(*fd > -1)
#ifdef WIN32
		closesocket(*fd);
#else
		close(*fd);
#endif
	*fd = -1;
}

/* buffer size checking that includes a debug error message - means it isn't
 * duplicated in all the functions that should check it */
static int int_check_buffer_size(unsigned int size)
{
	if(size > NAL_BUFFER_MAX_SIZE) {
#if NAL_DEBUG_LEVEL > 1
		NAL_fprintf(NAL_stderr(), "Error, NAL_ADDRESS_create with too large a "
				"buffer\n\n");
#endif
		return 0;
	}
	return 1;
}

/* These functions used to be exposed but for encapsulation reasons have been
 * made private. Pre-declaring them here makes the order of function
 * implementations less restrictive. */
static void NAL_ADDRESS_init(NAL_ADDRESS *addr);
static int NAL_ADDRESS_close(NAL_ADDRESS *addr);
static void NAL_LISTENER_init(NAL_LISTENER *list);
static int NAL_LISTENER_close(NAL_LISTENER *list);
static void NAL_CONNECTION_init(NAL_CONNECTION *list);
static int NAL_CONNECTION_close(NAL_CONNECTION *list);
static void NAL_SELECTOR_init(NAL_SELECTOR *list);
static int NAL_SELECTOR_close(NAL_SELECTOR *list);
static void NAL_BUFFER_init(NAL_BUFFER *list);
static int NAL_BUFFER_close(NAL_BUFFER *list);

/*********************/
/* ADDRESS FUNCTIONS */
/*********************/

NAL_ADDRESS *NAL_ADDRESS_malloc(void)
{
	NAL_ADDRESS *a = NAL_malloc(NAL_ADDRESS, 1);
	if(a)
		NAL_ADDRESS_init(a);
	return a;
}

void NAL_ADDRESS_free(NAL_ADDRESS *a)
{
	NAL_ADDRESS_close(a);
	NAL_free(NAL_ADDRESS, a);
}

static void NAL_ADDRESS_init(NAL_ADDRESS *addr)
{
	/* Fortunately, zero is fine for this structure! */
	NAL_zero(NAL_ADDRESS, addr);
}

static int NAL_ADDRESS_close(NAL_ADDRESS *addr)
{
	if(addr == NULL)
		return 0;
	/* So far "address" is completely static, so there's no real cleanup
	 * required, just reinitialisation. */
	NAL_ADDRESS_init(addr);
	return 1;
}

int NAL_ADDRESS_set_def_buffer_size(NAL_ADDRESS *addr,
		unsigned int def_buffer_size)
{
	if((addr == NULL) || !int_check_buffer_size(def_buffer_size))
		return 0;
	addr->def_buffer_size = def_buffer_size;
	return 1;
}

int NAL_ADDRESS_create(NAL_ADDRESS *addr, const char *addr_string,
			unsigned int def_buffer_size)
{
	int len;
	const char *start_ptr;
	char *fini_ptr, *tmp_ptr;
	/* IPv4 bits */
	unsigned long in_ip_piece;
	unsigned char in_ip[4];
	struct hostent *ip_lookup;
	int no_ip = 0;

	if((addr == NULL) || (addr_string == NULL))
		/* should *never* happen */
		abort();
	/* Try to catch any cases of being called with a used 'addr' */
	assert(addr->family == NAL_ADDRESS_TYPE_NULL);
	if(addr->family != NAL_ADDRESS_TYPE_NULL)
		goto err;
	/* Ensure the buffer size is acceptable */
	if(!int_check_buffer_size(def_buffer_size))
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
	/* We're an IPv4 address, and start_ptr points to the first character
	 * of the address part */
	len = strlen(start_ptr);
	if(len < 1)
		goto err;
	/* Logic: if our string contains another ":" we assume it's of the form
	 * IP[v4]:nnn.nnn.nnn.nnn:nnn, otherwise assume IP[v4]:nnn. Exception,
	 * if it's of the form IP[v4}::nnn, we treat it as equivalent to one
	 * colon. */
	if(((fini_ptr = strstr(start_ptr, ":")) == NULL) ||
			(start_ptr == fini_ptr)) {
		/* No colon, skip the IP address - this is listen-only */
		no_ip = 1;
		/* If it's a double colon, we need to increment start_ptr */
		if(fini_ptr)
			start_ptr++;
		goto ipv4_port;
	}
	/* Create a temporary string for the isolated hostname/ip-address */
	tmp_ptr = NAL_malloc(char, (int)(fini_ptr - start_ptr) + 1);
	if(!tmp_ptr)
		goto err;
	NAL_memcpy_n(unsigned char, tmp_ptr, start_ptr,
		(int)(fini_ptr - start_ptr));
	tmp_ptr[(int)(fini_ptr - start_ptr)] = '\0';
	ip_lookup = gethostbyname(tmp_ptr);
	NAL_free(char, tmp_ptr);
	if(!ip_lookup)
		/* Host not understood or recognised */
		goto err;
	/* Grab the IP address and move on */
	NAL_memcpy_n(unsigned char, in_ip, ip_lookup->h_addr_list[0], 4);
	/* Align start_ptr to the start of the "port" number. */
	start_ptr = fini_ptr + 1;
	/* Ok, this is an address that could be used for connecting */
	addr->caps |= NAL_ADDRESS_CAN_CONNECT;
	
ipv4_port:
	if(strlen(start_ptr) < 1)
		goto err;
	/* start_ptr points to the first character of the port part */
	in_ip_piece = strtoul(start_ptr, &fini_ptr, 10);
	if((in_ip_piece > 65535) || (*fini_ptr != '\0'))
		goto err;
	/* Plonk the ipv4 stuff into the sockaddr structure */
	int_sockaddr_from_ipv4(&addr->addr, (no_ip ? NULL : in_ip),
				(unsigned short)in_ip_piece);
	addr->caps |= NAL_ADDRESS_CAN_LISTEN;
	addr->family = NAL_ADDRESS_TYPE_IP;

#if NAL_DEBUG_LEVEL > 2
	NAL_fprintf(NAL_stderr(), "Info, successfully parsed '%s' as an IPv4 listen "
			"address\n", addr_string);
#endif
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
	int_sockaddr_from_unix(&addr->addr, start_ptr);
	addr->caps = NAL_ADDRESS_CAN_LISTEN | NAL_ADDRESS_CAN_CONNECT;
	addr->family = NAL_ADDRESS_TYPE_UNIX;
#if NAL_DEBUG_LEVEL > 2
	NAL_fprintf(NAL_stderr(), "Info, successfully parsed '%s' as a unix domain listen"
			" address\n", addr_string);
#endif
	return 1;
#endif

err:
#if NAL_DEBUG_LEVEL > 1
	NAL_fprintf(NAL_stderr(), "Error, '%s' is an invalid address\n\n",
			addr_string);
#endif
	/* Reverse any progress made up until the point of failure */
	NAL_ADDRESS_close(addr);
	return 0;
}

int NAL_ADDRESS_move(NAL_ADDRESS *to, NAL_ADDRESS *from)
{
	if((to == NULL) || (from == NULL))
		return 0;
	/* Try to catch any cases of being called with a used 'to' */
	assert(to->family == NAL_ADDRESS_TYPE_NULL);
	if(to->family != NAL_ADDRESS_TYPE_NULL)
		return 0;
	/* Fortunately, NAL_ADDRESS (for now) is a static structure and has no
	 * aggregation of other types, so we don't need to run any checks or
	 * call any functions for aggregated types, we just copy and init :-) */
	NAL_memcpy(NAL_ADDRESS, to, from);
	NAL_ADDRESS_close(from);
	return 1;
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

NAL_LISTENER *NAL_LISTENER_malloc(void)
{
	NAL_LISTENER *l = NAL_malloc(NAL_LISTENER, 1);
	if(l)
		NAL_LISTENER_init(l);
	return l;
}

void NAL_LISTENER_free(NAL_LISTENER *a)
{
	NAL_LISTENER_close(a);
	NAL_free(NAL_LISTENER, a);
}

static void NAL_LISTENER_init(NAL_LISTENER *list)
{
	NAL_ADDRESS_init(&list->addr);
	list->fd = -1;
}

static int NAL_LISTENER_close(NAL_LISTENER *list)
{
	if(list == NULL)
		return 0;
	int_close(&list->fd);
	NAL_ADDRESS_close(&list->addr);
	/* Now reinitialise */
	NAL_LISTENER_init(list);
	return 1;
}

int NAL_LISTENER_create(NAL_LISTENER *list, const NAL_ADDRESS *addr)
{
	int listen_fd = -1;

	if((list == NULL) || (addr == NULL))
		/* should *never* happen */
		abort();
	if(addr->family == NAL_ADDRESS_TYPE_NULL) 
		/* also should never happen */
		abort();
	/* Try to catch any cases of being called with a used 'list' */
	assert(list->addr.family == NAL_ADDRESS_TYPE_NULL);
	if(list->addr.family != NAL_ADDRESS_TYPE_NULL)
		goto err;
	if((addr->caps & NAL_ADDRESS_CAN_LISTEN) == 0) {
		/* Perhaps the string for the address was invalid? */
#if NAL_DEBUG_LEVEL > 1
		NAL_fprintf(NAL_stderr(), "Error, '%s' can't listen\n", addr->str_form);
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
	if(!int_create_socket(&listen_fd, addr->family))
		goto err;
	if((addr->family == NAL_ADDRESS_TYPE_IP) &&
			!int_set_reuse(listen_fd))
		goto err;
	if(!int_bind(listen_fd, &addr->addr, addr->family) ||
			!int_listen(listen_fd))
		goto err;
	/* Success! */
	NAL_memcpy(NAL_ADDRESS, &(list->addr), addr);
	list->fd = listen_fd;
	return 1;
err:
	int_close(&listen_fd);
	NAL_LISTENER_close(list);
	return 0;
}

int NAL_LISTENER_accept_block(const NAL_LISTENER *list, NAL_CONNECTION *conn)
{
	int conn_fd = -1;

	if((list == NULL) || (conn == NULL))
		/* should never happen */
		abort();
	/* Try to catch any cases of being called with a used 'conn' */
	assert(conn->addr.family == NAL_ADDRESS_TYPE_NULL);
	if(conn->addr.family != NAL_ADDRESS_TYPE_NULL)
		goto err;
	/* Do the accept */
	if(!int_accept(list->fd, &conn_fd) ||
			!int_make_non_blocking(conn_fd, 1) ||
			!NAL_CONNECTION_set_size(conn,
				list->addr.def_buffer_size))
		goto err;
	/* If appropriate, apply "nagle" setting */
	if((list->addr.family == NAL_ADDRESS_TYPE_IPv4) &&
			!int_set_nagle(conn_fd))
		goto err;
	/* Success! */
	NAL_memcpy(NAL_ADDRESS, &(conn->addr), &(list->addr));
	conn->fd = conn_fd;
	return 1;
err:
	int_close(&conn_fd);
	/* This takes care of all cleanup, including deallocation */
	NAL_CONNECTION_close(conn);
	return 0;
}

int NAL_LISTENER_accept(const NAL_LISTENER *list, NAL_SELECTOR *sel,
			NAL_CONNECTION *conn)
{
	unsigned char flags;
	int conn_fd = -1;

	if((list == NULL) || (sel == NULL) || (conn == NULL))
		abort();
	/* Try to catch any cases of being called with a used 'conn' */
	assert(conn->addr.family == NAL_ADDRESS_TYPE_NULL);
	if(conn->addr.family != NAL_ADDRESS_TYPE_NULL)
		goto err;
	int_selector_get_list(sel, list, &flags);
	if(flags & SELECTOR_FLAG_EXCEPT) {
#if NAL_DEBUG_LEVEL > 1
		NAL_fprintf(NAL_stderr(), "Warn, listener has exception flag set\n\n");
#endif
		goto err;
	}
	if(flags & SELECTOR_FLAG_READ) {
		/* Do the accept */
		if(!int_accept(list->fd, &conn_fd) ||
				!int_make_non_blocking(conn_fd, 1) ||
				!NAL_CONNECTION_set_size(conn,
					list->addr.def_buffer_size))
			goto err;
		/* If appropriate, apply "nagle" setting */
		if((list->addr.family == NAL_ADDRESS_TYPE_IPv4) &&
				!int_set_nagle(conn_fd))
			goto err;
		NAL_memcpy(NAL_ADDRESS, &(conn->addr), &(list->addr));
		conn->fd = conn_fd;
		int_selector_list_done(sel, list);
		return 1;
	}
err:
	int_close(&conn_fd);
	NAL_CONNECTION_close(conn);
	return 0;
}

/* Add a listener version of this theme for completeness */
int NAL_LISTENER_move(NAL_LISTENER *to, NAL_LISTENER *from)
{
	if((to == NULL) || (from == NULL))
		return 0;
	/* Try to catch any cases of being called with a used 'to' */
	assert(to->addr.family == NAL_ADDRESS_TYPE_NULL);
	if(to->addr.family != NAL_ADDRESS_TYPE_NULL)
		goto err;
	/* Now move the address across */
	if(!NAL_ADDRESS_move(&to->addr, &from->addr)) {
#if NAL_DEBUG_LEVEL > 2
		NAL_fprintf(NAL_stderr(), "Warn, NAL_LISTENER_move failing because of "
				"address_move errors\n");
#endif
		goto err;
	}
	/* Success, all that's needed is to move the file descriptor */
	to->fd = from->fd;
	from->fd = -1;
	/* The file descriptor and the address are "nulled", but use our close
	 * function to make anything else gets sorted out too */
	NAL_LISTENER_close(from);
	return 1;
err:
	NAL_LISTENER_close(to);
	return 0;
}

const NAL_ADDRESS *NAL_LISTENER_address(const NAL_LISTENER *list)
{
	return &list->addr;
}

/************************/
/* CONNECTION FUNCTIONS */
/************************/

NAL_CONNECTION *NAL_CONNECTION_malloc(void)
{
	NAL_CONNECTION *conn = NAL_malloc(NAL_CONNECTION, 1);
	if(conn)
		NAL_CONNECTION_init(conn);
	return conn;
	
}

void NAL_CONNECTION_free(NAL_CONNECTION *a)
{
	NAL_CONNECTION_close(a);
	NAL_free(NAL_CONNECTION, a);
}

static void NAL_CONNECTION_init(NAL_CONNECTION *conn)
{
	NAL_ADDRESS_init(&conn->addr);
	conn->fd = -1;
	conn->established = 0;
	NAL_BUFFER_init(&conn->read);
	NAL_BUFFER_init(&conn->send);
}

static int NAL_CONNECTION_close(NAL_CONNECTION *conn)
{
	if(conn == NULL)
		return 0;
	int_close(&conn->fd);
	/* clear the buffers */
	if(!NAL_CONNECTION_set_size(conn, 0))
		return 0;
	/* good aggregation programming practice. :-) */
	NAL_ADDRESS_close(&conn->addr);
	/* reinitialise */
	NAL_CONNECTION_init(conn);
	return 1;
}

int NAL_CONNECTION_create(NAL_CONNECTION *conn, const NAL_ADDRESS *addr)
{
	int fd = -1;

	if((conn == NULL) || (addr == NULL))
		/* should *never* happen */
		abort();
	/* Try to catch any cases of being called with a used 'conn' */
	assert(conn->addr.family == NAL_ADDRESS_TYPE_NULL);
	if(conn->addr.family != NAL_ADDRESS_TYPE_NULL)
		goto err;
	if(addr->family == NAL_ADDRESS_TYPE_NULL) 
		/* also should never happen */
		abort();
	if((addr->caps & NAL_ADDRESS_CAN_CONNECT) == 0) {
		/* Perhaps the string for the address was invalid? */
#if NAL_DEBUG_LEVEL > 1
		NAL_fprintf(NAL_stderr(), "Error, '%s' can't connect\n", addr->str_form);
#endif
		goto err;
	}
	if(!int_create_socket(&fd, addr->family) ||
			!int_make_non_blocking(fd, 1) ||
			!int_connect(fd, &addr->addr, addr->family,
				&conn->established) ||
			!NAL_CONNECTION_set_size(conn, addr->def_buffer_size))
		goto err;
	/* If appropriate, apply "nagle" setting */
	if((addr->family == NAL_ADDRESS_TYPE_IPv4) && !int_set_nagle(fd))
		goto err;
	/* Success! */
	NAL_memcpy(NAL_ADDRESS, &(conn->addr), addr);
	conn->fd = fd;
	return 1;
err:
	int_close(&fd);
	NAL_CONNECTION_close(conn);
	return 0;
}

/* This function never works on WIN32 */
int NAL_CONNECTION_create_pair(NAL_CONNECTION *conn1, NAL_CONNECTION *conn2,
			unsigned int def_buffer_size)
{
#ifndef WIN32
	int sv[2] = {-1,-1};

	if((conn1 == NULL) || (conn2 == NULL))
		/* should *never* happen */
		abort();
	if(!int_check_buffer_size(def_buffer_size))
		return 0;
	/* Try to catch any cases of being called with used 'conns' */
	assert(conn1->addr.family == NAL_ADDRESS_TYPE_NULL);
	assert(conn2->addr.family == NAL_ADDRESS_TYPE_NULL);
	if(conn1->addr.family != NAL_ADDRESS_TYPE_NULL)
		goto err;
	if(conn2->addr.family != NAL_ADDRESS_TYPE_NULL)
		goto err;
	if(!int_create_unix_pair(sv) ||
			!int_make_non_blocking(sv[0], 1) ||
			!int_make_non_blocking(sv[1], 1) ||
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
	int_close(sv);
	int_close(sv + 1);
	NAL_CONNECTION_close(conn1);
	NAL_CONNECTION_close(conn2);
#endif
	return 0;
}

int NAL_CONNECTION_create_dummy(NAL_CONNECTION *conn,
			unsigned int def_buffer_size)
{
	if(conn == NULL)
		/* should *never* happen */
		abort();
	if(!int_check_buffer_size(def_buffer_size))
		return 0;
	/* Try to catch any cases of being called with used a 'conn' */
	assert(conn->addr.family == NAL_ADDRESS_TYPE_NULL);
	if(conn->addr.family != NAL_ADDRESS_TYPE_NULL)
		return 0;
	/* We only use one buffer, so only expand one */
	if(!NAL_BUFFER_set_size(&conn->read, def_buffer_size))
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
	if((conn == NULL) || !int_check_buffer_size(size))
		return 0;
	if(!NAL_BUFFER_set_size(&conn->read, size) ||
			!NAL_BUFFER_set_size(&conn->send, size)) {
#if NAL_DEBUG_LEVEL > 1
		NAL_fprintf(NAL_stderr(), "Error, couldn't set buffer sizes\n");
#endif
		return 0;
	}
	return 1;
}

NAL_BUFFER *NAL_CONNECTION_get_read(NAL_CONNECTION *conn)
{
	if(conn == NULL)
		return NULL;
	return &conn->read;
}

NAL_BUFFER *NAL_CONNECTION_get_send(NAL_CONNECTION *conn)
{
	if(conn == NULL)
		return NULL;
	/* A "dummy" connection reads and writes into the same buffer, so handle
	 * this special case. */
	if(conn->fd == -2)
		return &conn->read;
	return &conn->send;
}

/* If this function returns zero (failure), then it is a bad thing and means
 * the connection should be closed by the caller. */
int NAL_CONNECTION_io_cap(NAL_CONNECTION *conn, NAL_SELECTOR *sel,
			unsigned int max_read, unsigned int max_send)
{
	unsigned char flags;
	int io_ret;

	if((conn == NULL) || (sel == NULL))
		return 0;
	/* If we're a dummy connection, "io" has no useful meaning */
	if(conn->fd == -2)
		return 1;
	int_selector_get_conn(sel, conn, &flags);
	if(flags & SELECTOR_FLAG_EXCEPT) {
#if NAL_DEBUG_LEVEL > 1
		NAL_fprintf(NAL_stderr(), "Warn, connection has exception flag set\n\n");
#endif
		goto closing;
	}
	/* Now logically, anything we've selected on should be something we
	 * want to do - eg. if we're selected for sending, it hardly makes
	 * sense that our output buffer should be empty? So, at a certain
	 * debugging level, we perform checks. WARNING: Beware of accidently
	 * building heisenburgs.... */
#if NAL_DEBUG_LEVEL > 1
	if((flags & SELECTOR_FLAG_READ) && NAL_BUFFER_full(&conn->read))
		abort();
	if((flags & SELECTOR_FLAG_SEND) && NAL_BUFFER_empty(&conn->send))
		abort();
#endif
	if(flags & SELECTOR_FLAG_READ) {
		io_ret = int_buffer_from_fd(&conn->read, conn->fd, max_read);
		if(io_ret <= 0) {
			/* (<0) --> error, (==0) --> clean disconnect */
			goto closing;
		}
		/* This ensures that a successful read from the socket will
		 * mark the connection as established if it isn't already. */
		conn->established = 1;
	}
	if(flags & SELECTOR_FLAG_SEND) {
		io_ret = int_buffer_to_fd(&conn->send, conn->fd, max_send);
		if(io_ret <= 0) {
			/* (<0) --> error, (==0) --> clean disconnect */
			goto closing;
		}
		/* This ensures that a successful read from the socket will
		 * mark the connection as established if it isn't already. */
		conn->established = 1;
	}
	/* Remove this connection from the select sets so a redundant call does
	 * nothing. */
	int_selector_conn_done(sel, conn);
	/* Success! */
	return 1;
closing:
#if NAL_DEBUG_LEVEL > 2
	if(NAL_BUFFER_notempty(&conn->send))
		NAL_fprintf(NAL_stderr(), "Warn, connection closing with unsent data\n");
	else if(NAL_BUFFER_notempty(&conn->read))
		NAL_fprintf(NAL_stderr(), "Warn, connection closing with received data\n");
	else
		NAL_fprintf(NAL_stderr(), "Info, connection with empty buffers will close\n");
#endif
	return 0;
}

int NAL_CONNECTION_io(NAL_CONNECTION *conn, NAL_SELECTOR *sel)
{
	return NAL_CONNECTION_io_cap(conn, sel, 0, 0);
}

/* Sometimes it's desirable for one part of the code to create (or accept)
 * a connection into say a local variable, and then pass it by pointer to
 * something that should "consume" the connection. This function does that by
 * copying the connection details into a new location and nullifying the values
 * in the previous location - eg. so a NAL_CONNECTION_close() on the previous
 * variable does not result in the connection being closed. */
int NAL_CONNECTION_move(NAL_CONNECTION *to, NAL_CONNECTION *from)
{
	if((to == NULL) || (from == NULL))
		return 0;
	/* Try to catch any cases of being called with used a 'to' */
	assert(to->addr.family == NAL_ADDRESS_TYPE_NULL);
	if(to->addr.family != NAL_ADDRESS_TYPE_NULL)
		goto err;
	/* First, the new connection needs identical buffers */
	if(!NAL_BUFFER_set_size(&to->read, NAL_BUFFER_size(&from->read)) ||
			!NAL_BUFFER_set_size(&to->send,
				NAL_BUFFER_size(&from->send))) {
#if NAL_DEBUG_LEVEL > 2
		NAL_fprintf(NAL_stderr(), "Warn, NAL_CONNECTION_move failing because of "
				"buffer_set_size errors\n");
#endif
		goto err;
	}
	/* Now move the address across */
	if(!NAL_ADDRESS_move(&to->addr, &from->addr)) {
#if NAL_DEBUG_LEVEL > 2
		NAL_fprintf(NAL_stderr(), "Warn, NAL_CONNECTIONn_move failing because of "
				"address_move errors\n");
#endif
		goto err;
	}
	/* Success, all that's needed is to move the file descriptor */
	to->fd = from->fd;
	to->established = from->established;
	from->fd = -1;
	/* The file descriptor and the address are "nulled", so we can use our
	 * close function to make sure the buffers get sorted without closing
	 * the file descriptor. */
	NAL_CONNECTION_close(from);
	return 1;
err:
	NAL_CONNECTION_close(to);
	return 0;
}

const NAL_ADDRESS *NAL_CONNECTION_address(const NAL_CONNECTION *conn)
{
	return &conn->addr;
}

int NAL_CONNECTION_is_established(const NAL_CONNECTION *conn)
{
	return conn->established;
}

int NAL_CONNECTION_get_fd(const NAL_CONNECTION *conn)
{
	return conn->fd;
}

/**********************/
/* SELECTOR FUNCTIONS */
/**********************/

NAL_SELECTOR *NAL_SELECTOR_malloc(void)
{
	NAL_SELECTOR *sel = NAL_malloc(NAL_SELECTOR, 1);
	if(sel)
		NAL_SELECTOR_init(sel);
	return sel;
}

void NAL_SELECTOR_free(NAL_SELECTOR *a)
{
	NAL_SELECTOR_close(a);
	NAL_free(NAL_SELECTOR, a);
}

static void int_selector_item_init(NAL_SELECTOR_item *item)
{
	FD_ZERO(&item->reads);
	FD_ZERO(&item->sends);
	FD_ZERO(&item->excepts);
	item->max = 0;
}

static void int_selector_item_close(NAL_SELECTOR_item *item)
{
	/* No cleanup required */
	int_selector_item_init(item);
}

static void NAL_SELECTOR_init(NAL_SELECTOR *sel)
{
	int_selector_item_init(&sel->last_selected);
	int_selector_item_init(&sel->to_select);
}

static int NAL_SELECTOR_close(NAL_SELECTOR *sel)
{
	if(sel == NULL)
		return 0;
	/* No cleanup required */
	NAL_SELECTOR_init(sel);
	return 1;
}

/* Workaround signed/unsigned conflicts between real systems and windows */
#ifndef WIN32
#define FD_SET2(a,b) FD_SET((a),(b))
#define FD_CLR2(a,b) FD_CLR((a),(b))
#else
#define FD_SET2(a,b) FD_SET((SOCKET)(a),(b))
#define FD_CLR2(a,b) FD_CLR((SOCKET)(a),(b))
#endif

int NAL_SELECTOR_add_conn_ex(NAL_SELECTOR *sel, const NAL_CONNECTION *conn,
			unsigned int flags)
{
	if((sel == NULL) || (conn == NULL))
		return 0;
	/* If we're a "dummy" connection, our file-descriptor is -2! */
	if(conn->fd == -2)
		return 1;
	/* We always select for excepts, but reads and sends depend on the
	 * buffers and the flags. */
	FD_SET2(conn->fd, &sel->to_select.excepts);
	if(NAL_BUFFER_notfull(&conn->read) && (flags & NAL_SELECT_FLAG_READ))
		FD_SET2(conn->fd, &sel->to_select.reads);
	if(NAL_BUFFER_notempty(&conn->send) && (flags & NAL_SELECT_FLAG_SEND))
		FD_SET2(conn->fd, &sel->to_select.sends);
	/* We need to adjust the max for the select() call */
	sel->to_select.max = ((sel->to_select.max <= (conn->fd + 1)) ?
				(conn->fd + 1) : sel->to_select.max);
	return 1;
}

int NAL_SELECTOR_add_conn(NAL_SELECTOR *sel, const NAL_CONNECTION *conn)
{
	return NAL_SELECTOR_add_conn_ex(sel, conn, NAL_SELECT_FLAG_RW);
}

int NAL_SELECTOR_del_conn(NAL_SELECTOR *sel, const NAL_CONNECTION *conn)
{
	if((sel == NULL) || (conn == NULL))
		return 0;
	FD_CLR2(conn->fd, &sel->to_select.reads);
	FD_CLR2(conn->fd, &sel->to_select.sends);
	FD_CLR2(conn->fd, &sel->to_select.excepts);
	return 1;
}

int NAL_SELECTOR_add_listener(NAL_SELECTOR *sel, const NAL_LISTENER *list)
{
	if((sel == NULL) || (list == NULL))
		return 0;
	FD_SET2(list->fd, &sel->to_select.excepts);
	FD_SET2(list->fd, &sel->to_select.reads);
	sel->to_select.max = ((sel->to_select.max <= (list->fd + 1)) ?
				(list->fd + 1) : sel->to_select.max);
	return 1;
}

int NAL_SELECTOR_del_listener(NAL_SELECTOR *sel, const NAL_LISTENER *list)
{
	if((sel == NULL) || (list == NULL))
		return 0;
	FD_CLR2(list->fd, &sel->to_select.reads);
	FD_CLR2(list->fd, &sel->to_select.excepts);
	return 1;
}

/* This function is now static and only used internally. It's predeclared up
 * the top somewhere but I leave the implementation down here in some kind of
 * semi-logical order. NB: As its internal, any error is fatal, so there's no
 * return value. */
static void int_selector_get_conn(const NAL_SELECTOR *sel,
			const NAL_CONNECTION *conn,
			unsigned char *flags)
{
	if((sel == NULL) || (conn == NULL) || (flags == NULL))
		/* This should *never* happen */
		abort();
	*flags = 0;
	/* If it's a dummy connection go quietly */
	if(conn->fd == -2)
		return;
	if(FD_ISSET(conn->fd, &sel->last_selected.reads))
		*flags |= SELECTOR_FLAG_READ;
	if(FD_ISSET(conn->fd, &sel->last_selected.sends))
		*flags |= SELECTOR_FLAG_SEND;
	if(FD_ISSET(conn->fd, &sel->last_selected.excepts))
		*flags |= SELECTOR_FLAG_EXCEPT;
}

/* ditto */
static void int_selector_get_list(const NAL_SELECTOR *sel,
			const NAL_LISTENER *list,
			unsigned char *flags)
{
	if((sel == NULL) || (list == NULL) || (flags == NULL))
		/* This should *never* happen */
		abort();
	*flags = 0;
	if(FD_ISSET(list->fd, &sel->last_selected.reads))
		*flags |= SELECTOR_FLAG_READ;
	if(FD_ISSET(list->fd, &sel->last_selected.excepts))
		*flags |= SELECTOR_FLAG_EXCEPT;
}

/* This function is used by NAL_CONNECTION_io() after processing a connection to
 * turn off read/write flags so that any redundant calls to not try to do
 * redundant reads or writes. */
static void int_selector_conn_done(NAL_SELECTOR *sel,
			const NAL_CONNECTION *conn)
{
	/* If it's a dummy connection go quietly */
	if(conn->fd == -2)
		return;
	FD_CLR2(conn->fd, &sel->last_selected.reads);
	FD_CLR2(conn->fd, &sel->last_selected.sends);
	/* We do not clear any exception flag that might be set, repeated calls
	 * to connection_io() should not retain flags for readability or
	 * writability, but it should retain flags for exceptions. */
}

/* ditto */
static void int_selector_list_done(NAL_SELECTOR *sel,
			const NAL_LISTENER *list)
{
	FD_CLR2(list->fd, &sel->last_selected.reads);
}

int NAL_SELECTOR_select(NAL_SELECTOR *sel, unsigned long usec_timeout,
			int use_timeout)
{
	struct timeval timeout;

	if(sel == NULL)
		return 0;
	timeout.tv_sec = usec_timeout / 1000000;
	timeout.tv_usec = usec_timeout % 1000000;
	/* Migrate to_select over to last_selected */
	int_selector_item_close(&sel->last_selected);
	NAL_memcpy(fd_set, &sel->last_selected.reads, &sel->to_select.reads);
	NAL_memcpy(fd_set, &sel->last_selected.sends, &sel->to_select.sends);
	NAL_memcpy(fd_set, &sel->last_selected.excepts, &sel->to_select.excepts);
	sel->last_selected.max = sel->to_select.max;
	int_selector_item_close(&sel->to_select);
	return select(sel->last_selected.max,
			&sel->last_selected.reads,
			&sel->last_selected.sends,
			&sel->last_selected.excepts,
			(use_timeout ? &timeout : NULL));
}

/* Specials, these relate to adding "other bits" to our select engine, most
 * notably, stdin (eg. we may want to break on input as well as network
 * activity). */

int NAL_stdin_set_non_blocking(int non_blocking)
{
	return int_make_non_blocking(fileno(NAL_stdin()), non_blocking);
}

int NAL_SELECTOR_stdin_add(NAL_SELECTOR *sel)
{
	int fd = fileno(NAL_stdin());

	if(sel == NULL)
		return 0;

	/* We always select for excepts, but reads and sends depend on the
	 * buffers. */
	FD_SET2(fd, &sel->to_select.reads);
	/* We need to adjust the max for the select() call */
	sel->to_select.max = ((sel->to_select.max <= fd + 1) ?
				(fd + 1) : sel->to_select.max);
	return 1;
}

int NAL_SELECTOR_stdin_readable(NAL_SELECTOR *sel)
{
	int ret, fd = fileno(NAL_stdin());

	/* This should only be called once per-select because we unset the flag
	 * for stdin once reading. This is say stdin is not accidently read a
	 * second time causing a block. */
	ret = FD_ISSET(fd, &sel->last_selected.reads);
	if(ret)
		FD_CLR2(fd, &sel->last_selected.reads);
	return ret;
}

/* This special sets our global flag that controls whether new ipv4 connections
 * (explicitly connected or via an accept()) have nagle turned off or not. */
int NAL_config_set_nagle(int enabled)
{
	int_use_nagle = (enabled ? 1 : 0);
	return 1;
}

/********************/
/* BUFFER FUNCTIONS */
/********************/

NAL_BUFFER *NAL_BUFFER_malloc(void)
{
	NAL_BUFFER *b = NAL_malloc(NAL_BUFFER, 1);
	if(b)
		NAL_BUFFER_init(b);
	return b;
}

void NAL_BUFFER_free(NAL_BUFFER *a)
{
	NAL_BUFFER_close(a);
	NAL_free(NAL_BUFFER, a);
}

/* This is the one function that has no macro equivalent. It's too important to
 * check for errors in a way that would be too messy (and dangerous) in a macro.
 * Also, it's overhead is substantial enough to not bother inlining. */
int NAL_BUFFER_set_size(NAL_BUFFER *buf, unsigned int size)
{
	unsigned char *next;

	/* Saves time, and avoids the degenerate case that fails realloc -
	 * namely when ptr is NULL (realloc becomes malloc) *and* size is 0
	 * (realloc becomes free). */
	if(size == buf->_size)
		return 1;
	if(size > NAL_BUFFER_MAX_SIZE) {
#if NAL_DEBUG_LEVEL > 1
		NAL_fprintf(NAL_stderr(), "Error, NAL_BUFFER_set_size() called with too "
				"large a size\n");
#endif
		return 0;
	}
	next = NAL_realloc(unsigned char, buf->_data, size);
	if(size && !next)
		return 0;
	buf->_data = next;
	buf->_size = size;
	return 1;
}

static void NAL_BUFFER_init(NAL_BUFFER *buf)
{
	NAL_zero(NAL_BUFFER, buf);
}

static int NAL_BUFFER_close(NAL_BUFFER *buf)
{
	if(buf == NULL)
		return 0;
	/* Deallocate anything we allocated before zeroing the structure */
	NAL_BUFFER_set_size(buf, 0);
	NAL_BUFFER_init(buf);
	return 1;
}

int NAL_BUFFER_empty(const NAL_BUFFER *buf)
{
	return (buf->_used == 0);
}

int NAL_BUFFER_full(const NAL_BUFFER *buf)
{
	return (buf->_used == buf->_size);
}

int NAL_BUFFER_notempty(const NAL_BUFFER *buf)
{
	return (buf->_used > 0);
}

int NAL_BUFFER_notfull(const NAL_BUFFER *buf)
{
	return (buf->_used < buf->_size);
}

unsigned int NAL_BUFFER_used(const NAL_BUFFER *buf)
{
	return buf->_used;
}

unsigned int NAL_BUFFER_unused(const NAL_BUFFER *buf)
{
	return (buf->_size - buf->_used);
}

const unsigned char *NAL_BUFFER_data(const NAL_BUFFER *buf)
{
	return buf->_data;
}

unsigned int NAL_BUFFER_size(const NAL_BUFFER *buf)
{
	return buf->_size;
}

unsigned int NAL_BUFFER_write(NAL_BUFFER *buf, const unsigned char *ptr,
		                unsigned int size)
{
	unsigned int towrite = NAL_BUFFER_unused(buf);
	if(towrite > size)
		towrite = size;
	if(towrite == 0)
		return 0;
	memcpy(buf->_data + buf->_used, ptr, towrite);
	buf->_used += towrite;
	return towrite;
}

unsigned int NAL_BUFFER_read(NAL_BUFFER *buf, unsigned char *ptr,
		                unsigned int size)
{
	unsigned int toread = NAL_BUFFER_used(buf);
	if(toread > size)
		toread = size;
	if(toread == 0)
		return 0;
	memcpy(ptr, buf->_data, toread);
	buf->_used -= toread;
	if(buf->_used > 0)
		memmove(buf->_data, buf->_data + toread, buf->_used);
	return toread;
}

unsigned char *NAL_BUFFER_read_ptr(NAL_BUFFER *buf)
{
	return buf->_data;
}

unsigned char *NAL_BUFFER_write_ptr(NAL_BUFFER *buf)
{
	return (buf->_data + buf->_used);
}

unsigned int NAL_BUFFER_takedata(NAL_BUFFER *buf,
		unsigned char *dest,
		unsigned int size)
{
	unsigned int totake = NAL_BUFFER_used(buf);
	if(totake > size)
		totake = size;
	if(dest)
		NAL_memcpy_n(unsigned char, dest, buf->_data, totake);
	buf->_used -= totake;
	if(buf->_used > 0)
		NAL_memmove_n(unsigned char, buf->_data,
				buf->_data + totake, buf->_used);
	return totake;
}

unsigned int NAL_BUFFER_wrote(NAL_BUFFER *buf, unsigned int size)
{
	unsigned int toadd = NAL_BUFFER_unused(buf);
	if(toadd > size)
		toadd = size;
	buf->_used += toadd;
	return toadd;
}
