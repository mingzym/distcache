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
#ifndef HEADER_PRIVATE_NAL_INTERNAL_H
#define HEADER_PRIVATE_NAL_INTERNAL_H

#ifndef HEADER_LIBSYS_PRE_H
	#error "Must include libsys/pre.h prior to libnal/nal.h"
#endif

#ifndef HEADER_LIBNAL_NAL_H
	#error "Must include libnal/nal.h prior to libnal/nal_internal.h"
#endif

/* Utility functions and types used inside libnal. Eventually these should be
 * hidden from API functions (only protocol implementations should require
 * them) but until that's organised, I'm putting everything here. */

/* Some platforms don't get socklen_t ... use int */
#ifndef socklen_t
#define socklen_t int
#endif

/* Flags used in determining what "kind" of address has been created */
#define NAL_ADDRESS_CAN_LISTEN	(unsigned char)0x01
#define NAL_ADDRESS_CAN_CONNECT	(unsigned char)0x02

/* nal_sock code will use this as a default in its call to listen(2) */
#define NAL_LISTENER_BACKLOG	511

/* An upper limit on the size of address strings that will be allowable */
#define NAL_ADDRESS_MAX_STR_LEN	255

/* This nal_sockaddr stuff is to encapsulate unix domain and ipv4 socket
 * code. */
typedef enum {
	nal_sockaddr_type_ip,
	nal_sockaddr_type_unix
} nal_sockaddr_type;
typedef struct st_nal_sockaddr {
	union {
		struct sockaddr_in val_in;
#ifndef WIN32
		struct sockaddr_un val_un;
#endif
	} val;
	nal_sockaddr_type type;
	unsigned char caps;
} nal_sockaddr;

/***********/
/* util_fd */
/***********/

int nal_fd_make_non_blocking(int fd, int non_blocking);
int nal_fd_buffer_to_fd(NAL_BUFFER *buf, int fd, unsigned int max_send);
int nal_fd_buffer_from_fd(NAL_BUFFER *buf, int fd, unsigned int max_read);
void nal_fd_close(int *fd);

/***************/
/* util_socket */
/***************/

int nal_sock_set_nagle(int fd, int use_nagle, nal_sockaddr_type type);
int nal_sock_sockaddr_from_ipv4(nal_sockaddr *addr, const char *start_ptr);
int nal_sock_sockaddr_from_unix(nal_sockaddr *addr, const char *start_ptr);
int nal_sock_create_socket(int *fd, nal_sockaddr *addr);
int nal_sock_create_unix_pair(int sv[2]);
int nal_sock_connect(int fd, const nal_sockaddr *addr, int *established);
int nal_sock_listen(int fd, const nal_sockaddr *addr);
int nal_sock_accept(int listen_fd, int *conn);
int nal_sock_is_connected(int fd);

/***********/
/* vtables */
/***********/

typedef struct st_NAL_CONNECTION_vtable {
	/* The size of "vtdata" the NAL_CONNECTION should provide */
	size_t vtdata_size;
	/* constructor after NAL_ADDRESS_vtable->create_connection() */
	int (*on_create)(NAL_CONNECTION *conn, const NAL_ADDRESS *addr);
	/* constructor after NAL_LISTENER_vtable->do_accept() */
	int (*on_accept)(NAL_CONNECTION *conn, const NAL_LISTENER *l);
	/* destructor */
	void (*on_destroy)(NAL_CONNECTION *conn);
	/* Handlers for NAL_CONNECTION functionality */
	int (*set_size)(NAL_CONNECTION *conn, unsigned int size);
	NAL_BUFFER *(*get_read)(const NAL_CONNECTION *conn);
	NAL_BUFFER *(*get_send)(const NAL_CONNECTION *conn);
	int (*is_established)(const NAL_CONNECTION *conn);
	int (*do_io)(NAL_CONNECTION *conn, NAL_SELECTOR *sel,
			unsigned int max_read, unsigned int max_send);
	void (*selector_add)(const NAL_CONNECTION *conn, NAL_SELECTOR *sel);
	void (*selector_del)(const NAL_CONNECTION *conn, NAL_SELECTOR *sel);
} NAL_CONNECTION_vtable;
void *nal_connection_get_vtdata(const NAL_CONNECTION *conn);
const NAL_CONNECTION_vtable *nal_connection_get_vtable(const NAL_CONNECTION *conn);

typedef struct st_NAL_LISTENER_vtable {
	/* The size of "vtdata" the NAL_CONNECTION should provide */
	size_t vtdata_size;
	/* constructor/destructor */
	int (*on_create)(NAL_LISTENER *l, const NAL_ADDRESS *addr);
	void (*on_destroy)(NAL_LISTENER *l);
	/* Handlers for NAL_LISTENER functionality */
	const NAL_CONNECTION_vtable *(*do_accept)(NAL_LISTENER *l,
						NAL_SELECTOR *sel);
	void (*selector_add)(const NAL_LISTENER *l, NAL_SELECTOR *sel);
	void (*selector_del)(const NAL_LISTENER *l, NAL_SELECTOR *sel);
} NAL_LISTENER_vtable;
void *nal_listener_get_vtdata(const NAL_LISTENER *l);
const NAL_LISTENER_vtable *nal_listener_get_vtable(const NAL_LISTENER *l);
const NAL_CONNECTION_vtable *nal_listener_accept_connection(NAL_LISTENER *l,
							NAL_SELECTOR *sel);

typedef struct st_NAL_ADDRESS_vtable {
	/* The size of "vtdata" the NAL_CONNECTION should provide */
	size_t vtdata_size;
	/* constructor/destructor */
	int (*on_create)(NAL_ADDRESS *addr, const char *addr_string);
	void (*on_destroy)(NAL_ADDRESS *addr);
	/* Handlers for NAL_ADDRESS functionality */
	int (*can_connect)(const NAL_ADDRESS *addr);
	int (*can_listen)(const NAL_ADDRESS *addr);
	const NAL_LISTENER_vtable *(*create_listener)(const NAL_ADDRESS *addr);
	const NAL_CONNECTION_vtable *(*create_connection)(const NAL_ADDRESS *addr);
	struct st_NAL_ADDRESS_vtable *next;
} NAL_ADDRESS_vtable;
void *nal_address_get_vtdata(const NAL_ADDRESS *addr);
const NAL_ADDRESS_vtable *nal_address_get_vtable(const NAL_ADDRESS *addr);
const NAL_LISTENER_vtable *nal_address_get_listener(const NAL_ADDRESS *addr);
const NAL_CONNECTION_vtable *nal_address_get_connection(const NAL_ADDRESS *addr);

/***************************/
/* Builtin address vtables */
/***************************/

const NAL_ADDRESS_vtable *NAL_ADDRESS_vtable_builtins(void);

/****************************************/
/* NAL_BUFFER - implemented in buffer.c */
/****************************************/

/* There's little point making data buffers bigger than this, but it can be
 * changed later if desired. To cut down latencies, buffers used for network IO
 * should only be big enough to ensure (a) "things fit", and (b) we can
 * aggregate as much data as possible into single "read"s and "sends" (rather
 * than sending multitudes of fragments. I strongly doubt it's possible to send
 * a IP packet as big as 32K, so why bother adding further to latency by letting
 * data-loops build up more than that before going back to the network code?
 * Anyway - it'll get changed if it's a problem ... for now it's a good check to
 * make sure the other code isn't too loose. */
#define NAL_BUFFER_MAX_SIZE  32768
#define nal_check_buffer_size(sz) (((sz) > NAL_BUFFER_MAX_SIZE) ? 0 : 1)

/********************************************/
/* NAL_SELECTOR - implemented in selector.c */
/********************************************/

#define SELECTOR_FLAG_READ	0x01
#define SELECTOR_FLAG_SEND	0x02
#define SELECTOR_FLAG_EXCEPT	0x04

/* set/unset operate on "to_select */
void nal_selector_fd_set(NAL_SELECTOR *sel, int fd, unsigned char flags);
void nal_selector_fd_unset(NAL_SELECTOR *sel, int fd);
/* test/clear operate on "last_selected" */
unsigned char nal_selector_fd_test(const NAL_SELECTOR *sel, int fd);
void nal_selector_fd_clear(NAL_SELECTOR *sel, int fd);

#endif /* !defined(HEADER_PRIVATE_NAL_INTERNAL_H) */
