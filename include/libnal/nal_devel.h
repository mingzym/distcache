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
#ifndef HEADER_LIBNAL_NAL_DEVEL_H
#define HEADER_LIBNAL_NAL_DEVEL_H

#ifndef HEADER_LIBNAL_NAL_H
	#error "Must include libnal/nal.h prior to libnal/nal_devel.h"
#endif

/* Predeclare our vtable types */
typedef struct st_NAL_ADDRESS_vtable NAL_ADDRESS_vtable;
typedef struct st_NAL_LISTENER_vtable NAL_LISTENER_vtable;
typedef struct st_NAL_CONNECTION_vtable NAL_CONNECTION_vtable;
typedef struct st_NAL_SELECTOR_vtable NAL_SELECTOR_vtable;

/***************/
/* NAL_ADDRESS */
/***************/

struct st_NAL_ADDRESS_vtable {
	/* As we have a global list of available types, this gives namespace */
	const char *unique_name;
	/* The size of "vtdata" the NAL_ADDRESS should provide */
	size_t vtdata_size;
	/* NULL-terminated array of string prefixes that correspond to this
	 * vtable. Should include trailing colon. */
	const char **prefixes;
	/* (De)Initialisations */
	int (*on_create)(NAL_ADDRESS *addr);
	void (*on_destroy)(NAL_ADDRESS *addr);
	void (*on_reset)(NAL_ADDRESS *addr);
	/* Handlers for NAL_ADDRESS functionality */
	int (*parse)(NAL_ADDRESS *addr, const char *addr_string);
	int (*can_connect)(const NAL_ADDRESS *addr);
	int (*can_listen)(const NAL_ADDRESS *addr);
	const NAL_LISTENER_vtable *(*create_listener)(const NAL_ADDRESS *addr);
	const NAL_CONNECTION_vtable *(*create_connection)(const NAL_ADDRESS *addr);
	struct st_NAL_ADDRESS_vtable *next;
};
int nal_address_set_vtable(NAL_ADDRESS *addr, const NAL_ADDRESS_vtable *vt);
const NAL_ADDRESS_vtable *nal_address_get_vtable(const NAL_ADDRESS *addr);
void *nal_address_get_vtdata(const NAL_ADDRESS *addr);
const NAL_LISTENER_vtable *nal_address_get_listener(const NAL_ADDRESS *addr);
const NAL_CONNECTION_vtable *nal_address_get_connection(const NAL_ADDRESS *addr);

/****************/
/* NAL_LISTENER */
/****************/

struct st_NAL_LISTENER_vtable {
	/* The size of "vtdata" the NAL_LISTENER should provide */
	size_t vtdata_size;
	/* (De)Initialisations */
	int (*on_create)(NAL_LISTENER *l);
	void (*on_destroy)(NAL_LISTENER *l);
	void (*on_reset)(NAL_LISTENER *l);
	/* Handlers for NAL_LISTENER functionality */
	int (*listen)(NAL_LISTENER *l, const NAL_ADDRESS *addr);
	const NAL_CONNECTION_vtable *(*pre_accept)(NAL_LISTENER *l,
						NAL_SELECTOR *sel);
	void (*selector_add)(const NAL_LISTENER *l, NAL_SELECTOR *sel);
	void (*selector_del)(const NAL_LISTENER *l, NAL_SELECTOR *sel);
	int (*finished)(const NAL_LISTENER *l);
	/* Extensions that may not be meaningful, case-by-case */
	int (*set_fs_owner)(NAL_LISTENER *l, const char *ownername,
				const char *groupname);
	int (*set_fs_perms)(NAL_LISTENER *l, const char *octal_string);
};
int nal_listener_set_vtable(NAL_LISTENER *l, const NAL_LISTENER_vtable *vtable);
const NAL_LISTENER_vtable *nal_listener_get_vtable(const NAL_LISTENER *l);
void *nal_listener_get_vtdata(const NAL_LISTENER *l);
const NAL_CONNECTION_vtable *nal_listener_pre_accept(NAL_LISTENER *l,
						NAL_SELECTOR *sel);

/******************/
/* NAL_CONNECTION */
/******************/

struct st_NAL_CONNECTION_vtable {
	/* The size of "vtdata" the NAL_CONNECTION should provide */
	size_t vtdata_size;
	/* (De)Initialisations */
	int (*on_create)(NAL_CONNECTION *conn);
	void (*on_destroy)(NAL_CONNECTION *conn);
	void (*on_reset)(NAL_CONNECTION *conn);
	/* after NAL_ADDRESS_vtable->create_connection() */
	int (*connect)(NAL_CONNECTION *conn, const NAL_ADDRESS *addr);
	/* after NAL_LISTENER_vtable->pre_accept() */
	int (*accept)(NAL_CONNECTION *conn, const NAL_LISTENER *l);
	/* Handlers for NAL_CONNECTION functionality */
	int (*set_size)(NAL_CONNECTION *conn, unsigned int size);
	NAL_BUFFER *(*get_read)(const NAL_CONNECTION *conn);
	NAL_BUFFER *(*get_send)(const NAL_CONNECTION *conn);
	int (*is_established)(const NAL_CONNECTION *conn);
	int (*do_io)(NAL_CONNECTION *conn, NAL_SELECTOR *sel,
			unsigned int max_read, unsigned int max_send);
	void (*selector_add)(const NAL_CONNECTION *conn, NAL_SELECTOR *sel,
			unsigned int flags);
	void (*selector_del)(const NAL_CONNECTION *conn, NAL_SELECTOR *sel);
};
int nal_connection_set_vtable(NAL_CONNECTION *conn, const NAL_CONNECTION_vtable *vtable);
const NAL_CONNECTION_vtable *nal_connection_get_vtable(const NAL_CONNECTION *conn);
void *nal_connection_get_vtdata(const NAL_CONNECTION *conn);

/***************************/
/* Builtin address vtables */
/***************************/

/* Returns the (linked-list of) address types currently available. */
const NAL_ADDRESS_vtable *NAL_ADDRESS_vtable_builtins(void);
/* Links in one or more new address types making them immediately available. */
void NAL_ADDRESS_vtable_link(NAL_ADDRESS_vtable *vt);

/****************/
/* NAL_SELECTOR */
/****************/

#define SELECTOR_FLAG_READ	0x01
#define SELECTOR_FLAG_SEND	0x02
#define SELECTOR_FLAG_EXCEPT	0x04

typedef enum {
	/* Invalid/uninitialised place-holder */
	NAL_SELECTOR_TYPE_ERROR = 0,
	/* Standard BSD(4.4) select */
	NAL_SELECTOR_TYPE_FDSELECT,
	/* Custom implementation types start here */
	NAL_SELECTOR_TYPE_CUSTOM = 100
} NAL_SELECTOR_TYPE;

struct st_NAL_SELECTOR_vtable {
	/* The size of "vtdata" the NAL_SELECTOR should provide */
	size_t vtdata_size;
	/* (De)Initialisations */
	int (*on_create)(NAL_SELECTOR *sel);
	void (*on_destroy)(NAL_SELECTOR *sel);
	void (*on_reset)(NAL_SELECTOR *sel);
	/* Handlers for NAL_SELECTOR functionality */
	NAL_SELECTOR_TYPE (*get_type)(const NAL_SELECTOR *sel);
	void (*fd_set)(NAL_SELECTOR *sel, int fd, unsigned char flags);
	void (*fd_unset)(NAL_SELECTOR *sel, int fd);
	unsigned char (*fd_test)(const NAL_SELECTOR *sel, int fd);
	void (*fd_clear)(NAL_SELECTOR *sel, int fd);
	int (*select)(NAL_SELECTOR *sel, unsigned long usec_timeout, int use_timeout);
};
/* used from NAL_SELECTOR API */
int nal_selector_set_vtable(NAL_SELECTOR *sel, const NAL_SELECTOR_vtable *vtable);
const NAL_SELECTOR_vtable *nal_selector_get_vtable(const NAL_SELECTOR *sel);
void *nal_selector_get_vtdata(const NAL_SELECTOR *sel);
/* used from inside NAL_CONNECTION/NAL_LISTENER implementations */
NAL_SELECTOR_TYPE nal_selector_get_type(const NAL_SELECTOR *sel);
void nal_selector_fd_set(NAL_SELECTOR *sel, int fd, unsigned char flags);
void nal_selector_fd_unset(NAL_SELECTOR *sel, int fd);
unsigned char nal_selector_fd_test(const NAL_SELECTOR *sel, int fd);
void nal_selector_fd_clear(NAL_SELECTOR *sel, int fd);

#endif /* !defined(HEADER_LIBNAL_NAL_DEVEL_H) */
