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

/* selectors implement their own storage of the listener and connection
 * registries. To allow them to avoid doing searches on every loop operation,
 * we let them tag connections/listeners with an opaque 'token' value when
 * adding objects. This makes it easier for these objects to interact without
 * lookups. (NB, the struct is just to improve type-safety.) */
typedef struct { int foo; } *NAL_SELECTOR_TOKEN;
#define NAL_SELECTOR_TOKEN_NULL	(NAL_SELECTOR_TOKEN)NULL

/* Notes about vtables:
 * on_create() - [COMPULSORY]
 *   Called during assignment of the vtable to an object. If this is an object
 *   being reused with the same vtable, the vtdata will be that left by the
 *   on_reset() call, otherwise it will be zeroed.
 * on_destroy() - [COMPULSORY]
 *   Called to cleanup vtdata before unmapping a vtable from an object. It
 *   should clean up all resources as there will be no other (guaranteed)
 *   opportunity to touch the vtdata after this call.
 * on_reset() - [COMPULSORY]
 *   Called to reset an object for future use. This can be used, for example,
 *   to "close" resources without deallocating them. The implementation will
 *   next have its on_create() handler called (if the object is reused with the
 *   same vtable) or on_destroy() handler called (if the object is being
 *   destroyed or used with a different vtable).
 * pre_close() - [OPTIONAL]
 *   Called prior to a _reset or _destroy operation. By the time an on_destroy()
 *   or on_reset() handler is called, the destruction process is already
 *   underway and any data that is the domain of the framework (rather than
 *   the vtable) may have already been cleaned up.
 */

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
	void (*pre_close)(NAL_ADDRESS *addr);
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
	int (*on_create)(NAL_LISTENER *);
	void (*on_destroy)(NAL_LISTENER *);
	void (*on_reset)(NAL_LISTENER *);
	void (*pre_close)(NAL_LISTENER *);
	/* Handlers for NAL_LISTENER functionality */
	int (*listen)(NAL_LISTENER *, const NAL_ADDRESS *);
	const NAL_CONNECTION_vtable *(*pre_accept)(NAL_LISTENER *);
	int (*finished)(const NAL_LISTENER *);
	/* Called before/after (un)binding (from/)to a selector */
	int (*pre_selector_add)(NAL_LISTENER *, const NAL_SELECTOR *);
	int (*post_selector_add)(NAL_LISTENER *, NAL_SELECTOR *,
				NAL_SELECTOR_TOKEN);
	void (*pre_selector_del)(NAL_LISTENER *, NAL_SELECTOR *,
				NAL_SELECTOR_TOKEN);
	void (*post_selector_del)(NAL_LISTENER *, const NAL_SELECTOR *);
	/* Called before/after a select */
	void (*pre_select)(NAL_LISTENER *, NAL_SELECTOR *, NAL_SELECTOR_TOKEN);
	void (*post_select)(NAL_LISTENER *, NAL_SELECTOR *, NAL_SELECTOR_TOKEN);
	/* Extensions that may not be meaningful, case-by-case */
	int (*set_fs_owner)(NAL_LISTENER *, const char *ownername,
				const char *groupname);
	int (*set_fs_perms)(NAL_LISTENER *, const char *octal_string);
};
int nal_listener_set_vtable(NAL_LISTENER *, const NAL_LISTENER_vtable *);
const NAL_LISTENER_vtable *nal_listener_get_vtable(const NAL_LISTENER *);
void *nal_listener_get_vtdata(const NAL_LISTENER *);
const NAL_CONNECTION_vtable *nal_listener_pre_accept(NAL_LISTENER *);
void nal_listener_pre_select(NAL_LISTENER *);
void nal_listener_post_select(NAL_LISTENER *);

/******************/
/* NAL_CONNECTION */
/******************/

struct st_NAL_CONNECTION_vtable {
	/* The size of "vtdata" the NAL_CONNECTION should provide */
	size_t vtdata_size;
	/* (De)Initialisations */
	int (*on_create)(NAL_CONNECTION *);
	void (*on_destroy)(NAL_CONNECTION *);
	void (*on_reset)(NAL_CONNECTION *);
	void (*pre_close)(NAL_CONNECTION *);
	/* after NAL_ADDRESS_vtable->create_connection() */
	int (*connect)(NAL_CONNECTION *, const NAL_ADDRESS *);
	/* after NAL_LISTENER_vtable->pre_accept() */
	int (*accept)(NAL_CONNECTION *, const NAL_LISTENER *);
	/* Handlers for NAL_CONNECTION functionality */
	int (*set_size)(NAL_CONNECTION *, unsigned int);
	NAL_BUFFER *(*get_read)(const NAL_CONNECTION *);
	NAL_BUFFER *(*get_send)(const NAL_CONNECTION *);
	int (*is_established)(const NAL_CONNECTION *);
	/* Called before/after (un)binding (from/)to a selector */
	int (*pre_selector_add)(NAL_CONNECTION *, const NAL_SELECTOR *);
	int (*post_selector_add)(NAL_CONNECTION *, NAL_SELECTOR *,
				NAL_SELECTOR_TOKEN);
	void (*pre_selector_del)(NAL_CONNECTION *, NAL_SELECTOR *,
				NAL_SELECTOR_TOKEN);
	void (*post_selector_del)(NAL_CONNECTION *, const NAL_SELECTOR *);
	/* Called before/after a 'select', depending on the selector model.
	 * 'pre_select' allows the connection to register specific events if
	 * appropriate (eg. this would apply for a select/poll-style selector
	 * but (perhaps) not for a win32 messagepump mode). 'post_select' can
	 * be called 0, 1, or many times to allow the connection to
	 * collect/send data. */
	void (*pre_select)(NAL_CONNECTION *, NAL_SELECTOR *, NAL_SELECTOR_TOKEN);
	void (*post_select)(NAL_CONNECTION *, NAL_SELECTOR *, NAL_SELECTOR_TOKEN);
	/* Expose results of 'post_select' I/O and/or do post-processing. This
	 * is the hook from the caller's NAL_CONNECTION_io() API, whereas the
	 * 'pre_select' and 'post_select' handlers are internal to the blocking
	 * NAL_SELECTOR_select() logic. */
	int (*do_io)(NAL_CONNECTION *);
};
int nal_connection_set_vtable(NAL_CONNECTION *, const NAL_CONNECTION_vtable *);
const NAL_CONNECTION_vtable *nal_connection_get_vtable(const NAL_CONNECTION *);
void *nal_connection_get_vtdata(const NAL_CONNECTION *);
void nal_connection_pre_select(NAL_CONNECTION *);
void nal_connection_post_select(NAL_CONNECTION *);

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

/* The "type" of a selector */
typedef enum {
	/* Invalid/uninitialised place-holder */
	NAL_SELECTOR_TYPE_ERROR = 0,
	/* Standard BSD(4.4) select */
	NAL_SELECTOR_TYPE_FDSELECT,
	/* poll(2) */
	NAL_SELECTOR_TYPE_FDPOLL,
	/* Custom implementation types start here */
	NAL_SELECTOR_TYPE_CUSTOM = 100
} NAL_SELECTOR_TYPE;

/* general-purpose "ctrl" commands are scoped as follows */
typedef enum {
	/* Control commands specific to fdselect and fdpoll start here */
	NAL_SELECTOR_CTRL_FD = 0x0100,
	/* Custom commands start here */
	NAL_SELECTOR_CTRL_CUSTOM = 0x0800
} NAL_SELECTOR_CTRL_TYPE;

struct st_NAL_SELECTOR_vtable {
	/* The size of "vtdata" the NAL_SELECTOR should provide */
	size_t vtdata_size;
	/* (De)Initialisations */
	int (*on_create)(NAL_SELECTOR *);
	void (*on_destroy)(NAL_SELECTOR *);
	void (*on_reset)(NAL_SELECTOR *);
	void (*pre_close)(NAL_SELECTOR *);
	/* Handlers for NAL_SELECTOR functionality */
	NAL_SELECTOR_TYPE (*get_type)(const NAL_SELECTOR *);
	int (*select)(NAL_SELECTOR *, unsigned long usec_timeout, int use_timeout);
	unsigned int (*num_objects)(const NAL_SELECTOR *);
	NAL_SELECTOR_TOKEN (*add_listener)(NAL_SELECTOR *, NAL_LISTENER *);
	NAL_SELECTOR_TOKEN (*add_connection)(NAL_SELECTOR *, NAL_CONNECTION *);
	void (*del_listener)(NAL_SELECTOR *, NAL_LISTENER *, NAL_SELECTOR_TOKEN);
	void (*del_connection)(NAL_SELECTOR *, NAL_CONNECTION *, NAL_SELECTOR_TOKEN);
	/* General purpose hook for implementation-specifics. Returns zero if
	 * the integer (command) parameter is not understood. Other "return"
	 * information should be handled in the opaque void* reference. */
	int (*ctrl)(NAL_SELECTOR *, int, void *);
};
/* used from NAL_SELECTOR API */
NAL_SELECTOR *nal_selector_new(const NAL_SELECTOR_vtable *);
const NAL_SELECTOR_vtable *nal_selector_get_vtable(const NAL_SELECTOR *);
void *nal_selector_get_vtdata(const NAL_SELECTOR *);
/* used from inside NAL_CONNECTION/NAL_LISTENER implementations */
NAL_SELECTOR_TYPE nal_selector_get_type(const NAL_SELECTOR *);
int nal_selector_ctrl(NAL_SELECTOR *, int, void *);

#endif /* !defined(HEADER_LIBNAL_NAL_DEVEL_H) */
