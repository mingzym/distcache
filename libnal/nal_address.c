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

#define SYS_GENERATING_LIB

#include <libsys/pre.h>
#include <libnal/nal.h>
#include "nal_internal.h"
#include <libsys/post.h>

/*****************************************************/
/* First some global address-type registry stuff ... */
/*****************************************************/

/* We make various address types automatically available by having them linked
 * in by default. I'm simply "extern"ing a reference here to the builtin
 * address type in proto_std.c, which will be our initial start-up list (its
 * "next" pointer is NULL at start-up). This avoids having various functions
 * pointing back and forth (that could get confused when exposing the
 * "internal" API for address type providers), and it also avoids maintaining a
 * separate table for registering address types (which would require the
 * builtins to be registered by the application on startup and would also
 * require cleanup on exit, both of which are undesirable). */

extern NAL_ADDRESS_vtable builtin_sock_addr_vtable;

/* API functions */

const NAL_ADDRESS_vtable *NAL_ADDRESS_vtable_builtins(void)
{
	return &builtin_sock_addr_vtable;
}

void NAL_ADDRESS_vtable_link(NAL_ADDRESS_vtable *vt)
{
	NAL_ADDRESS_vtable *i, *next;
	do {
		/* We do things this way so that we already have 'next' set
		 * as/when we NULL-terminate 'vt' for the linked-list. */
		next = vt->next;
		/* Check the existing global list doesn't have 'vt' */
		i = &builtin_sock_addr_vtable;
conflict_loop:
		if(strcmp(i->unique_name, vt->unique_name) == 0)
			/* Already got it, ignore 'vt' */
			continue;
		if(i->next) {
			i = i->next;
			goto conflict_loop;
		}
		/* Add 'vt' and null terminate */
		i->next = vt;
		vt->next = NULL;
	} while((vt = next) != NULL);
}

/**********************************************************/
/* Now, on to nice (non-global) NAL_ADDRESS API stuff ... */
/**********************************************************/

struct st_NAL_ADDRESS {
	/* Implementation (or NULL if not set) */
	const NAL_ADDRESS_vtable *vt;
	/* Implementation data */
	void *vt_data;
	/* Size of implementation data allocated */
	size_t vt_data_size;
	/* When resetting objects for reuse, this is set to allow 'vt' to be NULL */
	const NAL_ADDRESS_vtable *reset;
	/* def_buffer_size is handled directly by the API */
	unsigned int def_buffer_size;
};

/*************************/
/* nal_devel.h functions */
/*************************/

int nal_address_set_vtable(NAL_ADDRESS *a, const NAL_ADDRESS_vtable *vtable)
{
	/* Are we already mapped? */
	if(a->vt) {
		/* Notify the current vtable */
		if(a->vt->pre_close)
			a->vt->pre_close(a);
		/* Unmap the current usage */
		a->vt->on_reset(a);
		a->reset = a->vt;
		a->vt = NULL;
	}
	/* Do we have a mismatched reset to cleanup? */
	if(a->reset && (a->reset != vtable)) {
		a->reset->on_destroy(a);
		a->reset = NULL;
		SYS_zero_n(unsigned char, a->vt_data, a->vt_data_size);
	}
	/* Check our memory is ok (reset cases should already bypass this) */
	if(vtable->vtdata_size > a->vt_data_size) {
		assert(a->reset == NULL);
		if(a->vt_data)
			SYS_free(void, a->vt_data);
		a->vt_data = SYS_malloc(unsigned char, vtable->vtdata_size);
		if(!a->vt_data) {
			a->vt_data_size = 0;
			return 0;
		}
		a->vt_data_size = vtable->vtdata_size;
		SYS_zero_n(unsigned char, a->vt_data, vtable->vtdata_size);
	}
	if(vtable->on_create(a)) {
		a->vt = vtable;
		return 1;
	}
	return 0;
}

const NAL_ADDRESS_vtable *nal_address_get_vtable(const NAL_ADDRESS *addr)
{
	return addr->vt;
}

void *nal_address_get_vtdata(const NAL_ADDRESS *addr)
{
	return addr->vt_data;
}

const NAL_LISTENER_vtable *nal_address_get_listener(const NAL_ADDRESS *addr)
{
	if(addr->vt) return addr->vt->create_listener(addr);
	return NULL;
}

const NAL_CONNECTION_vtable *nal_address_get_connection(const NAL_ADDRESS *addr)
{
	if(addr->vt) return addr->vt->create_connection(addr);
	return NULL;
}

/*******************/
/* nal.h functions */
/*******************/

NAL_ADDRESS *NAL_ADDRESS_new(void)
{
	NAL_ADDRESS *a = SYS_malloc(NAL_ADDRESS, 1);
	if(a) {
		a->vt = NULL;
		a->vt_data = NULL;
		a->vt_data_size = 0;
		a->reset = NULL;
		a->def_buffer_size = 0;
	}
	return a;
}

void NAL_ADDRESS_free(NAL_ADDRESS *a)
{
	if(a->vt) {
		if(a->vt->pre_close)
			a->vt->pre_close(a);
		a->vt->on_destroy(a);
	} else if(a->reset)
		a->reset->on_destroy(a);
	if(a->vt_data) SYS_free(void, a->vt_data);
	SYS_free(NAL_ADDRESS, a);
}

void NAL_ADDRESS_reset(NAL_ADDRESS *a)
{
	if(a->vt) {
		if(a->vt->pre_close)
			a->vt->pre_close(a);
		a->vt->on_reset(a);
		a->reset = a->vt;
		a->vt = NULL;
	}
}

unsigned int NAL_ADDRESS_get_def_buffer_size(const NAL_ADDRESS *addr)
{
	return addr->def_buffer_size;
}

int NAL_ADDRESS_set_def_buffer_size(NAL_ADDRESS *addr,
			unsigned int def_buffer_size)
{
	if(!nal_check_buffer_size(def_buffer_size)) return 0;
	addr->def_buffer_size = def_buffer_size;
	return 1;
}

int NAL_ADDRESS_create(NAL_ADDRESS *addr, const char *addr_string,
			unsigned int def_buffer_size)
{
	unsigned int len;
	const NAL_ADDRESS_vtable *vtable = NAL_ADDRESS_vtable_builtins();
	if(addr->vt) return 0; /* 'addr' is in use */
	if(!NAL_ADDRESS_set_def_buffer_size(addr, def_buffer_size))
		return 0; /* 'def_buffer_size' is invalid */
	len = strlen(addr_string);
	if((len < 2) || (len > NAL_ADDRESS_MAX_STR_LEN))
		return 0; /* 'addr_string' can't be valid */
	while(vtable) {
		const char **pre = vtable->prefixes;
		while(*pre) {
			unsigned int pre_len = strlen(*pre);
			if((pre_len <= len) && (strncmp(*pre, addr_string,
							pre_len) == 0))
				goto done;
			pre++;
		}
		vtable = vtable->next; /* move to next address type */
	}
done:
	if(!vtable)
		return 0;
	if(!nal_address_set_vtable(addr, vtable) || !vtable->parse(addr, addr_string)) {
		NAL_ADDRESS_reset(addr);
		return 0;
	}
	return 1;
}

int NAL_ADDRESS_can_connect(const NAL_ADDRESS *addr)
{
	if(addr->vt) return addr->vt->can_connect(addr);
	return 0;
}

int NAL_ADDRESS_can_listen(const NAL_ADDRESS *addr)
{
	if(addr->vt) return addr->vt->can_listen(addr);
	return 0;
}

