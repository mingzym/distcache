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

struct st_NAL_ADDRESS {
	/* Implementation (or NULL if not set) */
	const NAL_ADDRESS_vtable *vt;
	/* Implementation data */
	void *vt_data;
	/* Size of implementation data allocated */
	size_t vt_data_size;
	/* def_buffer_size is handled directly by the API */
	unsigned int def_buffer_size;
};

/*****************************/
/* libnal internal functions */
/*****************************/

void *nal_address_get_vtdata(const NAL_ADDRESS *addr)
{
	return addr->vt_data;
}

const NAL_ADDRESS_vtable *nal_address_get_vtable(const NAL_ADDRESS *addr)
{
	return addr->vt;
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

/* Internal only function used to handle vt_data */
static int int_address_set_vt_size(NAL_ADDRESS *a, const NAL_ADDRESS_vtable *vtable)
{
	if(vtable->vtdata_size > 0) {
		if(a->vt_data) {
			if(a->vt_data_size >= vtable->vtdata_size)
				/* The existing vtdata is fine */
				return 1;
			/* We need to reallocate */
			SYS_free(void, a->vt_data);
		}
		a->vt_data = SYS_malloc(unsigned char, vtable->vtdata_size);
		if(!a->vt_data)
			return 0;
		SYS_zero_n(unsigned char, a->vt_data, vtable->vtdata_size);
		a->vt_data_size = vtable->vtdata_size;
	}
	/* All's well, more code-saving by setting the vtable for the caller */
	a->vt = vtable;
	return 1;
}

/*****************************/
/* NAL_ADDRESS API FUNCTIONS */
/*****************************/

NAL_ADDRESS *NAL_ADDRESS_new(void)
{
	NAL_ADDRESS *a = SYS_malloc(NAL_ADDRESS, 1);
	if(a) {
		a->vt = NULL;
		a->vt_data = NULL;
		a->def_buffer_size = 0;
	}
	return a;
}

void NAL_ADDRESS_free(NAL_ADDRESS *a)
{
	if(a->vt) a->vt->on_destroy(a);
	if(a->vt_data) SYS_free(void, a->vt_data);
	SYS_free(NAL_ADDRESS, a);
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
	int len;
	const NAL_ADDRESS_vtable *vtable = NAL_ADDRESS_vtable_builtins();
	if(addr->vt) return 0; /* 'addr' is in use */
	if(!NAL_ADDRESS_set_def_buffer_size(addr, def_buffer_size))
		return 0; /* 'def_buffer_size' is invalid */
	len = strlen(addr_string);
	if((len < 2) || (len > NAL_ADDRESS_MAX_STR_LEN))
		return 0; /* 'addr_string' can't be valid */
	while(vtable) {
		/* FIXME: We need to change the address vtable to include
		 * strings so that we only call on_create() on the successful
		 * implementation and not on everything we search. */
		if(!int_address_set_vt_size(addr, vtable))
			return 0;
		if(vtable->on_create(addr, addr_string))
			break; /* 'vtable' accepted this string */
		vtable = vtable->next; /* move to next address type */
	}
	if(!vtable) {
		/* no builtin vtable accepted 'addr_string' */
		addr->vt = NULL;
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

