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
	/* When resetting objects for reuse, this is set to allow 'vt' to be NULL */
	const NAL_ADDRESS_vtable *reset;
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
static int int_address_set_vt(NAL_ADDRESS *a, const NAL_ADDRESS_vtable *vtable)
{
	if(a->reset) {
		if(a->reset != vtable) {
			/* We need to cleanup because we're not reusing state */
			a->vt = a->reset;
			a->vt->on_destroy(a);
			a->reset = NULL;
			SYS_zero_n(unsigned char, a->vt_data, a->vt_data_size);
		} else
			/* We're reusing the previous state */
			goto ok;
	}
	/* We're not reusing, though there may be (zeroed) data allocated we
	 * can use if it's big enough. */
	if(vtable->vtdata_size > 0) {
		if(a->vt_data) {
			if(a->vt_data_size >= vtable->vtdata_size)
				/* The existing vtdata is fine */
				goto ok;
			/* We need to reallocate */
			SYS_free(void, a->vt_data);
		}
		a->vt_data = SYS_malloc(unsigned char, vtable->vtdata_size);
		if(!a->vt_data)
			return 0;
		SYS_zero_n(unsigned char, a->vt_data, vtable->vtdata_size);
		a->vt_data_size = vtable->vtdata_size;
	}
ok:
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
		a->reset = NULL;
		a->def_buffer_size = 0;
	}
	return a;
}

void NAL_ADDRESS_free(NAL_ADDRESS *a)
{
	if(a->vt) a->vt->on_destroy(a);
	else if(a->reset) a->reset->on_destroy(a);
	if(a->vt_data) SYS_free(void, a->vt_data);
	SYS_free(NAL_ADDRESS, a);
}

void NAL_ADDRESS_reset(NAL_ADDRESS *a)
{
	if(a->vt) {
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
	if(!vtable || !int_address_set_vt(addr, vtable) ||
			!vtable->on_create(addr, addr_string)) {
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

