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

struct st_NAL_LISTENER {
	/* Implementation (or NULL if not set) */
	const NAL_LISTENER_vtable *vt;
	/* Implementation data */
	void *vt_data;
	/* Size of implementation data allocated */
	size_t vt_data_size;
	/* When resetting objects for reuse, this is set to allow 'vt' to be NULL */
	const NAL_LISTENER_vtable *reset;
};

/* Internal only function used to handle vt_data */
static int int_listener_set_vt(NAL_LISTENER *a, const NAL_LISTENER_vtable *vtable)
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
/* libnal internal functions */
/*****************************/

void *nal_listener_get_vtdata(const NAL_LISTENER *l)
{
	return l->vt_data;
}

const NAL_LISTENER_vtable *nal_listener_get_vtable(const NAL_LISTENER *l)
{
	return l->vt;
}

const NAL_CONNECTION_vtable *nal_listener_accept_connection(NAL_LISTENER *l,
						NAL_SELECTOR *sel)
{
	if(l->vt) return l->vt->do_accept(l, sel);
	return NULL;
}

/******************************/
/* NAL_LISTENER API FUNCTIONS */
/******************************/

NAL_LISTENER *NAL_LISTENER_new(void)
{
	NAL_LISTENER *l = SYS_malloc(NAL_LISTENER, 1);
	if(l) {
		l->vt = NULL;
		l->vt_data = NULL;
		l->reset = NULL;
	}
	return l;
}

void NAL_LISTENER_free(NAL_LISTENER *list)
{
	if(list->vt) list->vt->on_destroy(list);
	else if(list->reset) list->reset->on_destroy(list);
	if(list->vt_data) SYS_free(void, list->vt_data);
	SYS_free(NAL_LISTENER, list);
}

void NAL_LISTENER_reset(NAL_LISTENER *list)
{
	if(list->vt) {
		list->vt->on_reset(list);
		list->reset = list->vt;
		list->vt = NULL;
	}
}

int NAL_LISTENER_create(NAL_LISTENER *list, const NAL_ADDRESS *addr)
{
	const NAL_LISTENER_vtable *vtable;
	if(list->vt) return 0; /* 'list' is in use */
	vtable = nal_address_get_listener(addr);
	if(!int_listener_set_vt(list, vtable))
		return 0;
	if(!vtable->on_create(list, addr)) {
		list->vt = NULL;
		return 0;
	}
	return 1;
}

void NAL_LISTENER_add_to_selector(const NAL_LISTENER *list,
				NAL_SELECTOR *sel)
{
	if(list->vt) list->vt->selector_add(list, sel);
}

void NAL_LISTENER_del_from_selector(const NAL_LISTENER *list,
				NAL_SELECTOR *sel)
{
	if(list->vt) list->vt->selector_del(list, sel);
}

