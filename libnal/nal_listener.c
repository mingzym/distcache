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
	/* def_buffer_size is handled directly by the API */
	unsigned int def_buffer_size;
};

/****************************/
/* nal_internal.h functions */
/****************************/

unsigned int nal_listener_get_def_buffer_size(const NAL_LISTENER *l)
{
	return l->def_buffer_size;
}

int nal_listener_set_def_buffer_size(NAL_LISTENER *l, unsigned int def_buffer_size)
{
	if(!nal_check_buffer_size(def_buffer_size)) return 0;
	l->def_buffer_size = def_buffer_size;
	return 1;
}

/*************************/
/* nal_devel.h functions */
/*************************/

int nal_listener_set_vtable(NAL_LISTENER *a, const NAL_LISTENER_vtable *vtable)
{
	/* Are we already mapped? */
	if(a->vt) {
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

const NAL_LISTENER_vtable *nal_listener_get_vtable(const NAL_LISTENER *l)
{
	return l->vt;
}

void *nal_listener_get_vtdata(const NAL_LISTENER *l)
{
	return l->vt_data;
}

const NAL_CONNECTION_vtable *nal_listener_pre_accept(NAL_LISTENER *l,
						NAL_SELECTOR *sel)
{
	if(l->vt) return l->vt->pre_accept(l, sel);
	return NULL;
}

/*******************/
/* nal.h functions */
/*******************/

NAL_LISTENER *NAL_LISTENER_new(void)
{
	NAL_LISTENER *l = SYS_malloc(NAL_LISTENER, 1);
	if(l) {
		l->vt = NULL;
		l->vt_data = NULL;
		l->vt_data_size = 0;
		l->reset = NULL;
		l->def_buffer_size = 0;
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
	if(!nal_listener_set_vtable(list, vtable) ||
			!nal_listener_set_def_buffer_size(list,
				NAL_ADDRESS_get_def_buffer_size(addr)) ||
			!vtable->listen(list, addr)) {
		NAL_LISTENER_reset(list);
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

int NAL_LISTENER_finished(const NAL_LISTENER *list)
{
	if(list->vt) return list->vt->finished(list);
	return 0;
}

/* Specialised functions - these should verify that the vtable has a non-NULL
 * handler, as not all vtable's support these. */

int NAL_LISTENER_set_fs_owner(NAL_LISTENER *list,
				const char *ownername,
				const char *groupname)
{
	if(list->vt && list->vt->set_fs_owner)
		return list->vt->set_fs_owner(list, ownername, groupname);
	return 0;
}

int NAL_LISTENER_set_fs_perms(NAL_LISTENER *list,
				const char *octal_string)
{
	if(list->vt && list->vt->set_fs_perms)
		return list->vt->set_fs_perms(list, octal_string);
	return 0;
}
