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

struct st_NAL_SELECTOR {
	/* Implementation (or NULL if not set) */
	const NAL_SELECTOR_vtable *vt;
	/* Implementation data */
	void *vt_data;
	/* Size of implementation data allocated */
	size_t vt_data_size;
	/* When resetting objects for reuse, this is set to allow 'vt' to be NULL */
	const NAL_SELECTOR_vtable *reset;
};

/*************************/
/* nal_devel.h functions */
/*************************/

int nal_selector_set_vtable(NAL_SELECTOR *a, const NAL_SELECTOR_vtable *vtable)
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

const NAL_SELECTOR_vtable *nal_selector_get_vtable(const NAL_SELECTOR *sel)
{
	return sel->vt;
}

void *nal_selector_get_vtdata(const NAL_SELECTOR *sel)
{
	return sel->vt_data;
}

NAL_SELECTOR_TYPE nal_selector_get_type(const NAL_SELECTOR *sel)
{
	if(!sel->vt) return NAL_SELECTOR_TYPE_ERROR;
	return sel->vt->get_type(sel);
}

void nal_selector_fd_set(NAL_SELECTOR *sel, int fd, unsigned char flags)
{
	if(sel->vt)
		sel->vt->fd_set(sel, fd, flags);
}

void nal_selector_fd_unset(NAL_SELECTOR *sel, int fd)
{
	if(sel->vt)
		sel->vt->fd_unset(sel, fd);
}

unsigned char nal_selector_fd_test(const NAL_SELECTOR *sel, int fd)
{
	if(!sel->vt) return 0;
	return sel->vt->fd_test(sel, fd);
}

void nal_selector_fd_clear(NAL_SELECTOR *sel, int fd)
{
	if(sel->vt)
		sel->vt->fd_clear(sel, fd);
}

/*******************/
/* nal.h functions */
/*******************/

NAL_SELECTOR *NAL_SELECTOR_new(void)
{
	NAL_SELECTOR *sel = SYS_malloc(NAL_SELECTOR, 1);
	if(sel) {
		sel->vt = NULL;
		sel->vt_data = NULL;
		sel->vt_data_size = 0;
		sel->reset = NULL;
		/* Unlike the other abstractions, we use a default
		 * implementation rather than staying NULL until a create()
		 * calls pins us to a vtable. */
		if(!nal_selector_set_vtable(sel, &sel_fdselect_vtable)) {
			SYS_free(NAL_SELECTOR, sel);
			return NULL;
		}
	}
	return sel;
}

void NAL_SELECTOR_free(NAL_SELECTOR *sel)
{
	if(sel->vt) sel->vt->on_destroy(sel);
	else if(sel->reset) sel->reset->on_destroy(sel);
	if(sel->vt_data) SYS_free(void, sel->vt_data);
	SYS_free(NAL_SELECTOR, sel);
}

void NAL_SELECTOR_reset(NAL_SELECTOR *sel)
{
	/* Unlike other abstractions, we use the default implementation in the
	 * constructor rather than requiring a create() function. As such, our
	 * reset should not follow the traditional logic, but map instead to
	 * "set_vtable" (which automatically handles existing 'vt' settings,
	 * resets, etc.) */
#if 0
	if(sel->vt) {
		sel->vt->on_reset(sel);
		sel->reset = sel->vt;
		sel->vt = NULL;
	}
#else
	/* This should never fail as no allocation should be required, but as
	 * we have no guarantees over the vtable in use ... */
	if(!nal_selector_set_vtable(sel, &sel_fdselect_vtable))
		/* Ignoring the error allows bad dominos */
		abort();
#endif
}

int NAL_SELECTOR_select(NAL_SELECTOR *sel, unsigned long usec_timeout,
			int use_timeout)
{
	if(sel->vt) return sel->vt->select(sel, usec_timeout, use_timeout);
	return -1;
}

