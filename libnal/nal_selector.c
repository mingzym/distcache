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

/*****************************************/
/* Intermediaire selector implementation */
/*****************************************/

static int dyn_on_create(NAL_SELECTOR *s) { return 1; }
static void dyn_on_destroy(NAL_SELECTOR *s) { }
static void dyn_on_reset(NAL_SELECTOR *s) { }
static NAL_SELECTOR_TYPE dyn_get_type(const NAL_SELECTOR *s) {
	return NAL_SELECTOR_TYPE_DYNAMIC; }
static int dyn_select(NAL_SELECTOR *s, unsigned long x, int y) { return -1; }
static unsigned int dyn_num_objects(const NAL_SELECTOR *s) { return 0; }
static const NAL_SELECTOR_vtable vtable_dyn = {
	0, /* vtdata_size */
	dyn_on_create,
	dyn_on_destroy,
	dyn_on_reset,
	NULL, /* pre_close */
	dyn_get_type,
	dyn_select,
	dyn_num_objects,
	NULL, /* add_listener - shouldn't be called */
	NULL, /* add_connection - shouldn't be called */
	NULL, /* del_listener - shouldn't be called */
	NULL, /* del_connection - shouldn't be called */
	NULL
};

/****************************/
/* nal_internal.h functions */
/****************************/

NAL_SELECTOR_TOKEN nal_selector_add_listener(NAL_SELECTOR *s, NAL_LISTENER *l)
{
	if(s->vt) return s->vt->add_listener(s, l);
	return NAL_SELECTOR_TOKEN_NULL;
}

NAL_SELECTOR_TOKEN nal_selector_add_connection(NAL_SELECTOR *s, NAL_CONNECTION *c)
{
	if(s->vt) return s->vt->add_connection(s, c);
	return NAL_SELECTOR_TOKEN_NULL;
}

void nal_selector_del_listener(NAL_SELECTOR *s, NAL_LISTENER *l, NAL_SELECTOR_TOKEN k)
{
	if(s->vt) s->vt->del_listener(s, l, k);
}

void nal_selector_del_connection(NAL_SELECTOR *s, NAL_CONNECTION *c, NAL_SELECTOR_TOKEN k)
{
	if(s->vt) s->vt->del_connection(s, c, k);
}

/*************************/
/* nal_devel.h functions */
/*************************/

NAL_SELECTOR *nal_selector_new(const NAL_SELECTOR_vtable *vtable)
{
	NAL_SELECTOR *sel = SYS_malloc(NAL_SELECTOR, 1);
	if(!sel) goto err;
	if(vtable->vtdata_size) {
		sel->vt_data = SYS_malloc(unsigned char, vtable->vtdata_size);
		if(!sel->vt_data) goto err;
	} else
		sel->vt_data = NULL;
	sel->vt = vtable;
	sel->vt_data_size = vtable->vtdata_size;
	SYS_zero_n(unsigned char, sel->vt_data, vtable->vtdata_size);
	if(!vtable->on_create(sel)) goto err;
	return sel;
err:
	if(sel) {
		if(sel->vt_data) SYS_free(void, sel->vt_data);
		SYS_free(NAL_SELECTOR, sel);
	}
	return NULL;
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

int nal_selector_ctrl(NAL_SELECTOR *sel, int cmd, void *p)
{
	if(sel->vt && sel->vt->ctrl)
		return sel->vt->ctrl(sel, cmd, p);
	return 0;
}

int nal_selector_dynamic_set(NAL_SELECTOR *s, const NAL_SELECTOR_vtable *vt) {
	assert(s->vt == &vtable_dyn);
	assert(s->vt_data == NULL);
	assert(s->vt_data_size == 0);
	assert(s->reset == NULL);
	if(s->vt != &vtable_dyn) return 0;
	if(vt->vtdata_size) {
		s->vt_data = SYS_malloc(unsigned char, vt->vtdata_size);
		if(!s->vt_data) return 0;
	}
	SYS_zero_n(unsigned char, s->vt_data, vt->vtdata_size);
	s->vt = vt;
	s->vt_data_size = vt->vtdata_size;
	if(!vt->on_create(s)) {
		SYS_free(void, s->vt_data);
		s->vt = &vtable_dyn;
		s->vt_data_size = 0;
		return 0;
	}
	return 1;
}

/*******************/
/* nal.h functions */
/*******************/

NAL_SELECTOR *NAL_SELECTOR_new(void)
{
	return nal_selector_new(&vtable_dyn);
}

void NAL_SELECTOR_free(NAL_SELECTOR *sel)
{
	assert(sel->vt);
	if(sel->vt->pre_close) sel->vt->pre_close(sel);
	sel->vt->on_destroy(sel);
	if(sel->vt_data) SYS_free(void, sel->vt_data);
	SYS_free(NAL_SELECTOR, sel);
}

void NAL_SELECTOR_reset(NAL_SELECTOR *sel)
{
	assert(sel->vt);
	if(sel->vt->pre_close) sel->vt->pre_close(sel);
	sel->vt->on_reset(sel);
}

int NAL_SELECTOR_select(NAL_SELECTOR *sel, unsigned long usec_timeout,
			int use_timeout)
{
	assert(sel->vt);
	return sel->vt->select(sel, usec_timeout, use_timeout);
}

unsigned int NAL_SELECTOR_num_objects(const NAL_SELECTOR *sel)
{
	assert(sel->vt);
	return sel->vt->num_objects(sel);
}
