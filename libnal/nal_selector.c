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
	sel->vt = vtable;
	if(vtable->vtdata_size) {
		sel->vt_data = SYS_malloc(unsigned char, vtable->vtdata_size);
		if(!sel->vt_data) goto err;
	} else
		sel->vt_data = NULL;
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

/*******************/
/* nal.h functions */
/*******************/

NAL_SELECTOR *NAL_SELECTOR_new(void)
{
	const NAL_SELECTOR_vtable *vt = NAL_SELECTOR_VT_DEFAULT();
	if(!vt) return NULL;
	return nal_selector_new(vt);
}

void NAL_SELECTOR_free(NAL_SELECTOR *sel)
{
	assert(sel->vt);
	sel->vt->on_destroy(sel);
	if(sel->vt_data) SYS_free(void, sel->vt_data);
	SYS_free(NAL_SELECTOR, sel);
}

void NAL_SELECTOR_reset(NAL_SELECTOR *sel)
{
	assert(sel->vt);
	sel->vt->on_reset(sel);
}

int NAL_SELECTOR_select(NAL_SELECTOR *sel, unsigned long usec_timeout,
			int use_timeout)
{
	assert(sel->vt);
	return sel->vt->select(sel, usec_timeout, use_timeout);
}

