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

struct st_NAL_CONNECTION {
	/* Implementation (or NULL if not set) */
	const NAL_CONNECTION_vtable *vt;
	/* Implementation data */
	void *vt_data;
	/* Size of implementation data allocated */
	size_t vt_data_size;
	/* When resetting objects for reuse, this is set to allow 'vt' to be NULL */
	const NAL_CONNECTION_vtable *reset;
	/* Associated selector ... */
	NAL_SELECTOR *sel;
	/* ... and token */
	NAL_SELECTOR_TOKEN sel_token;
};

/*************************/
/* nal_devel.h functions */
/*************************/

int nal_connection_set_vtable(NAL_CONNECTION *a, const NAL_CONNECTION_vtable *vtable)
{
	/* Are we already mapped? */
	if(a->vt) {
		/* Notify the current vtable */
		if(a->vt->pre_close)
			a->vt->pre_close(a);
		/* Unmap the current usage */
		if(a->sel) NAL_CONNECTION_del_from_selector(a);
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

const NAL_CONNECTION_vtable *nal_connection_get_vtable(const NAL_CONNECTION *conn)
{
	return conn->vt;
}

void *nal_connection_get_vtdata(const NAL_CONNECTION *conn)
{
	return conn->vt_data;
}

void nal_connection_pre_select(NAL_CONNECTION *conn)
{
	assert((conn->sel != NULL) && (conn->vt != NULL));
	conn->vt->pre_select(conn, conn->sel, conn->sel_token);
}

void nal_connection_post_select(NAL_CONNECTION *conn)
{
	assert((conn->sel != NULL) && (conn->vt != NULL));
	conn->vt->post_select(conn, conn->sel, conn->sel_token);
}

/*******************/
/* nal.h functions */
/*******************/

NAL_CONNECTION *NAL_CONNECTION_new(void)
{
	NAL_CONNECTION *conn = SYS_malloc(NAL_CONNECTION, 1);
	if(conn) {
		conn->vt = NULL;
		conn->vt_data = NULL;
		conn->vt_data_size = 0;
		conn->reset = NULL;
		conn->sel = NULL;
		conn->sel_token = NULL;
	}
	return conn;
}

void NAL_CONNECTION_free(NAL_CONNECTION *conn)
{
	if(conn->vt && conn->vt->pre_close) conn->vt->pre_close(conn);
	if(conn->sel) NAL_CONNECTION_del_from_selector(conn);
	if(conn->vt) conn->vt->on_destroy(conn);
	else if(conn->reset) conn->reset->on_destroy(conn);
	if(conn->vt_data) SYS_free(void, conn->vt_data);
	SYS_free(NAL_CONNECTION, conn);
}

void NAL_CONNECTION_reset(NAL_CONNECTION *conn)
{
	if(conn->vt && conn->vt->pre_close) conn->vt->pre_close(conn);
	if(conn->vt) {
		if(conn->sel) NAL_CONNECTION_del_from_selector(conn);
		conn->vt->on_reset(conn);
		conn->reset = conn->vt;
		conn->vt = NULL;
	}
}

int NAL_CONNECTION_create(NAL_CONNECTION *conn, const NAL_ADDRESS *addr)
{
	const NAL_CONNECTION_vtable *vtable;
	if(conn->vt || !NAL_ADDRESS_can_connect(addr))
		return 0;
	if((vtable = nal_address_get_connection(addr)) == NULL)
		return 0;
	if(!nal_connection_set_vtable(conn, vtable) ||
			!vtable->connect(conn, addr)) {
		NAL_CONNECTION_reset(conn);
		return 0;
	}
	return 1;
}

int NAL_CONNECTION_accept(NAL_CONNECTION *conn, NAL_LISTENER *list)
{
	const NAL_CONNECTION_vtable *vtable;
	if(conn->vt) return 0;
	if((vtable = nal_listener_pre_accept(list)) == NULL)
		return 0;
	if(!nal_connection_set_vtable(conn, vtable) ||
			!vtable->accept(conn, list)) {
		NAL_CONNECTION_reset(conn);
		return 0;
	}
	return 1;
}

int NAL_CONNECTION_set_size(NAL_CONNECTION *conn, unsigned int size)
{
	if(!nal_check_buffer_size(size))
		return 0;
	if(conn->vt) return conn->vt->set_size(conn, size);
	return 0;
}

NAL_BUFFER *NAL_CONNECTION_get_read(NAL_CONNECTION *conn)
{
	if(conn->vt) return conn->vt->get_read(conn);
	return NULL;
}

NAL_BUFFER *NAL_CONNECTION_get_send(NAL_CONNECTION *conn)
{
	if(conn->vt) return conn->vt->get_send(conn);
	return NULL;
}

/* "const" versions of the above */
const NAL_BUFFER *NAL_CONNECTION_get_read_c(const NAL_CONNECTION *conn)
{
	if(conn->vt) return conn->vt->get_read(conn);
	return NULL;
}

const NAL_BUFFER *NAL_CONNECTION_get_send_c(const NAL_CONNECTION *conn)
{
	if(conn->vt) return conn->vt->get_send(conn);
	return NULL;
}

int NAL_CONNECTION_io(NAL_CONNECTION *conn)
{
	if(conn->vt && conn->sel)
		return conn->vt->do_io(conn);
	return 0;
}

int NAL_CONNECTION_is_established(const NAL_CONNECTION *conn)
{
	if(conn->vt) return conn->vt->is_established(conn);
	return 0;
}

int NAL_CONNECTION_add_to_selector(NAL_CONNECTION *conn,
				NAL_SELECTOR *sel)
{
	if(conn->sel || !conn->vt || !conn->vt->pre_selector_add(conn, sel))
		return 0;
	if((conn->sel_token = nal_selector_add_connection(sel, conn)) ==
				NAL_SELECTOR_TOKEN_NULL) {
		conn->vt->post_selector_del(conn, sel);
		return 0;
	}
	conn->sel = sel;
	if(conn->vt->post_selector_add && !conn->vt->post_selector_add(conn,
				sel, conn->sel_token)) {
		NAL_CONNECTION_del_from_selector(conn);
		return 0;
	}
	return 1;
}

void NAL_CONNECTION_del_from_selector(NAL_CONNECTION *conn)
{
	if(conn->vt && conn->sel) {
		NAL_SELECTOR *sel = conn->sel;
		if(conn->vt->pre_selector_del)
			conn->vt->pre_selector_del(conn, sel, conn->sel_token);
		nal_selector_del_connection(conn->sel, conn, conn->sel_token);
		conn->sel = NULL;
		conn->sel_token = NULL;
		conn->vt->post_selector_del(conn, sel);
	}
}

