/* distcache, Distributed Session Caching technology
 * Copyright (C) 2000-2004  Geoff Thorpe, and Cryptographic Appliances, Inc.
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
#include "ctrl_fd.h"
#include <libsys/post.h>

#ifndef HAVE_SELECT

/* If we don't build select() support, return a NULL vtable */
const NAL_SELECTOR_vtable *sel_fdselect(void)
{
	return NULL;
}
NAL_SELECTOR *NAL_SELECTOR_new_fdselect(void)
{
	return NULL;
}

#else

/* These are the structure types we use */
typedef struct st_sel_item {
	fd_set reads;
	fd_set sends;
	fd_set excepts;
	int max;
} sel_item;
typedef struct st_sel_obj {
	union {
		NAL_CONNECTION *conn;
		NAL_LISTENER *listener;
	} obj;
	unsigned char what; /* 0==unused, 1==conn, 2==listener */
} sel_obj;
typedef struct st_sel_ctx {
	/* The result of a select */
	sel_item last_selected;
	/* The list we're building up to select with next */
	sel_item to_select;
	/* The table of objects */
	sel_obj *obj_table;
	unsigned int obj_used, obj_size;
} sel_ctx;
#define OBJ_TABLE_START	32
#define IDX2TOKEN(idx) (NAL_SELECTOR_TOKEN)((unsigned int)idx | 0x8000)
#define TOKEN2IDX(tok) ((unsigned int)tok & 0x7FFF)

/* Helper functions for the object table */
static void obj_table_zilch(sel_obj *items, unsigned int num)
{
	while(num--)
		(items++)->what = 0;
}
static int obj_table_init(sel_ctx *ctx)
{
	ctx->obj_table = SYS_malloc(sel_obj, OBJ_TABLE_START);
	if(!ctx->obj_table) return 0;
	obj_table_zilch(ctx->obj_table, OBJ_TABLE_START);
	ctx->obj_used = 0;
	ctx->obj_size = OBJ_TABLE_START;
	return 1;
}
static void obj_table_finish(sel_ctx *ctx)
{
	/* XXX: Should we warn when used>0? Probably */
	SYS_free(sel_obj, ctx->obj_table);
}
static void obj_table_reset(sel_ctx *ctx)
{
	/* XXX: as with finish? */
	ctx->obj_used = 0;
}
static int obj_table_add(sel_ctx *ctx)
{
	int loop = 0;
	if(ctx->obj_used == ctx->obj_size) {
		unsigned int newsize = ctx->obj_size * 3 / 2;
		sel_obj *newitems = SYS_malloc(sel_obj, newsize);
		if(!newitems) return -1;
		obj_table_zilch(newitems, newsize);
		if(ctx->obj_used)
			SYS_memcpy_n(sel_obj, newitems, ctx->obj_table,
					ctx->obj_used);
		SYS_free(sel_obj, ctx->obj_table);
		ctx->obj_table = newitems;
		ctx->obj_size = newsize;
	}
	while(ctx->obj_table[loop].what != 0)
		loop++;
	ctx->obj_used++;
	return loop;
}
static NAL_SELECTOR_TOKEN obj_table_add_listener(sel_ctx *ctx,
					NAL_LISTENER *listener)
{
	int loc = obj_table_add(ctx);
	if(loc < 0) return NAL_SELECTOR_TOKEN_NULL;
	ctx->obj_table[loc].what = 2;
	ctx->obj_table[loc].obj.listener = listener;
	return IDX2TOKEN(loc);
}
static NAL_SELECTOR_TOKEN obj_table_add_connection(sel_ctx *ctx,
					NAL_CONNECTION *conn)
{
	int loc = obj_table_add(ctx);
	if(loc < 0) return NAL_SELECTOR_TOKEN_NULL;
	ctx->obj_table[loc].what = 1;
	ctx->obj_table[loc].obj.conn = conn;
	return IDX2TOKEN(loc);
}
static void obj_table_del(sel_ctx *ctx, NAL_SELECTOR_TOKEN tok)
{
	unsigned int idx = TOKEN2IDX(tok);
	assert(idx < ctx->obj_size);
	assert(ctx->obj_table[idx].what != 0);
	assert(ctx->obj_used > 0);
	ctx->obj_table[idx].what = 0;
	ctx->obj_used--;
}
static void obj_table_pre_select(sel_ctx *ctx)
{
	unsigned int loop = 0;
	sel_obj *item = ctx->obj_table;
	while(loop < ctx->obj_size) {
		switch(item->what) {
		case 1:
			nal_connection_pre_select(item->obj.conn);
			break;
		case 2:
			nal_listener_pre_select(item->obj.listener);
			break;
		default:
			break;
		}
		item++;
		loop++;
	}
}
static void obj_table_post_select(sel_ctx *ctx)
{
	unsigned int loop = 0;
	sel_obj *item = ctx->obj_table;
	while(loop < ctx->obj_size) {
		switch(item->what) {
		case 1:
			nal_connection_post_select(item->obj.conn);
			break;
		case 2:
			nal_listener_post_select(item->obj.listener);
			break;
		default:
			break;
		}
		item++;
		loop++;
	}
}

/**************************/
/* predeclare our vtables */
/**************************/

/* Predeclare the selector functions */
static int sel_on_create(NAL_SELECTOR *);
static void sel_on_destroy(NAL_SELECTOR *);
static void sel_on_reset(NAL_SELECTOR *);
static NAL_SELECTOR_TYPE sel_get_type(const NAL_SELECTOR *);
static int sel_select(NAL_SELECTOR *, unsigned long usec_timeout, int use_timeout);
static unsigned int sel_num_objects(const NAL_SELECTOR *);
static NAL_SELECTOR_TOKEN sel_add_listener(NAL_SELECTOR *, NAL_LISTENER *);
static NAL_SELECTOR_TOKEN sel_add_connection(NAL_SELECTOR *, NAL_CONNECTION *);
static void sel_del_listener(NAL_SELECTOR *, NAL_LISTENER *, NAL_SELECTOR_TOKEN);
static void sel_del_connection(NAL_SELECTOR *, NAL_CONNECTION *, NAL_SELECTOR_TOKEN);
static int sel_ctrl(NAL_SELECTOR *, int, void *);
static const NAL_SELECTOR_vtable sel_fdselect_vtable = {
	sizeof(sel_ctx),
	sel_on_create,
	sel_on_destroy,
	sel_on_reset,
	NULL, /* pre_close */
	sel_get_type,
	sel_select,
	sel_num_objects,
	sel_add_listener,
	sel_add_connection,
	sel_del_listener,
	sel_del_connection,
	sel_ctrl
};
/* Expose this implementation */
const NAL_SELECTOR_vtable *sel_fdselect(void)
{
	return &sel_fdselect_vtable;
}
NAL_SELECTOR *NAL_SELECTOR_new_fdselect(void)
{
	return nal_selector_new(&sel_fdselect_vtable);
}

/***************************************/
/* Internal (sel_item) implementations */
/***************************************/

/* Workaround signed/unsigned conflicts between real systems and windows */
#ifndef WIN32
#define FD_SET2(a,b) FD_SET((a),(b))
#define FD_CLR2(a,b) FD_CLR((a),(b))
#else
#define FD_SET2(a,b) FD_SET((SOCKET)(a),(b))
#define FD_CLR2(a,b) FD_CLR((SOCKET)(a),(b))
#endif

static void nal_selector_item_init(sel_item *item)
{
	FD_ZERO(&item->reads);
	FD_ZERO(&item->sends);
	FD_ZERO(&item->excepts);
	item->max = 0;
}

static void nal_selector_item_flip(sel_item *to,
				sel_item *from)
{
	SYS_memcpy(fd_set, &to->reads, &from->reads);
	SYS_memcpy(fd_set, &to->sends, &from->sends);
	SYS_memcpy(fd_set, &to->excepts, &from->excepts);
	to->max = from->max;
	nal_selector_item_init(from);
}

static int nal_selector_item_select(sel_item *item,
		unsigned long usec_timeout, int use_timeout)
{
	struct timeval timeout;
	if(use_timeout) {
		timeout.tv_sec = usec_timeout / 1000000;
		timeout.tv_usec = usec_timeout % 1000000;
	}
	return select(item->max, &item->reads, &item->sends, &item->excepts,
			(use_timeout ? &timeout : NULL));
}

/************************************/
/* selector implementation handlers */
/************************************/

static int sel_on_create(NAL_SELECTOR *sel)
{
	sel_ctx *ctx = nal_selector_get_vtdata(sel);
	if(!obj_table_init(ctx)) return 0;
	nal_selector_item_init(&ctx->last_selected);
	nal_selector_item_init(&ctx->to_select);
	return 1;
}

static void sel_on_destroy(NAL_SELECTOR *sel)
{
	sel_ctx *ctx = nal_selector_get_vtdata(sel);
	obj_table_finish(ctx);
}

static void sel_on_reset(NAL_SELECTOR *sel)
{
	sel_ctx *ctx = nal_selector_get_vtdata(sel);
	obj_table_reset(ctx);
	nal_selector_item_init(&ctx->last_selected);
	nal_selector_item_init(&ctx->to_select);
}

static NAL_SELECTOR_TYPE sel_get_type(const NAL_SELECTOR *sel)
{
	return NAL_SELECTOR_TYPE_FDSELECT;
}

static int sel_select(NAL_SELECTOR *sel, unsigned long usec_timeout,
			int use_timeout)
{
	int res;
	sel_ctx *ctx = nal_selector_get_vtdata(sel);
	/* Pre-select */
	obj_table_pre_select(ctx);
	/* Migrate to_select over to last_selected */
	nal_selector_item_flip(&ctx->last_selected, &ctx->to_select);
	res = nal_selector_item_select(&ctx->last_selected, usec_timeout,
				use_timeout);
	/* Post-select */
	if(res > 0) obj_table_post_select(ctx);
	return res;
}

static unsigned int sel_num_objects(const NAL_SELECTOR *sel)
{
	sel_ctx *ctx = nal_selector_get_vtdata(sel);
	return ctx->obj_used;
}

static NAL_SELECTOR_TOKEN sel_add_listener(NAL_SELECTOR *sel,
				NAL_LISTENER *listener)
{
	sel_ctx *ctx = nal_selector_get_vtdata(sel);
	return obj_table_add_listener(ctx, listener);
}

static NAL_SELECTOR_TOKEN sel_add_connection(NAL_SELECTOR *sel,
				NAL_CONNECTION *conn)
{
	sel_ctx *ctx = nal_selector_get_vtdata(sel);
	return obj_table_add_connection(ctx, conn);
}

static void sel_del_listener(NAL_SELECTOR *sel, NAL_LISTENER *listener,
				NAL_SELECTOR_TOKEN token)
{
	sel_ctx *ctx = nal_selector_get_vtdata(sel);
	obj_table_del(ctx, token);
}

static void sel_del_connection(NAL_SELECTOR *sel, NAL_CONNECTION *conn,
				NAL_SELECTOR_TOKEN token)
{
	sel_ctx *ctx = nal_selector_get_vtdata(sel);
	obj_table_del(ctx, token);
}

static void sel_fd_set(NAL_SELECTOR *sel, NAL_SELECTOR_TOKEN token,
				int fd, unsigned char flags)
{
	sel_ctx *ctx = nal_selector_get_vtdata(sel);
	if(flags & SELECTOR_FLAG_READ)
		FD_SET2(fd, &ctx->to_select.reads);
	if(flags & SELECTOR_FLAG_SEND)
		FD_SET2(fd, &ctx->to_select.sends);
	if(flags & SELECTOR_FLAG_EXCEPT)
		FD_SET2(fd, &ctx->to_select.excepts);
	ctx->to_select.max = ((ctx->to_select.max <= (fd + 1)) ?
				(fd + 1) : ctx->to_select.max);
}

static unsigned char sel_fd_test(const NAL_SELECTOR *sel,
				NAL_SELECTOR_TOKEN token, int fd)
{
	unsigned char flags = 0;
	sel_ctx *ctx = nal_selector_get_vtdata(sel);
	if(FD_ISSET(fd, &ctx->last_selected.reads))
		flags |= SELECTOR_FLAG_READ;
	if(FD_ISSET(fd, &ctx->last_selected.sends))
		flags |= SELECTOR_FLAG_SEND;
	if(FD_ISSET(fd, &ctx->last_selected.excepts))
		flags |= SELECTOR_FLAG_EXCEPT;
	return flags;
}

static int sel_ctrl(NAL_SELECTOR *sel, int cmd, void *p)
{
	switch(cmd) {
	case NAL_FD_CTRL_FDSET:
		{
		NAL_FD_FDSET *args = p;
		sel_fd_set(sel, args->token, args->fd, args->flags);
		}
		break;
	case NAL_FD_CTRL_FDTEST:
		{
		NAL_FD_FDTEST *args = p;
		args->flags = sel_fd_test(sel, args->token, args->fd);
		}
		break;
	default:
		abort();
		return 0;
	}
	return 1;
}

#endif
