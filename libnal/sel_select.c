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

/* These are the structure types we use */
typedef struct st_sel_item {
	fd_set reads;
	fd_set sends;
	fd_set excepts;
	int max;
} sel_item;
typedef struct st_sel_ctx {
	/* The result of a select */
	sel_item last_selected;
	/* The list we're building up to select with next */
	sel_item to_select;
} sel_ctx;

/**************************/
/* predeclare our vtables */
/**************************/

/* Predeclare the selector functions */
static int sel_on_create(NAL_SELECTOR *sel);
static void sel_on_destroy(NAL_SELECTOR *sel);
static void sel_on_reset(NAL_SELECTOR *sel);
static NAL_SELECTOR_TYPE sel_get_type(const NAL_SELECTOR *sel);
static void sel_fd_set(NAL_SELECTOR *sel, int fd, unsigned char flags);
static void sel_fd_unset(NAL_SELECTOR *sel, int fd);
static unsigned char sel_fd_test(const NAL_SELECTOR *sel, int fd);
static void sel_fd_clear(NAL_SELECTOR *sel, int fd);
static int sel_select(NAL_SELECTOR *sel, unsigned long usec_timeout, int use_timeout);
/* This is extern'd in the nal_internal.h header, and used as the default vtable */
const NAL_SELECTOR_vtable sel_fdselect_vtable = {
	sizeof(sel_ctx),
	sel_on_create,
	sel_on_destroy,
	sel_on_reset,
	sel_get_type,
	sel_fd_set,
	sel_fd_unset,
	sel_fd_test,
	sel_fd_clear,
	sel_select,
};

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
	/* ... because it works this way */
	sel_on_reset(sel);
	return 1;
}

static void sel_on_destroy(NAL_SELECTOR *sel)
{
}

static void sel_on_reset(NAL_SELECTOR *sel)
{
	sel_ctx *ctx = nal_selector_get_vtdata(sel);
	nal_selector_item_init(&ctx->last_selected);
	nal_selector_item_init(&ctx->to_select);
}

static NAL_SELECTOR_TYPE sel_get_type(const NAL_SELECTOR *sel)
{
	return NAL_SELECTOR_TYPE_FDSELECT;
}

static void sel_fd_set(NAL_SELECTOR *sel, int fd, unsigned char flags)
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

static void sel_fd_unset(NAL_SELECTOR *sel, int fd)
{
	sel_ctx *ctx = nal_selector_get_vtdata(sel);
	FD_CLR2(fd, &ctx->to_select.reads);
	FD_CLR2(fd, &ctx->to_select.sends);
	FD_CLR2(fd, &ctx->to_select.excepts);
}

static unsigned char sel_fd_test(const NAL_SELECTOR *sel, int fd)
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

static void sel_fd_clear(NAL_SELECTOR *sel, int fd)
{
	sel_ctx *ctx = nal_selector_get_vtdata(sel);
	FD_CLR2(fd, &ctx->last_selected.reads);
	FD_CLR2(fd, &ctx->last_selected.sends);
	FD_CLR2(fd, &ctx->last_selected.excepts);
}

static int sel_select(NAL_SELECTOR *sel, unsigned long usec_timeout,
			int use_timeout)
{
	int res;
	sel_ctx *ctx = nal_selector_get_vtdata(sel);
	/* Migrate to_select over to last_selected */
	nal_selector_item_flip(&ctx->last_selected, &ctx->to_select);
	return nal_selector_item_select(&ctx->last_selected, usec_timeout,
				use_timeout);
}

