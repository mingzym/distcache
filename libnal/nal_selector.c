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

/********************/
/* Select interface */
/********************/

typedef struct _NAL_SELECTOR_item {
	fd_set reads;
	fd_set sends;
	fd_set excepts;
	int max;
} NAL_SELECTOR_item;

struct st_NAL_SELECTOR {
	/* The result of a select */
	NAL_SELECTOR_item last_selected;
	/* The list we're building up to select with next */
	NAL_SELECTOR_item to_select;
};

/* Workaround signed/unsigned conflicts between real systems and windows */
#ifndef WIN32
#define FD_SET2(a,b) FD_SET((a),(b))
#define FD_CLR2(a,b) FD_CLR((a),(b))
#else
#define FD_SET2(a,b) FD_SET((SOCKET)(a),(b))
#define FD_CLR2(a,b) FD_CLR((SOCKET)(a),(b))
#endif

static int nal_selector_item_init(NAL_SELECTOR_item *item)
{
	FD_ZERO(&item->reads);
	FD_ZERO(&item->sends);
	FD_ZERO(&item->excepts);
	item->max = 0;
	return 1;
}

static void nal_selector_item_finish(NAL_SELECTOR_item *item)
{
	/* nop */
}

static void nal_selector_item_flip(NAL_SELECTOR_item *to,
				NAL_SELECTOR_item *from)
{
	SYS_memcpy(fd_set, &to->reads, &from->reads);
	SYS_memcpy(fd_set, &to->sends, &from->sends);
	SYS_memcpy(fd_set, &to->excepts, &from->excepts);
	to->max = from->max;
	nal_selector_item_init(from);
}

static int nal_selector_item_select(NAL_SELECTOR_item *item,
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

/*******************************************************/
/* Select interface - functions local to libnal source */
/*******************************************************/

/* set/unset operate on "to_select */

void nal_selector_fd_set(NAL_SELECTOR *sel, int fd, unsigned char flags)
{
	if(flags & SELECTOR_FLAG_READ)
		FD_SET2(fd, &sel->to_select.reads);
	if(flags & SELECTOR_FLAG_SEND)
		FD_SET2(fd, &sel->to_select.sends);
	if(flags & SELECTOR_FLAG_EXCEPT)
		FD_SET2(fd, &sel->to_select.excepts);
	sel->to_select.max = ((sel->to_select.max <= (fd + 1)) ?
				(fd + 1) : sel->to_select.max);
}

void nal_selector_fd_unset(NAL_SELECTOR *sel, int fd)
{
	FD_CLR2(fd, &sel->to_select.reads);
	FD_CLR2(fd, &sel->to_select.sends);
	FD_CLR2(fd, &sel->to_select.excepts);
}

/* test/clear operate on "last_selected" */

unsigned char nal_selector_fd_test(const NAL_SELECTOR *sel, int fd)
{
	unsigned char flags = 0;
	if(FD_ISSET(fd, &sel->last_selected.reads))
		flags |= SELECTOR_FLAG_READ;
	if(FD_ISSET(fd, &sel->last_selected.sends))
		flags |= SELECTOR_FLAG_SEND;
	if(FD_ISSET(fd, &sel->last_selected.excepts))
		flags |= SELECTOR_FLAG_EXCEPT;
	return flags;
}

void nal_selector_fd_clear(NAL_SELECTOR *sel, int fd)
{
	FD_CLR2(fd, &sel->last_selected.reads);
	FD_CLR2(fd, &sel->last_selected.sends);
	FD_CLR2(fd, &sel->last_selected.excepts);
}

/**********************/
/* SELECTOR FUNCTIONS */
/**********************/

NAL_SELECTOR *NAL_SELECTOR_new(void)
{
	NAL_SELECTOR *sel = SYS_malloc(NAL_SELECTOR, 1);
	if(sel) {
		if(!nal_selector_item_init(&sel->last_selected))
			goto err;
		if(!nal_selector_item_init(&sel->to_select)) {
			nal_selector_item_finish(&sel->last_selected);
			goto err;
		}
	}
	return sel;
err:
	SYS_free(NAL_SELECTOR, sel);
	return NULL;
}

void NAL_SELECTOR_free(NAL_SELECTOR *a)
{
	nal_selector_item_finish(&a->last_selected);
	nal_selector_item_finish(&a->to_select);
	SYS_free(NAL_SELECTOR, a);
}

int NAL_SELECTOR_select(NAL_SELECTOR *sel, unsigned long usec_timeout,
			int use_timeout)
{
	struct timeval timeout;

	timeout.tv_sec = usec_timeout / 1000000;
	timeout.tv_usec = usec_timeout % 1000000;
	/* Migrate to_select over to last_selected */
	nal_selector_item_flip(&sel->last_selected, &sel->to_select);
	return nal_selector_item_select(&sel->last_selected, usec_timeout,
				use_timeout);
}

