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
#include "ctrl_fd.h"
#include <libsys/post.h>

#ifndef HAVE_POLL

/* If we don't build poll() support, return a NULL vtable */
const NAL_SELECTOR_vtable *sel_fdpoll(void)
{
	return NULL;
}
NAL_SELECTOR *NAL_SELECTOR_new_fdpoll(void)
{
	return NULL;
}

#else

typedef struct st_sel_obj {
	union {
		NAL_CONNECTION *conn;
		NAL_LISTENER *listener;
	} obj;
	unsigned char what; /* 0==unused, 1==conn, 2==listener */
	/* Hook logic for pre/post-select ... see the code lower down */
	unsigned int idx_start, idx_total;
} sel_obj;
typedef struct st_sel_ctx {
	/* The poll array. This is repopulated during each pre_select round,
	 * but the array is expanded as needed and never shrunk (except during
	 * destruction, of course). */
	struct pollfd *pollfds;
	unsigned int pfds_used, pfds_size;
	/* The table of connection and listener objects. */
	sel_obj *obj_table;
	unsigned int obj_used, obj_size;
	/* Used during pre_select and post_select to check we only get
	 * callbacks for tokens belonging to the object we're hooking at the
	 * time. */
	NAL_SELECTOR_TOKEN hook_current;
} sel_ctx;
#define OBJ_TABLE_START		32
#define POLLFD_TABLE_START	4	/* Just for testing */
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
	ctx->pollfds = SYS_malloc(struct pollfd, POLLFD_TABLE_START);
	if(!ctx->pollfds) {
		SYS_free(sel_obj, ctx->obj_table);
		return 0;
	}
	obj_table_zilch(ctx->obj_table, OBJ_TABLE_START);
	ctx->obj_used = 0;
	ctx->obj_size = OBJ_TABLE_START;
	ctx->pfds_used = 0;
	ctx->pfds_size = POLLFD_TABLE_START;
	return 1;
}
static void obj_table_finish(sel_ctx *ctx)
{
	if(ctx->obj_used)
		SYS_fprintf(SYS_stderr, "Warning, selector destruction leaves "
				"dangling objects\n");
	SYS_free(sel_obj, ctx->obj_table);
	SYS_free(struct pollfd, ctx->pollfds);
}
static void obj_table_reset(sel_ctx *ctx)
{
	if(ctx->obj_used)
		SYS_fprintf(SYS_stderr, "Warning, selector reset leaves "
				"dangling objects\n");
	ctx->obj_used = 0;
	ctx->pfds_used = 0;
}
static int pollfds_expand(sel_ctx *ctx)
{
	struct pollfd *newitems;
	unsigned int newsize;
	if(ctx->pfds_used < ctx->pfds_size)
		return 1;
	newsize = ctx->pfds_size * 3 / 2;
	newitems = SYS_malloc(struct pollfd, newsize);
	if(!newitems) return 0;
	if(ctx->pfds_used)
		SYS_memcpy_n(struct pollfd, newitems, ctx->pollfds,
				ctx->pfds_used);
	SYS_free(struct pollfd, ctx->pollfds);
	ctx->pollfds = newitems;
	ctx->pfds_size = newsize;
	return 1;
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
/* Implemented lower down with the "fd_set" callbacks that will be used by the
 * connection/listener implementations we hook. */
static void obj_table_pre_select(sel_ctx *ctx);
static void obj_table_post_select(sel_ctx *ctx);
/**************************/
/* predeclare our vtables */
/**************************/

/* Predeclare the selector functions */
static int sel_on_create(NAL_SELECTOR *);
static void sel_on_destroy(NAL_SELECTOR *);
static void sel_on_reset(NAL_SELECTOR *);
static NAL_SELECTOR_TYPE sel_get_type(const NAL_SELECTOR *);
static int sel_select(NAL_SELECTOR *, unsigned long usec_timeout, int use_timeout);
static NAL_SELECTOR_TOKEN sel_add_listener(NAL_SELECTOR *, NAL_LISTENER *);
static NAL_SELECTOR_TOKEN sel_add_connection(NAL_SELECTOR *, NAL_CONNECTION *);
static void sel_del_listener(NAL_SELECTOR *, NAL_LISTENER *, NAL_SELECTOR_TOKEN);
static void sel_del_connection(NAL_SELECTOR *, NAL_CONNECTION *, NAL_SELECTOR_TOKEN);
static int sel_ctrl(NAL_SELECTOR *, int, void *);
static const NAL_SELECTOR_vtable sel_fdpoll_vtable = {
	sizeof(sel_ctx),
	sel_on_create,
	sel_on_destroy,
	sel_on_reset,
	sel_get_type,
	sel_select,
	sel_add_listener,
	sel_add_connection,
	sel_del_listener,
	sel_del_connection,
	sel_ctrl
};
/* Expose this implementation */
const NAL_SELECTOR_vtable *sel_fdpoll(void)
{
	return &sel_fdpoll_vtable;
}
NAL_SELECTOR *NAL_SELECTOR_new_fdpoll(void)
{
	return nal_selector_new(&sel_fdpoll_vtable);
}

/************************************/
/* selector implementation handlers */
/************************************/

static int sel_on_create(NAL_SELECTOR *sel)
{
	sel_ctx *ctx = nal_selector_get_vtdata(sel);
	if(!obj_table_init(ctx)) return 0;
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
}

static NAL_SELECTOR_TYPE sel_get_type(const NAL_SELECTOR *sel)
{
	return NAL_SELECTOR_TYPE_FDPOLL;
}

static int sel_select(NAL_SELECTOR *sel, unsigned long usec_timeout,
			int use_timeout)
{
	int res;
	sel_ctx *ctx = nal_selector_get_vtdata(sel);
	/* Pre-select */
	obj_table_pre_select(ctx);
	/* Call the blocking poll(2) function */
	res = poll(ctx->pollfds, ctx->pfds_used, use_timeout ?
				(int)(usec_timeout / 1000) : -1);
	/* Post-select */
	if(res > 0) obj_table_post_select(ctx);
	return res;
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

/* The following code handles the hooking with listener and connection
 * implementations. In particular, we use tokens so that we can invoke those
 * implementations in such a way that they can callback to us whilst processing
 * their hooks and we can understand what's up. */
static void obj_table_pre_select(sel_ctx *ctx)
{
	unsigned int loop = 0;
	sel_obj *item = ctx->obj_table;
	/* Reset the pollfd usage to zero */
	ctx->pfds_used = 0;
	while(loop < ctx->obj_size) {
		/* Prior to hooking the 'pre_select' set these, we will adjust
		 * them from within any callbacks the hook makes. This allows a
		 * listener or connection object to register zero, one, or
		 * multiple fds in the pollfd array for one NAL object. */
		item->idx_start = ctx->pfds_used;
		item->idx_total = 0;
		ctx->hook_current = IDX2TOKEN(loop);
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
		if(item->idx_total) {
			/* The hooks registered pollfd entries */
			assert(item->idx_start + item->idx_total == ctx->pfds_used);
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
		/* For now, we call hooks for every object that registered at
		 * least one fd with pre-select, however it would probably be
		 * better to also bypass hooks when the object's registered fds
		 * had no events. */
		if(item->idx_total) {
			ctx->hook_current = IDX2TOKEN(loop);
			/* XXX: For the above note, we could loop here from
			 * item->idx_start for item->idx_total fds and check if
			 * pfd->revents is zero for them all. If so -> no need
			 * for post_select. */
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
		}
		item++;
		loop++;
	}
}

static void sel_fd_set(NAL_SELECTOR *sel, NAL_SELECTOR_TOKEN token,
				int fd, unsigned char flags)
{
	struct pollfd *pfd;
	sel_ctx *ctx = nal_selector_get_vtdata(sel);
	unsigned int idx = TOKEN2IDX(token);
	sel_obj *obj = ctx->obj_table + idx;
	assert(token == ctx->hook_current);
	assert(idx < ctx->obj_size);
	assert((obj->what == 1) || (obj->what == 2));
	if(!pollfds_expand(ctx)) {
		/* XXX: no return type is possible because the API function
		 * driving us is NAL_SELECTOR_select() and that has no
		 * particular error handling to cover this. */
		SYS_fprintf(SYS_stderr, "Warning, expansion for fd_set failed\n");
		return;
	}
	/* XXX: If ever a hook called sel_fd_set more than once with a matching
	 * 'fd', only the first one's results will be picked up in sel_fd_test
	 * later on. The smart-ass solution is to check here and OR the flags,
	 * but I'm looking for simplicity ... */
	assert(obj->idx_start + obj->idx_total == ctx->pfds_used);
	pfd = ctx->pollfds + (obj->idx_start + obj->idx_total++);
	pfd->fd = fd;
	pfd->events = ((flags & SELECTOR_FLAG_READ) ? POLLIN : 0) |
		((flags & SELECTOR_FLAG_SEND) ? POLLOUT : 0) |
		((flags & SELECTOR_FLAG_EXCEPT) ?
			POLLERR | POLLHUP | POLLNVAL : 0);
	ctx->pfds_used++;
}

static unsigned char sel_fd_test(const NAL_SELECTOR *sel,
				NAL_SELECTOR_TOKEN token, int fd)
{
	unsigned int loop = 0;
	sel_ctx *ctx = nal_selector_get_vtdata(sel);
	unsigned int idx = TOKEN2IDX(token);
	sel_obj *obj = ctx->obj_table + idx;
	assert(token == ctx->hook_current);
	assert(idx < ctx->obj_size);
	assert((obj->what == 1) || (obj->what == 2));
	assert(!obj->idx_total ||
		((obj->idx_start + obj->idx_total) <= ctx->pfds_used));
	while(loop < obj->idx_total) {
		struct pollfd *pfd = ctx->pollfds +
			(obj->idx_start + loop++);
		if(pfd->fd == fd) {
			unsigned char flags = 0;
			if(pfd->revents & POLLIN)
				flags |= SELECTOR_FLAG_READ;
			if(pfd->revents & POLLOUT)
				flags |= SELECTOR_FLAG_SEND;
			/* poll() exhibits a behaviour that a peer's send()
			 * followed by a close() could arrive here as POLLIN
			 * and POLLERR it seems. So only set EXCEPT if there
			 * aren't other flags involved. */
			if(!flags && (pfd->revents & (POLLERR|POLLHUP|POLLNVAL)))
				flags = SELECTOR_FLAG_EXCEPT;
			return flags;
		}
	}
	assert(NULL == "sel_fd_test had no collision!");
	return 0;
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
