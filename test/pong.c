/* distcache, Distributed Session Caching technology
 * Copyright (C) 2000-2003  Geoff Thorpe, and Cryptographic Appliances, Inc.
 * Copyright (C) 2004       The Distcache.org project
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

#define SYS_GENERATING_EXE

#include <libsys/pre.h>
#include <libnal/nal.h>
#include "timing.h"
#include <libsys/post.h>

typedef enum {
	NET_NULL,
	NET_CLIENT,
	NET_SERVER
} NET_MODE;

#define MAX_SIZE		(32*1024)
#define MIN_REQUEST		1
#define MIN_RESPONSE		1
#define BUFFER_SIZE		MAX_SIZE
#define DEF_NUM_CONNS		1
#define DEF_REQUEST		10
#define DEF_RESPONSE		1024
#define DEF_LOOP		1
#define DEF_REPEAT		10
#define DEF_UNITS		UNITS_bits

#ifdef SUPPORT_UPDATE
IMPLEMENT_UNITS()
#endif

static void usage(void)
{
	SYS_fprintf(SYS_stderr,
"Usage:   nal_ping [options ...] < [ -connect | -accept ] address >\n"
"where options include;\n"
"   -num <num>          - default=%d\n"
"   -request <num>      - default=%d\n"
"   -response <num>     - default=%d\n"
"   -loop <num>         - default=%d\n"
"   -repeat <num>       - default=%d\n"
"   -reverse\n",
DEF_NUM_CONNS, DEF_REQUEST, DEF_RESPONSE, DEF_LOOP, DEF_REPEAT);
#ifdef SUPPORT_UPDATE
	SYS_fprintf(SYS_stderr,
"   -update <secs>      - default=<none>\n"
"   -units [k|m|g]<b|B> - default='%s'\n"
"'units' displays traffic rates as bits or bytes per second.\n"
"An optional prefix can scale to kilo, mega, or giga bits/bytes.\n",
UNITS2STR(DEF_UNITS));
#endif
	SYS_fprintf(SYS_stderr,
"Using -loop allows requests/responses to be repeated over the same\n"
"connection, whereas -repeat indicates how many times a connection\n"
"should be reopened. The network server (-accept) must have a loop\n"
"value matching the client, however -repeat is ignored and -num is\n"
"only used as a maximum (it will not accept more than -num connections\n"
"at a time).\n");
	SYS_fprintf(SYS_stderr,
"When using -connect (ie. network client), it is assumed we send the\n"
"the request and then read the response. With -accept, the converse\n"
"is assumed. Specifying -reverse can invert the request/response roles.\n");
}

static int util_parsenum(const char *s, unsigned int *num)
{
	char *endptr;
	unsigned long int val;
	val = strtoul(s, &endptr, 10);
	if((val == ULONG_MAX) || !endptr || (*endptr != '\0')) {
		SYS_fprintf(SYS_stderr, "Error, bad number '%s'\n", s);
		return 0;
	}
	*num = val;
	return 1;
}

static int err_noarg(const char *s)
{
	SYS_fprintf(SYS_stderr, "Error: missing argument for '%s'\n", s);
	usage();
	return 1;
}

static int err_unknown(const char *s)
{
	SYS_fprintf(SYS_stderr, "Error: unknown switch '%s'\n", s);
	usage();
	return 1;
}

/* Static data for use in reading/writing (initialised in main()) */
static unsigned char garbage[MAX_SIZE];

typedef struct st_pongctx {
	/* Fixed context data */
	const NAL_ADDRESS *addr;
	NAL_SELECTOR *sel;
	int id, requestor;
	unsigned int num_loop, num_repeat, size_request, size_response;
	NET_MODE mode;
	/* State */
	int step, done;
	NAL_CONNECTION *conn;
	unsigned int loop, repeat, step_offset;
} pongctx;

static int pongctx_io(pongctx *ctx);

static pongctx *pongctx_new(const NAL_ADDRESS *addr, NAL_SELECTOR *sel, int id,
				int requestor, unsigned int num_loop,
				unsigned int num_repeat, unsigned int size_request,
				unsigned int size_response, NET_MODE mode)
{
	pongctx *ret = SYS_malloc(pongctx, 1);
	if(!ret) goto err;
	ret->conn = NAL_CONNECTION_new();
	if(!ret->conn) goto err;
	/* Fixed data */
	ret->addr = addr;
	ret->sel = sel;
	ret->id = id;
	ret->requestor = requestor;
	ret->num_loop = num_loop;
	ret->num_repeat = num_repeat;
	ret->size_request = size_request;
	ret->size_response = size_response;
	ret->mode = mode;
	/* state */
	ret->step = ret->done = 0;
	ret->loop = ret->repeat = ret->step_offset = 0;
	if((mode == NET_CLIENT) && (!NAL_CONNECTION_create(ret->conn, addr) ||
				!NAL_CONNECTION_add_to_selector(ret->conn, sel)))
		goto err;
	if((mode == NET_CLIENT) && (pongctx_io(ret) < 0)) goto err;
	return ret;
err:
	if(ret) {
		if(ret->conn) NAL_CONNECTION_free(ret->conn);
		SYS_free(pongctx, ret);
	}
	return NULL;
}

static void pongctx_free(pongctx *ctx)
{
	NAL_CONNECTION_free(ctx->conn);
	SYS_free(pongctx, ctx);
}

/* returns -1 for error, or the amount of data read+written */
static int pongctx_io(pongctx *ctx)
{
	int ret = 0;
	if(ctx->done) {
		assert(ctx->mode == NET_CLIENT);
		return ret;
	}
	if(!NAL_CONNECTION_io(ctx->conn)) {
		if(!NAL_CONNECTION_is_established(ctx->conn))
			SYS_fprintf(SYS_stderr, "(%d) Connection failed\n", ctx->id);
		else
			SYS_fprintf(SYS_stderr, "(%d) Disconnection\n", ctx->id);
		return -1;
	}
	/* handle non-blocking connects */
	if(!NAL_CONNECTION_is_established(ctx->conn)) return ret;
	/* post-processing */
post_processing:
	if(ctx->requestor) {
		/* Requestor */
		if(!ctx->step) {
			/* Send the request */
			unsigned int num_sent = NAL_BUFFER_write(
				NAL_CONNECTION_get_send(ctx->conn), garbage,
				ctx->size_request - ctx->step_offset);
			ctx->step_offset += num_sent;
			ret += num_sent;
			if(ctx->step_offset == ctx->size_request) {
				ctx->step = 1;
				ctx->step_offset = 0;
			} else
				return ret;
		}
		if(ctx->step) {
			/* Read the response */
			unsigned int num_read = NAL_BUFFER_read(
				NAL_CONNECTION_get_read(ctx->conn), NULL,
				ctx->size_response - ctx->step_offset);
			ctx->step_offset += num_read;
			ret += num_read;
			if(ctx->step_offset == ctx->size_response)
				goto moveon;
			return ret;
		}
	} else {
		/* Responder */
		if(!ctx->step) {
			/* Read the request */
			unsigned int num_read = NAL_BUFFER_read(
				NAL_CONNECTION_get_read(ctx->conn), NULL,
				ctx->size_request - ctx->step_offset);
			ctx->step_offset += num_read;
			ret += num_read;
			if(ctx->step_offset == ctx->size_request) {
				ctx->step = 1;
				ctx->step_offset = 0;
			} else
				return ret;
		}
		if(ctx->step == 1) {
			/* Write the response */
			unsigned int num_sent = NAL_BUFFER_write(
				NAL_CONNECTION_get_send(ctx->conn), garbage,
				ctx->size_response - ctx->step_offset);
			ctx->step_offset += num_sent;
			ret += num_sent;
			if(ctx->step_offset == ctx->size_response)
				ctx->step = 2;
			else
				return ret;
		}
		assert(ctx->step == 2);
		/* Wait for the outgoing buffer to empty */
		if(NAL_BUFFER_empty(NAL_CONNECTION_get_send(ctx->conn)))
			goto moveon;
		return ret;
	}
moveon:
	ctx->step = 0;
	ctx->step_offset = 0;
	if(++ctx->loop < ctx->num_loop)
		/* A new transaction on the same conn */
		goto post_processing;
	/* We close the connection */
	ctx->loop = 0;
	NAL_CONNECTION_reset(ctx->conn);
	/* For a server, we're "done". For a client, we're done if we've
	 * finished repeating. */
	if((ctx->mode == NET_SERVER) || (++ctx->repeat == ctx->num_repeat)) {
		ctx->done = 1;
		return ret;
	}
	/* Reconnect the client */
	if(!NAL_CONNECTION_create(ctx->conn, ctx->addr) ||
			!NAL_CONNECTION_add_to_selector(ctx->conn, ctx->sel))
		return -1;
	goto post_processing;
}

#define ARG_INC do {argc--;argv++;} while(0)
#define ARG_CHECK(a) \
	if(argc < 2) \
		return err_noarg(a); \
	ARG_INC

int main(int argc, char *argv[])
{
	int tmp, ret = 1;
	unsigned int loop, loop_limit;
	pongctx **ctx;
	int requestor, reverse = 0;
	const char *str_addr = NULL;
	NET_MODE mode = NET_NULL;
	unsigned int num_conns = DEF_NUM_CONNS;
	unsigned int size_request = DEF_REQUEST;
	unsigned int size_response = DEF_RESPONSE;
	unsigned int num_loop = DEF_LOOP;
	unsigned int num_repeat = DEF_REPEAT;
	NAL_ADDRESS *addr;
	NAL_SELECTOR *sel;
	NAL_LISTENER *listener = NULL;
#ifdef SUPPORT_UPDATE
	unsigned int update = 0;
	UNITS units = DEF_UNITS;
	/* Timing variables for '-update' */
	/* initialising tt1 because gcc can't see that I don't need to */
	time_t tt1 = 0, tt2;
	struct timeval tv1, tv2;
	struct rusage ru1, ru2;
	unsigned int traffic = 0;
#endif

	ARG_INC;
	while(argc) {
		if(strcmp(*argv, "-connect") == 0) {
			ARG_CHECK("-connect");
			if(mode != NET_NULL) {
				SYS_fprintf(SYS_stderr, "Error, -connect or "
					"-accept must be specified once only\n");
				return 1;
			}
			mode = NET_CLIENT;
			str_addr = *argv;
		} else if(strcmp(*argv, "-accept") == 0) {
			ARG_CHECK("-accept");
			if(mode != NET_NULL) {
				SYS_fprintf(SYS_stderr, "Error, -connect or "
					"-accept must be specified once only\n");
				return 1;
			}
			mode = NET_SERVER;
			str_addr = *argv;
		} else if(strcmp(*argv, "-num") == 0) {
			ARG_CHECK("-num");
			if(!util_parsenum(*argv, &num_conns))
				return 1;
		} else if(strcmp(*argv, "-request") == 0) {
			ARG_CHECK("-request");
			if(!util_parsenum(*argv, &size_request))
				return 1;
		} else if(strcmp(*argv, "-response") == 0) {
			ARG_CHECK("-response");
			if(!util_parsenum(*argv, &size_response))
				return 1;
		} else if(strcmp(*argv, "-loop") == 0) {
			ARG_CHECK("-loop");
			if(!util_parsenum(*argv, &num_loop))
				return 1;
		} else if(strcmp(*argv, "-repeat") == 0) {
			ARG_CHECK("-repeat");
			if(!util_parsenum(*argv, &num_repeat))
				return 1;
		} else if(strcmp(*argv, "-reverse") == 0) {
			reverse = 1;
#ifdef SUPPORT_UPDATE
		} else if(strcmp(*argv, "-update") == 0) {
			ARG_CHECK("-update");
			if(!util_parsenum(*argv, &update))
				return 1;
		} else if(strcmp(*argv, "-units") == 0) {
			ARG_CHECK("-units");
			if(!util_parseunits(*argv, &units))
				return 1;
#endif
		} else
			return err_unknown(*argv);
		ARG_INC;
	}
	if(mode == NET_NULL) {
		SYS_fprintf(SYS_stderr, "Error, must specify -accept or -connect\n");
		return 1;
	}
	if((size_request < MIN_REQUEST) || (size_response < MIN_RESPONSE) ||
			(size_request > MAX_SIZE) || (size_response > MAX_SIZE)) {
		SYS_fprintf(SYS_stderr, "Error, -request or -response out of range\n");
		return 1;
	}
	requestor = ((mode == NET_SERVER) ? 0 : 1);
	if(reverse) requestor = !requestor;
	loop_limit = (mode == NET_SERVER ? 0 : num_conns);
	srand(time(NULL));
	for(loop = 0; loop < MAX_SIZE; loop += sizeof(int))
		*((int *)(garbage + loop)) = rand();
	SYS_sigpipe_ignore();
	if((ctx = SYS_malloc(pongctx*, num_conns)) == NULL) abort();
	addr = NAL_ADDRESS_new();
	sel = NAL_SELECTOR_new();
	if(!addr || !sel) abort();
	if(!NAL_ADDRESS_create(addr, str_addr, BUFFER_SIZE)) abort();
	if(mode == NET_SERVER) {
		if((listener = NAL_LISTENER_new()) == NULL) abort();
		if(!NAL_LISTENER_create(listener, addr) ||
				!NAL_LISTENER_add_to_selector(listener, sel))
			abort();
	}
	for(loop = 0; loop < num_conns; loop++)
		if((ctx[loop] = pongctx_new(addr, sel, loop, requestor, num_loop,
				num_repeat, size_request, size_response,
				mode)) == NULL)
			abort();
#ifdef SUPPORT_UPDATE
	if(update) {
		tt1 = time(NULL);
		SYS_gettime(&tv1);
		getrusage(RUSAGE_SELF, &ru1);
		SYS_fprintf(SYS_stderr,
"\n"
"Note, '-update' statistics have accurate timing but the traffic measurements\n"
"are based on transfers between user-space fifo buffers. As such, they should\n"
"only be considered accurate \"on average\". Also, the traffic measured is\n"
"two-way, identical traffic is passing in both directions so you can consider\n"
"each direction to be half the advertised throughput value. (We measure receive\n"
"data and double it.)\n"
"\n");
	}
#endif
	do {
		/* Select */
		if((tmp = NAL_SELECTOR_select(sel, 0, 0)) <= 0) {
			SYS_fprintf(SYS_stderr, "Error, NAL_SELECTOR_select() "
				"returned <= 0\n");
			goto err;
		}
		if((mode == NET_SERVER) && (loop_limit < num_conns) &&
				NAL_CONNECTION_accept(ctx[loop_limit]->conn,
					listener)) {
			if(!NAL_CONNECTION_add_to_selector(ctx[loop_limit]->conn,
							sel))
				abort();
			ctx[loop_limit]->step = 0;
			ctx[loop_limit]->done = 0;
			ctx[loop_limit]->loop = 0;
			ctx[loop_limit]->repeat = 0;
			ctx[loop_limit]->step_offset = 0;
			if(pongctx_io(ctx[loop_limit]) < 0) goto err;
			if(++loop_limit == num_conns)
				NAL_LISTENER_del_from_selector(listener);
		}
		/* Post-process */
		loop = 0;
		while(loop < loop_limit) {
			int res = pongctx_io(ctx[loop]);
			if(res < 0) goto err;
			traffic += res;
			if(ctx[loop]->done) {
				loop_limit--;
				/* Add the listener back? */
				if((mode == NET_SERVER) && (loop_limit + 1 ==
								num_conns) &&
						!NAL_LISTENER_add_to_selector(
							listener, sel))
					abort();
				/* Swap the 'done' entry with the tail */
				if(loop < loop_limit) {
					pongctx *foo = ctx[loop];
					ctx[loop] = ctx[loop_limit];
					ctx[loop_limit] = foo;
				}
			} else
				loop++;
		}
#ifdef SUPPORT_UPDATE
		/* Check if an update is required */
		if(update && ((tt2 = time(NULL)) >= (time_t)(tt1 + update))) {
			unsigned long msecs, muser, msys;
			double rate;
			SYS_gettime(&tv2);
			getrusage(RUSAGE_SELF, &ru2);
			msecs = SYS_msecs_between(&tv1, &tv2);
			muser = SYS_msecs_between(&ru1.ru_utime, &ru2.ru_utime);
			msys = SYS_msecs_between(&ru1.ru_stime, &ru2.ru_stime);
			/* Convert bytes to the required double */
			rate = util_tounits(traffic, units);
			/* Adjust according to milli-seconds (and duplexity) */
			rate = 2000.0 * rate / (double)msecs;
			SYS_fprintf(SYS_stdout, "Update: %ld msecs elapsed, %.2f %s/s, "
				"%.1f%% user, %.1f%% kernel\n", msecs, rate,
				UNITS2STR(units), (100.0 * muser)/((float)msecs),
				(100.0 * msys)/((float)msecs));
			tt1 = tt2;
			SYS_timecpy(&tv1, &tv2);
			SYS_memcpy(struct rusage, &ru1, &ru2);
			traffic = 0;
		}
#endif
	/* keep looping until the connections are done and the selector is
	 * empty. This allows non-blocking closes to complete for libnal
	 * implementations that support it. */
	} while((mode == NET_SERVER) || loop_limit || NAL_SELECTOR_num_objects(sel));
	/* Done */
	ret = 0;
err:
	for(loop = 0; loop < num_conns; loop++)
		pongctx_free(ctx[loop]);
	SYS_free(pongctx*, ctx);
	if(listener) NAL_LISTENER_free(listener);
	NAL_SELECTOR_free(sel);
	NAL_ADDRESS_free(addr);
	return ret;
}
