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

#define MAX_PING_SIZE		(32*1024)
#define DEF_SERVER_ADDRESS	"UNIX:/tmp/foo"
#define BUFFER_SIZE		MAX_PING_SIZE
#define DEF_PING_SIZE		1024
#define DEF_PING_NUM		10
#define DEF_NUM_CONNS		1
#define DEF_UNITS		UNITS_bits

#ifdef SUPPORT_UPDATE
IMPLEMENT_UNITS()
#endif

static void usage(void)
{
	SYS_fprintf(SYS_stderr,
"Usage:   nal_ping [options ...]\n"
"where options include;\n"
"   -connect <addr>     - default='%s'\n"
"   -num <num>          - default=%d\n"
"   -size <num>         - default=%d\n"
"   -repeat <num>       - default=%d\n"
"   -mode <style>       - default='block'\n",
DEF_SERVER_ADDRESS, DEF_NUM_CONNS, DEF_PING_SIZE, DEF_PING_NUM);
#ifdef SUPPORT_UPDATE
	SYS_fprintf(SYS_stderr,
"   -update <secs>      - default=<none>\n"
"   -units [k|m|g]<b|B> - default='%s'\n", UNITS2STR(DEF_UNITS));
#endif
	SYS_fprintf(SYS_stderr,
"   -peek\n"
"   -quiet\n"
#ifdef SUPPORT_UPDATE
"'units' displays traffic rates as bits or bytes per second.\n"
"An optional prefix can scale to kilo, mega, or giga bits/bytes.\n"
#endif
"alternative styles for '-mode' are;\n"
"   zero    - all packets are zero\n"
"   block   - each packet set to a different byte\n"
"   noise   - messy data\n"
"   speed   - initialised once only and responses aren't checked\n");
}

typedef enum {
	pingmode_zero,
	pingmode_block,
	pingmode_noise,
	pingmode_speed
} pingmode_t;

static int util_parsemode(const char *s, pingmode_t *mode)
{
	if(strcmp(s, "zero") == 0)
		*mode = pingmode_zero;
	else if(strcmp(s, "block") == 0)
		*mode = pingmode_block;
	else if(strcmp(s, "noise") == 0)
		*mode = pingmode_noise;
	else if(strcmp(s, "speed") == 0)
		*mode = pingmode_speed;
	else {
		SYS_fprintf(SYS_stderr, "Error, '%s' is not a recognised mode\n", s);
		return 0;
	}
	return 1;
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

static void bindump(const unsigned char *data, unsigned int len)
{
#define LINEWIDTH 16
	unsigned int tot = 0, pos = 0;
	while(len--) {
		if(!pos)
			SYS_fprintf(SYS_stdout, "%04d: ", tot);
		SYS_fprintf(SYS_stdout, "0x%02x ", *(data++));
		if(++pos == LINEWIDTH) {
			SYS_fprintf(SYS_stdout, "\n");
			pos = 0;
		}
		tot++;
	}
	if(pos)
		SYS_fprintf(SYS_stdout, "\n");
}

#define ARG_INC do {argc--;argv++;} while(0)
#define ARG_CHECK(a) \
	if(argc < 2) \
		return err_noarg(a); \
	ARG_INC

typedef struct st_pingctx {
	int connected, inread, id, done, peek, quiet;
	pingmode_t pingmode;
	NAL_CONNECTION *conn;
	unsigned int loop, counter, num_repeat, num_size;
	unsigned char packet[MAX_PING_SIZE], response[MAX_PING_SIZE];
} pingctx;

static void pingctx_newpacket(pingctx *ctx)
{
	switch(ctx->pingmode) {
	case pingmode_zero:
		SYS_zero_n(unsigned char, ctx->packet, ctx->num_size);
		break;
	case pingmode_block:
		SYS_cover_n(ctx->counter + time(NULL), unsigned char,
			ctx->packet, ctx->num_size);
		break;
	case pingmode_speed:
		/* Only initialise once, by falling through to noise. NB,
		 * pingmode_speed has a special hook in pingctx_new() to force
		 * this prior to timing. */
		if(ctx->counter) break;
	case pingmode_noise:
	{
		unsigned int loop = ctx->num_size;
		unsigned char *p = ctx->packet;
		/* nb: base and mult are initialised to avoid gcc
		 * warnings, it's not smart enough to realise the
		 * (!duration) branch executes immediately. */
		unsigned int base = 0, mult = 0, duration = 0;
		srand(ctx->counter + time(NULL));
		do {
			if(!duration) {
				/* refresh */
				base = (int)(65536.0 * rand() /
					(RAND_MAX+1.0));
				mult = 1 + (int)(65536.0 * rand() /
					(RAND_MAX+1.0));
				duration = 1 + (int)(100.0 * rand() /
					(RAND_MAX+1.0));
			}
			base *= mult;
			base += mult;
			*(p++) = (base >> 24) ^ (base & 0xFF);
		} while(duration--, loop--);
	}
		break;
	default:
		/* bug */
		abort();
	}
	ctx->counter++;
	if(ctx->peek)
		SYS_fprintf(SYS_stdout,
"peek: I sent 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x [...]\n",
		ctx->packet[0], ctx->packet[1], ctx->packet[2],
		ctx->packet[3], ctx->packet[4], ctx->packet[5],
		ctx->packet[6], ctx->packet[7]);
}

static int pingctx_checkpacket(pingctx *ctx)
{
	if(ctx->peek)
		SYS_fprintf(SYS_stdout,
"peek: I read 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x [...]\n",
		ctx->response[0], ctx->response[1], ctx->response[2],
		ctx->response[3], ctx->response[4], ctx->response[5],
		ctx->response[6], ctx->response[7]);
	if((ctx->pingmode != pingmode_speed) && (memcmp(ctx->packet,
				ctx->response, ctx->num_size) != 0)) {
		unsigned int loop = 0;
		while(ctx->packet[loop] == ctx->response[loop])
			loop++;
		SYS_fprintf(SYS_stderr,
"(%d) Read error: bad match at offset %d\n",
			ctx->id, loop);
		if(!ctx->quiet) {
			SYS_fprintf(SYS_stdout, "output packet was;\n");
			bindump(ctx->packet, ctx->num_size);
			SYS_fprintf(SYS_stdout, "response packet was;\n");
			bindump(ctx->response, ctx->num_size);
		}
		return 0;
	}
	ctx->loop++;
	if(!ctx->quiet)
		SYS_fprintf(SYS_stdout, "(%d) Packet %d ok\n", ctx->id,
			ctx->loop);
	return 1;
}

static int pingctx_io(pingctx *ctx);

static pingctx *pingctx_new(const NAL_ADDRESS *addr, NAL_SELECTOR *sel, int id,
				unsigned int num_repeat, unsigned int num_size,
				pingmode_t pingmode, int peek, int quiet)
{
	pingctx *ret = SYS_malloc(pingctx, 1);
	if(!ret) goto err;
	ret->conn = NAL_CONNECTION_new();
	if(!ret->conn) goto err;
	if(!NAL_CONNECTION_create(ret->conn, addr)) goto err;
	if(!NAL_CONNECTION_add_to_selector(ret->conn, sel)) goto err;
	ret->connected = 0;
	ret->loop = 0;
	ret->counter = 0;
	ret->id = id;
	ret->done = 0;
	ret->num_repeat = num_repeat;
	ret->num_size = num_size;
	ret->pingmode = pingmode;
	ret->peek = peek;
	ret->quiet = quiet;
	/* If we're in speed mode, generate garbage *once* in advance of any
	 * timing. */
	if(ret->pingmode == pingmode_speed)
		pingctx_newpacket(ret);
	/* Needed in case the connect is already complete (eg. unix domain). */
	if(pingctx_io(ret) < 0) goto err;
	return ret;
err:
	abort();
	if(ret) {
		if(ret->conn) NAL_CONNECTION_free(ret->conn);
		SYS_free(pingctx, ret);
	}
	return NULL;
}

static void pingctx_free(pingctx *ctx)
{
	NAL_CONNECTION_free(ctx->conn);
	SYS_free(pingctx, ctx);
}

/* returns -1 for error, or the amount of data consumed (read) */
static int pingctx_io(pingctx *ctx)
{
	int ret = 0;
	if(ctx->done) return 0;
	if(!NAL_CONNECTION_io(ctx->conn)) {
		if(!ctx->connected)
			SYS_fprintf(SYS_stderr, "(%d) Connection failed\n", ctx->id);
		else
			SYS_fprintf(SYS_stderr, "(%d) Disconnection\n", ctx->id);
		return -1;
	}
	if(!ctx->connected) {
		if(!NAL_CONNECTION_is_established(ctx->conn))
			/* Still connecting */
			return 0;
		ctx->connected = 1;
		ctx->inread = 0;
	}
	while(1) switch(ctx->inread) {
	case 1:
		/* reading */
		if(NAL_BUFFER_used(NAL_CONNECTION_get_read(ctx->conn)) <
					ctx->num_size)
			return ret;
		if(NAL_BUFFER_read(NAL_CONNECTION_get_read(ctx->conn),
				ctx->response, ctx->num_size) != ctx->num_size) {
			SYS_fprintf(SYS_stderr, "(%d) Read error: bad length\n",
				ctx->id);
			return -1;
		}
		if(!pingctx_checkpacket(ctx))
			return -1;
		ret += ctx->num_size;
		ctx->inread = 0;
	case 0:
		/* writing */
		if(ctx->loop == ctx->num_repeat) {
			ctx->done = 1;
			NAL_CONNECTION_reset(ctx->conn);
			return ret;
		}
		if(NAL_BUFFER_unused(NAL_CONNECTION_get_send(ctx->conn)) <
						ctx->num_size)
			return ret;
		pingctx_newpacket(ctx);
		if(NAL_BUFFER_write(NAL_CONNECTION_get_send(ctx->conn),
				ctx->packet, ctx->num_size) != ctx->num_size) {
			SYS_fprintf(SYS_stderr, "(%d) Write error\n", ctx->id);
			return -1;
		}
		ctx->inread = 1;
		break;
	default:
		SYS_fprintf(SYS_stderr, "Error, internal bug!\n");
		abort();
	}
}

int main(int argc, char *argv[])
{
	int tmp, ret = 1;
	unsigned int loop, done;
	pingctx **ctx;
	const char *str_addr = DEF_SERVER_ADDRESS;
	unsigned int num_repeat = DEF_PING_NUM;
	unsigned int num_size = DEF_PING_SIZE;
	unsigned int num_conns = DEF_NUM_CONNS;
	pingmode_t pingmode = pingmode_block;
	int peek = 0, quiet = 0;
	NAL_ADDRESS *addr;
	NAL_SELECTOR *sel;
#ifdef SUPPORT_UPDATE
	unsigned int update = 0;
	UNITS units = DEF_UNITS;
	/* Timing variables for '-update' */
	time_t tt1, tt2;
	struct timeval tv1, tv2;
	struct rusage ru1, ru2;
	unsigned int traffic = 0;
#endif

	ARG_INC;
	while(argc) {
		if(strcmp(*argv, "-connect") == 0) {
			ARG_CHECK("-connect");
			str_addr = *argv;
		} else if(strcmp(*argv, "-num") == 0) {
			ARG_CHECK("-num");
			if(!util_parsenum(*argv, &num_conns))
				return 1;
		} else if(strcmp(*argv, "-repeat") == 0) {
			ARG_CHECK("-repeat");
			if(!util_parsenum(*argv, &num_repeat))
				return 1;
		} else if(strcmp(*argv, "-size") == 0) {
			ARG_CHECK("-size");
			if(!util_parsenum(*argv, &num_size))
				return 1;
			if(!num_size || (num_size > MAX_PING_SIZE)) {
				SYS_fprintf(SYS_stderr, "Error, '%d' is "
					"out of range\n", num_size);
				return 1;
			}
		} else if(strcmp(*argv, "-mode") == 0) {
			ARG_CHECK("-mode");
			if(!util_parsemode(*argv, &pingmode))
				return 1;
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
		} else if(strcmp(*argv, "-peek") == 0)
			peek = 1;
		else if(strcmp(*argv, "-quiet") == 0) {
			quiet = 1;
		} else
			return err_unknown(*argv);
		ARG_INC;
	}
	SYS_sigpipe_ignore();
	if((ctx = SYS_malloc(pingctx*, num_conns)) == NULL) abort();
	addr = NAL_ADDRESS_new();
	sel = NAL_SELECTOR_new();
	if(!addr || !sel) abort();
	if(!NAL_ADDRESS_create(addr, str_addr, BUFFER_SIZE)) abort();
	for(loop = 0; loop < num_conns; loop++)
		if((ctx[loop] = pingctx_new(addr, sel, loop, num_repeat,
				num_size, pingmode, peek, quiet)) == NULL)
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
		/* Post-process */
		done = 0;
		for(loop = 0; loop < num_conns; loop++) {
			int res = pingctx_io(ctx[loop]);
			if(res < 0) goto err;
			traffic += res;
			if(ctx[loop]->done)
				done++;
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
	} while((done < num_conns) || NAL_SELECTOR_num_objects(sel));
	/* Done */
	ret = 0;
err:
	for(loop = 0; loop < num_conns; loop++)
		pingctx_free(ctx[loop]);
	SYS_free(pingctx*, ctx);
	NAL_SELECTOR_free(sel);
	NAL_ADDRESS_free(addr);
	return ret;
}
