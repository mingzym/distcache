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

#define SYS_GENERATING_EXE

#include <libsys/pre.h>
#include <libnal/nal.h>
#include <libsys/post.h>

#define MAX_PING_SIZE		(32*1024)
#define DEF_SERVER_ADDRESS	"UNIX:/tmp/foo"
#define BUFFER_SIZE		MAX_PING_SIZE
#define DEF_PING_SIZE		1024
#define DEF_PING_NUM		10
#define DEF_NUM_CONNS		1

static void usage(void)
{
	SYS_fprintf(SYS_stderr, "Usage:   PING [options ...]\n");
	SYS_fprintf(SYS_stderr, "where options include;\n");
	SYS_fprintf(SYS_stderr, "   -connect <addr>   - default='%s'\n", DEF_SERVER_ADDRESS);
	SYS_fprintf(SYS_stderr, "   -num <num>        - default=%d\n", DEF_NUM_CONNS);
	SYS_fprintf(SYS_stderr, "   -size <num>       - default=%d\n", DEF_PING_SIZE);
	SYS_fprintf(SYS_stderr, "   -repeat <num>     - default=%d\n", DEF_PING_NUM);
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

#define ARG_INC do {argc--;argv++;} while(0)
#define ARG_CHECK(a) \
	if(argc < 2) \
		return err_noarg(a); \
	ARG_INC

typedef struct st_pingctx {
	int connected, id, done;
	NAL_CONNECTION *conn;
	unsigned int loop, counter, num_repeat, num_size;
	unsigned char packet[MAX_PING_SIZE], response[MAX_PING_SIZE];
} pingctx;

static int pingctx_io(pingctx *ctx);

static pingctx *pingctx_new(const NAL_ADDRESS *addr, NAL_SELECTOR *sel, int id,
				unsigned int num_repeat, unsigned int num_size)
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
	if(!pingctx_io(ret)) goto err;
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

static int pingctx_io(pingctx *ctx)
{
	time_t munge;
	if(ctx->done) return 1;
	if(!NAL_CONNECTION_io(ctx->conn)) {
		if(!ctx->connected)
			SYS_fprintf(SYS_stderr, "(%d) Connection failed\n", ctx->id);
		else
			SYS_fprintf(SYS_stderr, "(%d) Disconnection\n", ctx->id);
		return 0;
	}
	if(!ctx->connected) {
		if(!NAL_CONNECTION_is_established(ctx->conn))
			/* Still connecting */
			return 1;
		ctx->connected = 1;
		goto write_ping;
	}
	/* reading */
	if(NAL_BUFFER_used(NAL_CONNECTION_get_read(ctx->conn)) < ctx->num_size)
		return 1;
	if(NAL_BUFFER_read(NAL_CONNECTION_get_read(ctx->conn), ctx->response,
					ctx->num_size) != ctx->num_size) {
		SYS_fprintf(SYS_stderr, "(%d) Read error: bad length\n", ctx->id);
		return 0;
	}
	if(memcmp(ctx->packet, ctx->response, ctx->num_size) != 0) {
		SYS_fprintf(SYS_stderr, "(%d) Read error: bad match\n", ctx->id);
		return 0;
	}
	SYS_fprintf(SYS_stderr, "(%d) Packet %d ok\n", ctx->id, ++ctx->loop);
write_ping:
	if(ctx->loop == ctx->num_repeat) {
		ctx->done = 1;
		NAL_CONNECTION_reset(ctx->conn);
		return 1;
	}
	munge = time(NULL);
	SYS_cover_n(ctx->counter++ + munge, unsigned char, ctx->packet, ctx->num_size);
	if(NAL_BUFFER_write(NAL_CONNECTION_get_send(ctx->conn), ctx->packet,
					ctx->num_size) != ctx->num_size) {
		SYS_fprintf(SYS_stderr, "(%d) Write error\n", ctx->id);
		return 0;
	}
	return 1;
}

int main(int argc, char *argv[])
{
	int tmp;
	unsigned int loop, done;
	pingctx **ctx;
	const char *str_addr = DEF_SERVER_ADDRESS;
	unsigned int num_repeat = DEF_PING_NUM;
	unsigned int num_size = DEF_PING_SIZE;
	unsigned int num_conns = DEF_NUM_CONNS;
	NAL_ADDRESS *addr = NAL_ADDRESS_new();
	NAL_SELECTOR *sel = NAL_SELECTOR_new();
	if(!addr || !sel) abort();
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
		} else
			return err_unknown(*argv);
		ARG_INC;
	}
	if((ctx = SYS_malloc(pingctx*, num_conns)) == NULL) abort();
	if(!NAL_ADDRESS_create(addr, str_addr, BUFFER_SIZE)) abort();
	for(loop = 0; loop < num_conns; loop++)
		if((ctx[loop] = pingctx_new(addr, sel, loop,
				num_repeat, num_size)) == NULL)
			abort();
mainloop:
	/* Select */
	while((tmp = NAL_SELECTOR_select(sel, 0, 0)) <= 0)
		;
	/* Post-process */
	done = 0;
	for(loop = 0; loop < num_conns; loop++) {
		if(!pingctx_io(ctx[loop]))
			return 1;
		if(ctx[loop]->done)
			done++;
	}
	if(done < num_conns) goto mainloop;
	/* Done */
	for(loop = 0; loop < num_conns; loop++)
		pingctx_free(ctx[loop]);
	SYS_free(pingctx*, ctx);
	NAL_SELECTOR_free(sel);
	NAL_ADDRESS_free(addr);
	return 0;
}
