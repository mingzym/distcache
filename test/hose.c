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
#include <libsys/post.h>

#define DEF_SERVER_ADDRESS	"UNIX:/tmp/foo"
#define BUFFER_SIZE		(32*1024)
#define DEF_CHUNK_SIZE		2051	/* Keep things interesting */
#define MIN_CHUNK_SIZE		10
#define DEF_CHUNK_LAG		0
#define DEF_PING_NUM		0	/* Keep repeating */
#define DEF_NUM_CONNS		1

static void usage(void)
{
	SYS_fprintf(SYS_stderr,
"Usage:   nal_hose [options ...]\n"
"where options include;\n"
"   -connect <addr>   - default='%s'\n"
"   -num <num>        - default=%d\n"
"   -size <num>       - default=%d\n"
"   -repeat <num>     - default=%d\n"
"   -lag <num>        - default=%d\n"
"   -quiet\n",
DEF_SERVER_ADDRESS, DEF_NUM_CONNS, DEF_CHUNK_SIZE, DEF_PING_NUM, DEF_CHUNK_LAG);
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
	int connected, id, done, quiet;
	NAL_CONNECTION *conn;
	unsigned int num_read, num_written, repeat, size, lag;
} pingctx;

static int pingctx_io(pingctx *ctx);

static pingctx *pingctx_new(const NAL_ADDRESS *addr, NAL_SELECTOR *sel, int id,
			unsigned int repeat, unsigned int size,
			unsigned int lag, unsigned int quiet)
{
	pingctx *ret = SYS_malloc(pingctx, 1);
	if(!ret) goto err;
	ret->conn = NAL_CONNECTION_new();
	if(!ret->conn) goto err;
	if(!NAL_CONNECTION_create(ret->conn, addr)) goto err;
	if(!NAL_CONNECTION_add_to_selector(ret->conn, sel)) goto err;
	ret->connected = 0;
	ret->id = id;
	ret->done = 0;
	ret->num_read = 0;
	ret->num_written = 0;
	ret->repeat = repeat;
	ret->size = size;
	ret->lag = lag;
	ret->quiet = quiet;
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

static unsigned int uint32_read(const unsigned char **p)
{
	unsigned int tmp = *((*p)++);
	tmp = (tmp << 8) | *((*p)++);
	tmp = (tmp << 8) | *((*p)++);
	tmp = (tmp << 8) | *((*p)++);
	return tmp;
}

static void uint32_write(unsigned char **p, unsigned int val)
{
	*((*p)++) = (val >> 24) & 0xFF;
	*((*p)++) = (val >> 16) & 0xFF;
	*((*p)++) = (val >> 8) & 0xFF;
	*((*p)++) = val & 0xFF;
}

static int pingctx_io(pingctx *ctx)
{
	const unsigned char *cdata;
	unsigned int num, seed, loop, base, mult, total, used;
	unsigned char *p;
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

	total = NAL_BUFFER_used(NAL_CONNECTION_get_read(ctx->conn));
	cdata = NAL_BUFFER_data(NAL_CONNECTION_get_read(ctx->conn));
	used = 0;
	while((total - used) >= ctx->size) {
		/* ok, we have complete chunk(s) to read */
		ctx->num_read++;
		num = uint32_read(&cdata);
		seed = uint32_read(&cdata);
		if(num != ctx->num_read) {
			SYS_fprintf(SYS_stderr, "(%d) Read error: bad chunk header\n", ctx->id);
			return 0;
		}
		/* seed the prng and verify the data */
		srand(seed);
		loop = ctx->size - 8;
		base = (int)(65536.0 * rand()/(RAND_MAX+1.0));
		mult = 1 + (int)(65536.0 * rand()/(RAND_MAX+1.0));
		do {
			base *= mult;
			base += mult;
			if(*(cdata++) != ((base >> 24) ^ (base & 0xFF))) {
				SYS_fprintf(SYS_stderr, "(%d) Read error: bad match at "
					"offset %d\n", ctx->id, ctx->size - loop);
				return 0;
			}
		} while(--loop);
		/* data ok, consume the packet */
		used += ctx->size;
		if(!ctx->quiet)
			SYS_fprintf(SYS_stdout, "(%d) Packet %d read ok\n",
					ctx->id, ctx->num_read);
		if(ctx->num_read == ctx->repeat) {
			ctx->done = 1;
			NAL_CONNECTION_reset(ctx->conn);
			return 1;
		}
	}
	if(used && NAL_BUFFER_read(NAL_CONNECTION_get_read(ctx->conn),
					NULL, used) != used) {
		SYS_fprintf(SYS_stderr, "(%d) Read error\n", ctx->id);
		return 0;
	}

write_ping:
	total = NAL_BUFFER_unused(NAL_CONNECTION_get_send(ctx->conn));
	p = NAL_BUFFER_write_ptr(NAL_CONNECTION_get_send(ctx->conn));
	used = 0;
	while((total - used) >= ctx->size) {
		/* Are we already done? */
		if(ctx->num_written == ctx->repeat) break;
		/* Are we supposed to limit lag? */
		if(ctx->num_read + ctx->lag < ctx->num_written) break;
		/* OK, we'll write a chunk */
		ctx->num_written++;
		seed = ctx->num_written + time(NULL);
		seed &= 0xFFFF;
		uint32_write(&p, ctx->num_written);
		uint32_write(&p, seed);
		srand(seed);
		loop = ctx->size - 8;
		base = (int)(65536.0 * rand()/(RAND_MAX+1.0));
		mult = 1 + (int)(65536.0 * rand()/(RAND_MAX+1.0));
		do {
			base *= mult;
			base += mult;
			*(p++) = (base >> 24) ^ (base & 0xFF);
		} while(--loop);
		used += ctx->size;
	}
	if(used)
		NAL_BUFFER_wrote(NAL_CONNECTION_get_send(ctx->conn), used);
	return 1;
}

int main(int argc, char *argv[])
{
	int tmp, ret = 1;
	unsigned int loop, done;
	pingctx **ctx;
	const char *str_addr = DEF_SERVER_ADDRESS;
	unsigned int repeat = DEF_PING_NUM;
	unsigned int size = DEF_CHUNK_SIZE;
	unsigned int lag = DEF_CHUNK_LAG;
	unsigned int num_conns = DEF_NUM_CONNS;
	int quiet = 0;
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
			if(!util_parsenum(*argv, &repeat))
				return 1;
		} else if(strcmp(*argv, "-lag") == 0) {
			ARG_CHECK("-lag");
			if(!util_parsenum(*argv, &lag))
				return 1;
		} else if(strcmp(*argv, "-size") == 0) {
			ARG_CHECK("-size");
			if(!util_parsenum(*argv, &size))
				return 1;
			if(!size || (size < MIN_CHUNK_SIZE) ||
						(size > BUFFER_SIZE)) {
				SYS_fprintf(SYS_stderr, "Error, '%d' is "
					"out of range\n", size);
				return 1;
			}
		} else if(strcmp(*argv, "-quiet") == 0) {
			quiet = 1;
		} else
			return err_unknown(*argv);
		ARG_INC;
	}
	if((ctx = SYS_malloc(pingctx*, num_conns)) == NULL) abort();
	if(!NAL_ADDRESS_create(addr, str_addr, BUFFER_SIZE)) abort();
	for(loop = 0; loop < num_conns; loop++)
		if((ctx[loop] = pingctx_new(addr, sel, loop, repeat,
				size, lag, quiet)) == NULL)
			abort();
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
			if(!pingctx_io(ctx[loop]))
				goto err;
			if(ctx[loop]->done)
				done++;
		}
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
