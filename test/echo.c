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

/* TODO:
 *   The use of the "traffic" variable in the main loop is a hack. This is not
 *   really how much data that has been exchanged over the socket, nor even the
 *   amount exchanged over the user/kernel boundary, but the amount
 *   read/written into the NAL_CONNECTION buffers. Over time, this averages out
 *   anyway, but it'd be better to support logging inside the NAL_CONNECTION
 *   type itself and expose this instead.
 */

/* To monitor the number of accepted connections, define this */
#define ECHO_DEBUG_CLIENTS

#define DEF_SERVER_ADDRESS	"UNIX:/tmp/foo"
#define BUFFER_SIZE		(32*1024)
#define MAX_CONNS		512
#define DEF_UNITS		UNITS_bits

#ifdef SUPPORT_UPDATE
IMPLEMENT_UNITS()
#endif

static void usage(void)
{
	SYS_fprintf(SYS_stderr,
"Usage:   nal_echo [options ...]\n"
"where options include;\n"
"   -accept <addr>      - default='%s'\n"
"   -max <num>          - default=%d\n"
"   -errinject <num>    - default=<none>\n"
"   -dump\n", DEF_SERVER_ADDRESS, MAX_CONNS);
#ifdef SUPPORT_UPDATE
	SYS_fprintf(SYS_stderr,
"   -update <secs>      - default=<none>\n"
"   -units [k|m|g]<b|B> - default='%s'\n"
"'units' displays traffic rates as bits or bytes per second.\n"
"An optional prefix can scale to kilo, mega, or giga bits/bytes.\n",
UNITS2STR(DEF_UNITS));
#endif
	SYS_fprintf(SYS_stderr,
"'errinject' will insert 0xdeadbeef into output every\n"
"<num> times the selector logic breaks.\n");
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

/* helper wrapper for NAL_BUFFER_transfer() */
static unsigned int my_transfer(NAL_BUFFER *dest, NAL_BUFFER *src, int dump);

int main(int argc, char *argv[])
{
	int tmp;
	unsigned int loop = 0;
	unsigned conns_used = 0;
	NAL_CONNECTION *conn[MAX_CONNS];
	const char *str_addr = DEF_SERVER_ADDRESS;
	unsigned int num_conns = MAX_CONNS;
	unsigned int errinject = 0;
	int dump = 0;
	NAL_ADDRESS *addr;
	NAL_LISTENER *listener;
	NAL_SELECTOR *sel;
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
		if(strcmp(*argv, "-accept") == 0) {
			ARG_CHECK("-accept");
			str_addr = *argv;
		} else if(strcmp(*argv, "-max") == 0) {
			ARG_CHECK("-max");
			if(!util_parsenum(*argv, &num_conns))
				return 1;
			if(!num_conns || (num_conns > MAX_CONNS)) {
				SYS_fprintf(SYS_stderr, "Error, '%d' is out of bounds "
					"for -max\n", num_conns);
				return 1;
			}
		} else if(strcmp(*argv, "-dump") == 0)
			dump = 1;
		else if(strcmp(*argv, "-errinject") == 0) {
			ARG_CHECK("-errinject");
			if(!util_parsenum(*argv, &errinject))
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
		} else
			return err_unknown(*argv);
		ARG_INC;
	}
	SYS_sigpipe_ignore();
	addr = NAL_ADDRESS_new();
	listener = NAL_LISTENER_new();
	sel = NAL_SELECTOR_new();
	if(!addr || !listener || !sel) abort();
	while(loop < num_conns)
		if((conn[loop++] = NAL_CONNECTION_new()) == NULL)
			abort();
	if(!NAL_ADDRESS_create(addr, str_addr, BUFFER_SIZE)) abort();
	if(!NAL_LISTENER_create(listener, addr)) abort();
	if(!NAL_LISTENER_add_to_selector(listener, sel)) abort();
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
"each direction to be half the advertised throughput value.\n"
"\n");
	}
#endif
reselect:
	tmp = NAL_SELECTOR_select(sel, 0, 0);
	if(tmp <= 0) {
		SYS_fprintf(SYS_stderr, "Error, NAL_SELECTOR_select() returned 0\n");
		return 1;
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
	while((conns_used < num_conns) && NAL_CONNECTION_accept(conn[conns_used],
						listener)) {
		if(!NAL_CONNECTION_add_to_selector(conn[conns_used], sel))
			abort();
		conns_used++;
#ifdef ECHO_DEBUG_CLIENTS
		SYS_fprintf(SYS_stderr, "ECHO: added a conn (now have %d)\n",
			conns_used);
#endif
		if(conns_used == num_conns)
			NAL_LISTENER_del_from_selector(listener);
	}
	for(loop = 0; loop < conns_used; ) {
		if(!NAL_CONNECTION_io(conn[loop])) {
			NAL_CONNECTION_reset(conn[loop]);
			conns_used--;
#ifdef ECHO_DEBUG_CLIENTS
			SYS_fprintf(SYS_stderr, "ECHO: removed a conn (now have %d)\n",
				conns_used);
#endif
			if((conns_used + 1) == num_conns)
				if(!NAL_LISTENER_add_to_selector(listener, sel))
					abort();
			if(loop < conns_used) {
				NAL_CONNECTION *ptmp = conn[loop];
				conn[loop] = conn[conns_used];
				conn[conns_used] = ptmp;
			}
		} else {
			static unsigned int inject = 0;
			static const unsigned char deadbeef[] =
				{ 0xde, 0xad, 0xbe, 0xef };
			NAL_BUFFER *buf_send = NAL_CONNECTION_get_send(conn[loop]);
			NAL_BUFFER *buf_read = NAL_CONNECTION_get_read(conn[loop]);
			/* To ensure error injections work, don't allow
			 * injections *OR* transfers unless there's at least 4
			 * bytes available. */
			if(NAL_BUFFER_unused(buf_send) >= sizeof(deadbeef)) {
				if(errinject && (++inject == errinject)) {
					NAL_BUFFER_write(buf_send, deadbeef,
						sizeof(deadbeef));
					inject = 0;
				}
				traffic += my_transfer(buf_send, buf_read, dump);
			}
			loop++;
		}
	}
	if(NAL_LISTENER_finished(listener)) {
		NAL_LISTENER_del_from_selector(listener);
		if(!conns_used)
			/* Clients are all gone too */
			return 0;
	}
	goto reselect;
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

static unsigned int my_transfer(NAL_BUFFER *dest, NAL_BUFFER *src, int dump)
{
	const unsigned char *sptr;
	unsigned int len;
	if(!dump) return NAL_BUFFER_transfer(dest, src, 0);
	/* ... otherwise, we implement our own for debugging ... */
	len = NAL_BUFFER_used(src);
	if(len > NAL_BUFFER_unused(dest)) len = NAL_BUFFER_unused(dest);
	if(!len) return 0;
	sptr = NAL_BUFFER_data(src);
	SYS_fprintf(SYS_stderr, "transferring data (%d bytes):\n", len);
	bindump(sptr, len);
	if((NAL_BUFFER_write(dest, sptr, len) != len) ||
			(NAL_BUFFER_read(src, NULL, len) != len)) {
		SYS_fprintf(SYS_stderr, "Error, internal bug!\n");
		abort();
	}
	return len;
}

