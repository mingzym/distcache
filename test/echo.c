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

typedef enum {
	UNITS_BYTES,
	UNITS_KILO,
	UNITS_MEGA,
	UNITS_GIGA
} UNITS;
static const char *UNITS_str[] = {
	"bits", "kbits", "Mbits", "Gbits" };

#define UNITS2STR(u)		UNITS_str[(u)]

#define DEF_SERVER_ADDRESS	"UNIX:/tmp/foo"
#define BUFFER_SIZE		(32*1024)
#define MAX_CONNS		64
#define DEF_UNITS		UNITS_BYTES

/* Only support "-update" if we have the goodies */
#if defined(HAVE_GETTIMEOFDAY) && defined(HAVE_GETRUSAGE)
#define SUPPORT_UPDATE
#endif

static void usage(void)
{
	SYS_fprintf(SYS_stderr, "Usage:   ECHO [options ...]\n");
	SYS_fprintf(SYS_stderr, "where options include;\n");
	SYS_fprintf(SYS_stderr, "   -accept <addr>    - default='%s'\n", DEF_SERVER_ADDRESS);
	SYS_fprintf(SYS_stderr, "   -max <num>        - default=%d\n", MAX_CONNS);
	SYS_fprintf(SYS_stderr, "   -errinject <num>  - default=<none>\n");
#ifdef SUPPORT_UPDATE
	SYS_fprintf(SYS_stderr, "   -update <secs>    - default=<none>\n");
	SYS_fprintf(SYS_stderr, "   -units <b,k,m,g>  - default='%s'\n", UNITS2STR(DEF_UNITS));
	SYS_fprintf(SYS_stderr, "'units' displays traffic rates as bits, kilobits,\n");
	SYS_fprintf(SYS_stderr, "megabits, or gigabits per second.\n");
#endif
	SYS_fprintf(SYS_stderr, "'errinject' will insert 0xdeadbeef into output every\n");
	SYS_fprintf(SYS_stderr, "<num> times the selector logic breaks.\n");
}

#ifdef SUPPORT_UPDATE
static int util_parseunits(const char *s, UNITS *u)
{
	if(strlen(s) != 1) goto err;
	switch(*s) {
	case 'b': *u = UNITS_BYTES; break;
	case 'k': *u = UNITS_KILO; break;
	case 'm': *u = UNITS_MEGA; break;
	case 'g': *u = UNITS_GIGA; break;
	default: goto err;
	}
	return 1;
err:
	SYS_fprintf(SYS_stderr, "Error, bad unit '%s'\n", s);
	return 0;
}
#endif

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

int main(int argc, char *argv[])
{
	int tmp;
	unsigned int loop = 0;
	unsigned conns_used = 0;
	NAL_CONNECTION *conn[MAX_CONNS];
	const char *str_addr = DEF_SERVER_ADDRESS;
	unsigned int num_conns = MAX_CONNS;
	unsigned int errinject = 0;
	NAL_ADDRESS *addr;
	NAL_LISTENER *listener;
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
		} else if(strcmp(*argv, "-errinject") == 0) {
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
"each direction to be half the advertised value.\n"
"\n");
#endif
	}
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
		rate = 2000.0 * traffic / (double)msecs;
		switch(units) {
		case UNITS_GIGA: rate /= 1024;
		case UNITS_MEGA: rate /= 1024;
		case UNITS_KILO: rate /= 1024;
		case UNITS_BYTES: break;
		default: abort(); /* bug */
		}
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
				if(++inject == errinject) {
					NAL_BUFFER_write(buf_send, deadbeef,
						sizeof(deadbeef));
					inject = 0;
				}
				traffic += NAL_BUFFER_transfer(buf_send, buf_read, 0);
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
