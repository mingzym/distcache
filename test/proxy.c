/* distcache, Distributed Session Caching technology
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

#define MAX_PAIRS		10
#define MAX_CONNS		512
#define BUFFER_SIZE		(16*1024)
#define DEF_UNITS		UNITS_bits

#ifdef SUPPORT_UPDATE
IMPLEMENT_UNITS()
#endif

static void usage(void)
{
	SYS_fprintf(SYS_stderr,
"Usage:   nal_proxy [options ...]\n"
"where options include;\n"
"   -pair <addr1> <addr2>\n");
#ifdef SUPPORT_UPDATE
	SYS_fprintf(SYS_stderr,
"   -update <secs>      - default=<none>\n"
"   -units [k|m|g]<b|B> - default='%s'\n", UNITS2STR(DEF_UNITS));
#endif
#ifdef SUPPORT_UPDATE
	SYS_fprintf(SYS_stderr,
"'units' displays traffic rates as bits or bytes per second.\n"
"An optional prefix can scale to kilo, mega, or giga bits/bytes.\n");
#endif
}

/*******************/
/* Interface pairs */
/*******************/

typedef struct st_pair_t {
	/* cmd-line parameters */
	const char *addr1, *addr2;
	/* addresses */
	NAL_ADDRESS *addr_listener, *addr_connection;
	/* listening interface */
	NAL_LISTENER *listener;
} pair_t;

static pair_t		pairs[MAX_PAIRS];
static unsigned int	pairs_used = 0, pairs_cursor = 0;

static void pairs_destroy(void)
{
	unsigned int loop = 0;
	pair_t *item = pairs;
	while(loop++ < pairs_used) {
		NAL_LISTENER_free(item->listener);
		NAL_ADDRESS_free(item->addr_listener);
		NAL_ADDRESS_free(item->addr_connection);
		item++;
	}
	pairs_used = pairs_cursor = 0;
}

static int util_parsepair(const char *p1, const char *p2)
{
	NAL_ADDRESS *addr1, *addr2;
	if(pairs_used >= MAX_PAIRS) {
		SYS_fprintf(SYS_stderr, "Error, too many interface pairs\n");
		return 0;
	}
	addr1 = NAL_ADDRESS_new();
	addr2 = NAL_ADDRESS_new();
	if(!addr1 || !addr2) abort();
	if(!NAL_ADDRESS_create(addr1, p1, BUFFER_SIZE) ||
			!NAL_ADDRESS_can_listen(addr1)) {
		SYS_fprintf(SYS_stderr, "Error, '%s' is an invalid addres\n", p1);
		return 0;
	}
	if(!NAL_ADDRESS_create(addr2, p2, BUFFER_SIZE) ||
			!NAL_ADDRESS_can_connect(addr2)) {
		SYS_fprintf(SYS_stderr, "Error, '%s' is an invalid addres\n", p2);
		return 0;
	}
	pairs[pairs_used].addr1 = p1;
	pairs[pairs_used].addr2 = p2;
	pairs[pairs_used].addr_listener = addr1;
	pairs[pairs_used].addr_connection = addr2;
	pairs[pairs_used].listener = NULL;
	SYS_fprintf(SYS_stderr, "Parsed pair %d: %s -> %s\n", pairs_used, p1, p2);
	pairs_used++;
	return 1;
}

static int util_startpairs(NAL_SELECTOR *sel)
{
	unsigned int foo = 0;
	while(foo < pairs_used) {
		if((pairs[foo].listener = NAL_LISTENER_new()) == NULL) abort();
		if(!NAL_LISTENER_create(pairs[foo].listener,
					pairs[foo].addr_listener) ||
				!NAL_LISTENER_add_to_selector(pairs[foo].listener, sel)) {
			SYS_fprintf(SYS_stderr, "Error, can't listen on %s\n",
					pairs[foo].addr1);
			return 0;
		}
		foo++;
	}
	return 1;
}

/******************************/
/* Connection pairs (tunnels) */
/******************************/

typedef struct st_tunnel_t {
	NAL_CONNECTION *conn1, *conn2;
	int use1, use2;
	int dead1, dead2;
	unsigned int pair;
} tunnel_t;

static tunnel_t		conns[MAX_CONNS];
static unsigned int	conns_used = 0;

static void conns_destroy(void)
{
	unsigned int loop = 0;
	tunnel_t *item = conns;
	while(loop++ < conns_used) {
		NAL_CONNECTION_free(item->conn1);
		NAL_CONNECTION_free(item->conn2);
		item++;
	}
	conns_used = 0;
}

static int conns_accept(NAL_CONNECTION *conn, NAL_SELECTOR *sel)
{
	unsigned int loop = 0;
	if(conns_used == MAX_CONNS) return 0;
	while(loop++ < pairs_used) {
		int tmp = pairs_cursor;
		pair_t *item = pairs + tmp;
		if(++pairs_cursor == pairs_used) pairs_cursor = 0;
		if(NAL_CONNECTION_accept(conn, item->listener)) {
			if(!NAL_CONNECTION_add_to_selector(conn, sel)) abort();
			conns[conns_used].conn1 = conn;
			if((conns[conns_used].conn2 = NAL_CONNECTION_new()) == NULL) abort();
			if(!NAL_CONNECTION_create(conns[conns_used].conn2,
					item->addr_connection)) abort();
			if(!NAL_CONNECTION_add_to_selector(conns[conns_used].conn2, sel)) abort();
			conns[conns_used].use1 = 0;
			conns[conns_used].use2 = 0;
			conns[conns_used].dead1 = 0;
			conns[conns_used].dead2 = 0;
			conns[conns_used].pair = tmp;
			conns_used++;
			SYS_fprintf(SYS_stderr, "Adding a tunnel -> total %d "
				"(from pair %d)\n", conns_used, tmp);
			return 1;
		}
	}
	return 0;
}

static unsigned int conns_io(NAL_SELECTOR *sel)
{
	unsigned int total = 0;
	unsigned int foo = 0;
	tunnel_t *item = conns;
	while(foo < conns_used) {
		if(!item->dead1 && !NAL_CONNECTION_io(item->conn1))
			item->dead1 = 1;
		if(!item->dead2 && !NAL_CONNECTION_io(item->conn2))
			item->dead2 = 1;
		if(item->dead1) {
			/* Check if conn2 has flushed */
			if(!item->dead2 && NAL_BUFFER_empty(
					NAL_CONNECTION_get_send(item->conn2)))
				item->dead2 = 1;
		} else if(item->dead2) {
			/* Check if conn1 has flushed */
			if(!item->dead1 && NAL_BUFFER_empty(
					NAL_CONNECTION_get_send(item->conn1)))
				item->dead1 = 1;
		} else {
			unsigned int tmp;
			/* Both are up, try forwarding */
			if(item->use1 && NAL_BUFFER_empty(
					NAL_CONNECTION_get_send(item->conn1)))
				item->use1 = 0;
			if(item->use2 && NAL_BUFFER_empty(
					NAL_CONNECTION_get_send(item->conn2)))
				item->use2 = 0;
			if(!item->use1 && NAL_BUFFER_notempty(
						NAL_CONNECTION_get_read(item->conn2)) &&
					(tmp = NAL_BUFFER_transfer(
						NAL_CONNECTION_get_send(item->conn1),
						NAL_CONNECTION_get_read(item->conn2), 0))) {
				item->use1 = 1;
				total += tmp;
			}
			if(!item->use2 && NAL_BUFFER_notempty(
						NAL_CONNECTION_get_read(item->conn1)) &&
					(tmp = NAL_BUFFER_transfer(
						NAL_CONNECTION_get_send(item->conn2),
						NAL_CONNECTION_get_read(item->conn1), 0))) {
				item->use2 = 1;
				total += tmp;
			}
		}
		if(item->dead1 && item->dead2) {
			/* Remove */
			NAL_CONNECTION_free(item->conn1);
			NAL_CONNECTION_free(item->conn2);
			if(foo < conns_used--)
				SYS_memcpy_n(tunnel_t, item, item + 1, conns_used - foo);
			SYS_fprintf(SYS_stderr, "Dropping a tunnel -> total %d "
				"(from pair %d)\n", conns_used, item->pair);
		} else {
			/* Move on */
			foo++;
			item++;
		}
	}
	return total;
}

/****************/
/* main() stuff */
/****************/

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
	int ret = 1;
	NAL_SELECTOR *sel;
	NAL_CONNECTION *conn = NULL;
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
		if(strcmp(*argv, "-pair") == 0) {
			const char *pair1, *pair2;
			ARG_CHECK("-pair");
			pair1 = *argv;
			ARG_CHECK("-pair");
			pair2 = *argv;
			if(!util_parsepair(pair1, pair2))
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
	if(!pairs_used) {
		SYS_fprintf(SYS_stderr, "Error, you must specify at least one pair\n");
		return 1;
	}
	SYS_sigpipe_ignore();
	sel = NAL_SELECTOR_new();
	if(!sel) abort();
	if(!util_startpairs(sel)) abort();

#ifdef SUPPORT_UPDATE
	if(update) {
		tt1 = time(NULL);
		SYS_gettime(&tv1);
		getrusage(RUSAGE_SELF, &ru1);
	}
#endif
	do {
		int tmp;
		/* Select */
		if((tmp = NAL_SELECTOR_select(sel, 0, 0)) <= 0) {
			SYS_fprintf(SYS_stderr, "Error, NAL_SELECTOR_select() "
				"returned <= 0\n");
			goto err;
		}
		/* Post-process */
#ifdef SUPPORT_UPDATE
		traffic += conns_io(sel);
#else
		conns_io(sel);
#endif
		if(!conn && ((conn = NAL_CONNECTION_new()) == NULL)) goto err;
		if(conns_accept(conn, sel))
			conn = NULL;
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
	} while(NAL_SELECTOR_num_objects(sel));
	/* Done */
	ret = 0;
err:
	conns_destroy();
	pairs_destroy();
	NAL_SELECTOR_free(sel);
	if(conn) NAL_CONNECTION_free(conn);
	return ret;
}
