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

/* To monitor the number of accepted connections, define this */
#define ECHO_DEBUG_CLIENTS

#define DEF_SERVER_ADDRESS	"UNIX:/tmp/foo"
#define BUFFER_SIZE		(32*1024)
#define MAX_CONNS		64

static void usage(void)
{
	SYS_fprintf(SYS_stderr, "Usage:   ECHO [options ...]\n");
	SYS_fprintf(SYS_stderr, "where options include;\n");
	SYS_fprintf(SYS_stderr, "   -accept <addr>    - default='%s'\n", DEF_SERVER_ADDRESS);
	SYS_fprintf(SYS_stderr, "   -max <num>        - default=%d\n", MAX_CONNS);
	SYS_fprintf(SYS_stderr, "   -errinject <num>  - default=<none>\n");
	SYS_fprintf(SYS_stderr, "'errinject' will insert 0xdeadbeef into output every\n");
	SYS_fprintf(SYS_stderr, "<num> times the selector logic breaks\n");
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
reselect:
	tmp = NAL_SELECTOR_select(sel, 0, 0);
	if(tmp <= 0) goto reselect;
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
				NAL_BUFFER_transfer(buf_send, buf_read, 0);
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
