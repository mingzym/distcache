/* distcache, Distributed Session Caching technology
 * Copyright (C) 2000-2002  Geoff Thorpe, and Cryptographic Appliances, Inc.
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
#include <libnal/common.h>
#include <libnal/nal.h>
#include <libdistcache/dc_enc.h>
#include <libdistcacheserver/dc_server.h>

static const char *def_server = NULL;
static const unsigned int def_sessions = 512;
static const unsigned long def_progress = 0;
#ifndef WIN32
static const char *def_pidfile = NULL;
#endif

#define MAX_SESSIONS		DC_CACHE_MAX_SIZE
#define MAX_PROGRESS		(unsigned long)1000000
#define SERVER_BUFFER_SIZE	4096

/* Prototypes used by main() */
static int do_server(const char *address, unsigned int max_sessions,
			unsigned long progress, int daemon_mode,
			const char *pidfile);

static int usage(void)
{
	NAL_fprintf(NAL_stderr(), "\n"
"Usage: sserver [options]     where 'options' are from;\n"
#ifndef WIN32
"  -daemon          (detach and run in the background)\n"
#endif
"  -listen <addr>   (act as a server listening on address 'addr')\n"
"  -sessions <num>  (make the cache hold a maximum of 'num' sessions)\n"
"  -progress <num>  (report cache progress at least every 'num' operations)\n"
#ifndef WIN32
"  -pidfile <path>  (a file to store the process ID in)\n"
#endif
"  -<h|help|?>      (display this usage message)\n"
"\n"
"Eg. sserver -listen IP:9001\n"
"  will start a session cache server listening on port 9001 for all TCP/IP\n"
"  interfaces.\n"
"\n");
	/* Return 0 because main() can use this is as a help
	 * screen which shouldn't return an "error" */
	return 0;
}
static const char *CMD_HELP1 = "-h";
static const char *CMD_HELP2 = "-help";
static const char *CMD_HELP3 = "-?";
#ifndef WIN32
static const char *CMD_DAEMON = "-daemon";
static const char *CMD_PIDFILE = "-pidfile";
#endif
static const char *CMD_SERVER = "-listen";
static const char *CMD_SESSIONS = "-sessions";
static const char *CMD_PROGRESS = "-progress";

static int err_noarg(const char *arg)
{
	NAL_fprintf(NAL_stderr(), "Error, -%s requires an argument\n", arg);
	usage();
	return 1;
}
static int err_badrange(const char *arg)
{
	NAL_fprintf(NAL_stderr(), "Error, -%s given an invalid argument\n", arg);
	usage();
	return 1;
}
static int err_badswitch(const char *arg)
{
	NAL_fprintf(NAL_stderr(), "Error, \"%s\" not recognised\n", arg);
	usage();
	return 1;
}

/*****************/
/* MAIN FUNCTION */
/*****************/

#define ARG_INC {argc--;argv++;}
#define ARG_CHECK(a) \
	if(argc < 2) \
		return err_noarg(a); \
	ARG_INC

int main(int argc, char *argv[])
{
	int sessions_set = 0;
	/* Overridables */
	unsigned int sessions = 0;
	const char *server = def_server;
	unsigned long progress = def_progress;
#ifndef WIN32
	int daemon_mode = 0;
	const char *pidfile = def_pidfile;
#endif

	ARG_INC;
	while(argc > 0) {
		if((strcmp(*argv, CMD_HELP1) == 0) ||
				(strcmp(*argv, CMD_HELP2) == 0) ||
				(strcmp(*argv, CMD_HELP3) == 0))
			return usage();
#ifndef WIN32
		if(strcmp(*argv, CMD_DAEMON) == 0)
			daemon_mode = 1;
		else if(strcmp(*argv, CMD_PIDFILE) == 0) {
			ARG_CHECK(CMD_PIDFILE);
			pidfile = *argv;
		} else
#endif
		if(strcmp(*argv, CMD_SERVER) == 0) {
			ARG_CHECK(CMD_SERVER);
			server = *argv;
		} else if(strcmp(*argv, CMD_SESSIONS) == 0) {
			ARG_CHECK(CMD_SESSIONS);
			sessions = (unsigned int)atoi(*argv);
			sessions_set = 1;
		} else if(strcmp(*argv, CMD_PROGRESS) == 0) {
			ARG_CHECK(CMD_PROGRESS);
			progress = (unsigned long)atoi(*argv);
			if(progress > MAX_PROGRESS)
				return err_badrange(CMD_PROGRESS);
		} else
			return err_badswitch(*argv);
		ARG_INC;
	}

	/* Scrutinise the settings */
	if(!server) {
		NAL_fprintf(NAL_stderr(), "Error, must provide -listen\n");
		return 1;
	}
	if(!sessions_set)
		sessions = def_sessions;
	if((sessions < 1) || (sessions > MAX_SESSIONS))
		return err_badrange(CMD_SESSIONS);
	if(!NAL_sigpipe_ignore()) {
#if NAL_DEBUG_LEVEL > 0
		NAL_fprintf(NAL_stderr(), "Error, couldn't ignore SIGPIPE\n");
#endif
		return 1;
	}
	return do_server(server, sessions, progress, daemon_mode, pidfile);
}

static int do_server(const char *address, unsigned int max_sessions,
			unsigned long progress, int daemon_mode,
			const char *pidfile)
{
	int res;
	struct timeval now, last_now;
	unsigned int total = 0, tmp_total;
	unsigned long ops = 0, tmp_ops;
	NAL_CONNECTION *conn = NULL;
	NAL_ADDRESS *addr = NAL_ADDRESS_malloc();
	NAL_SELECTOR *sel = NAL_SELECTOR_malloc();
	NAL_LISTENER *listener = NAL_LISTENER_malloc();
	DC_SERVER *server = NULL;

	if(!DC_SERVER_set_default_cache() ||
			((server = DC_SERVER_new(max_sessions)) == NULL) ||
			!addr || !sel || !listener) {
		NAL_fprintf(NAL_stderr(), "Error, malloc/initialisation failure\n");
		goto err;
	}
	if(!NAL_ADDRESS_create(addr, address, SERVER_BUFFER_SIZE) ||
			!NAL_ADDRESS_can_listen(addr) ||
			!NAL_LISTENER_create(listener, addr)) {
		NAL_fprintf(NAL_stderr(), "Error, can't listen on '%s'\n",
				address);
		goto err;
	}
#ifndef WIN32
	/* If we're going daemon() mode, do it now */
	if(daemon_mode) {
		/* working directory becomes "/" */
		/* stdin/stdout/stdout -> /dev/null */
		if(!NAL_daemon(0)) {
			NAL_fprintf(NAL_stderr(), "Error, couldn't detach!\n");
			return 1;
		}
	}
	/* If we're storing our pid, do it now */
	if(pidfile) {
		FILE *fp = fopen(pidfile, "w");
		if(!fp) {
			NAL_fprintf(NAL_stderr(), "Error, couldn't open 'pidfile' "
					"at '%s'.\n", pidfile);
			return 1;
		}
		NAL_fprintf(fp, "%lu", (unsigned long)NAL_getpid());
		fclose(fp);
	}
#endif
	/* Set "last_now" to the current-time */
	NAL_gettime(&last_now);
network_loop:
	if(!conn) {
		conn = NAL_CONNECTION_malloc();
		if(!conn)
			goto err;
	}
	if(!NAL_SELECTOR_add_listener(sel, listener) ||
			!DC_SERVER_clients_to_sel(server, sel)) {
		NAL_fprintf(NAL_stderr(), "Error, selector error\n");
		goto err;
	}
	/* Automatically break every half-second */
	res = NAL_SELECTOR_select(sel, 500000, 1);
	if(res < 0) {
		if(errno == EINTR)
			goto network_loop;
		NAL_fprintf(NAL_stderr(), "Error, select() failed\n");
		goto err;
	}
	/* This entire state-machine logic will operate with one single idea of
	 * "the time". */
	NAL_gettime(&now);
	tmp_ops = DC_SERVER_num_operations(server);
	if(NAL_msecs_between(&last_now, &now) < 1000) {
		/* We try to observe a 1-second noise limit and only violate it
		 * if a "-progress" counter was specified that we've tripped. */
		if(!progress || ((tmp_ops / progress) == (ops / progress)))
			goto skip_totals;
	}
	/* It's at least a second since the last update - so now we check (a) if
	 * the numer of stored sessions has changed, and (b) if the number of
	 * cache operations (divided by 'progress') has increased. If neither,
	 * we don't create any noise. */
	tmp_total = DC_SERVER_items_stored(server, &now);
	if((tmp_total == total) && (!progress ||
			((tmp_ops / progress) == (ops / progress)))) {
		if(res <= 0)
			/* Total hasn't changed, and the select broke without network
			 * activity, just ignore everything and go back. */
			goto network_loop;
		/* The totals haven't changed, and there was network activity */
		goto skip_totals;
	}
	/* Either we tripped the specified "-progress" counter, or it has been
	 * at least 1 second since we last printed something and the number of
	 * cached sessions or number of cache operations has changed. */
	NAL_fprintf(NAL_stdout(), "Info, total operations = % 7lu  (+ % 5u), "
		"total sessions = % 5u  (%c% 3u)\n", tmp_ops, tmp_ops - ops,
		tmp_total, (tmp_total > total ? '+' :
			(tmp_total == total ? '=' : '-')),
		(tmp_total > total ? tmp_total - total : total - tmp_total));
	NAL_timecpy(&last_now, &now);
	total = tmp_total;
	ops = tmp_ops;
skip_totals:
	/* Do I/O first, in case clients are dropped making room for accepts
	 * that would otherwise fail. */
	if(!DC_SERVER_clients_io(server, sel, &now)) {
		NAL_fprintf(NAL_stderr(), "Error, I/O failed\n");
		goto err;
	}
	/* Now handle new connections */
	if(NAL_LISTENER_accept(listener, sel, conn)) {
		/* New client! */
		if(!DC_SERVER_new_client(server, conn,
					DC_CLIENT_FLAG_IN_SERVER))
			NAL_fprintf(NAL_stderr(), "Error, accept couldn't be handled\n");
		else
			/* Mark the connection as consumed */
			conn = NULL;
	}
	goto network_loop;
err:
	if(addr)
		NAL_ADDRESS_free(addr);
	if(sel)
		NAL_SELECTOR_free(sel);
	if(server)
		DC_SERVER_free(server);
	return 1;
}

