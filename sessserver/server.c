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
#include <distcache/dc_server.h>
#include <distcache/dc_plug.h>
#include <distcache/dc_internal.h>
#include <libsys/post.h>

static const char *def_server = NULL;
static const unsigned int def_sessions = 512;
static const unsigned long def_progress = 0;
#ifndef WIN32
static const char *def_pidfile = NULL;
static const char *def_user = NULL;
static const char *def_sockowner = NULL;
static const char *def_sockgroup = NULL;
static const char *def_sockperms = NULL;
#endif

/* Avoid the dreaded "greater than the length `509' ISO C89 compilers are
 * required to support" warning by splitting this into an array of strings. */
static const char *usage_msg[] = {
"",
"Usage: dc_server [options]     where 'options' are from;",
#ifndef WIN32
"  -daemon           (detach and run in the background)",
#endif
"  -listen <addr>    (act as a server listening on address 'addr')",
"  -sessions <num>   (make the cache hold a maximum of 'num' sessions)",
"  -progress <num>   (report cache progress at least every 'num' operations)",
#ifndef WIN32
"  -user <user>      (run daemon as given user)",
"  -sockowner <user> (controls ownership of unix domain listening socket)",
"  -sockgroup <user> (controls ownership of unix domain listening socket)",
"  -sockperms <oct>  (set permissions of unix domain listening socket)",
"  -pidfile <path>   (a file to store the process ID in)",
"  -killable         (exit cleanly on a SIGUSR1 or SIGUSR2 signal)",
#endif
"  -<h|help|?>       (display this usage message)",
"\n",
"Eg. dc_server -listen IP:9001",
"  will start a session cache server listening on port 9001 for all TCP/IP",
"  interfaces.",
"", NULL};

#define MAX_SESSIONS		DC_CACHE_MAX_SIZE
#define MAX_PROGRESS		(unsigned long)1000000
#define SERVER_BUFFER_SIZE	4096

/* Prototypes used by main() */
static int do_server(const char *address, unsigned int max_sessions,
			unsigned long progress, int daemon_mode,
			const char *pidfile, int killable, const char *user,
			const char *sockowner, const char *sockgroup,
			const char *sockperms);

static int usage(void)
{
	const char **u = usage_msg;
	while(*u)
		SYS_fprintf(SYS_stderr, "%s\n", *(u++));
	/* Return 0 because main() can use this is as a help
	 * screen which shouldn't return an "error" */
	return 0;
}
static const char *CMD_HELP1 = "-h";
static const char *CMD_HELP2 = "-help";
static const char *CMD_HELP3 = "-?";
#ifndef WIN32
static const char *CMD_DAEMON = "-daemon";
static const char *CMD_USER = "-user";
static const char *CMD_SOCKOWNER = "-sockowner";
static const char *CMD_SOCKGROUP = "-sockgroup";
static const char *CMD_SOCKPERMS = "-sockperms";
static const char *CMD_PIDFILE = "-pidfile";
static const char *CMD_KILLABLE = "-killable";
#endif
static const char *CMD_SERVER = "-listen";
static const char *CMD_SESSIONS = "-sessions";
static const char *CMD_PROGRESS = "-progress";

static int err_noarg(const char *arg)
{
	SYS_fprintf(SYS_stderr, "Error, -%s requires an argument\n", arg);
	usage();
	return 1;
}
static int err_badrange(const char *arg)
{
	SYS_fprintf(SYS_stderr, "Error, -%s given an invalid argument\n", arg);
	usage();
	return 1;
}
static int err_badswitch(const char *arg)
{
	SYS_fprintf(SYS_stderr, "Error, \"%s\" not recognised\n", arg);
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

/* Used to spot if we have recieved SIGUSR1 or SIGUSR2 */
static int got_signal = 0;

int main(int argc, char *argv[])
{
	int sessions_set = 0;
	/* Overridables */
	unsigned int sessions = 0;
	const char *server = def_server;
	unsigned long progress = def_progress;
#ifndef WIN32
	int daemon_mode = 0;
	int killable = 0;
	const char *pidfile = def_pidfile;
	const char *user = def_user;
	const char *sockowner = def_sockowner;
	const char *sockgroup = def_sockgroup;
	const char *sockperms = def_sockperms;
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
		else if(strcmp(*argv, CMD_KILLABLE) == 0) {
			killable = 1;
		} else if(strcmp(*argv, CMD_PIDFILE) == 0) {
			ARG_CHECK(CMD_PIDFILE);
			pidfile = *argv;
		} else if(strcmp(*argv, CMD_USER) == 0) {
			ARG_CHECK(CMD_USER);
			user = *argv;
		} else if(strcmp(*argv, CMD_SOCKOWNER) == 0) {
			ARG_CHECK(CMD_SOCKOWNER);
			sockowner = *argv;
		} else if(strcmp(*argv, CMD_SOCKGROUP) == 0) {
			ARG_CHECK(CMD_SOCKGROUP);
			sockgroup = *argv;
		} else if(strcmp(*argv, CMD_SOCKPERMS) == 0) {
			ARG_CHECK(CMD_SOCKPERMS);
			sockperms = *argv;
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
		SYS_fprintf(SYS_stderr, "Error, must provide -listen\n");
		return 1;
	}
	if(!sessions_set)
		sessions = def_sessions;
	if((sessions < 1) || (sessions > MAX_SESSIONS))
		return err_badrange(CMD_SESSIONS);
	if(!SYS_sigpipe_ignore()) {
#if SYS_DEBUG_LEVEL > 0
		SYS_fprintf(SYS_stderr, "Error, couldn't ignore SIGPIPE\n");
#endif
		return 1;
	}
	if(!SYS_sigusr_interrupt(&got_signal)) {
#if SYS_DEBUG_LEVEL > 0
		SYS_fprintf(SYS_stderr, "Error, couldn't ignore SIGUSR[1|2]\n");
#endif
		return 1;
	}
	return do_server(server, sessions, progress, daemon_mode, pidfile,
			killable, user, sockowner, sockgroup, sockperms);
}

static int do_server(const char *address, unsigned int max_sessions,
			unsigned long progress, int daemon_mode,
			const char *pidfile, int killable, const char *user,
			const char *sockowner, const char *sockgroup,
			const char *sockperms)
{
	int res, ret = 1;
	struct timeval now, last_now;
	unsigned int total = 0, tmp_total;
	unsigned long ops = 0, tmp_ops;
	NAL_CONNECTION *conn = NULL;
	NAL_ADDRESS *addr = NAL_ADDRESS_new();
	NAL_SELECTOR *sel = NAL_SELECTOR_new();
	NAL_LISTENER *listener = NAL_LISTENER_new();
	DC_SERVER *server = NULL;

	if(!DC_SERVER_set_default_cache() ||
			((server = DC_SERVER_new(max_sessions)) == NULL) ||
			!addr || !sel || !listener) {
		SYS_fprintf(SYS_stderr, "Error, malloc/initialisation failure\n");
		goto err;
	}
	if(!NAL_ADDRESS_create(addr, address, SERVER_BUFFER_SIZE) ||
			!NAL_ADDRESS_can_listen(addr) ||
			!NAL_LISTENER_create(listener, addr)) {
		SYS_fprintf(SYS_stderr, "Error, can't listen on '%s'\n",
				address);
		goto err;
	}
#ifndef WIN32
	if((sockowner || sockgroup) && !NAL_LISTENER_set_fs_owner(listener,
						sockowner, sockgroup))
		SYS_fprintf(SYS_stderr, "Warning, can't set socket ownership "
			"to user '%s' and group '%s', continuing anyway\n",
			sockowner ? sockowner : "(null)",
			sockgroup ? sockgroup : "(null)");
	if(sockperms && !NAL_LISTENER_set_fs_perms(listener, sockperms))
		SYS_fprintf(SYS_stderr, "Warning, can't set socket permissions "
				"to '%s', continuing anyway\n", sockperms);
	/* If we're going daemon() mode, do it now */
	if(daemon_mode) {
		/* working directory becomes "/" */
		/* stdin/stdout/stderr -> /dev/null */
		if(!SYS_daemon(0)) {
			SYS_fprintf(SYS_stderr, "Error, couldn't detach!\n");
			return 1;
		}
	}
	/* If we're storing our pid, do it now */
	if(pidfile) {
		FILE *fp = fopen(pidfile, "w");
		if(!fp) {
			SYS_fprintf(SYS_stderr, "Error, couldn't open 'pidfile' "
					"at '%s'.\n", pidfile);
			return 1;
		}
		SYS_fprintf(fp, "%lu", (unsigned long)SYS_getpid());
		fclose(fp);
	}
	if(user) {
		if(!SYS_setuid(user)) {
			SYS_fprintf(SYS_stderr, "Error, couldn't become user "
				    "'%s'.\n", user);
			return 1;
		}
	}
#endif
	/* Set "last_now" to the current-time */
	SYS_gettime(&last_now);
network_loop:
	if(NAL_LISTENER_finished(listener)) {
		if(DC_SERVER_clients_empty(server)) {
			/* Clean shutdown */
			ret = 0;
			goto err;
		}
	} else {
		if(!conn) {
			conn = NAL_CONNECTION_new();
			if(!conn)
				goto err;
		}
		NAL_LISTENER_add_to_selector(listener, sel);
	}
	if(!DC_SERVER_clients_to_sel(server, sel)) {
		SYS_fprintf(SYS_stderr, "Error, selector error\n");
		goto err;
	}
	/* Automatically break every half-second. NB: we skip the select if
	 * SIGUSR1 or SIGUSR2 has arrived to improve the chances we don't
	 * needlessly wait half a second before closing down. Of course,
	 * there's still a race condition whereby we might go into the select
	 * anyway but after the signal has been handled, but the chances are
	 * much greater that the signal arrives in the logical processing above
	 * or the select itself. Anyway, this is to make administration more
	 * responsive, not to seal off any theoretical possibility of a delay
	 * in the shutdown. */
	if(!killable || !got_signal)
		res = NAL_SELECTOR_select(sel, 500000, 1);
	else
		res = -1;
	if(res < 0) {
		if(!killable)
			goto network_loop;
		if(got_signal)
			/* We're killable and the negative return is because of
			 * a signal interruption, in this case we return
			 * main()'s version of "success". */
			ret = 0;
		else if(errno == EINTR) {
			SYS_fprintf(SYS_stderr, "Error, select interrupted for unknown "
					"signal, continuing\n");
			goto network_loop;
		} else
			SYS_fprintf(SYS_stderr, "Error, select() failed\n");
		goto err;
	}
	/* This entire state-machine logic will operate with one single idea of
	 * "the time". */
	SYS_gettime(&now);
	tmp_ops = DC_SERVER_num_operations(server);
	if(SYS_msecs_between(&last_now, &now) < 1000) {
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
	SYS_fprintf(SYS_stderr, "Info, total operations = %7lu  (+ %5lu), "
		"total sessions = %5u  (%c%3u)\n", tmp_ops, tmp_ops - ops,
		tmp_total, (tmp_total > total ? '+' :
			(tmp_total == total ? '=' : '-')),
		(tmp_total > total ? tmp_total - total : total - tmp_total));
	SYS_timecpy(&last_now, &now);
	total = tmp_total;
	ops = tmp_ops;
skip_totals:
	/* Do I/O first, in case clients are dropped making room for accepts
	 * that would otherwise fail. */
	if(!DC_SERVER_clients_io(server, sel, &now)) {
		SYS_fprintf(SYS_stderr, "Error, I/O failed\n");
		goto err;
	}
	/* Now handle new connections */
	if(!NAL_LISTENER_finished(listener) && NAL_CONNECTION_accept(conn,
							listener, sel)) {
		/* New client! */
		if(!DC_SERVER_new_client(server, conn,
					DC_CLIENT_FLAG_IN_SERVER))
			SYS_fprintf(SYS_stderr, "Error, accept couldn't be handled\n");
		else
			/* Mark the connection as consumed */
			conn = NULL;
	}
	goto network_loop;
err:
	if(addr) NAL_ADDRESS_free(addr);
	if(sel) NAL_SELECTOR_free(sel);
	if(conn) NAL_CONNECTION_free(conn);
	if(listener) NAL_LISTENER_free(listener);
	if(server)
		DC_SERVER_free(server);
	return killable;
}

