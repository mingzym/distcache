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
#define IN_SYS_C

#include <libsys/sys.h>

#ifdef WIN32

/************************************************************************/
/* WIN32 gets no process or signal code, but gets a network initialiser */
/************************************************************************/

int sockets_init(void)
{
	WORD wVersionRequested;
	WSADATA wsaData;

	wVersionRequested = MAKEWORD(2, 2);
	if(WSAStartup(wVersionRequested, &wsaData) != 0)
		return 0;
	return 1;
}

#else

/**************************************/
/* Process model related utility code */
/**************************************/

pid_t SYS_getpid(void)
{
	return getpid();
}

/*
 * SYS_daemon() is a utility function to make the current process a "daemon"
 * such that it detaches from the current termisys and holds the attributes
 * normally associated with daemon processes.
 *
 * The "nochdir" parameter, if zero, changes the current working directory to
 * "/", thereby preventing the daemon process keeping a hold on directories
 * (Where this might be useful is, for example, NFS file systems preventing
 * those machines from unmounting the exported file system.)
 *
 * Returns non-zero for success, zero otherwise.
 */
int SYS_daemon(int nochdir)
{
#ifdef HAVE_DAEMON
       if(daemon(nochdir, 0) == -1)
	       return 0;
       return 1;
#else
       /* The system has no daemon() function, so we have to duplicate
	* the functiosysity.  */
	pid_t pid;

	if ( (pid = fork()) < 0)
		return 0;
	else if (pid != 0)
		exit(0);

	/* At this point we're the child process, and our parent has been
	 * killed off */

	setsid();

	if (!nochdir)
		chdir("/");

	umask(0);

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	return 1;
#endif
}

/*******************************/
/* SIGNAL related utility code */
/*******************************/

int SYS_sigpipe_ignore(void)
{
	struct sigaction sig;

	sig.sa_handler = SIG_IGN;
	sigemptyset(&sig.sa_mask);
	sig.sa_flags = 0;
	if(sigaction(SIGPIPE, &sig, NULL) != 0) {
#if SYS_DEBUG_LEVEL > 0
		SYS_fprintf(SYS_stderr, "Error, couldn't ignore SIGPIPE\n\n");
#endif
		return 0;
	}
	return 1;
}

#endif /* !defined(WIN32) */

/*******************************/
/* Time manipulation functions */
/*******************************/

int SYS_timecmp(const struct timeval *a, const struct timeval *b)
{
	if(a->tv_sec < b->tv_sec)
		return -1;
	else if(a->tv_sec > b->tv_sec)
		return 1;
	if(a->tv_usec < b->tv_usec)
		return -1;
	else if(a->tv_usec > b->tv_usec)
		return 1;
	return 0;
}

void SYS_gettime(struct timeval *tv)
{
#ifdef WIN32
	/* GetSystemTimeAsFileTime seems to be the only capable win32 API call
	 * that (a) has a high-enough resolution (100 nanoseconds in theory),
	 * (b) no sudden 1-hour skews thanks to local time handling, and (c) no
	 * wraparound (GetTickCount() would be better but it wraps after 49
	 * days). */
	FILETIME decimillisecs;
	unsigned __int64 crud;
	GetSystemTimeAsFileTime(&decimillisecs);
	/* FILETIME has 2 32-bit DWORD components, representing the number of
	 * 100-nanosecond intervals since Jan 1, 1601. Convert them to
	 * microseconds first. Then subsitute enough years to ensure 32-bits of
	 * resolution is enough for the seconds components. (We substract
	 * slightly less than 400 years, so we're counting from around mid
	 * 2000). */
	crud = ((unsigned __int64)decimillisecs.dwHighDateTime << 32) +
		(unsigned __int64)decimillisecs.dwLowDateTime;
	crud /= 10;
	/* 12,614,400,000 seconds is slightly less than 400 years */
	crud -= (unsigned __int64)12614400000 * (unsigned __int64)1000000;
	tv->tv_sec = (long)(crud / 1000000);
	tv->tv_usec = (long)(crud % 1000000);
#else
	if(gettimeofday(tv, NULL) != 0)
		/* This should never happen unless tv pointed outside the
		 * accessible address space, so abort() as an alternative
		 * to segfaulting :-) */
		abort();
#endif
}

int SYS_expirycheck(const struct timeval *timeitem, unsigned long msec_expiry,
		const struct timeval *timenow)
{
	struct timeval threshold;
	unsigned long usec_expiry = msec_expiry * 1000;
	SYS_memcpy(struct timeval, &threshold, timeitem);
	threshold.tv_sec = threshold.tv_sec + (usec_expiry / 1000000L);
	threshold.tv_usec += (usec_expiry % 1000000);
	if(threshold.tv_usec > 1000000) {
		threshold.tv_usec -= 1000000;
		threshold.tv_sec++;
	}
	if(timercmp(timenow, &threshold, <))
		/* Not expired yet */
		return 0;
	/* Expired */
	return 1;
}

void SYS_timecpy(struct timeval *dest, const struct timeval *src)
{
	SYS_memcpy(struct timeval, dest, src);
}

void SYS_timeadd(struct timeval *res, const struct timeval *I,
		unsigned long msecs)
{
	unsigned long carry = I->tv_usec + (msecs * 1000);
	res->tv_usec = carry % 1000000;
	carry /= 1000000;
	res->tv_sec = I->tv_sec + carry;
}

void SYS_timesub(struct timeval *res, const struct timeval *I,
		unsigned long msecs)
{
	unsigned long sub_low = (msecs % 1000) * 1000;
	unsigned long sub_high = msecs / 1000;
	if((unsigned long)I->tv_usec < sub_low) {
		sub_high++;
		res->tv_usec = (I->tv_usec + 1000000) - sub_low;
	} else
		res->tv_usec = I->tv_usec - sub_low;
	res->tv_sec = I->tv_sec - sub_high;
}

unsigned long SYS_msecs_between(const struct timeval *a, const struct timeval *b)
{
	unsigned long toret;
	const struct timeval *tmp;

	if(SYS_timecmp(a, b) > 0) {
		tmp = a;
		a = b;
		b = tmp;
	}
	/* Now we now that a <= b */
	toret = (unsigned long)1000000 * (b->tv_sec - a->tv_sec);
	if(b->tv_usec > a->tv_usec)
		toret += b->tv_usec - a->tv_usec;
	else
		toret -= a->tv_usec - b->tv_usec;
	return (toret / 1000);
}

