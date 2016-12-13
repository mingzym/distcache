# Process this file with autoconf to produce a configure script.
AC_INIT([distcache],2.0.0,[distcache-users@lists.sourceforge.net])

WANT_AUTOCONF=2.5
WANT_AUTOMAKE=1.8

echo ""
echo "---------------------------------------------"
echo "Configuring Distcache libraries and utilities"
echo "---------------------------------------------"

AC_CONFIG_AUX_DIR([build/aux])
AC_CONFIG_MACRO_DIR([build])

AM_INIT_AUTOMAKE([-Wall -Werror foreign no-installinfo no-installman subdir-objects 1.5.2])

AC_CONFIG_SRCDIR(sessserver/server.c)
AM_CONFIG_HEADER(include/config.h)

# Remove -Werror if it exists
REMOVE_WERROR

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_DISABLE_SHARED
AM_PROG_AR
LT_INIT

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h netdb.h time.h unistd.h pwd.h grp.h limits.h \
		  netinet/in.h netinet/tcp.h \
		  sys/poll.h sys/resource.h sys/socket.h sys/stat.h sys/time.h \
		  sys/types.h sys/un.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for system libraries
AC_CHECK_LIB(dl, dlopen,)
AC_CHECK_LIB(dld, shl_load,)
AC_CHECK_LIB(nsl, gethostent,)
AC_CHECK_LIB(socket, socket,)

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([gethostbyname gettimeofday getrusage memmove memset select \
		socket strstr strtol strtoul daemon getrusage setuid getpwnam \
		getgrnam chown chmod getsockname poll])

# This makes sure "@VERSION@" can be used in Makefile.am's for things like
# pod2man. I've noticed that some versions of autoconf (or automake?) don't
# define this, the following trick seems to fix that.
VERSION=$PACKAGE_VERSION
AC_SUBST(VERSION)

#AX_CHECK_OPENSSL
# Declare all the SSL-related stuff
TOP_LEVEL_SSL

AM_COND_IF([COND_SSL],[
AX_CHECK_OPENSSL
DISTCACHE_WITH_SSL])

# Put -Werror back in if it was wanted
REPLACE_WERROR

AC_CONFIG_FILES([Makefile
		 libdistcache/Makefile
		 libdistcacheserver/Makefile
		 libnal/Makefile
		 libsys/Makefile
		 sessclient/Makefile
		 sessserver/Makefile
		 snoop/Makefile
		 test/Makefile
		 util/Makefile
		 ssl/Makefile
		 ssl/swamp/Makefile
		 ssl/libnalssl/Makefile
		 doc/Makefile
		 include/Makefile
		 include/distcache/Makefile
		 include/libnal/Makefile
		 include/libsys/Makefile
		 devel/Makefile])

AC_OUTPUT

