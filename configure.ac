# Process this file with autoconf to produce a configure script.
AC_INIT(distcache, 0.1, distcache-users@lists.sourceforge.net)
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_SRCDIR(sessserver/server.c)
AM_CONFIG_HEADER(config/config.h)

AM_INIT_AUTOMAKE

# Make sure the top-level directory is available as an include path
TOP_DIR=`pwd`
CFLAGS="$CFLAGS -I$TOP_DIR"

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_DISABLE_SHARED
AM_PROG_LIBTOOL

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([assert.h errno.h fcntl.h netdb.h signal.h stdarg.h])
AC_CHECK_HEADERS([stdio.h stdlib.h string.h unistd.h])
AC_CHECK_HEADERS([netinet/in.h netinet/tcp.h])
AC_CHECK_HEADERS([sys/socket.h sys/stat.h sys/time.h sys/types.h sys/un.h sys/wait.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([gethostbyname gettimeofday memmove memset select socket strstr strtoul])

AC_CHECK_LIB(dl, dlopen)
AC_CHECK_LIB(nsl, gethostent)
AC_CHECK_LIB(socket, socket)

# Find out where OpenSSL is
DISTCACHE_WITH_SSL

AC_CONFIG_FILES([Makefile
		 libdistcache/Makefile
		 libdistcacheserver/Makefile
		 libnal/Makefile
		 sessclient/Makefile
		 sessserver/Makefile
		 test/Makefile])
AC_OUTPUT
