# Process this file with autoconf to produce a configure script.
AC_INIT(distcache, 0.4pre1, distcache-users@lists.sourceforge.net)
#AC_CONFIG_AUX_DIR(config)
AC_CONFIG_SRCDIR(sessserver/server.c)
#AM_CONFIG_HEADER(config/config.h)
AM_CONFIG_HEADER(config.h)

AM_INIT_AUTOMAKE([dist-bzip2 no-define])

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_DISABLE_SHARED
AM_PROG_LIBTOOL

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h netdb.h time.h unistd.h netinet/in.h netinet/tcp.h])
AC_CHECK_HEADERS([sys/socket.h sys/stat.h sys/time.h sys/types.h sys/un.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for system libraries
AC_CHECK_LIB(dl, dlopen)
AC_CHECK_LIB(dld, shl_load)
AC_CHECK_LIB(nsl, gethostent)
AC_CHECK_LIB(socket, socket)

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([gethostbyname gettimeofday memmove memset select socket strstr strtoul])
AC_CHECK_FUNCS([daemon])

# Find out where OpenSSL is
#DISTCACHE_WITH_SSL

AC_CONFIG_FILES([Makefile
		 libdistcache/Makefile
		 libdistcacheserver/Makefile
		 libnal/Makefile
		 sessclient/Makefile
		 sessserver/Makefile
		 snoop/Makefile
		 test/Makefile
		 doc/Makefile
		 include/Makefile
		 include/distcache/Makefile
		 include/libnal/Makefile
		 devel/Makefile])
AC_OUTPUT

