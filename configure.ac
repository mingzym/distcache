# Process this file with autoconf to produce a configure script.
AC_INIT(distcache, 1.4.5dev, distcache-users@lists.sourceforge.net)

echo ""
echo "---------------------------------------------"
echo "Configuring Distcache libraries and utilities"
echo "---------------------------------------------"

AM_INIT_AUTOMAKE(distcache, 1.4.5dev)

AC_CONFIG_SRCDIR(sessserver/server.c)
AM_CONFIG_HEADER(config.h)

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_DISABLE_SHARED
AM_PROG_LIBTOOL

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h netdb.h time.h unistd.h pwd.h grp.h \
		  netinet/in.h netinet/tcp.h \
		  sys/resource.h sys/socket.h sys/stat.h sys/time.h \
		  sys/types.h sys/un.h])

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
AC_CHECK_FUNCS([gethostbyname gettimeofday memmove memset select socket strstr \
		strtoul daemon getrusage setuid getpwnam getgrnam chown chmod \
		getsockname])

# This makes sure "@VERSION@" can be used in Makefile.am's for things like
# pod2man. I've noticed that some versions of autoconf (or automake?) don't
# define this, the following trick seems to fix that.
VERSION=$PACKAGE_VERSION
AC_SUBST(VERSION)

# Declare all the SSL-related stuff
TOP_LEVEL_SSL

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
		 doc/Makefile
		 include/Makefile
		 include/distcache/Makefile
		 include/libnal/Makefile
		 include/libsys/Makefile
		 devel/Makefile])

AC_OUTPUT

