AC_INIT(distcache-ssl, 1.4.4dev, distcache-users@lists.sourceforge.net)

echo ""
echo "------------------------------------"
echo "Configuring SSL/TLS-specific targets"
echo "------------------------------------"

AM_INIT_AUTOMAKE(distcache-ssl, 1.4.4dev)

AC_CONFIG_SRCDIR(swamp/swamp.c)
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
AC_CHECK_HEADERS([fcntl.h netdb.h time.h unistd.h netinet/in.h netinet/tcp.h \
		  sys/socket.h sys/stat.h sys/time.h sys/types.h sys/un.h])

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
AC_CHECK_FUNCS([gethostbyname gettimeofday memmove memset select socket strstr strtoul \
		daemon strtol strdup])

# Declare all the SSL-related stuff
DISTCACHE_WITH_SSL

# This makes sure "@VERSION@" can be used in Makefile.am's for things like
# pod2man. I've noticed that some versions of autoconf (or automake?) don't
# define this, the following trick seems to fix that.
VERSION=$PACKAGE_VERSION
AC_SUBST(VERSION)

AC_CONFIG_FILES([Makefile
		 swamp/Makefile])
AC_OUTPUT

