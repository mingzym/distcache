dnl
dnl TODO:
dnl - Checks for further dependencies required by libssl.a or libcrypto.a
dnl   (e.g. -ldl)
dnl - Support shared libraries when specifying --with-ssl. This is only
dnl   supported when looking through system directories (i.e. when --with-ssl
dnl   is omitted).
dnl
AC_DEFUN([DISTCACHE_WITH_SSL],[
AH_TEMPLATE(HAVE_ENGINE, [Define to 1 if your OpenSSL has ENGINE support])
AH_TEMPLATE(HAVE_SWAMP, [Define to 1 if you are building sslswamp])
if test "x$dc_ssltk_base" = "x"; then
	dnl initialise the variables we use
	dc_ssltk_base=""
	dc_ssltk_inc=""
	dc_ssltk_lib=""

	dnl Determine the SSL/TLS toolkit's base directory, if any
	AC_MSG_CHECKING(for SSL/TLS toolkit base)

	AC_ARG_WITH(ssl, AC_HELP_STRING([--with-ssl=/path/to/openssl],
		[use the specified OpenSSL installation or build tree]), [
		dnl This ensures $withval is actually a directory and that it is absolute
		dc_ssltk_base="`cd $withval ; pwd`"
	])
	if test "x$dc_ssltk_base" = "x"; then
		AC_MSG_RESULT(none)
	else
		AC_MSG_RESULT($dc_ssltk_base)
	fi
	dnl Run header and version checks
	if test "x$dc_ssltk_base" != "x"; then
		dc_ssltk_inc="-I$dc_ssltk_base/include"
		CPPFLAGS="$CPPFLAGS $dc_ssltk_inc"
	fi

	AC_CHECK_HEADERS([openssl/opensslv.h openssl/ssl.h], [], [
		AC_MSG_ERROR([No SSL/TLS headers were available])])
	AC_MSG_CHECKING(for OpenSSL version)
	AC_TRY_COMPILE([#include <openssl/opensslv.h>],
[#if !defined(OPENSSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x0090609f
#error "invalid openssl version"
#endif],
		[dnl Replace this with OPENSSL_VERSION_TEXT from opensslv.h?
			AC_MSG_RESULT(OK)],
		[AC_MSG_RESULT([not encouraging])
		echo "WARNING: OpenSSL version may contain security vulnerabilities!"])
	AC_MSG_CHECKING(for OpenSSL ENGINE support)
	AC_TRY_COMPILE([#include <openssl/engine.h>],
[#if !defined(ENGINE_METHOD_ALL)
#error "engine header looks busted"
#endif],
		[AC_MSG_RESULT(yes)
			AC_DEFINE(HAVE_ENGINE)],
		[AC_MSG_RESULT(no)])
	dnl Run library checks
	if test "x$dc_ssltk_base" != "x"; then
		if test -d "$dc_ssltk_base/lib"; then
			dc_ssltk_lib="$dc_ssltk_base/lib"
		else
			dc_ssltk_lib="$dc_ssltk_base"
		fi
		LDFLAGS="$LDFLAGS -L$dc_ssltk_lib"
	fi
	liberrors=""
	AC_CHECK_LIB(crypto, SSLeay_version, [], [liberrors="yes"])
	AC_CHECK_LIB(ssl, SSL_CTX_new, [], [liberrors="yes"])
	if test "x$liberrors" != "x"; then
		AC_MSG_ERROR([... Error, SSL/TLS libraries were missing or unusable])
	fi

	AC_ARG_ENABLE(swamp,
	AC_HELP_STRING(
		[--enable-swamp],
		[build the 'sslswamp' SSL/TLS utility]),
[
	AC_MSG_CHECKING(whether to build sslswamp)
	if test "x$enableval" != "x"; then
		if test "$enableval" != "yes" -a "$enableval" != "no"; then
			AC_MSG_ERROR("invalid syntax: --enable-swamp=$enableval")
		fi
	fi
	if test "x$enableval" != "no"; then
		AC_DEFINE(HAVE_SWAMP)
		AC_MSG_RESULT(yes)
	else
		AC_MSG_RESULT(no)
	fi
])
fi
])
