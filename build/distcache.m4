dnl
dnl IMPORTANT NOTE:
dnl These two definitions are copied to ssl's acinclude.m4. Any
dnl modifications to one should be reproduced in the other.
dnl

dnl
dnl REMOVE_WERROR
dnl
AC_DEFUN([REMOVE_WERROR],[
dc_werror_set="no"
AC_MSG_CHECKING(whether -Werror is set)
echo "$CFLAGS" | grep -e "-Werror" > /dev/null 2>&1 && dc_werror_set="yes"
if test "$dc_werror_set" = "no"; then
	AC_MSG_RESULT(no)
else
	AC_MSG_RESULT(yes)
	CFLAGS=`echo $CFLAGS | sed -e "s/-Werror//g"`
fi
])

dnl
dnl REPLACE WERROR
dnl
AC_DEFUN([REPLACE_WERROR],[
AC_MSG_CHECKING(whether to reinsert -Werror)
if test "$dc_werror_set" = "yes"; then
	AC_MSG_RESULT(yes)
	CFLAGS="-Werror $CFLAGS"
else
	AC_MSG_RESULT(no)
fi
])

dnl
dnl TOP_LEVEL_SSL
dnl
AC_DEFUN([TOP_LEVEL_SSL],[
dc_ssl_enable="yes"
AC_ARG_ENABLE(ssl,
AC_HELP_STRING(
	[--disable-ssl],
	[disable all SSL-specific targets]),
[
	if test "x$enableval" != "x"; then
		if test "$enableval" != "yes" -a "$enableval" != "no"; then
			AC_MSG_ERROR("invalid syntax: --enable-ssl=$enableval")
		fi
		dc_ssl_enable=$enableval
	fi
])
if test "$dc_ssl_enable" = "yes"; then
	sslheaders="nal_ssl.h"
else
	sslheaders=""
fi
AM_CONDITIONAL([COND_SSL], [test "$dc_ssl_enable" = yes])

AC_SUBST(sslheaders)
AH_TEMPLATE(PREFER_POLL, [Define to 1 if you prefer poll over select])
dc_poll_prefer="yes"
AC_ARG_ENABLE(poll,
AC_HELP_STRING(
	[--disable-poll],
	[prefer 'select' to 'poll' if both available]),
[
	if test "x$enableval" != "x"; then
		if test "$enableval" != "yes" -a "$enableval" != "no"; then
			AC_MSG_ERROR("invalid syntax: --enable-poll=$enableval")
		fi
		dc_poll_prefer=$enableval
	fi
])
AC_MSG_CHECKING(whether to prefer poll over select)
if test "$dc_poll_prefer" = "yes"; then
	AC_DEFINE(PREFER_POLL)
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

dnl Put in stubs. These are properly implemented in ssl/acinclude.m4
dnl but we want them to appear in "./configure --help"
AC_ARG_WITH(ssl, AC_HELP_STRING([--with-ssl=/path/to/openssl],
	[use the specified OpenSSL installation or build tree]), [])
AC_ARG_ENABLE(swamp, AC_HELP_STRING([--disable-swamp],
	[don't build the 'sslswamp' SSL/TLS utility]), [])
])

dnl
dnl TODO:
dnl - Checks for further dependencies required by libssl.a or libcrypto.a
dnl   (e.g. -ldl)
dnl
AC_DEFUN([DISTCACHE_WITH_SSL],[
AH_TEMPLATE(HAVE_ENGINE, [Define to 1 if your OpenSSL has ENGINE support])
if test "x$dc_ssltk_base" = "x"; then
    dnl initialise the variables we use
    dc_ssltk_base=""
    dc_ssltk_inc=""
    dc_ssltk_lib=""

    dnl Determine the SSL/TLS toolkit's base directory, if any
    AC_MSG_CHECKING(for SSL/TLS toolkit base)

    AC_ARG_WITH(ssl, AC_HELP_STRING([--with-ssl=/path/to/openssl],
        [use the specified OpenSSL installation or build tree]), [
        dnl This ensures $withval is actually a directory and that it is
        dnl absolute.
        if test -d "$withval"; then
            dc_ssltk_base="`cd "$withval" ; pwd`"
        elif test -d "../$withval"; then
            dc_ssltk_base="`cd "../$withval" ; pwd`"
        else
            AC_MSG_ERROR([invalid directory: "$withval"])
        fi
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

    dnl Default value
    dc_ssl_swamp="yes"
    AC_ARG_ENABLE(swamp,
    AC_HELP_STRING(
        [--disable-swamp],
        [don't build the 'sslswamp' SSL/TLS utility]),
    [
        if test "x$enableval" != "x"; then
            if test "$enableval" != "yes" -a "$enableval" != "no"; then
                AC_MSG_ERROR("invalid syntax: --enable-swamp=$enableval")
            fi
            dc_ssl_swamp=$enableval
        fi
    ])
    AC_MSG_CHECKING(whether to build sslswamp)
    if test "$dc_ssl_swamp" = "yes"; then
        AC_MSG_RESULT(yes)
        swamp_dir="swamp"
    else
        AC_MSG_RESULT(no)
    fi
    AM_CONDITIONAL([COND_SWAMP], [test "$dc_ssl_swamp" = yes])
fi
])
