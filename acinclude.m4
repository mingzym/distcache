dnl
dnl Autoconf macro to look for OpenSSL libraries and header files. If
dnl found, the variables "OPENSSL_CFLAGS" and "OPENSSL_LIBS" will be
dnl AC_SUBST() and HAVE_OPENSSL will be defined.
dnl
dnl If OpenSSL isn't found, the macro displays sends a message to
dnl AC_MSG_WARN() and the script continues.
dnl
dnl TODO:
dnl - Checks for further dependencies required by libssl.a or libcrypto.a
dnl   (e.g. -ldl)
dnl - Support shared libraries when specifying --with-ssl. This is only
dnl   supported when looking through system directories (i.e. when --with-ssl
dnl   is omitted).
dnl
AC_DEFUN([DISTCACHE_WITH_SSL],[
AH_TEMPLATE(HAVE_OPENSSL, [Define to 1 if you have OpenSSL installed])
AC_ARG_WITH(ssl,
AC_HELP_STRING(
	[--with-ssl=/path/to/openssl],
	[use the specified OpenSSL installation or build tree]),
[
	dnl ossl_found is a tri-state "bool":
	dnl     "no"  (not found)
	dnl     "yes" (found)
	dnl     "n/a" (used when --without-ssl is specified)
	ossl_found="yes"
	ossl_not_found_reason=""

	AC_MSG_CHECKING([for OpenSSL])

	if test "x$withval" = "xno" ; then
		ossl_found="n/a"
	elif test -d "$withval" ; then
		if test -s "$withval/lib/libcrypto.a" ; then
			ossl_lib_path="$withval/lib"
		elif test -s "$withval/libcrypto.a" ; then
			ossl_lib_path="$withval"
		else
			ossl_not_found_reason="can't find libraries"
			ossl_found="no"
		fi

		if test -d "$withval/include/openssl" ; then
			ossl_include_path="$withval/include"
		else
			ossl_not_found_reason="can't find header files"
			ossl_found="no"
		fi
	else
		ossl_not_found_reason="no such directory '$withval'"
		ossl_found="no"
	fi

	if test "x$ossl_found" = "xyes" ; then
		OPENSSL_LIBS="-L$ossl_lib_path -lssl -lcrypto"
		OPENSSL_CFLAGS="-I$ossl_include_path"
		AC_SUBST(OPENSSL_LIBS)
		AC_SUBST(OPENSSL_CFLAGS)
		AC_DEFINE(HAVE_OPENSSL)
		AC_MSG_RESULT([yes: $withval])
	elif test "x$ossl_found" = "xno" ; then
		AC_MSG_RESULT([no])
		AC_MSG_WARN([Failed to find OpenSSL: $ossl_not_found_reason])
	else
		AC_MSG_RESULT([no])
	fi
],
[
	AC_MSG_NOTICE([checking for system installation of OpenSSL...])

	ossl_found_libs=1
	ossl_found_headers=1
	ossl_not_found_reason=""

	AC_PATH_PROG(PKG_CONFIG, pkg-config, no)
	if test "$PKG_CONFIG" != "no" && ${PKG_CONFIG} openssl; then
		AC_MSG_NOTICE([using OpenSSL location from pkg-config])
		OPENSSL_CFLAGS="$CPPFLAGS `${PKG_CONFIG} --cflags openssl`"
		OPENSSL_LIBS="$LDFLAGS `${PKG_CONFIG} --libs openssl`"
	else

	AC_CHECK_LIB(ssl, SSL_CTX_new, [],
		[
			ossl_found_libs=0
			ossl_not_found_reason="can't find libraries"
		])
	AC_CHECK_LIB(crypto, CRYPTO_set_mem_functions, [],
		[
			ossl_found_libs=0
			ossl_not_found_reason="can't find libraries"
		])
	
	AC_CHECK_HEADERS(openssl/ssl.h, [],
		[
			ossl_found_headers=0
			ossl_not_found_reason="can't find header files"
		])

	if test "x$ossl_found_libs" = "x1" -a \
			"x$ossl_found_headers" = "x1" ; then
		OPENSSL_LIBS="-lssl -lcrypto"
		OPENSSL_CFLAGS="" # None are needed.
		AC_SUBST(OPENSSL_LIBS)
		AC_SUBST(OPENSSL_CFLAGS)
		AC_DEFINE(HAVE_OPENSSL)
	else
		AC_MSG_WARN([Probe for system OpenSSL failed: $ossl_not_found_reason])
	fi
	fi
])])

