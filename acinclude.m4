dnl
dnl Autoconf macro to look for OpenSSL libraries and header files. If
dnl found, the variables "OPENSSL_CFLAGS" and "OPENSSL_LIBS" will be
dnl AC_SUBST().
dnl
dnl If OpenSSL isn't found, the macro calls AC_MSG_ERROR() which will
dnl then abandon the script.
dnl
dnl TODO:
dnl Currently, this doesn't support looking up further dependencies on
dnl libssl.a or libcrypto.a (e.g. -ldl). Neither does it support shared
dnl libraries when probing when specifying --with-ssl on the command
dnl line. This is left to probing the system directories (i.e. when
dnl --with-ssl *isn't* on the configure command line).
dnl
AC_DEFUN([DISTCACHE_WITH_SSL],[
AH_TEMPLATE(HAVE_OPENSSL, [Define to 1 if you have OpenSSL installed])
AC_ARG_WITH(ssl,
AC_HELP_STRING(
	[--with-ssl=/path/to/openssl],
	[use the specified OpenSSL installation or build tree]),
[
	ossl_found=1
	ossl_not_found_reason=""

	AC_MSG_CHECKING([for OpenSSL in $withval])

	if test -d "$withval" ; then
		if test -s "$withval/lib/libcrypto.a" ; then
			ossl_lib_path="$withval/lib"
		elif test -s "$withval/libcrypto.a" ; then
			ossl_lib_path="$withval"
		else
			ossl_not_found_reason="can't find libraries"
			ossl_found=0
		fi

		if test -d "$withval/include/openssl" ; then
			ossl_include_path="$withval/include"
		else
			ossl_not_found_reason="can't find header files"
			ossl_found=0
		fi
	else
		ossl_not_found_reason="no such directory $withval"
		ossl_found=0
	fi

	if test "x$ossl_found" = "x1" ; then
		OPENSSL_LIBS="-L$ossl_lib_path -lssl -lcrypto"
		OPENSSL_CFLAGS="-I$ossl_include_path"
		AC_SUBST(OPENSSL_LIBS)
		AC_SUBST(OPENSSL_CFLAGS)
		AC_DEFINE(HAVE_OPENSSL)
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
		AC_MSG_ERROR([Giving up probing for OpenSSL: $ossl_not_found_reason])
	fi
],
[
	AC_MSG_NOTICE([checking for system installation of OpenSSL...])

	ossl_found_libs=1
	ossl_found_headers=1
	ossl_not_found_reason=""

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
		AC_MSG_ERROR([Probe for system OpenSSL failed: $ossl_not_found_reason])
	fi
])])

