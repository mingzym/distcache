dnl
dnl TOP_LEVEL_SSL
dnl
AC_DEFUN([TOP_LEVEL_SSL],[
dnl Default value
dc_ssl_enable="yes"
dnl Implement --enable-ssl
AC_ARG_ENABLE(ssl,
AC_HELP_STRING(
	[--enable-ssl],
	[build the SSL-specific targets]),
[
	if test "x$enableval" != "x"; then
		if test "$enableval" != "yes" -a "$enableval" != "no"; then
			AC_MSG_ERROR("invalid syntax: --enable-ssl=$enableval")
		fi
		dc_ssl_enable=$enableval
	fi
])
if test "$dc_ssl_enable" = "yes"; then
	AC_CONFIG_SUBDIRS(ssl)
fi
AM_CONDITIONAL(HAVE_SSL_SUBDIR, test "$dc_ssl_enable" = "yes")
dnl Put a stub for --with-ssl. This is properly implemented in ssl/acinclude.m4
dnl but we want the option to appear in "./configure --help"
AC_ARG_WITH(ssl, AC_HELP_STRING([--with-ssl=/path/to/openssl],
	[use the specified OpenSSL installation or build tree]), [])
])

