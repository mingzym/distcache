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
	AC_CONFIG_SUBDIRS(ssl)
fi

dnl Put in stubs. These are properly implemented in ssl/acinclude.m4
dnl but we want them to appear in "./configure --help"
AC_ARG_WITH(ssl, AC_HELP_STRING([--with-ssl=/path/to/openssl],
	[use the specified OpenSSL installation or build tree]), [])
AC_ARG_ENABLE(swamp, AC_HELP_STRING([--disable-swamp],
	[don't build the 'sslswamp' SSL/TLS utility]), [])
])
