dnl
dnl TOP_LEVEL_SSL
dnl
AC_DEFUN([TOP_LEVEL_SSL],[
dnl Default value
dc_ssl_enable="no"
dc_ssl_params=""
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
dnl Local stubs for the autoconf parameters for ssl/
AC_ARG_WITH(ssl,
AC_HELP_STRING(
	[--with-ssl=<path>],
	[specify the path to OpenSSL]),
[
	dnl Make sure the path is absolute
	tmp_base="`cd $withval ; pwd`"
	dc_ssl_params="$dc_ssl_params --with-ssl=$tmp_base"
])
AC_ARG_ENABLE(swamp,
AC_HELP_STRING(
	[--enable-swamp],
	[build the 'sslswamp' SSL/TLS utility]),
[
	dc_ssl_params="$dc_ssl_params --enable-swamp=$enableval"
])
])

dnl
dnl DO_SSL_CONFIG
dnl
AC_DEFUN([DO_SSL_CONFIG],
[
	if test "x$dc_ssl_enable" = "xyes"; then
		echo ""
		echo "Configuring SSL/TLS-specific targets;"
		dnl Add any --prefix to the configure arguments
		dc_ssl_params="--prefix=$prefix $dc_ssl_params"
		dnl This workaround is required for out-of-tree builds
		if test ! -d ssl ; then
			mkdir ssl
		fi
		dc_ssl_dir="`cd $srcdir && cd ssl && pwd`"
		dc_ssl_params="--srcdir=$dc_ssl_dir $dc_ssl_params"
		(cd ssl && echo "$dc_ssl_dir/configure $dc_ssl_params" | sh) || exit 1
	fi
])
