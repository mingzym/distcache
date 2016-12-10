AM_CPPFLAGS		= -I$(top_srcdir)/include -I$(top_builddir) @OPENSSL_INCLUDES@
AM_CFLAGS		= -I$(top_srcdir)/include -I$(top_builddir) @OPENSSL_INCLUDES@
AM_LDFLAGS = @OPENSSL_LDFLAGS@
lib_LTLIBRARIES		= libnalssl.la
libnalssl_la_SOURCES	= bss_nal.c
libnalssl_la_LDFLAGS	= -version-info 1:1:0
