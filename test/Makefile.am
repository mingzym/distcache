INCLUDES		= -I$(top_srcdir) -I$(top_builddir) @OPENSSL_CFLAGS@

bin_PROGRAMS		= dc_test
dc_test_SOURCES		= dc_test.c
dc_test_LDADD		= $(top_builddir)/libdistcache/libdistcache.la \
		     	  $(top_builddir)/libnal/libnal.la \
			  @OPENSSL_LIBS@

