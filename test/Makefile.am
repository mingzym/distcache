INCLUDES		= -I$(top_srcdir) @OPENSSL_CFLAGS@

bin_PROGRAMS		= test_session
test_session_SOURCES	= test_session.c
test_session_LDADD	= $(top_builddir)/libdistcache/libdistcache.la \
		     	  $(top_builddir)/libnal/libnal.la \
			  @OPENSSL_LIBS@

