bin_PROGRAMS		= test_session

INCLUDES		= @OPENSSL_CFLAGS@

test_session_SOURCES	= test_session.c
test_session_LDADD	= $(top_builddir)/libdistcache/libdistcache.la \
		     	  $(top_builddir)/libnal/libnal.la \
			  @OPENSSL_LIBS@

