INCLUDES=-I$(top_srcdir)

bin_PROGRAMS	 = sserver
sserver_SOURCES	 = server.c
sserver_LDADD	 = $(top_builddir)/libdistcacheserver/libdistcacheserver.la \
		   $(top_builddir)/libdistcache/libdistcache.la \
		   $(top_builddir)/libnal/libnal.la

