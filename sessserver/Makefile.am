INCLUDES=-I$(top_srcdir)/include -I$(top_builddir)/config

bin_PROGRAMS	 = dc_server
dc_server_SOURCES= server.c
dc_server_LDADD	 = $(top_builddir)/libdistcacheserver/libdistcacheserver.la \
		   $(top_builddir)/libdistcache/libdistcache.la \
		   $(top_builddir)/libnal/libnal.la

