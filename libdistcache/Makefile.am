INCLUDES		= -I$(top_srcdir)/include -I$(top_builddir)

lib_LTLIBRARIES		= libdistcache.la
libdistcache_la_SOURCES = dc_client.c dc_enc.c
libdistcache_la_LDFLAGS	= -version-info 1:1:0
libdistcache_la_LIBADD	= ../libnal/libnal.la
