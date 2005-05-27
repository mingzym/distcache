INCLUDES			= -I$(top_srcdir)/include -I$(top_builddir)

lib_LTLIBRARIES			= libdistcacheserver.la
libdistcacheserver_la_SOURCES	= dc_server.c dc_server_default.c
libdistcacheserver_la_LDFLAGS	= -version-info 1:1:0
libdistcacheserver_la_LIBADD	= ../libdistcache/libdistcache.la ../libnal/libnal.la

