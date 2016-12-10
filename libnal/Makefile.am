AM_CPPFLAGS		= -I$(top_srcdir)/include -I$(top_builddir)

lib_LTLIBRARIES		= libnal.la
libnal_la_SOURCES	= nal_internal.h \
			  nal_address.c nal_listener.c nal_connection.c \
			  nal_selector.c nal_buffer.c nal_codec.c \
			  util_fd.c util_socket.c sel_select.c sel_poll.c \
			  proto_std.c proto_fd.c ctrl_fd.h
libnal_la_LDFLAGS	= -version-info 1:1:0

