pemdir			= $(datadir)/swamp
pem_DATA		= CA.pem A-client.pem
EXTRA_DIST		= $(pem_DATA)

bin_PROGRAMS		= sslswamp
sslswamp_SOURCES	= swamp.c text_msg.c utils.c swamp_conf.c \
		 	  dist_pattern.c serv_iterator.c swamp.h
sslswamp_CFLAGS		= -I$(top_srcdir)/include -I$(top_builddir) @OPENSSL_INCLUDES@ -DCACERT_PATH=\"$(pemdir)/CA.pem\"
sslswamp_LDFLAGS	= @OPENSSL_LDFLAGS@
sslswamp_LDADD 		= @OPENSSL_LIBS@ $(top_builddir)/libsys/libsys.la \
			  $(top_builddir)/libnal/libnal.la

sslswamp_manpagelist	= sslswamp.1
sslswamp_podlist	= sslswamp.pod
EXTRA_DIST		+= $(sslswamp_manpagelist) $(sslswamp_podlist)

CLEANFILES		= *.1

man_MANS		= $(sslswamp_manpagelist)

docdir			= $(datadir)/doc/sslswamp

SUFFIXES		= .pod .1

.pod.1:
	pod2man --section=1 --release=@VERSION@ --center=distcache --date=`date +%Y.%m.%d` \
	$< $@

