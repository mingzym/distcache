INCLUDES		= -I$(top_srcdir)/../include -I$(top_builddir)

pemdir			= $(datadir)/swamp
pem_DATA		= CA.pem A-client.pem
EXTRA_DIST		= $(pem_DATA)

bin_PROGRAMS		= sslswamp
sslswamp_SOURCES	= swamp.c text_msg.c utils.c swamp_conf.c \
		 	  dist_pattern.c serv_iterator.c swamp.h
sslswamp_CFLAGS		= -DCACERT_PATH=\"$(pemdir)/CA.pem\"
sslswamp_LDADD		= $(top_builddir)/../libsys/libsys.la \
			  $(top_builddir)/../libnal/libnal.la

sslswamp_manpagelist	= sslswamp.1
sslswamp_podlist	= sslswamp.pod
# FIXME: Disabling HTML builds for the same reason as in ../../doc/Makefile.am
#swamp_htmllist		= sslswamp.html
#
#EXTRA_DIST		+= $(sslswamp_manpagelist) $(sslswamp_htmllist) $(sslswamp_podlist)
EXTRA_DIST		+= $(sslswamp_manpagelist) $(sslswamp_podlist)

CLEANFILES		= *.1 *.html

man_MANS		= $(sslswamp_manpagelist)

docdir			= $(datadir)/doc/sslswamp
#doc_DATA		= $(sslswamp_htmllist)

SUFFIXES		= .pod .1 .html

.pod.1:
	pod2man --section=1 --release=@VERSION@ --center=distcache --date=`date +%Y.%m.%d` \
	$< $@

#.pod.html:
#	echo "FIXME" && exit 1
#
