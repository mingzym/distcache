EXTRA_DIST = distcache.pod \
	     dc_server.1 dc_client.1 dc_snoop.1 dc_test.1 \
	     DC_PLUG_new.2 DC_PLUG_read.2 DC_CTX_new.2 \
	     NAL_ADDRESS_new.2 \
	     distcache.8

CLEANFILES = *.1 *.2 *.8 *.html

man_MANS = dc_server.1 dc_client.1 dc_snoop.1 dc_test.1 \
	   DC_PLUG_new.2 DC_PLUG_read.2 DC_CTX_new.2 \
	   NAL_ADDRESS_new.2 \
	   distcache.8

docdir = $(datadir)/doc/distcache
doc_DATA = dc_server.html dc_client.html dc_snoop.html dc_test.html \
	   DC_PLUG_new.html DC_PLUG_read.html DC_CTX_new.html \
	   NAL_ADDRESS_new.html \
	   distcache.html

SUFFIXES = .pod .1 .2 .8 .html

# FIXME: "--release=0.3" should be replaced with something automatic
.pod.1:
	pod2man --section=1 --release=0.3 --center=distcache --date=`date +%Y.%m.%d` \
	$< $@

# FIXME: "--release=0.3" should be replaced with something automatic
.pod.2:
	pod2man --section=2 --release=0.3 --center=distcache --date=`date +%Y.%m.%d` \
	$< $@

# FIXME: "--release=0.3" should be replaced with something automatic
.pod.8:
	pod2man --section=8 --release=0.3 --center=distcache --date=`date +%Y.%m.%d` \
	$< $@

.pod.html:
	pod2html --infile=$< --outfile=$@ --podpath=. --title distcache.8
	rm -f pod2htmd.x~~ pod2htmi.x~~

