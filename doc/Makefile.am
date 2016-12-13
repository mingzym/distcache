dc_manpagelist = \
		 dc_server.1 dc_client.1 dc_snoop.1 dc_test.1 \
		 DC_PLUG_new.2 DC_PLUG_read.2 DC_CTX_new.2 DC_SERVER_new.2 \
		 NAL_ADDRESS_new.2 NAL_CONNECTION_new.2 NAL_LISTENER_new.2 \
		 NAL_SELECTOR_new.2 NAL_BUFFER_new.2 NAL_decode_uint32.2 \
		 distcache.8
# Keep this maintained by copying the manpagelist and running s/[0-9]/pod/g
dc_podlist = \
		 dc_server.pod dc_client.pod dc_snoop.pod dc_test.pod \
		 DC_PLUG_new.pod DC_PLUG_read.pod DC_CTX_new.pod DC_SERVER_new.pod \
		 NAL_ADDRESS_new.pod NAL_CONNECTION_new.pod NAL_LISTENER_new.pod \
		 NAL_SELECTOR_new.pod NAL_BUFFER_new.pod NAL_decode_uint32.pod \
		 distcache.pod
EXTRA_DIST = $(dc_manpagelist) $(dc_podlist)

CLEANFILES = *.1 *.2 *.8

man_MANS = $(dc_manpagelist)

docdir = $(datadir)/doc/distcache

SUFFIXES = .pod .1 .2 .8

.pod.1:
	pod2man --section=1 --release=@VERSION@ --center=distcache --date=`date +%Y.%m.%d` \
	$< $@

.pod.2:
	pod2man --section=2 --release=@VERSION@ --center=distcache --date=`date +%Y.%m.%d` \
	$< $@

.pod.8:
	pod2man --section=8 --release=@VERSION@ --center=distcache --date=`date +%Y.%m.%d` \
	$< $@

