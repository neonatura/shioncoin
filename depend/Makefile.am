
if GIT_LIBSHARE 
noinst_SCRIPTS = share

share:
	git clone https://github.com/neonatura/share
	mkdir -p share/build
	cd share && ./autogen.sh
	cd share/build && ../configure && make

clean-local:
	rm -rf share
endif

