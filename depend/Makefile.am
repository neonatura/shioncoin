
if GIT_LIBSHARE 
noinst_SCRIPTS = share

share:
	git clone https://github.com/neonatura/share
	mkdir -p share/build
	cd share/build && ../configure --disable-java && make
clean-local:
	rm -rf share
endif
