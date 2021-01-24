


noinst_SCRIPTS = \
	.notice \
	libshare.a

noinst_PROGRAMS = \
	sx sxc readsexe sxsh \
	shattr \
	shcat \
	shcert \
	shcp \
	shdb \
	shdelta \
	shdiff \
	shfsck \
	shinfo \
	shln \
	shls \
	shpatch \
	shstat \
	shpref \
	shpasswd \
	shpkg \
	shrev \
	shrm

if WINDOWS
else
noinst_SCRIPTS += \
	libshare.so libshare.so.5 \
	libshare.so.5.0.$(version_patch)
endif
if HAVE_DOXYGEN
noinst_SCRIPTS += html man
endif


html: $(top_builddir)/doc/libshare/html
	rm -rf html
	cp -fr $(top_builddir)/doc/libshare/html .

man: $(top_builddir)/doc/libshare/man
	rm -rf man
	cp -fr $(top_builddir)/doc/libshare/man .


.notice:
	@echo > .notice
	@echo ""
	@echo "The  libshare library and it's components has been built."
	@echo ""
	@echo "It is now safe to perform a 'make install'."
	@echo "Perform a 'make check' for additional tests afterwards."
	@echo ""
	@echo "Check out the 'bin/' directory for programs and libraries."
	@echo "Documentation is located in the bin/html/ directory."
	@echo ""


libshare.a:
	ln -sf $(top_builddir)/src/share-lib/.libs/libshare.a  .

libshare.so:
	ln -sf $(top_builddir)/src/share-lib/.libs/libshare.so . 

libshare.so.5:
	ln -sf $(top_builddir)/src/share-lib/.libs/libshare.so.5 .

libshare.so.5.0.$(version_patch):
	ln -sf $(top_builddir)/src/share-lib/.libs/libshare.so.5.0.$(version_patch) .


sx$(EXEEXT):
	ln -sf $(top_builddir)/src/sexe/.libs/sx$(EXEEXT) .

sxc$(EXEEXT):
	ln -sf $(top_builddir)/src/sexe/.libs/sxc$(EXEEXT) .

readsexe$(EXEEXT):
	ln -sf $(top_builddir)/src/sexe/.libs/readsexe$(EXEEXT) .

sxsh$(EXEEXT):
	ln -sf $(top_builddir)/src/sexe/shell/.libs/sxsh$(EXEEXT) .

shcat$(EXEEXT):
	ln -sf $(top_builddir)/src/share-util/static/shcat$(EXEEXT) .

shstat$(EXEEXT):
	ln -sf $(top_builddir)/src/share-util/static/shstat$(EXEEXT) .

shls$(EXEEXT):
	ln -sf $(top_builddir)/src/share-util/static/shls$(EXEEXT) .

shattr$(EXEEXT):
	ln -sf $(top_builddir)/src/share-util/static/shattr$(EXEEXT) .

shpref$(EXEEXT):
	ln -sf $(top_builddir)/src/share-util/static/shpref$(EXEEXT) .

shrm$(EXEEXT):
	ln -sf $(top_builddir)/src/share-util/static/shrm$(EXEEXT) .

shrev$(EXEEXT):
	ln -sf $(top_builddir)/src/share-util/static/shrev$(EXEEXT) .

shcp$(EXEEXT):
	ln -sf $(top_builddir)/src/share-util/static/shcp$(EXEEXT) .

shdiff$(EXEEXT):
	ln -sf $(top_builddir)/src/share-util/static/shdiff$(EXEEXT) .

shdelta$(EXEEXT):
	ln -sf $(top_builddir)/src/share-util/static/shdelta$(EXEEXT) .

shpatch$(EXEEXT):
	ln -sf $(top_builddir)/src/share-util/static/shpatch$(EXEEXT) .

shln$(EXEEXT):
	ln -sf $(top_builddir)/src/share-util/static/shln$(EXEEXT) .

shpkg$(EXEEXT):
	ln -sf $(top_builddir)/src/share-util/static/shpkg$(EXEEXT) .

shpasswd$(EXEEXT):
	ln -sf $(top_builddir)/src/share-util/static/shpasswd$(EXEEXT) .

shinfo$(EXEEXT):
	ln -sf $(top_builddir)/src/share-util/static/shinfo$(EXEEXT) .

shcert$(EXEEXT):
	ln -sf $(top_builddir)/src/share-util/static/shcert$(EXEEXT) .

shdb$(EXEEXT):
	ln -sf $(top_builddir)/src/share-util/static/shdb$(EXEEXT) .

shfsck$(EXEEXT):
	ln -sf $(top_builddir)/src/share-util/static/shfsck$(EXEEXT) .

