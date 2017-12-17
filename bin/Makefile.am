

noinst_PROGRAMS = shc$(EXEEXT) shcoind$(EXEEXT) .notice$(EXTEXT)

if USDE_SERVICE
noinst_PROGRAMS += usde$(EXTEXT)

usde$(EXTEXT):
	ln -sf $(top_builddir)/src/coin-console/usde$(EXTEXT)
endif

if EMC2_SERVICE
noinst_PROGRAMS += emc2$(EXTEXT)

emc2$(EXTEXT):
	ln -sf $(top_builddir)/src/coin-console/emc2$(EXTEXT)
endif

shcoind$(EXEEXT): docs
	ln -sf $(top_builddir)/src/share-coin/shcoind$(EXEEXT)

shc$(EXEEXT):
	ln -sf $(top_builddir)/src/coin-console/shc$(EXEEXT)

if HAVE_DOXYGEN
docs:
	ln -sf $(top_builddir)/doc/html/ docs
else
docs:
	echo > docs
endif


.notice$(EXTEXT):
	@echo > .notice$(EXTEXT)
	@echo ""
	@echo "It is now safe to perform a 'make install'."
	@echo ""

