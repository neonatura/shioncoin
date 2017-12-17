

noinst_PROGRAMS = shc$(EXEEXT) shcoind$(EXEEXT) .notice$(EXTEXT)
noinst_SCRIPTS =

if USDE_SERVICE
noinst_SCRIPTS += .usde$(EXEEXT)

.usde$(EXEEXT):
	ln -sf $(top_builddir)/src/coin-console/usde$(EXTEXT)
	@echo > .usde$(EXEEXT)
endif

if EMC2_SERVICE
noinst_SCRIPTS += .emc2$(EXEEXT)

.emc2$(EXEEXT):
	ln -sf $(top_builddir)/src/coin-console/emc2$(EXTEXT)
	@echo > .emc2$(EXEEXT)
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

