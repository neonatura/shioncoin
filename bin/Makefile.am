

noinst_PROGRAMS = shc$(EXEEXT) shcoind$(EXEEXT) .notice$(EXEEXT) 
noinst_SCRIPTS =

if HAVE_GIT
noinst_SCRIPTS += ChangeLog
ChangeLog:
	git --git-dir $(top_srcdir)/.git log > ChangeLog || touch ChangeLog
endif

if EMC2_SERVICE
noinst_SCRIPTS += .emc2$(EXEEXT)

.emc2$(EXEEXT):
	ln -sf $(top_builddir)/src/coin-console/emc2$(EXEEXT)
	@echo > .emc2$(EXEEXT)
endif

shcoind$(EXEEXT): docs
	ln -sf $(top_builddir)/src/shioncoin/shcoind$(EXEEXT)

shc$(EXEEXT):
	ln -sf $(top_builddir)/src/coin-console/shc$(EXEEXT)

if HAVE_DOXYGEN
docs:
	ln -sf $(top_builddir)/doc/html/ docs
else
docs:
	echo > docs
endif


.notice$(EXEEXT):
	@echo > .notice$(EXEEXT)
	@echo ""
	@echo "It is now safe to perform a 'make install'."
	@echo ""

