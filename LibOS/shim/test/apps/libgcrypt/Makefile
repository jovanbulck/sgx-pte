include gpgerr-defs.mk

src: $(GPGERR_SO)

$(GPGERR_SO): $(GPGERR_SRC)/Makefile
	cd $(GPGERR_SRC) && $(MAKE)
	cd $(GPGERR_SRC) && $(MAKE) install

$(GPGERR_SRC)/Makefile: $(GPGERR_SRC)/configure
	cd $(GPGERR_SRC) && \
		./configure --prefix=$(shell readlink -f $(GPGERR_INSTALL))

$(GPGERR_SRC)/configure: $(GPGERR_SRC).tar.bz2
	tar -xjf $<

srcclean:
	rm -Rf $(GPGERR_SRC)
