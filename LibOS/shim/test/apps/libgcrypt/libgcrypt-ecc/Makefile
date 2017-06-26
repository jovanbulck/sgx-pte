# Makefile builds both versions; choose below which one to link to Graphene app
GCRY_VERSION        = 1.7.5
#GCRY_VERSION        = 1.6.3

# comment out if not parsing flush+flush measurements
PARSE_FF            = _ff

# Choose test application below
#   main_eddsa: attack EdDSA signing
#   main_mpi: perform microbenchmarks
MAIN                = main_eddsa
#MAIN                = main_mpi

LIBGCRYPT           = libgcrypt-$(GCRY_VERSION)
GCRY_INSTALL        = $(LIBGCRYPT)/local
GCRY_CONFIG         = $(GCRY_INSTALL)/bin/libgcrypt-config
GCRY_ALL            = libgcrypt-1.6.3 libgcrypt-1.7.5

target = main
manifests = $(target).manifest
exec_target = $(manifests)

extra_rules = \
	-e 's:\$$(PAL):../pal_loader:g' \
	-e 's:\$$(GCRYDIR):$(GCRY_INSTALL)/lib:g' \
	-e 's:\$$(GPGERRDIR):../$(GPGERR_INSTALL)/lib:g' \
	-e 's:\$$(DEBUGTYPE):$(if $(DEBUG),inline,none):g'

level = ../../../
include ../gpgerr-defs.mk
include ../../../Makefile

CFLAGS              += `$(GCRY_CONFIG) --cflags`
LDFLAGS             += `$(GCRY_CONFIG) --libs`

all: main

main: $(MAIN).o
	@echo "[ now linking.. ]"
	$(CC) $^ $(LDFLAGS) -o $@
	ln -sf $(LIBGCRYPT) libgcrypt
	ln -sf parse_$(GCRY_VERSION)$(PARSE_FF).py parse.py
	
%.o : %.c
	@echo [ $< ]
	$(CC) -g $(CFLAGS) -c $< -o $@

src: gpgerrsrc $(GCRY_ALL)

gpgerrsrc:
	$(MAKE) -C .. src

.SECONDARY:
libgcrypt-%: libgcrypt-%/Makefile
	cd $@ && $(MAKE)
	cd $@ && $(MAKE) install

.SECONDARY:
%/Makefile: %/configure
	cd $* && ./configure --prefix=$(shell readlink -f $*/local)

%/configure: %.tar.bz2
	tar -xjf $<
	if [ "$*" = "libgcrypt-1.6.3" ]; then \
	    cd $* && patch -p1 < ../gcry-1.6.3-secure-eddsa-session-key.patch; \
	fi

distclean: clean
	rm -f *.o *.manifest.sgx *.sig *.token
	rm -f gdb_page_trace.txt gdb_page_count.txt
	rm -f measurements.txt measurements_raw.txt measurements_parsed.txt
	rm -f libgcrypt parse.py

srcclean: clean distclean
	$(MAKE) -C .. srcclean
	rm -Rf $(GCRY_ALL)
