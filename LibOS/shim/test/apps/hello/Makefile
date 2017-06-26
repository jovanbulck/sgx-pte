
manifests = helloworld.manifest

target = helloworld
exec_target = $(manifests)

extra_rules = \
	-e 's:\$$(PAL):../pal_loader:g' \
	-e 's:\$$(DEBUGTYPE):$(if $(DEBUG),inline,none):g'

level = ../../
include ../../Makefile

helloworld: helloworld.o asm_vars.o asm.o
	@echo "[ now linking.. ]"
	@# link through the compiler to avoid linking errors
	$(CC) $(LDFLAGS) $^ -o $@

asm.S: build_asm.py
	./build_asm.py

%.o : %.S 
	@echo [ $< ]
	$(CC) $(CFLAGS) -c $< -o $@

%.o : %.c
	@echo [ $< ]
	$(CC) $(CFLAGS) -c $< -o $@

distclean: clean
	rm -f *.o *.manifest.sgx *.sig *.token asm.S
