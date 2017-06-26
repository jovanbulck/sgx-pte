ifneq ($(KERNELRELEASE),)
	ccflags-y += -I$(PWD)/linux-sgx-driver
	graphene-sgx-y := \
		gsgx_main.o gsgx_attacker.o gsgx_attacker_pte_set.o
	obj-m += graphene-sgx.o
else
KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)
ISGXDIR  = $(realpath ./linux-sgx-driver)

default: linux-sgx-driver/isgx.h
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) CFLAGS_MODULE="-DDEBUG -g -O0" \
	KBUILD_EXTRA_SYMBOLS=$(ISGXDIR)/Module.symvers modules

linux-sgx-driver/isgx.h:
	@./link-intel-driver.py
endif

load: default
	./load.sh
	sudo sysctl -w vm.mmap_min_addr="0"
	dmesg | tail

clean:
	rm -vrf *.o *.ko *.order *.symvers *.mod.c .tmp_versions .*o.cmd
