#ifndef _X86_GSGX_USER_H
#define _X86_GSGX_USER_H

#include <linux/ioctl.h>
#include <linux/stddef.h>
#include <linux/types.h>

#define GSGX_FILE	"/dev/gsgx"
#define GSGX_MINOR	MISC_DYNAMIC_MINOR

#define GSGX_IOCTL_ENCLAVE_CREATE	_IOWR('p', 0x01, struct gsgx_enclave_create)
#define GSGX_IOCTL_ENCLAVE_ADD_PAGES	_IOW('p',  0x02, struct gsgx_enclave_add_pages)
#define GSGX_IOCTL_ENCLAVE_INIT		_IOW('p',  0x03, struct gsgx_enclave_init)
#define GSGX_IOCTL_SPY_START        _IOR('p', 0x04, struct gsgx_spy_info)
#define GSGX_IOCTL_SPY_STOP         _IOR('p', 0x05, void*)
#define GSGX_IOCTL_SPY_WAIT         _IOR('p', 0x06, void*)
#define GSGX_IOCTL_SPY_INIT         _IOR('p', 0x07, void*)

#define GSGX_ENCLAVE_CREATE_NO_ADDR	((unsigned long) -1)

struct gsgx_enclave_create {
	uint64_t src;
};

#define GSGX_ENCLAVE_ADD_PAGES_SKIP_EEXTEND	0x1
#define GSGX_ENCLAVE_ADD_PAGES_REPEAT_SRC	0x2

struct gsgx_enclave_add_pages {
	uint64_t flags;
	uint64_t addr;
	uint64_t user_addr;
	uint64_t size;
	uint64_t secinfo;
};

struct gsgx_enclave_init {
	uint64_t addr;
	uint64_t sigstruct;
	uint64_t einittoken;
};

struct gsgx_spy_info
{
    uint64_t ipi_cpu_nb;
    uint64_t cur_tcs;
    uint64_t aep;
};

#endif /* _X86_GSGX_USER_H */
