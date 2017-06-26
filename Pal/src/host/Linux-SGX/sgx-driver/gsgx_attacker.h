#ifndef GSGX_ATTACKER_H
#define GSGX_ATTACKER_H

#include "gsgx.h"

long gsgx_ioctl_spy_init(struct file *filep, unsigned int cmd,
                    unsigned long arg);

long gsgx_ioctl_spy_stop(struct file *filep, unsigned int cmd,
                    unsigned long arg);

long gsgx_ioctl_spy_wait(struct file *filep, unsigned int cmd,
                    unsigned long arg);

long gsgx_ioctl_spy_start(struct file *filep, unsigned int cmd,
                    unsigned long arg);

void gsgx_attacker_setup(void);

void gsgx_attacker_teardown(void);

#endif
