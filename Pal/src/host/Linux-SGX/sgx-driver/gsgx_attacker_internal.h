#ifndef GSGX_ATTACKER_INTERNAL_H
#define GSGX_ATTACKER_INTERNAL_H

#include "graphene-sgx.h"
#include "gsgx_attacker.h"
#include "gsgx_attacker_config.h"

/* Helper functions. */

pte_t *get_pte_adrs(uint64_t address);

struct victim_ipi_init_info {
    int victim_cpu;
    uint64_t cur_tcs;
    uint64_t erip_base;
    uint64_t aep;
};

void ipi_handler(void);
void victim_ipi_init(void *info);
void victim_ipi_final(void *info);

void gsgx_spy_thread(struct gsgx_spy_info *arg);

#if CONFIG_EDBGRD_RIP
    /*
     * Symbols exported by patched linux-sgx-driver LKM.
     */
    extern int isgx_vma_access(struct vm_area_struct *vma, unsigned long addr,
                    void *buf, int len, int write);
    extern unsigned long isgx_get_enclave_base(struct vm_area_struct *vma);
    extern unsigned long isgx_get_enclave_ssaframesize(
        struct vm_area_struct *vma);

    uint64_t edbgrd_ssa(unsigned long tcs_address, int ssa_field_offset);
#endif

void gsgx_flush(void* p);
unsigned long gsgx_reload(void* p);

/* Precompiler macros. */

#define RET_WARN_ON( cond, rv )                                             \
    WARN_ON(cond);                                                          \
    if (cond) return rv                                                     \

#define ACCESS_MASK             0x20
#define DIRTY_MASK              0x40
#define ACCESSED(pte_pt)        (pte_pt && (*pte_pt & ACCESS_MASK) != 0)
#define DIRTY(pte_pt)           (pte_pt && (*pte_pt & DIRTY_MASK) != 0)

#define CLEAR_AD(pte_pt)        \
    if (pte_pt) (*pte_pt = *pte_pt & (~ACCESS_MASK) & (~DIRTY_MASK))

#define PRINT_AD(pte_pt)   \
    printk("\t--> A/D PTE(%s) is %d/%d\n", #pte_pt, \
    ACCESSED(pte_pt), DIRTY(pte_pt))

/* NOTE: incorrect GPRSGX size in Intel manual vol. 3D June 2016 p.38-7 */
#define SGX_TCS_OSSA_OFFSET         16
#define SGX_GPRSGX_SIZE             184
#define SGX_GPRSGX_RIP_OFFSET       136
#define SGX_GPRSGX_RAX_OFFSET       0

#if CONFIG_DISABLE_CACHE
    /*
     * Set CR0.CD bit to disable caching on current CPU.
     */
    #define CR0_DISABLE_CACHE                                               \
        asm volatile (                                                      \
            "mov %%cr0, %%rax\n\t"                                          \
            "or $(1 << 30),%%rax\n\t" /* set CD but not NW bit */           \
            "movq %%rax, %%cr0\n\t"                                         \
            "wbinvd\n\t"               /* flush */                          \
            "or $(1 << 29),%%rax\n\t"  /* now set the NW bit */             \
            "movq %%rax, %%cr0\n\t"                                         \
            ::: "%rax","%rcx","%rdx");

    /*
     * Clear CR0.CD/NW bit to re-enable caching on current CPU.
     */
    #define CR0_ENABLE_CACHE                                                \
        asm volatile (                                                      \
            "mov %%cr0, %%rax\n\t"                                          \
            "and $~(1 << 30), %%rax\n\t"                                    \
            "and $~(1 << 29), %%rax\n\t"                                    \
            "movq %%rax, %%cr0\n\t"                                         \
            ::: "%rax");                                                    
#else
    #define CR0_DISABLE_CACHE
    #define CR0_ENABLE_CACHE
#endif

#endif
