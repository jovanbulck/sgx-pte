#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/syscall.h>
#define SYSDUMP_NB      311

#define VERIFY_KEY      0
#define VERIFY_SIG      0
#define GCRY_DEBUG      0
#define DO_SYSDUMP      1

/* Test case 2 from libgcrypt-1.6.3/tests/t-ed25519.inp */
#define PK      "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
#define SK      "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
#define MSG     "72"
#define SIG     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"

/* The 512 bits secret scalar r for this message (output by libgcrypt debug):
DBG:      r: 4f71d012df3c371af3ea4dc38385ca5bb7272f90cb1b008b3ed601c76de1d496 \
DBG:         e30cbf625f0a756a678d8f256d5325595cccc83466f36db18f0178eb9925edd3
*/

static char const sample_pk[] =
    "(public-key"
    " (ecc"
    "  (curve \"Ed25519\")"
    "  (flags eddsa)"
    "  (q #" PK "#)"
    "))";

static char const sample_sk[] =
    "(private-key"
    " (ecc"
    "  (curve \"Ed25519\")"
    "  (flags eddsa)"
    "  (d #" SK "#)"
    "  (q #" PK "#)"
    "))";

static char const sample_msg[] =
    "(data"
    " (flags eddsa)"
    " (hash-algo sha512)"
    " (value #" MSG "#)"
    ")";

gpg_error_t rc;

#define GCRY_ASSERT( fct ) \
    rc = fct; \
    if (rc) \
    { \
        printf("GCRY_ASSERT failed for %s: %s/%s\n", #fct, \
               gcry_strsource(rc), \
               gcry_strerror(rc)); \
        abort(); \
    }

void dump_gcry_sexp(gcry_sexp_t s)
{
    unsigned char buf[1000] = {0};
    assert( gcry_sexp_sprint(s, GCRYSEXP_FMT_DEFAULT, buf, 999) );
    printf("dump_gcry_sexp is:\n%s\n", buf);
}

void dump_signature(gcry_sexp_t sig)
{
    gcry_sexp_t tmp, tmp2;
    char *sig_r = NULL, *sig_s = NULL, *sig_rs_string, *p;
    size_t sig_r_len, sig_s_len;
    int i;

    tmp = gcry_sexp_find_token(sig, "sig-val", 0);
    if (tmp)
    {
        tmp2 = tmp;
        tmp = gcry_sexp_find_token(tmp2, "eddsa", 0);
        gcry_sexp_release(tmp2);
        if (tmp)
        {
            tmp2 = tmp;
            tmp = gcry_sexp_find_token(tmp2, "r", 0);
            if (tmp)
            {
                sig_r = gcry_sexp_nth_buffer(tmp, 1, &sig_r_len);
                gcry_sexp_release(tmp);
            }
            tmp = gcry_sexp_find_token(tmp2, "s", 0);
            if (tmp)
            {
                sig_s = gcry_sexp_nth_buffer(tmp, 1, &sig_s_len);
                gcry_sexp_release(tmp);
            }
            gcry_sexp_release(tmp2);
        }
    }
    assert(sig_r && sig_s);
    
    sig_rs_string = malloc (2*(sig_r_len + sig_s_len)+1);
    p = sig_rs_string;
    *p = 0;
    for (i=0; i < sig_r_len; i++, p += 2)
        snprintf (p, 3, "%02x", sig_r[i]);
    for (i=0; i < sig_s_len; i++, p += 2)
        snprintf (p, 3, "%02x", sig_s[i]);
   
    printf("signature is %s\n", sig_rs_string);

    gcry_free(sig_r);
    gcry_free(sig_s);
    free(sig_rs_string);
}

int main (int argc, char **argv)
{
    gcry_sexp_t pk, sk, msg, sig;

    printf("\n[main] hi from main with libgcrypt v%s\n",
        gcry_check_version(NULL));

    /* See libgcrypt manual v1.6.3 Sect. 2.4
     * Allocate a pool of 16k secure memory. This make the secure memory
     * available and also drops privileges where needed.
     * NOTE: running in libgcrypt outputs "warning: using insecure memory", but
     * the secure flags are set on the MPIs anyway, so that the hardened
     * ec_mul_point version is executed.
     */
    gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, GCRY_DEBUG, 0);
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    GCRY_ASSERT( gcry_sexp_new (&pk, sample_pk, 0, 1) );
    dump_gcry_sexp(pk);
    GCRY_ASSERT( gcry_sexp_new (&sk, sample_sk, 0, 1) );
    dump_gcry_sexp(sk);
    GCRY_ASSERT( gcry_sexp_new (&msg, sample_msg, 0, 1) );
    dump_gcry_sexp(msg);

    #if VERIFY_KEY
        GCRY_ASSERT( gcry_pk_testkey(sk) );
        printf("pk_testkey verified correctly!\n");
    #endif

    #if DO_SYSDUMP
        syscall(SYSDUMP_NB, 0x0);
    #endif
    GCRY_ASSERT( gcry_pk_sign(&sig, msg, sk) );
    #if DO_SYSDUMP
        syscall(SYSDUMP_NB, 0x1);
    #endif

    dump_gcry_sexp(sig);
    dump_signature(sig);

    #if VERIFY_SIG
        GCRY_ASSERT( gcry_pk_verify(sig, msg, pk) );
        printf("signature verified correctly!\n");
    #endif

    gcry_sexp_release(pk);
    gcry_sexp_release(sk);
    gcry_sexp_release(msg);
    gcry_sexp_release(sig);

    printf("[main] all done!\n");
    return 0;
}
