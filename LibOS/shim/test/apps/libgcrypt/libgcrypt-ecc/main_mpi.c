#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/syscall.h>
#define SYSDUMP     311

#define DO_SYSDUMP      1
#define USE_SECMEM      0

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

void dump_gcry_scalar(gcry_mpi_t s)
{
    unsigned char buf[100] = {0};

    GCRY_ASSERT( gcry_mpi_print(GCRYMPI_FMT_HEX, buf, 99, NULL, s) );
    printf("dump_gcry_scalar is %s (%d bits)\n", buf,
        gcry_mpi_get_nbits(s));
}

void dump_gcry_point(gcry_mpi_point_t p)
{
    gcry_mpi_t x = gcry_mpi_new(0);
    gcry_mpi_t y = gcry_mpi_new(0);
    gcry_mpi_t z = gcry_mpi_new(0);
    unsigned char buf[3][100] = {{0}, {0}, {0}};

    gcry_mpi_point_get(x, y, z, p);

    GCRY_ASSERT( gcry_mpi_print(GCRYMPI_FMT_HEX, buf[0], 99, NULL, x) );
    GCRY_ASSERT( gcry_mpi_print(GCRYMPI_FMT_HEX, buf[1], 99, NULL, x) );
    GCRY_ASSERT( gcry_mpi_print(GCRYMPI_FMT_HEX, buf[2], 99, NULL, x) );
    printf("dump_gcry_point is (%s, %s, %s)\n", buf[0], buf[1], buf[2] );

    gcry_mpi_release(x);
    gcry_mpi_release(y);
    gcry_mpi_release(z);
}

int main (int argc, char **argv)
{
    gcry_mpi_point_t point, res;
    gcry_mpi_t scalar;
    gcry_ctx_t ctx;
    int in;

    if (argc != 2) {
        printf("usage: %s <number>\n", argv[0]);
        return -1;
    }
    in = strtol(argv[1], NULL, 0);

    printf("\n[main] hi from main with libgcrypt v%s and input %#x\n",
        gcry_check_version(NULL), in);

    /* see libgcrypt manual v1.6.3 Sect. 2.4 */
    /* Allocate a pool of 16k secure memory. This make the secure memory
    available and also drops privileges where needed. */
    gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    /* see libgcrypt manual v1.6.3 Sects. 12.7, 14.2, 6.2.3 */
    res = gcry_mpi_point_new(0);
    GCRY_ASSERT( gcry_mpi_ec_new(&ctx, NULL, "Ed25519") )
    assert( point = gcry_mpi_ec_get_point("g", ctx, 0) );
    GCRY_ASSERT( gcry_mpi_scan(&scalar, GCRYMPI_FMT_HEX, argv[1], 0, NULL) );

#if USE_SECMEM
    /* tell libgcrypt to treat the scalar as confidential data */
    gcry_mpi_set_flag(scalar, GCRYMPI_FLAG_SECURE);
#endif

    dump_gcry_scalar(scalar);
    dump_gcry_point(res);

#if DO_SYSDUMP
    syscall(SYSDUMP, 0x0);
#endif
    gcry_mpi_ec_mul(res, scalar, point, ctx);
#if DO_SYSDUMP
    syscall(SYSDUMP, 0x1);
#endif

    dump_gcry_point(res);

    gcry_ctx_release(ctx);
    gcry_mpi_point_release(res);
    gcry_mpi_point_release(point);
    gcry_mpi_release(scalar);

    printf("[main] all done!\n");
    return 0;
}
