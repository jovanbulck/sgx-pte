#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdlib.h>

#define SYSDUMP                 311
#define NB_MICROBENCHMARKS      10000

/*
 * asm_vars.S ensures these are allocated on different data pages.
 */
extern uint64_t a, b;

void maccess(void* p)
{
  asm volatile ("movq (%0), %%rax\n"
    :
    : "c" (p)
    : "rax");
}

void mdirty(void* p)
{
  asm volatile ("movq $1, (%0)\n"
    :
    : "c" (p)
    : "rax");
}

/*
 * Proof-of-concept function to show PTE caching behavior leaks secret-
 * dependent data accesses.
 */
void inc_input(int input)
{
    if (input)
        a++;
    else
        b++;
}

int rsa_n = 57677;
int rsa_e = 11;
int rsa_d = 20771; //16'b0101000100100011

void do_square_multiply(int input)
{
    int i, mask = 0x8000;
    int cipher = 65;
    long long res = 1;
    
    for (i=15; i >= 0; i--)
    {
        res = (res * res) % rsa_n;
        if (/*rsa_d*/ input & mask)
        {
            res = (res * cipher) % rsa_n;
            /* secret-dependent data access */
            maccess(&b);
        }
        mask = mask >> 1;

        /* access every loop iteration */
        maccess(&a);
        
        /* delay to allow IPI to arrive in time before the next iteration.. */
        for (int j = 0; j < 100; j++); //TODO
    }
}

int asm_microbenchmark(void* p);
void *asm_microbenchmark_slide;

int main(int argc, char ** argv)
{
    if (argc != 2) {
        printf("usage: helloworld <number>\n");
        return -1;
    }
    int in = strtol(argv[1], NULL, 0);

    printf("\n\nHello world from enclaved app binary with input %#x\n", in);
    printf("\t--> a at %p; b at %p; microbenchmark slide at %p\n", &a, &b,
        &asm_microbenchmark_slide);

    printf("calling asm_microbenchmark %d times..\n", NB_MICROBENCHMARKS);

    //XXX dry run to prevent page faults
    asm_microbenchmark(&a);

    int rv = 0;
    syscall(SYSDUMP, 0x0);
    for (int j=0; j < NB_MICROBENCHMARKS; j++)
        rv = asm_microbenchmark(&a);
    syscall(SYSDUMP, 0x1);

    printf("asm_microbenchmark returned %d\n", rv);

#if 0
    printf("calling do_square_multiply..\n");
    do_square_multiply(in);
    
    /* Custom system call to intra-enclave libOS. */
    int rv = syscall(SYSDUMP, 0xbeef);
    printf("SYSDUMP returned %d\n", rv);

    puts("accessing &a and &b");
    maccess(&a);
    maccess(&b);

    printf("conditionally incrementing with input=%d\n", in);
    inc_input(in);
    
    /*
     * Test whether our spy thread is accurate enough to separate successive
     * maccess/mdirty operations.
     */
    printf("maccess(&a); mdirty(&a)..\n");
    maccess(&a);
    mdirty(&a);
    
    /*
     * Test whether our spy thread is accurate enough to separate successive
     * maccess operations (requires timely IPI arrival).
     * TODO running the spy thread in kernel mode should (drastically) reduce
     * the amount of time needed to send the IPI..
     */
    printf("maccess(&a); maccess(&a)..\n");
    maccess(&a);
    for (int i=0; i<1000; i++);
    maccess(&a);
    
    for (int i = 0; i < 16; i++)
    {
        maccess(&a);
        
        for (int j = 0; j < 1000; j++);
    }
#endif
    
    return 0;
}
