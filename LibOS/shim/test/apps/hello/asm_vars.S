/* 
 * Manually align private enclave variables on different pages.
 * (NOTE: ensure a and b are sufficiently far apart so that their respective
 *  PTE entries do not fit together within a single cache line)
 */
	.data
	.global c
    .align 0x1000   /* 4KiB */
c:
    .space 0x200000

	.data
	.global a
    .align 0x1000   /* 4KiB */
a:
    .space 0x200000

    .data
    .global b
    .align 0x1000   /* 4KiB */
b:
    .space 0x100000
    
    .text
    .global call_b
    .align 0x1000   /* 4KiB */
call_b:
    retq
	.space 0x1000
