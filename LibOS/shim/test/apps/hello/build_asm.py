#!/usr/bin/python3

import string

NB_INST     = 5000 #100000
ASM_INST    = "nop"
#ASM_INST    = "add $0x1, (counter_mem)"
#ASM_INST    = "add $0x1, %rax"

template = string.Template('''
    /* ====== auto generated asm code from Python script ======= */

    .data
    .global counter_mem
    counter_mem:
    .word 0x0

    .text
    .global asm_microbenchmark
    /* first parameter passed in %rdi */
    asm_microbenchmark:
    movq    $$0x0, (counter_mem)
    movq    $$0xdead, %rax
    movq    (%rdi), %rbx
    .text
    .global asm_microbenchmark_slide
    asm_microbenchmark_slide:
     $asmCode
    movq    (counter_mem), %rax
    retq
''')

asm = (ASM_INST + '\n') * NB_INST
code = template.substitute(asmCode=asm)

with open('asm.S', 'w') as the_file:
    the_file.write(code)
