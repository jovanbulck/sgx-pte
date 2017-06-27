#!/usr/bin/python3
import re

INFILE          = 'measurements_raw.txt'
OUTFILE         = 'measurements.txt'
THRESHOLD       = 10000 

# XXX length of the slide instruction in bytes:
# nop                       1
# add $0x1, %rax            4
# add $0x1, (counter_mem)   8
INST_LEN        = 1

nz = 0

with open(INFILE, 'r') as fi, open(OUTFILE, 'w') as fo:
    for l in fi.readlines():
        m = re.search('offset=0x([0-9A-Fa-f]+)', l)
        if m:
            i = int(m.groups()[0], base=16) / INST_LEN
            if i < THRESHOLD:
                fo.write(str(i) + '\n')
                if i != 0:
                    nz += 1
            else:
                print('parse.py: filtering outlier {0}'.format(i))

print("parse.py: non-zero count={0}".format(nz))
