#!/usr/bin/python3
import gdb
from collections import Counter
import json

#XXX adjust to desired breakpoint (first line after for loop)
FOR_LOOP_BREAK  = 'ec.c:1296'

TRACE_FILE      = 'gdb_page_trace.txt'
COUNT_FILE      = 'gdb_page_count.txt'
PAGE_MASK       = 0xFFFFFFFFFFFFF000
NB_ITERATIONS   = 15

it_cnt = Counter()
it_nb_inst = 0

def trace_page(f, page, nb_inst, name):
    global it_nb_inst
    it_cnt[hex(page)] += 1
    it_nb_inst += nb_inst
    f.write('{0: <12}\t{1}\t{2}'.format(hex(page), nb_inst, name))

def trace_iteration(f, nb):
    f.write('\n' + '-' * 60 + '\n')
    f.write('ITERATION {0}\n'.format(nb))
    f.write('-' * 60 + '\n\n')

def trace_count(f, nb):
    global it_nb_inst
    d = dict(it_cnt)
    if '0x0' in d:
        del d['0x0']
    f.write('Page access counts:\n')
    f.write(json.dumps(d, indent=4, sort_keys=True))
    f.write('\n\nTotals:\n')
    f.write('    accessed pages = {0}\n'.format(len(d.keys())))
    f.write('    page trace length = {0}\n'.format(sum(d.values())))
    f.write('    executed instructions = {0}\n'.format(it_nb_inst))

with open(TRACE_FILE, 'w') as ft, open(COUNT_FILE, 'w') as fc:
    gdb.execute('file ./main')
    gdb.execute('b ' + FOR_LOOP_BREAK)
    #gdb.execute('layout asm')
    gdb.execute('run 0xdead')

    prev_pc_page = 0x0
    prev_pc_name = '<none>\n'
    nb_inst = 0
    bp = gdb.breakpoints()[0]

    for i in range(1, NB_ITERATIONS + 1):
        print('\nCollecting page access trace loop iteration {0}...'.format(i))
        trace_iteration(fc, i)
        trace_iteration(ft, i)
        ft.write('PAGE\t\tNB_INST\t\tNAME\n')

        it_cnt.clear()
        it_nb_inst = 0

        while bp.hit_count < i + 1:
            pc_str = gdb.execute('p $rip', to_string=True)
            pc_parts = pc_str.split(' ') 
            pc = int(pc_parts[4], base=16)
            pc_page = pc & PAGE_MASK
            try:
                pc_name = pc_parts[5]
            except IndexError:
                pc_name = '<gdb_idx_error>'

            if pc_page != prev_pc_page:
                trace_page(ft, prev_pc_page, nb_inst, prev_pc_name)
                nb_inst = 0
                prev_pc_page = pc_page
                prev_pc_name = pc_name

            gdb.execute('si', to_string=True)
            nb_inst += 1

        trace_page(ft, prev_pc_page, nb_inst, prev_pc_name)
        trace_count(fc, i)

print("\nDone! Results written to '{0}' and '{1}'.\n".format(
    TRACE_FILE, COUNT_FILE))
gdb.execute('q')
