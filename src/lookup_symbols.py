#!/usr/bin/env ptython3

import os

system_map_fname = os.getenv("LINUX_SYSTEM_MAP")
assert system_map_fname and "Specify the LINUX_SYSTEM_MAP env var with the path to your current kernel system map"

try:
    fd = open(system_map_fname)
except:
    raise RuntimeError(system_map_fname + ' not found, please specify another system map file using the LINUX_SYSTEM_MAP env var')

system_map = map(lambda x: x.split(), fd.read().split('\n'))

register_chrdev_region = None
sys_call_table = None
__x64_sys_read = None
__x64_sys_write = None
flush_tlb_mm_range = None
zap_page_range = None
_etext = None

for e in system_map:
    if len(e) < 3: continue
    if e[2] == 'register_chrdev_region':
        register_chrdev_region = int(e[0], 16)
    elif e[2] == 'sys_call_table':
        sys_call_table = int(e[0], 16)
    elif e[2] == '__x64_sys_read':
        __x64_sys_read = int(e[0], 16)
    elif e[2] == '__x64_sys_write':
        __x64_sys_write = int(e[0], 16)
    elif e[2] == 'flush_tlb_mm_range':
        flush_tlb_mm_range = int(e[0], 16)
    elif e[2] == 'zap_page_range':
        zap_page_range = int(e[0], 16)
    elif e[2] == '_etext':
        _etext = int(e[0], 16)

assert register_chrdev_region != None
assert sys_call_table != None
assert __x64_sys_read != None
assert __x64_sys_write != None
assert flush_tlb_mm_range != None
assert zap_page_range != None
assert _etext != None

with open('symbols.h', 'w') as f:
    f.write('''#ifndef __AFL_SNAPSHOT_SYMBOLS_H__
#define __AFL_SNAPSHOT_SYMBOLS_H__

#define SYMADDR(offset) ((unsigned long)register_chrdev_region - \\
                         0x%x + (offset))

#define SYMADDR_sys_call_table SYMADDR(0x%x)
#define SYMADDR___x64_sys_read SYMADDR(0x%x)
#define SYMADDR___x64_sys_write SYMADDR(0x%x)
#define SYMADDR_flush_tlb_mm_range SYMADDR(0x%x)
#define SYMADDR_zap_page_range SYMADDR(0x%x)
#define SYMADDR__etext SYMADDR(0x%x)

#endif
''' % (register_chrdev_region, sys_call_table, __x64_sys_read, __x64_sys_write, flush_tlb_mm_range, zap_page_range, _etext))
