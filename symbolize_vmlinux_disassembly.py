#!/usr/bin/env python3

import argparse
import bisect
import re
from sys import stdin


def symbol_by_addr(index, addr):
    if addr >= 0xffffffffffff0000:
        return None
    ind = bisect.bisect(index, (addr, '~'))
    if ind:
        entry = index[ind - 1]
        offset = addr - entry[0]
        return entry[1], offset
    return None


def symbol_by_addr_print(index, addr):
    res = symbol_by_addr(index, addr)
    if res is None:
        return None
    (symbol, offset) = res
    if offset:
        return '{}+0x{:x}'.format(symbol, offset)
    return symbol


def symbolize(disassembly, system_map_path):
    with open(system_map_path, 'r') as f:
        system_map = [(int(addr, 16), name) for (addr, _, name) in map(lambda x: x.split(), f)]
    pattern = re.compile('0xffffffff[0-9a-f]+')
    insn_addr = re.compile('([0-9a-f]+):')
    for line in disassembly:
        match = re.match(insn_addr, line)
        if match:
            addr = int(match[1], 16)
            sym = symbol_by_addr(system_map, addr)
            if sym and sym[1] == 0:
                print('\n{:08x} <{}>:'.format(addr, sym[0]))
        match = re.search(pattern, line)
        if match:
            addr = int(match[0], 16)
            desc = symbol_by_addr_print(system_map, addr)
            if desc:
                line = '{} <{}>{}'.format(line[0:match.end()], desc, line[match.end():])
        print(line, end='')


def main():
    parser = argparse.ArgumentParser(description='Symbolize vmlinux disassembly using System.map.')
    parser.add_argument('system_map_path', help='path to System.map file')
    parser.add_argument('input', nargs='?', help='path to disassembly file (stdin used if not present)')
    args = parser.parse_args()
    with (open(args.input, 'r') if args.input else stdin) as disassembly:
        symbolize(disassembly, args.system_map_path)


if __name__ == '__main__':
    main()
