#!/usr/bin/env python3
"""Resolve authenticated call slots around the RPC 502 environment helper."""

import argparse
import json
from pathlib import Path
import struct

from analyze_zut_trace import image_info
from audit_archived_iokit_open_retirement import THIN_SHA
from audit_daemon_iokit_retirement import (
    CS, Image, branch_census, fixups, instructions, select_bank,
)
from daemon_rpc502_context_probe import ContextProbe


POOL = 0x1010ab960
TABLE = 0x1010ab1a0
BANK_56 = (0x101032570, 0x101032670)
BANK_78 = (0x101032770, 0x101032870)
BANK_9A = (0x101032970, 0x101032a70)
BANK_BC = (0x101032b70, 0x101032c70)
HELPER = '0x100de1430'
DLSYM = 'libSystem/_dlsym'
EXPORT_NAMES = ['IWvA5fm4IwMS88oQXDANCS', 'JY0DfiUyFiVcNw89R4t']

CALLS = (
    (0x100de1794, BANK_9A, 0x5e, 2, 0x9a, 0xc052, 'libSystem/_sysctlbyname'),
    (0x100de189c, BANK_78, 0x6a, 0xc6, 0xcc, 0xc052, '0x100ddc63c'),
    (0x100de1a2c, BANK_9A, 0xd5, 0x6b, 0xcc, 0xc052, '0x100ddc63c'),
    (0x100de1ab0, BANK_9A, 0x5e, 0x3b, 0xd3, 0x19ad, 'libSystem/_puts'),
    (0x100de1b58, BANK_BC, 0x2b, 0x56, 0xca, 0xc052, 'libSystem/_dlopen'),
    (0x100de1c2c, BANK_BC, 0x2b, 0x67, 0xdb, 0x19ad, DLSYM),
    (0x100de1d30, BANK_56, 0xb7, 0xb1, 0xdb, 0x19ad, DLSYM),
    (0x100de7a8c, BANK_BC, 0x2c, 0x62, 0xe7, 0x19ad, HELPER),
    (0x100de7f7c, BANK_BC, 0x27, 0x40, 0xeb, 0xc052, '0x100de574c'),
    (0x100de8540, BANK_BC, 0x56, 0x99, 0xe7, 0x19ad, HELPER),
)

SELECTOR_SITES = (
    (0x100de170c, 0x100de1728), (0x100de1870, 0x100de188c), (0x100de1a08, 0x100de1a1c),
    (0x100de1a64, 0x100de1a78), (0x100de1af0, 0x100de1b10), (0x100de1bc8, 0x100de1be0),
    (0x100de1cd4, 0x100de1cec), (0x100de7a5c, 0x100de7a78), (0x100de7f10, 0x100de7f24),
    (0x100de8514, 0x100de8530),
)

PROVENANCE = {
    0x100de57f4: 'ldp x12, x14, [x26, #0x168]',
    0x100de5934: 'ldr x11, [x26, #0xb0]',
    0x100de5938: 'sub x12, x11, #0xc',
    0x100de5978: 'sub w8, w8, #0xf1',
    0x100de5984: 'str x8, [sp, #0x58]',
    0x100de6b00: 'mov x28, x14',
    0x100de6b04: 'mov x26, x12',
    0x100de6bac: 'stp x26, x28, [sp, #0x28]',
    0x100de7a50: 'ldr x10, [sp, #0x30]',
    0x100de7a64: 'ldr x11, [sp, #0x28]',
    0x100de7a7c: 'ldr x22, [sp, #0x58]',
    0x100de7a84: 'sub x0, x29, #0x78',
    0x100de7a94: 'ldur w24, [x29, #-0x74]',
    0x100de815c: 'sub w8, w8, #0x4c',
    0x100de8164: 'sub x1, x8, #0xc',
    0x100de82b0: 'mov x22, x19',
    0x100de8428: 'ldr x26, [x23, #0x170]',
    0x100de843c: 'ldr x12, [x23, #0xb0]',
    0x100de8440: 'sub x12, x12, #0xc',
    0x100de8444: 'str x12, [sp, #8]',
    0x100de851c: 'ldr x10, [sp, #8]',
    0x100de8538: 'sub x0, x29, #0x78',
    0x100de8544: 'ldur w28, [x29, #-0x74]',
    0x100de158c: 'ldr w12, [x0]',
    0x100de1598: 'stp x0, x10, [sp, #0x40]',
    0x100de1df4: 'ldr x9, [sp, #0x40]',
    0x100de1df8: 'str w8, [x9, #4]',
}


def audit_calls(path):
    identity = image_info(path)
    assert identity['sha256'] == THIN_SHA and identity['uuid'] == '204741e9-b89f-32b4-9321-51f3975c7cac'
    image = Image(path)
    fixup = fixups(path)
    for offset, expected in ((0x10, TABLE + 12), (0x170, BANK_BC[0]), (0xb0, BANK_BC[1] + 12)):
        assert fixup[POOL + offset]['target'] == hex(expected)
    base_checks = []
    for left, right, key, add in ((*BANK_78, 0x60, -0xf1), (*BANK_BC, 0x56, -0x4c),
                                  (*BANK_BC, 0x2b, -0x72)):
        index, bank = select_bank(image, left, right, key, add)
        assert index == 2
        base_checks.append(bank)
    provenance = {}
    for address, expected in PROVENANCE.items():
        row, = instructions(image, address, 4)
        assert row['mnemonic'] + ' ' + row['operands'] == expected, row
        provenance[hex(address)] = row

    code = next(section for section in identity['text_sections'] if section['section'] == '__text')
    base = int(code['address'], 16)
    sites, stubs = branch_census(image.read(base, code['size']), base)
    selected = {modifier: [] for modifier in (0x19ad, 0xc052)}
    calls = {}
    for call, selector in zip(CALLS, SELECTOR_SITES, strict=True):
        pc, banks, key, add, expected_index, modifier, target = call
        key_word, = instructions(image, selector[0], 4)
        add_word, = instructions(image, selector[1], 4)
        assert key_word['mnemonic'] == 'mov' and int(key_word['operands'].split('#')[-1], 0) == key, key_word
        assert add_word['mnemonic'] == 'add' and int(add_word['operands'].split('#')[-1], 0) == add, add_word
        index, proof = select_bank(image, *banks, key, add)
        assert index == expected_index
        slot = TABLE + 8 * index
        rec = fixup[slot]
        word, = struct.unpack('<Q', image.read(slot, 8))
        assert (rec['target'], rec['modifier'], rec['address_diversity'], rec['key']) == (
            target, modifier, 0, 'IA')
        assert word >> 63 == 1 and (word >> 32) & 0xffff == modifier and (word >> 48) & 7 == 0
        if rec['kind'] == 'auth-rebase':
            assert (word >> 62) & 1 == 0 and (word & 0xffffffff) + 0x100000000 == int(target, 16)
        else:
            assert rec['kind'] == 'auth-bind' and (word >> 62) & 1 == 1
        word_moves, branch = instructions(image, pc - 4, 8)
        assert word_moves['operands'] == f'x17, #{modifier:#x}'
        assert branch['mnemonic'] == 'blraa' and branch['operands'].endswith(', x17')
        selected[modifier].append(hex(pc))
        calls[hex(pc)] = {'bank': proof, 'slot': hex(slot), 'original_word': hex(word), 'target': target,
                          'branch': branch, 'selector_key': key_word, 'selector_addend': add_word,
                          'conditional_bank_roots': pc == 0x100de7a8c}
    assert selected[0xc052] == sites[0xc052]
    assert len(set(sites[0x19ad]) - set(selected[0x19ad])) == 15
    for addr in set(sites[0x19ad]) - set(selected[0x19ad]):
        word, = CS.disasm(image.read(int(addr, 16), 4), int(addr, 16))
        assert word.mnemonic == 'braa'
    return {'sha256': identity['sha256'], 'uuid': identity['uuid'], 'text_bytes': code['size'],
            'calls': calls, 'provenance': provenance, 'table_base_selectors': base_checks,
            'remaining_19ad_tail_branches': sorted(set(sites[0x19ad]) - set(selected[0x19ad])),
            'direct_stub_calls': stubs}


class HelperProbe(ContextProbe):
    def __init__(self, value, status):
        super().__init__(model_once=True, model_heap=True, model_locks=True,
                         sysctl_vmm=value, sysctl_status=status)
        self.model_loader = True
        self.wrapper_frame = None
        self.frame_result = None

    def hook(self, u, address, size, user):
        if address == 0x100de8540:
            assert self.wrapper_frame is None and self.reg(8) == int(HELPER, 16)
            assert self.reg(22) == TABLE and self.reg(0) == self.reg(29) - 0x78
            self.wrapper_frame = self.reg(0)
        if address == 0x100de8544:
            assert self.wrapper_frame == self.reg(29) - 0x78
            self.frame_result, = struct.unpack('<I', u.mem_read(self.wrapper_frame + 4, 4))
        return super().hook(u, address, size, user)


def audit_replays():
    cases = []
    for value, status in ((0, 0), (1, 0), (1, -1)):
        probe = HelperProbe(value, status)
        result = probe.run()
        assert result['source_sha256'] == THIN_SHA
        sysctl, = (r for r in probe.records if r.get('name') == 'libSystem/_sysctlbyname')
        assert (sysctl['return_pc'], sysctl['return_value']) == ('0x100de1798', status)
        query, = (r for r in probe.records if r['kind'] == 'sysctl_call_boundary')
        assert query['name_ascii'] == 'kern.hv_vmm_present'
        assert query['old_capacity_bytes'] == 4 and int(query['new_pointer'], 16) == query['new_size'] == 0
        observed = [r['string_argument'] for r in probe.records if r.get('name') == DLSYM]
        puts = [r['return_pc'] for r in probe.records if r.get('name') == 'libSystem/_puts']
        diagnostic = value == 1 and status == 0
        assert probe.frame_result == (0x2e3bd2ce if diagnostic else 0xd1c48a3f)
        assert observed == ([] if diagnostic else EXPORT_NAMES)
        assert puts == (['0x100de1ab4'] if diagnostic else [])
        assert not result['native_target_executed']
        assert not result['target_host_ipc_files_or_system_calls_executed']
        cases.append({'sysctl_output_fixture': value, 'sysctl_status_fixture': status,
                      'helper_call': '0x100de8540', 'helper_target': HELPER,
                      'frame_result_u32': hex(probe.frame_result), 'loader_export_queries': observed,
                      'sysctl_name': query['name_ascii'], 'diagnostic_call': diagnostic})
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('daemon', type=Path)
    args = parser.parse_args()
    print(json.dumps({'original': audit_calls(args.daemon), 'replays': audit_replays()},
                     indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
