#!/usr/bin/env python3
"""Check the installed early node and data allocation handoffs."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path

from audit_daemon_iokit_native_registry import command, sysctl
from audit_live_fairplay_cf_receive import assert_instructions
from audit_live_fairplay_connection_retirement import verify_fixup
from audit_live_fairplay_context_lifecycle import CODE_DELTA, POOL, TABLE, read_descriptor, replay_proof
from audit_live_fairplay_early_header import HeaderReplay, NODE_CALL, NODE_TYPE, SUCCESS
from audit_live_fairplay_entry import verify_layout
from audit_live_fairplay_uidlist import receipt
from audit_live_kext_selector26 import Collection, IDENTITIES

CHECKS = {
    'early_node': '3376d0d190a8232484d92074e75335086aabaffe545e590388bcc886a83f79bb',
    'early_data': '1528647bc86b5a33d1da3bb156346aa0b30b46e5f8cc44437f3b00a61b8bd7bb',
}
AUDITS = {
    'early_node': 'd6b3b0f4b052311c33d374105c862ac7e21547f524bd327f163186553d292265',
    'early_data': 'c2a584dacc8d8d909b28406d10179bb05f649ddf1169264026b9554da299fb3d',
}
DATA_CALL = 0xfffffe000a6a29d8
WRITER = 0xfffffe000a695c64
WRITER_CUT = 0xfffffe000a695c74
NODE_FREE = 0xfffffe000a6a5374
FREE_TYPE = 0xfffffe0008492a40


class DataReplay(HeaderReplay):
    """Continue through the archived node and data register returns."""

    def allocation(self, word, archived):
        if self.pc not in (NODE_CALL, DATA_CALL):
            return super().allocation(word, archived)
        assert word.mnemonic == 'blraa'
        target = self.reg(word.reg_name(word.operands[0].reg))
        length = int.from_bytes(self.payload[6:10], 'big')
        if self.pc == NODE_CALL:
            name, argument, modifier = '_IOMallocTypeImpl', NODE_TYPE, 0xd0c8
            result = self.input['node_result_fixture']
            assert result
        else:
            name, argument, modifier = '_IOMallocData', length + 10, 0xca0c
            result = self.input['data_result_fixture']
            S, C, _, node = (int(cut['result'], 16) for cut in self.cuts)
            assert self.value(node, 16) == 0
            assert self.value(node + 0x10, 4) == length + 10
            assert self.value(S + 0xca8, 8) == 0x622f763938943e93 + length
            assert self.value(C + 0x58, 8) == node
            assert not any(a in self.state for a in range(node + 0x14, node + 0x20))
        assert (target, self.g[0], self.g[17]) == (self.image.named(name), argument, modifier)
        assert archived['target_executed'] is False and archived['model_memory_writes'] == 0
        assert result == int(archived['result_X0_fixture'], 16)
        self.cuts.append(dict(pc=hex(self.pc), target=hex(target), name=name,
                              arguments=[hex(argument)], result=hex(result)))
        self.g[0] = result
        for j in range(1, 18):
            self.g[j] = 0xf000000000000000 + j * 0x1111
        self.nzcv = 0xf0000000
        self.g[30] = self.pc + 4
        return self.pc + 4

    def writer_cells(self, S, C):
        rows = []
        for previous in self.row['writer_input_cells']:
            pc = int(previous['source_PC'], 16) + CODE_DELTA
            root = previous['root']
            offset = int(previous['offset'], 16)
            width = previous['size_bytes']
            word, = self.cs.disasm(self.image.read(pc, 4), pc)
            assert word.mnemonic == ('ldrh' if width == 2 else 'ldr')
            assert word.reg_name(word.operands[0].reg).startswith('x' if width == 8 else 'w')
            mem = word.operands[1].mem
            assert word.reg_name(mem.base) == ('x3' if root == 'S' else 'x11')
            assert not mem.index and mem.disp == offset
            address = (S if root == 'S' else C) + offset
            assert address == int(previous['address'], 16)
            mask = bytes(int(address + j in self.state) for j in range(width))
            assert mask.hex() == previous['known_mask_hex']
            rows.append(dict(pc=hex(pc), root=root, offset=hex(offset), size_bytes=width,
                             source_defined_bytes=sum(mask)))
        assert len(rows) == 12
        assert sum(row['size_bytes'] for row in rows) == 64
        assert sum(row['source_defined_bytes'] for row in rows) == 18
        return rows

    def verify_boundary(self, source, extent):
        S, C, container, node, data = (int(cut['result'], 16) for cut in self.cuts)
        length = self.input['wire_length32']
        assert (source, extent) == (self.base, self.extent)
        assert self.value(C + 0x20, 8) == container
        assert self.value(C + 0x58, 8) == node
        assert self.value(S + 0xa10, 8) == 10 + length
        assert self.value(node, 16) == 0
        assert self.value(node + 0x10, 4) == 10 + length
        assert self.value(node + 0x18, 8) == data
        assert not any(a in self.state for a in range(node + 0x14, node + 0x18))
        base = int(self.row['earlier_data']['address'], 16)
        assert not any(a in self.state for a in range(base, base + 64))
        expected_reads = [6, 7, 8, 9, 0, 1, 2, 3, 4, 5]
        if self.input['wire_type16'] in (0x9777, 0x8485):
            expected_reads.extend(range(10, 10 + length))
        assert self.input_loads == expected_reads

        result = dict(pc=hex(self.pc), source_defined_node_bytes=28,
                      requested_size_bytes=length + 10, source_written_data_bytes=0)
        if data:
            assert self.pc == WRITER_CUT and self.g[16] == node + 0x18
            assert self.g[3] == S and self.g[11] == C
            assert self.g[1] == SUCCESS and self.g[23] == self.input['wire_tag32'] ^ 0x2502309f
            edge = self.edges[-1]
            assert edge['target'] == hex(WRITER) and edge['modifier64'] == '0xdfc5'
            result.update(kind='writer_setup', pointer_cell=hex(self.g[16]),
                          required_cells=self.writer_cells(S, C))
        else:
            assert self.pc == NODE_FREE and self.g[:2] == [FREE_TYPE, node]
            instr, = self.cs.disasm(self.image.read(self.pc, 4), self.pc)
            assert instr.mnemonic == 'blraa' and self.g[17] == 0x4d6a
            assert self.reg(instr.reg_name(instr.operands[0].reg)) == self.image.named('_IOFreeTypeImpl')
            result.update(kind='node_retirement_request', descriptor=hex(FREE_TYPE))
        return result


def check_bindings(image, node, data):
    specs = (
        (node['data_allocation_bank'], (0x840, 0xbb8, 0), TABLE, image.named('_IOMallocData')),
        (data['bank_rules'][0], (0x840, 0xbb8, 0), TABLE, image.named('_IOFreeTypeImpl')),
        (data['bank_rules'][1], (0x4f0, 0x578, -4), POOL, FREE_TYPE),
    )
    rules = []
    for row, (left, right, bias), base, target in specs:
        banks = []
        roots = []
        for offset in (left, right):
            address = int(image.pointer(POOL + offset)['target'], 16)
            roots.append(verify_fixup(image, POOL + offset, address))
            banks.append(image.read(address + bias, 256))
        L, R = banks
        if 'left256_hex' in row:
            assert L.hex() == row['left256_hex'] and R.hex() == row['right256_hex']
        key = int(row['key'], 16)
        constant, = {x ^ R[L[x] ^ key] for x in range(256)}
        index = constant + int(row['additive'], 16)
        assert constant == int(row['constant'], 16) and index == int(row['index'], 16)
        assert int(row['bias'], 16) == 0
        fixup = verify_fixup(image, base + 8 * index, target, row['original_pointer']['diversity'])
        rules.append(dict(index=hex(index), constant=hex(constant), roots=roots, fixup=fixup))
    alloc = read_descriptor(image, NODE_TYPE, 'site.FPTTLVNode', '1121', 32)
    free = read_descriptor(image, FREE_TYPE, 'site.FPTTLVNode', '1121', 32)
    return dict(rules=rules, allocate=alloc, retire=free, raw_type_images_match=alloc['bytes'] == free['bytes'])


def check_wrappers(image):
    typed, lower, data = map(image.named, ('_IOMallocTypeImpl', '_kalloc_type_impl', '_IOMallocData'))
    assert (typed, lower, data) == (0xfffffe000c509774, 0xfffffe000bd46a80, 0xfffffe000c509c2c)
    return assert_instructions(image.read, (
        (typed + 4, 'ldr', 'w8, [x0, #0x28]'),
        (typed + 8, 'tst', 'w8, #0x10'),
        (typed + 12, 'mov', 'w8, #4'),
        (typed + 16, 'mov', 'w9, #0x8004'),
        (typed + 20, 'csel', 'w1, w9, w8, eq'),
        (typed + 24, 'b', '#0xfffffe000bd46a80'),
        (lower + 24, 'and', 'w10, w1, #7'),
        (data + 16, 'mov', 'x19, x0'),
        (data + 20, 'adrp', 'x0, #0xfffffe0007f98000'),
        (data + 24, 'add', 'x0, x0, #0x788'),
        (data + 28, 'mov', 'x1, x19'),
        (data + 32, 'mov', 'w2, #0x1000'),
        (data + 36, 'movk', 'w2, #3, lsl #16'),
        (data + 40, 'mov', 'x3, #0'),
        (data + 44, 'bl', '#0xfffffe000bd464ac'),
    ))


def audit(path):
    build = command('sw_vers', '-buildVersion').strip().decode()
    assert build == '26C5035r' and sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    image = Collection(path, IDENTITIES[1])
    archived = {name: receipt(f'userclient_{name}_checks', digest) for name, digest in CHECKS.items()}
    assert all(row['kernel_collection_sha256'] == IDENTITIES[0][0] for row in archived.values())
    node = archived['early_node']['source']
    data = archived['early_data']['source']
    spans = [span for span in node['spans'] if span['label'].startswith('source_')]
    layout = verify_layout(image, {'early_node': dict(node, spans=spans), 'early_data': data})
    bindings = check_bindings(image, node, data)
    lower = check_wrappers(image)
    cases = [DataReplay(image, row).replay() for row in archived['early_data']['cases']
             if row['input']['declared_size64'] <= 0xffffffff]
    assert len(cases) == 48
    proofs = []
    for name, digest in AUDITS.items():
        prior = receipt(f'userclient_{name}_audit', digest)
        assert prior['checks_sha256'] == CHECKS[name]
        group = prior['source_proofs']
        if name == 'early_node':
            group = group[:4]
        proofs.extend(group)
    assert len(proofs) == 13
    with ThreadPoolExecutor(max_workers=4) as workers:
        replays = list(workers.map(replay_proof, proofs))
    return dict(build=build, identity=IDENTITIES[1], historical_checks=CHECKS, historical_audits=AUDITS,
                layout=layout, bindings=bindings, lower_wrappers=lower, cases=cases, source_proofs=replays,
                native_transaction_observed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    print(json.dumps(audit(parser.parse_args().collection), indent=2))
