#!/usr/bin/env python3
"""Replay installed FPMessage formation through the common-parser boundary."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from copy import copy
from functools import partial
from hashlib import sha256
import json
from pathlib import Path

from audit_daemon_iokit_native_registry import command, sysctl
from audit_live_fairplay_cf_receive import assert_instructions
from audit_live_fairplay_connection_retirement import verify_fixup
from audit_live_fairplay_context_lifecycle import POOL, POOL_ROOTS, TABLE, read_descriptor, replay_proof
from audit_live_fairplay_early_publication import PROOF_TIMEOUT_SECONDS
from audit_live_fairplay_entry import CONTROLLERS, in_private, shifted, verify_layout
from audit_live_fairplay_message_attributes import (
    ATTR_SUCCESS, CHECKS as ATTRIBUTE_CHECKS, U64, AttributeReplay, attribute_cases, verify_attribute_source,
)
from audit_live_fairplay_shared_table import EXTRA_BANKS
from audit_live_fairplay_uidlist import receipt
from audit_live_kext_selector26 import Collection, IDENTITIES

CHECKS = 'ee8476cd7d45c03decdb7b7c0262a92b996c4f0ee7bdd2edc86aaf6666c86c61'
AUDIT = 'd617ec6a8652f52a94965058f3279b8b4d4c776e0cb9f164e20e8428a32d4144'
INSTALLED_ATTRIBUTE = 'c30355bdca35f59d4cb55aac427786a335bdfeab2b64e5be8e23a6ecc8ac2a6e'
MESSAGE = 0x630001e000
PARSER = shifted('0xfffffe000a636338')
ERROR = shifted('0xfffffe000a6621e4')
ZERO = shifted('0xfffffe000a687d64')
ZERO_CALL = shifted('0xfffffe000a657648')
ALLOCATE_CALL = shifted('0xfffffe000a657758')
DESCRIPTOR = 0xfffffe0008492000
BANK_NAMES = {
    'clear': ('AL', 'AR'), 'allocate': ('FL', 'FR'), 'descriptor': ('UL', 'UR'),
    'mask1': ('AL', 'AR'), 'mask2': ('VL', 'VR'), 'mask3': ('FL', 'FR'),
}
MASK_TARGETS = {'mask1': 0xfffffe00079501e4, 'mask2': 0xfffffe000794cb4c, 'mask3': 0xfffffe000793c324}
CONTEXT_STORES = {
    shifted(hex(0xfffffe0000000000+pc)): (root, offset, width)
    for pc, root, offset, width in [
        (0xa6575c4, 'C', 0x5d0, 8), (0xa6575c8, 'C', 0x430, 8),
        (0xa6575cc, 'S', 0x150, 4), (0xa6575d4, 'C', 0x498, 8),
        (0xa6575d8, 'C', 0xa8, 8), (0xa6575dc, 'C', 0x620, 8),
        (0xa6575e0, 'C', 0x6b0, 8), (0xa6575e4, 'S', 0x18, 4),
        (0xa6575e8, 'S', 0xa60, 4), (0xa6575ec, 'C', 0x380, 8),
        (0xa657794, 'C', 0x788, 8), (0xa653898, 'C', 0x448, 8),
        (0xa6538a8, 'F', 0x9e0, 4), (0xa6538dc, 'F', 0x480, 4),
        (0xa6538ec, 'F', 0x9d0, 8), (0xa656b98, 'C', 0x718, 8),
        (0xa656b9c, 'C', 0x18, 8), (0xa656bcc, 'S', 0xc8, 4),
        (0xa656bd0, 'S', 0x1e0, 4), (0xa641b1c, 'S', 0xab8, 4),
    ]
}


def verify_source(image, checks, allocate):
    source = checks['source']
    layout = verify_layout(image, {'message': source})
    spans = layout['spans']['message']
    assert len(spans) == 24 and sum(s['words'] for s in spans) == 628
    assert len(layout['branch_fixups']) == 25
    relocated = [
        (0xfffffe000a6988d4, 'adrp', 'x10, #0xfffffe0008488000'),
        (0xfffffe000a6988d8, 'add', 'x10, x10, #0x9a0'),
        (0xfffffe000a694d64, 'adrp', 'x25, #0xfffffe0008488000'),
        (0xfffffe000a694d68, 'add', 'x25, x25, #0x9a0'),
    ]
    assert [int(w['address'], 16) for s in spans for w in s['changes']] == [x[0] for x in relocated]
    layout['pool_relocations'] = assert_instructions(image.read, relocated)
    zero = checks['zero_helper_envelope']
    raw = bytes.fromhex(zero['bytes_hex'])
    assert len(raw) == 360 and sha256(raw).hexdigest() == zero['sha256']
    assert image.read(ZERO, len(raw)) == raw
    layout['zero'] = dict(start=hex(ZERO), words=90, sha256=zero['sha256'])

    roots = {name: (slot, target, bias)
             for slot, (target, name, bias) in (POOL_ROOTS | EXTRA_BANKS).items()}
    targets = dict(clear=ZERO, allocate=allocate, descriptor=DESCRIPTOR, **MASK_TARGETS)
    bank_bases, bindings, root_fixups = {}, {}, {}
    for row in checks['message_bank_rules']:
        name = row['name']
        arrays = []
        for side, key in zip(('L', 'R'), BANK_NAMES[name], strict=True):
            slot, target, bias = roots[key]
            record = checks['message_banks'][name+'_'+side]
            data = image.read(target+bias, 256)
            assert data.hex() == record['bytes_hex']
            arrays.append(data)
            bank_bases[int(record['address'], 16)] = target+bias
            root_fixups[key] = verify_fixup(image, POOL+slot, target)
        left, right = arrays
        key = int(row['key'], 16)
        constant, = {i ^ right[left[i] ^ key] for i in range(256)}
        index = constant + int(row['additive'], 16)
        assert (constant, index) == (int(row['constant'], 16), int(row['index'], 16))
        pointer = row['original_pointer']
        slot = (TABLE if pointer['authenticated'] else POOL)+8*index
        target = (targets[name]-int(row['bias'], 16)) & U64
        bindings[name] = verify_fixup(image, slot, target, pointer['diversity'])
    assert bindings.keys() == targets.keys()
    arrays = []
    for row, bias in zip(checks['message_mask_arrays'], (-4, -6, 0), strict=True):
        address = MASK_TARGETS[row['name']] + bias
        data = image.read(address, 16)
        assert data.hex() == row['bytes_hex']
        arrays.append(data)
    mask = bytes(((-0x37*(i-15)-0x39)&255)^a^b^c^0x70
                 for i, (a,b,c) in enumerate(zip(*arrays, strict=True)))
    assert mask.hex() == checks['message_mask16_hex']
    descriptor = read_descriptor(image, DESCRIPTOR, 'site.FPMessage', '1122222222222222', 128)
    old = bytes.fromhex(checks['message_descriptor']['normalized64_bytes_hex'])
    current = bytes.fromhex(descriptor['bytes'])
    assert current[:16] == old[:16] and current[24:32] == old[24:32] and current[40:] == old[40:]
    layout.update(banks=root_fixups, bank_selections=bindings, mask16_hex=mask.hex(), descriptor=descriptor)
    allowed = {shifted(word['pc']) for span in source['spans'] for word in span['instructions']}
    return layout, allowed, bank_bases, mask


class MessageReplay(AttributeReplay):
    message_reads = None

    def condition(self, name):
        if name == 'gt':
            return not (self.nzcv & (1 << 30)) and bool(self.nzcv & (1 << 31)) == bool(self.nzcv & (1 << 28))
        return super().condition(name)

    def step(self, word):
        mnemonic, ops = word.mnemonic, word.operands
        if mnemonic in ('cbz', 'cbnz'):
            value = self.operand(word, ops[0])
            take = (value == 0) == (mnemonic == 'cbz')
            return (ops[1].imm & U64) if take else self.pc+4
        if mnemonic in ('ldr', 'str', 'strb') and word.writeback and len(ops) == 3:
            register = word.reg_name(ops[0].reg)
            base = word.reg_name(ops[1].mem.base)
            width = 1 if mnemonic == 'strb' else 4 if register.startswith('w') else 8
            address = self.reg(base)
            assert ops[1].mem.disp == 0 and not ops[1].mem.index
            if mnemonic == 'ldr':
                self.set(register, self.load(address, width))
            else:
                self.store(address, width, self.reg(register))
            self.set(base, address+ops[2].imm)
            return self.pc+4
        if mnemonic in ('neg', 'ubfx', 'bfxil', 'madd', 'subs'):
            dest = word.reg_name(ops[0].reg)
            width = 32 if dest.startswith('w') else 64
            a = self.operand(word, ops[1], width)
            if mnemonic == 'neg':
                value = -a
            elif mnemonic == 'ubfx':
                value = (a >> ops[2].imm) & ((1 << ops[3].imm)-1)
            elif mnemonic == 'bfxil':
                mask = (1 << ops[3].imm)-1
                value = (self.reg(dest) & ~mask) | ((a >> ops[2].imm) & mask)
            elif mnemonic == 'madd':
                value = a*self.operand(word, ops[2], width)+self.operand(word, ops[3], width)
            else:
                b = self.operand(word, ops[2], width)
                sign = 1 << (width-1)
                value = (a-b) & (2*sign-1)
                self.nzcv = ((value >> (width-1)) << 31) | ((value == 0) << 30)
                self.nzcv |= ((a >= b) << 29) | (bool((a^b)&(a^value)&sign) << 28)
            self.set(dest, value)
            return self.pc+4
        return super().step(word)

    def load(self, address, width, discarded=False):
        value = super().load(address, width, discarded)
        if self.message_reads is not None and self.attr <= address < self.attr+112:
            assert not discarded and address+width <= self.attr+112
            self.message_reads.append((self.pc, address-self.attr, width, value))
        return value

    def clear(self, dest, link):
        assert self.pc == ZERO and self.g[0] == dest and self.g[1] == 0 and self.g[2] == 32
        before = len(self.publication_stores)
        saved, sp = self.g[19:31], self.sp
        sites = []
        while self.pc != link:
            assert len(sites) < 150 and ZERO <= self.pc < ZERO+360
            sites.append(hex(self.pc))
            self.ix += 1
            word, = self.cs.disasm(self.image.read(self.pc, 4), self.pc)
            self.pc = self.step(word)
        assert self.g[19:31] == saved and self.sp == sp
        assert self.g[0] == dest+(31 if dest & 7 else 32)
        stores = self.publication_stores[before:]
        addresses = []
        for _, addr, width, value in stores:
            assert value == '0x0'
            addresses.extend(range(int(addr, 16), int(addr, 16)+width))
        assert sorted(addresses) == list(range(dest, dest+32))
        return dict(alignment=dest & 7, instruction_visits=len(sites), sites=sites, stores=stores,
                    return_delta=self.g[0]-dest)

    def check_alignments(self):
        cases = []
        for alignment in range(8):
            r = copy(self)
            r.g, r.state = self.g.copy(), self.state.copy()
            r.private_writes, r.edges, r.publication_stores = [], [], []
            dest, link = 0x630001e800+alignment, ZERO_CALL+4
            assert not any(dest+i in self.state for i in range(32))
            r.g[:3] = [dest, 0, 32]
            r.g[30], r.pc = link, ZERO
            cases.append(r.clear(dest, link))
        assert len({site for case in cases for site in case['sites']}) == 80
        return cases

    def initialize(self, allowed, roots, archive, mask, allocate, success, attribute):
        F = self.sp
        S, C, H, J, Z = (int(cut['result'], 16) for cut in self.cuts)
        assert self.pc == ATTR_SUCCESS and self.g[8] == C+0x360
        self.attr = A = self.value(C+0x1b0, 8)
        assert A == int(attribute['attribute_address'], 16)
        I, encoded = self.g[20], self.g[22]
        assert I == int(archive['original_input64'], 16) and encoded == archive['original_extent32'] ^ 0x31ae0066
        assert archive['original_extent32'] == 14
        assert len(archive['message_additional_source_cells']) == 5
        for cell in archive['message_additional_source_cells']:
            offset = int(cell['offset'], 16)
            old = int.from_bytes(bytes.fromhex(cell['reconstructed_bytes_hex']), 'little')
            assert cell['size_bytes'] == 8
            expected = CONTROLLERS[1] if offset == 0xa38 else roots.get(old, old)
            assert self.value(F+offset, 8) == expected
        assert self.value(F+0x3e8, 8) == S+0xcc8
        assert in_private(MESSAGE, 128) and not any(MESSAGE+i in self.state for i in range(128))
        M = MESSAGE if success else 0
        holes = {0x52, 0x53, 0x6d, 0x6e, 0x6f}
        attr = tuple(self.state.get(A+i) for i in range(112))
        assert {i for i,v in enumerate(attr) if v is None} == holes
        protected = self.value(Z, 14)
        workspace = self.value(S+0xd0c, 4)
        self.message_reads = []
        first_store, first_edge = len(self.publication_stores), len(self.edges)
        visits = 0
        clear, allocator = None, None
        endpoint = PARSER if success else ERROR
        while self.pc != endpoint:
            assert visits < 6*len(allowed) and self.pc in allowed, hex(self.pc)
            self.ix += 1
            word, = self.cs.disasm(self.image.read(self.pc, 4), self.pc)
            if self.pc == ZERO_CALL:
                assert clear is None and self.step(word) == ZERO and self.g[30] == ZERO_CALL+4
                assert self.edges[-1]['modifier64'] == '0x46ae'
                self.pc = ZERO
                clear = self.clear(S+0xcc8, ZERO_CALL+4)
            elif self.pc == ALLOCATE_CALL:
                assert allocator is None and self.g[0] == DESCRIPTOR
                allocator = self.external_return(word, self.pc, F, allocate, 0xd0c8, M, 0)
                self.pc += 4
            else:
                assert word.mnemonic != 'blraa'
                self.pc = self.step(word)
            visits += 1
        assert clear is not None and allocator is not None
        assert self.sp == F and self.value(S+0xcc8, 32) == 0
        assert self.value(S+0xd0c, 4) == workspace and self.value(Z, 14) == protected
        assert self.value(H, 16) == (J << 64) | J and self.value(J+0x18, 8) == Z
        assert tuple(self.state.get(A+i) for i in range(112)) == attr
        assert self.value(C+0x5d0, 8) == shifted('0xfffffe000a636d34')
        assert self.value(C+0x430, 8) == C+0x360 and self.value(C+0x498, 8) == I
        assert self.value(S+0x150, 4) == encoded and self.value(C+0x788, 8) == M
        stores = self.publication_stores[first_store:]
        zero_stores = {tuple(store) for store in clear['stores']}
        frame_roots = dict(F=F, C=C, S=S)
        written = set()
        for pc_text, address, width, value in stores:
            pc, addr = int(pc_text, 16), int(address, 16)
            if success and M <= addr < M+128:
                assert addr+width <= M+128
                written.update(range(addr-M, addr-M+width))
            elif (pc_text, address, width, value) not in zero_stores:
                root, offset, expected_width = CONTEXT_STORES[pc]
                assert (addr, width) == (frame_roots[root]+offset, expected_width)
        output = None
        status = None
        if success:
            covered = {i for _, off, n, _ in self.message_reads for i in range(off, off+n)}
            assert covered == set(range(112))-holes
            want = {i: 0 for i in range(16)}
            for src, dst, length in ((0,0x10,4), (8,0x18,64), (0x48,0x58,8),
                                     (0x50,0x60,2), (0x54,0x64,4), (0x68,0x78,4)):
                want.update({dst+i: attr[src+i] for i in range(length)})
            mode_zero = attribute['profile'] == 'mode_zero'
            want.update({0x14+i: b for i,b in enumerate(bytes([int(mode_zero),0,0,0]))})
            want.update({0x68+i: attr[0x58+i]^b for i,b in enumerate(mask)})
            want[0x7c] = 0xca | (attr[0x6c]&1)
            assert set(want) == set(range(128))-{0x62,0x63,0x7d,0x7e,0x7f}
            assert {i for i in range(128) if M+i in self.state} == written == want.keys()
            assert all(self.state[M+i] == b for i,b in want.items())
            output = ''.join(f'{want[i]:02x}' if i in want else '??' for i in range(128))
            assert self.value(C+0x718, 8) == M and self.value(C+0x18, 8) == I
            assert self.value(S+0xc8, 4) == encoded and self.value(S+0x1e0, 4) == 0xfbb3f478
            expected_edge = (shifted('0xfffffe000a656c04'), 0xb40b)
        else:
            assert not self.message_reads and not any(MESSAGE+i in self.state for i in range(128))
            status = self.value(S+0xab8, 4)
            assert status == 0xce515bb2
            expected_edge = (shifted('0xfffffe000a641b38'), 0x682a)
        edges = self.edges[first_edge:]
        assert (edges[-1]['pc'], edges[-1]['target'], edges[-1]['modifier64']) == (
            hex(expected_edge[0]), hex(endpoint), hex(expected_edge[1]))
        return dict(success=success, profile=attribute['profile'], endpoint=hex(endpoint), message=hex(M),
                    input_pointer=hex(I), encoded_extent=hex(encoded), instruction_visits=visits,
                    clear=clear, allocator=allocator, message_bytes_hex_or_unknown=output,
                    published_status=hex(status) if status is not None else None,
                    attribute_reads=[dict(pc=hex(pc), offset=off, width=width, value=hex(value))
                                     for pc,off,width,value in self.message_reads],
                    stores=stores, edges=edges)


def audit(path):
    build = command('sw_vers', '-buildVersion').strip().decode()
    assert build == '26C5035r' and sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    image = Collection(path, IDENTITIES[1])
    checks = receipt('userclient_message_initialization_checks', CHECKS)
    prior = receipt('userclient_message_initialization_audit', AUDIT)
    attributes = receipt('userclient_message_attributes_checks', ATTRIBUTE_CHECKS)
    installed = receipt('live_fairplay_message_attributes_audit', INSTALLED_ATTRIBUTE)
    assert checks['attribute_source'] == attributes['source']
    assert prior['checks_sha256'] == CHECKS
    assert checks['kernel_collection_sha256'] == prior['kernel_collection_sha256'] == IDENTITIES[0][0]
    assert installed['identity'] == list(IDENTITIES[1]) and installed['historical_checks_sha256'] == ATTRIBUTE_CHECKS
    allocate, random = image.named('_IOMallocTypeImpl'), image.named('_random')
    layout, allowed, roots, mask = verify_source(image, checks, allocate)
    a_layout, a_allowed, banks = verify_attribute_source(image, attributes, allocate, random)
    historical = {r['predecessor_case_index']: r for r in checks['predecessor_states']}
    expected = {(r['fixture'], r['result']['profile']): r for r in installed['cases']}
    cases, alignments = [], None
    for success in (True, False):
        for case, replay in attribute_cases(image, attributes, a_layout, a_allowed, banks,
                                            modes=('mode_zero', 'mode_nonzero'), replay_type=MessageReplay):
            name, index, attribute = case['fixture'], case['case_index'], case['result']
            assert json.loads(json.dumps(case)) == expected[(name, attribute['profile'])]
            if alignments is None:
                alignments = replay.check_alignments()
            observed = replay.initialize(allowed, roots, historical[index], mask, allocate, success, attribute)
            cases.append(dict(fixture=name, case_index=index, result=observed))
    assert len(cases) == 8 and len(prior['source_proofs']) == 425
    # Recheck the all-alignment and all-extent contracts. The eight concrete
    # message cases independently exercise the installed constructor.
    proofs = [p for p in prior['source_proofs'] if not p['semantic_contract'].startswith('actual_attribute')]
    assert len(proofs) == 45
    with ThreadPoolExecutor(max_workers=4) as workers:
        results = list(workers.map(partial(replay_proof, timeout_seconds=PROOF_TIMEOUT_SECONDS), proofs))
    return dict(build=build, identity=IDENTITIES[1], layout=layout, cases=cases, alignment_controls=alignments,
                source_proofs=results, historical_checks_sha256=CHECKS, historical_audit_sha256=AUDIT,
                installed_attribute_audit_sha256=INSTALLED_ATTRIBUTE, native_allocator_observed=False,
                native_PAC_verified=False, native_transaction_observed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    print(json.dumps(audit(parser.parse_args().collection), indent=2))
