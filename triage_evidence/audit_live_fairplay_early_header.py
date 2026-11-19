#!/usr/bin/env python3
"""Replay the installed first TLV decode on the archived input fixtures."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path

from audit_daemon_iokit_native_registry import command, sysctl
from audit_live_fairplay_connection_retirement import verify_fixup
from audit_live_fairplay_context_lifecycle import POOL, TABLE, read_descriptor, replay_proof
from audit_live_fairplay_entry import InstalledReplay, TLV_FREE, TLV_RELEASE, verify_layout
from audit_live_fairplay_uidlist import receipt
from audit_live_kext_selector26 import Collection, IDENTITIES
from replay_userclient_early_header import Replay as HeaderSemantics

CHECKS = '7ee41a58e79feb63c87fb5642245eb2328afb6f7acb355271553884d4547fdf1'
AUDIT = 'b8834843c39433e4e3fa6b1bbed8c275e7c5d0d51f09260a651a975ca6a8b2ef'
NODE_CALL = 0xfffffe000a6a27f4
NODE_TYPE = 0xfffffe0008491f40
CALLBACK = 0xfffffe000a6a2d30
SUCCESS = 0x31ae0066
U64_MASK = 0x8f98c6acce5848ca


class HeaderReplay(InstalledReplay, HeaderSemantics):
    """Supply only the archived input bytes before installed core entry."""

    def __init__(self, image, row):
        super().__init__(image, row)
        self.base, self.extent, _ = self.input['inputs8'][:3]
        self.payload = bytes.fromhex(self.input['input_fixture_hex'])
        self.end = self.base + len(self.payload)
        self.input_loads = []
        assert 0 < len(self.payload) <= 64
        assert self.input['declared_size64'] == self.extent
        assert self.input['FPTTLV_result_fixture'] != 0

    def load(self, address, width, discarded=False):
        if self.base <= address < self.end:
            offset = address - self.base
            assert width == 1 and not discarded and offset < self.extent
            assert address not in self.state
            self.private_reads.append((address, width, discarded))
            self.input_loads.append(offset)
            return self.payload[offset]
        return super().load(address, width, discarded)

    def store(self, address, width, value):
        assert address + width <= self.base or address >= self.end
        super().store(address, width, value)

    def verify_boundary(self, source, extent):
        assert (source, extent) == (self.base, self.extent)
        S, C, container = (int(cut['result'], 16) for cut in self.cuts)
        assert self.value(C + 0x98, 8) == source
        assert self.value(C + 0xb0, 8) == container
        assert self.value(container, 16) == 0
        assert self.value(S + 0xb5c, 4) == extent ^ SUCCESS
        raw_tag = int.from_bytes(self.payload[:4], 'big')
        raw_type = int.from_bytes(self.payload[4:6], 'big')
        raw_length = int.from_bytes(self.payload[6:10], 'big')
        assert (raw_tag, raw_type, raw_length) == (
            self.input['wire_tag32'], self.input['wire_type16'], self.input['wire_length32'],
        )
        type_class = {0x9777: 'u32', 0x8485: 'u64', 0x50db: 'span'}.get(raw_type, 'unknown')
        length_fits = extent >= 10 and raw_length <= extent - 10
        accepted = length_fits and (
            type_class == 'span' or (type_class, raw_length) in {('u32', 4), ('u64', 8)}
        )
        expected_offsets = []
        if extent >= 10:
            expected_offsets.extend(range(6, 10))
        if length_fits:
            expected_offsets.extend(range(6))
        if accepted and type_class in ('u32', 'u64'):
            expected_offsets.extend(range(10, 10 + raw_length))
        assert self.input_loads == expected_offsets
        cursor = self.value(S + 0xa10, 8)
        assert cursor == (10 + raw_length if accepted else 0)
        word, = self.cs.disasm(self.image.read(self.pc, 4), self.pc)
        assert word.mnemonic == 'blraa'
        target = self.reg(word.reg_name(word.operands[0].reg))
        if accepted and type_class in ('u32', 'u64'):
            payload_value = int.from_bytes(self.payload[10:10 + raw_length], 'big')
        else:
            payload_value = 0

        if accepted and (type_class != 'span' or raw_tag != 0):
            assert self.pc == NODE_CALL
            assert target == self.image.named('_IOMallocTypeImpl') and self.g[0] == NODE_TYPE
            assert self.g[17] == 0xd0c8
            assert self.value(C + 0x260, 8) == CALLBACK
            assert self.value(C + 0x20, 8) == container
            assert self.value(S + 0x1d0, 4) == raw_tag ^ SUCCESS
            assert self.value(S + 0x1b2, 2) == raw_type ^ 0xa2e3
            assert self.value(S + 0x94, 4) == raw_length ^ SUCCESS
            expected_32 = payload_value if type_class == 'u32' else 0
            expected_64 = payload_value if type_class == 'u64' else 0
            assert self.value(S + 0x110, 4) == expected_32 ^ SUCCESS
            assert self.value(S + 0xad0, 8) == expected_64 ^ U64_MASK
            assert self.value(C + 0x168, 8) == (source + 10 if type_class == 'span' else 0)
            outcome = 'node_allocation'
        else:
            assert self.pc == TLV_RELEASE and target == self.image.named('_IOFreeTypeImpl')
            assert self.g[:2] == [TLV_FREE, container]
            status = SUCCESS if accepted else 0xce515bb8
            offset = 0x418 if accepted else 0x3d0
            assert self.value(S + 0xc94, 4) == status
            assert self.g[19] == C + offset and self.value(C + offset, 8) == container
            outcome = 'span_success_release' if accepted else 'parser_failure_release'
        return dict(pc=hex(self.pc), target=hex(target), kind=outcome,
                    profile=self.input['profile'], type_class=type_class,
                    source_cursor_bytes=cursor, input_load_offsets=self.input_loads)


def node_bindings(image, source):
    specs = dict(
        node_allocation=((0xf50, -4), (0xf20, -4), TABLE, image.named('_IOMallocTypeImpl')),
        node_descriptor=((0xb70, 0), (0xa10, 0), POOL, NODE_TYPE),
    )
    rules = {}
    for row in source['bank_rules']:
        name = row['name']
        left, right, base, target = specs[name]
        banks = []
        roots = []
        for offset, bias in (left, right):
            address = int(image.pointer(POOL + offset)['target'], 16)
            roots.append(verify_fixup(image, POOL + offset, address))
            banks.append(image.read(address + bias, 256))
        L, R = banks
        assert L.hex() == row['left256_hex'] and R.hex() == row['right256_hex']
        key = int(row['key'], 16)
        constant, = {x ^ R[L[x] ^ key] for x in range(256)}
        index = constant + int(row['additive'], 16)
        assert constant == int(row['constant'], 16) and index == int(row['index'], 16)
        unadjusted = (target - int(row['bias'], 16)) % (1 << 64)
        fixup = verify_fixup(image, base + 8 * index, unadjusted, row['original_pointer']['diversity'])
        rules[name] = dict(roots=roots, index=hex(index), constant=hex(constant), fixup=fixup)
    descriptor = read_descriptor(image, NODE_TYPE, 'site.FPTTLVNode', '1121', 32)
    return dict(rules=rules, descriptor=descriptor)


def audit(path):
    build = command('sw_vers', '-buildVersion').strip().decode()
    assert build == '26C5035r' and sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    image = Collection(path, IDENTITIES[1])
    archived = receipt('userclient_early_header_checks', CHECKS)
    assert archived['kernel_collection_sha256'] == IDENTITIES[0][0]
    proof_source = receipt('userclient_early_header_audit', AUDIT)
    assert proof_source['checks_sha256'] == CHECKS
    source = archived['source']
    layout = verify_layout(image, {'early_header': source})
    bindings = node_bindings(image, source)
    cases = [HeaderReplay(image, row).replay() for row in archived['cases']
             if row['input']['declared_size64'] <= 0xffffffff]
    assert len(cases) == 66
    proofs = proof_source['source_proofs']
    assert len(proofs) == 10
    with ThreadPoolExecutor(max_workers=4) as workers:
        replays = list(workers.map(replay_proof, proofs))
    return dict(build=build, identity=IDENTITIES[1], checks_sha256=CHECKS, proof_audit_sha256=AUDIT,
                layout=layout, node_bindings=bindings, cases=cases, source_proofs=replays,
                native_transaction_observed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    print(json.dumps(audit(parser.parse_args().collection), indent=2))
