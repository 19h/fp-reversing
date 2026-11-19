#!/usr/bin/env python3
"""Follow both installed FPMessage lookup-miss paths to fallback allocation."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
from struct import Struct

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

from audit_live_fairplay_connection_retirement import verify_fixup
from audit_live_fairplay_context_lifecycle import CODE_DELTA, POOL, TABLE, function_starts
from audit_live_fairplay_early_header import SUCCESS
from audit_live_fairplay_entry import STAGING_CALL, TLV_RELEASE
from audit_live_fairplay_message_initialization import MESSAGE
from audit_live_fairplay_message_parse_completion import NODE, RECORD, RecordReplay, audit as completion_audit
from audit_live_fairplay_message_parser import CONTAINER, FLAG_TARGETS
from audit_live_fairplay_uidlist import receipt
from kext_port_tools import IMAGE as ORIGINAL, TABLE as ORIGINAL_TABLE, qword
from verify_interface_contracts import Image

PREVIOUS = '5d0c609727072fe5fe69ba6857068b9aa6e49de2d8b44762bc8f4c142d058643'
DAEMON_HASH = '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
PACKET_CONTRACTS = '1375c22829b5d3f28ae1ca4921540ab7fac817559917447dc69f0cb72aee9a3c'
KEXT_LOOKUP = 0xfffffe000a6a3c44
LOOKUP_RETURN = 0xfffffe000a6a3cf0
MISS = 0xce515bda
DATA_FREE = 0xfffffe000a6a1978
NODE_FREE = 0xfffffe000a6a1898
MESSAGE_FREE = 0xfffffe000a6a1bb0
ATTRIBUTE_FREE = 0xfffffe000a697cb4
DESCRIPTORS = {
    NODE_FREE: (0xfffffe00084928c0, 'site.FPTTLVNode', '1121', 0x64, 32),
    TLV_RELEASE: (0xfffffe0008492880, 'site.FPTTLV', '11', 0xe4, 16),
    MESSAGE_FREE: (0xfffffe0008491e00, 'site.FPMessage', '1122222222222222', 0x64, 128),
    ATTRIBUTE_FREE: (0xfffffe00084923c0, 'site.FPMessageAttr', '', 0x6c, 112),
}
DAEMON_KEYS = (
    (0x5c241ab2, 0x10066e5d4, 0x10066e5e8, 0xd719dce3),
    (0x7976211a, 0x1008b35c4, 0x1008b35d8, 0xf24be74b),
    (0xfd2821c7, 0x1006d6c18, 0x1006d6c2c, 0x7615e796),
)
POOL_RELOCATIONS = (
    (0xfffffe000a697ca0, 'x9'), (0xfffffe000a6a173c, 'x9'), (0xfffffe000a6a1880, 'x9'),
    (0xfffffe000a6a1b9c, 'x9'), (0xfffffe000a6a3cdc, 'x10'),
)


def daemon_keys(path):
    image = Image(path)
    assert sha256(image.data).hexdigest() == DAEMON_HASH
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    rows = []
    for raw, start, emitter, encoded in DAEMON_KEYS:
        words = list(decoder.disasm(image.read(start, emitter+4-start), start))
        first, second = words[:2]
        assert (first.mnemonic, first.op_str) == ('mov', f'w9, #{encoded & 0xffff:#x}')
        assert (second.mnemonic, second.op_str) == ('movk', f'w9, #{encoded >> 16:#x}, lsl #16')
        writes = {word.reg_name(reg) for word in words[2:] for reg in word.regs_access()[1]}
        assert len(words)*4 == emitter+4-start and {'w9', 'x9'}.isdisjoint(writes)
        assert words[-1].address == emitter and words[-1].mnemonic == 'braa' and encoded ^ 0x8b3dc651 == raw
        rows.append(dict(decoded_tag=hex(raw), encoded_daemon_tag=hex(encoded), key_site=hex(start),
                         transfer_site=hex(emitter), instructions=[(hex(i.address), i.bytes.hex()) for i in words]))
    return rows


def packet_fields():
    capture = receipt('adid_avp_packet_contracts', PACKET_CONTRACTS)
    packet = bytes.fromhex(capture['baseline_method100_request']['bytes144'])
    header = Struct('>IHI')
    offset, fields = 0, []
    while offset < len(packet):
        tag, kind, length = header.unpack_from(packet, offset)
        assert offset+header.size+length <= len(packet)
        fields.append((offset, tag, kind, length))
        offset += header.size+length
    assert len(packet) == offset == 144
    assert fields[1:3] == [(18, 0x7976211a, 0x9777, 4), (32, 0xfd2821c7, 0x50db, 80)]
    assert packet[28:32] == bytes(4)
    return dict(decoded_sha256=PACKET_CONTRACTS, packet_sha256=sha256(packet).hexdigest(),
                outer_headers=fields, option_u32=0)


class ModeReplay(RecordReplay):
    retired = ()

    def check_live(self, address, width):
        assert all(address+width <= base or base+size <= address for base, size in self.retired)

    def load(self, address, width, discarded=False):
        self.check_live(address, width)
        return super().load(address, width, discarded)

    def store(self, address, width, value):
        self.check_live(address, width)
        super().store(address, width, value)

    def lookup_and_retire(self, mode):
        zero = mode == 'mode_zero'
        assert self.pc == FLAG_TARGETS[0 if zero else 1]
        S, C, H, J, Z = (int(cut['result'], 16) for cut in self.cuts)
        A, F = self.value(C+0x1b0, 8), self.sp
        I, N = self.input_address, self.input_extent
        assert self.value(MESSAGE, 8) == CONTAINER and self.value(MESSAGE+8, 8) == 0
        H2 = CONTAINER
        raw_status = 0xce515b45 if zero else MISS
        sites, calls, lookups = [], [], []
        roots = function_starts(self.image)
        start = self.image.named('_PRnut72j9')
        end = roots[roots.index(start)+1]
        retirement = ((DATA_FREE, RECORD, N), (NODE_FREE, NODE, 32), (TLV_RELEASE, H2, 16),
                      (MESSAGE_FREE, MESSAGE, 128), (ATTRIBUTE_FREE, A, 112),
                      (DATA_FREE, Z, N), (NODE_FREE, J, 32), (TLV_RELEASE, H, 16))
        expected_lookups = ((0x8f, 0x6d8a1ad4, C+0x68, 0xfffffe000a6a3e5c),) if zero else (
            (0x7f, 0x48d8217c, C+0x710, 0xfffffe000a6a2dc4),
            (0x88, 0xcc8621a1, C+0xa0, 0xfffffe000a6a4540),
        )
        emitters = (0xfffffe000a6a2418,) if zero else (0xfffffe000a6954bc, 0xfffffe000a6a3370)
        first = len(self.parser_reads), len(self.publication_stores), len(self.edges), len(self.input_loads)
        while self.pc != STAGING_CALL:
            assert start <= self.pc < end and len(sites) < 1600, hex(self.pc)
            self.ix += 1
            sites.append(hex(self.pc))
            word, = self.cs.disasm(self.image.read(self.pc, 4), self.pc)
            if self.pc == KEXT_LOOKUP:
                index, key, output = self.g[8:11]
                edge = self.edges[-1]
                assert edge['target'] == hex(self.pc) and edge['modifier64'] == '0xee9'
                assert self.g[22] == H2 and self.value(H2, 8) == NODE and self.value(NODE, 8) == 0
                assert self.value(output, 8) == 0
                lookups.append(dict(index=hex(index), encoded_key=hex(key), decoded_key=hex(key ^ SUCCESS),
                                    output=hex(output), emitter=edge['pc']))
            if self.pc == LOOKUP_RETURN:
                row = lookups[-1]
                assert 'callback' not in row and self.g[23] == MISS and self.value(int(row['output'], 16), 8) == 0
                row.update(callback=hex(self.g[8]), status=hex(MISS))
            if word.mnemonic == 'blraa':
                site, base, size = retirement[len(calls)]
                assert self.pc == site
                if site == DATA_FREE:
                    symbol, args, modifier = '_IOFreeData', (base, size), 0x85d
                else:
                    symbol, args, modifier = '_IOFreeTypeImpl', (DESCRIPTORS[site][0], base), 0x4d6a
                assert tuple(self.g[:2]) == args
                api = self.external_return(word, site, F, self.image.named(symbol), modifier, 0, 10+len(calls))
                calls.append(dict(api, symbol=symbol, arguments=list(map(hex, args)), object=hex(base), size_bytes=size))
                self.retired = (*self.retired, (base, size))
                self.pc += 4
            else:
                self.pc = self.step(word)
        assert len(self.retired) == len(retirement) and self.sp == F
        assert self.value(S+0xd98, 4) == self.value(S+0xab8, 4) == self.value(S+0x1c, 4) == raw_status
        clears = (0x1d0, 0x788, 0x360, 0x1b0, 0x418)
        assert all(self.value(C+off, 8) == 0 for off in clears)
        assert [tuple(int(row[k], 16) for k in ('index', 'encoded_key', 'output', 'callback'))
                for row in lookups] == list(expected_lookups)
        assert [int(row['emitter'], 16) for row in lookups] == list(emitters)
        loads = self.parser_reads[first[0]:]
        records = [(int(addr, 16)-RECORD, width) for _, addr, width, _ in loads
                   if RECORD <= int(addr, 16) < RECORD+N]
        assert records == [(offset, 1) for _ in expected_lookups for offset in range(4)]
        assert len(self.input_loads) == first[3] and not any(I <= int(addr, 16) < I+N for _, addr, _, _ in loads)
        word, = self.cs.disasm(self.image.read(self.pc, 4), self.pc)
        target = self.image.named('_IOMallocData')
        assert word.mnemonic == 'blraa' and self.reg(word.reg_name(word.operands[0].reg)) == target
        assert self.g[17] == 0xca0c and self.g[0] == N
        pending = dict(pc=hex(self.pc), target=hex(target), modifier=hex(self.g[17]), requested_bytes=N)
        stores = self.publication_stores[first[1]:]
        status_stores = [(0xfffffe000a6a4ea8, S+0xd98), (0xfffffe000a682cac, S+0xab8),
                         (0xfffffe000a682dc8, S+0x1c)]
        assert [(hex(pc), hex(addr), 4, hex(raw_status)) for pc, addr in status_stores] == [
            row for row in stores if int(row[1], 16) in {addr for _, addr in status_stores}]
        return dict(sites=sites, lookups=lookups, raw_status=hex(raw_status), calls=calls, pending=pending,
                    cleared_offsets=list(map(hex, clears)), loads=loads, stores=stores,
                    edges=self.edges[first[2]:])


def source_comparison(image, cases):
    sites = {int(site, 16) for row in cases for site in row['result']['sites']} | {STAGING_CALL}
    words = {}
    for site in sorted(sites):
        installed = image.read(site, 4)
        original = ORIGINAL.read(site-CODE_DELTA, 4)
        words[hex(site)] = installed.hex()
        if installed != original:
            word, = image.instructions(site, 4)
            words[hex(site)] = dict(original=original.hex(), installed=installed.hex(), operands=word.op_str,
                                    mnemonic=word.mnemonic)
    assert len(words) == 1088
    relocated = {hex(site+offset) for site, _ in POOL_RELOCATIONS for offset in (0, 4)}
    assert {site for site, word in words.items() if isinstance(word, dict)} == relocated
    for site, register in POOL_RELOCATIONS:
        image.instruction(site, 'adrp', f'{register}, #{POOL & ~0xfff:#x}')
        image.instruction(site+4, 'add', f'{register}, {register}, #{POOL & 0xfff:#x}')
    external = {image.named('_IOFreeTypeImpl'): 0xfffffe000c4ba368,
                image.named('_IOFreeData'): 0xfffffe000c4ba84c,
                image.named('_IOMallocData'): 0xfffffe000c4ba60c}
    fixups = {}
    for case in cases:
        for _, address, width, loaded in case['result']['loads']:
            slot, target = int(address, 16), int(loaded, 16)
            if width != 8 or not TABLE <= slot < TABLE+0x8000 or address in fixups:
                continue
            row = image.pointer(slot)
            assert row['auth'] and row['target'] == loaded
            previous = qword(ORIGINAL_TABLE+slot-TABLE)
            assert previous == external.get(target, target-CODE_DELTA)
            fixups[address] = verify_fixup(image, slot, target, row['diversity'])
    assert len(fixups) == 54
    return dict(words=words, fixups=fixups)


def descriptor_report(image):
    descriptors = {}
    for site, (address, name, signature, flags, size) in DESCRIPTORS.items():
        assert image.read(address+40, 8) == flags.to_bytes(4, 'little')+size.to_bytes(4, 'little')
        pointers = {}
        for offset, field, text in ((16, 'name', name), (32, 'signature', signature)):
            pointer = image.pointer(address+offset)
            target = int(pointer['target'], 16)
            encoded = text.encode()+b'\0'
            assert image.read(target, len(encoded)) == encoded
            pointers[field] = verify_fixup(image, address+offset, target)
        descriptors[hex(site)] = dict(descriptor=hex(address), name=name, signature=signature, flags=flags,
                                      size_bytes=size, fixups=pointers)
    return descriptors


def audit(collection, daemon):
    previous = receipt('live_fairplay_message_parse_completion_audit', PREVIOUS)
    records = []
    image = None

    def collect(row, replay):
        nonlocal image
        image = replay.image
        result = replay.lookup_and_retire(row['mode'])
        records.append(dict(fixture=row['fixture'], mode=row['mode'], patterned_scratch=row['patterned_scratch'],
                            result=result))

    regenerated = completion_audit(collection, replay_type=ModeReplay, observe_case=collect)
    assert json.loads(json.dumps(regenerated)) == previous and len(records) == 8
    return dict(identity=regenerated['identity'], previous_sha256=PREVIOUS, cases=records,
                source=source_comparison(image, records), descriptors=descriptor_report(image),
                daemon_sha256=DAEMON_HASH, daemon_keys=daemon_keys(daemon), packet_fields=packet_fields(),
                native_retirement_observed=False, native_matched_transaction=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('daemon', type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.collection, args.daemon), indent=2))
