#!/usr/bin/env python3
"""Audit the local caller that produces the FairPlayIOKit class-selection phase."""

from bisect import bisect_right
from hashlib import sha256
import json
from struct import pack, unpack_from

import z3

import audit_daemon_selector26_class_gate as gate
import audit_daemon_selector26_class_retry as retry
from audit_daemon_selector26_match_entry import api_return, branch
from audit_daemon_selector26_return import FIXUP_SLOTS, SPANS, number
from daemon_receive_tools import CS, FIXUPS, IMAGE, POOL, TABLE, bank, verify_original_fixups
from recover_rpc502_parser_ownership import starts
from resolve_kernel_collection_interfaces import commands

CALL = 0x100636dfc
ENTRY = 0x1004382b4
CALLER_SP = gate.F + 0x150
PHASE_IN = 0x219a
PHASE_NEXT = 0x21d4
LEFT = 0x101031da0
RIGHT = 0x100e99900
LIVE_LEFT = 0x1010c4670
LIVE_RIGHT = 0x1010b8e50
NO_CLASS_CALL = 0x1006340c8
ACCEPTED = 0x10053ec30


class CallerFrame(gate.GateFrame):
    def load(self, address, width):
        pointer = number(address)
        pool_value = FIXUPS.get(pointer, {}).get('target')
        if width == 8 and POOL <= pointer < POOL + 0x7000 and isinstance(pool_value, int):
            self.loads.append((self.pc, pointer, width))
            FIXUP_SLOTS.add(pointer)
            return pool_value
        if width == 1 and any(base <= pointer < base + 256 for base in (LEFT, RIGHT)):
            self.loads.append((self.pc, pointer, width))
            return IMAGE.read(pointer, 1)[0]
        return super().load(address, width)


def prefix(compare_matches):
    f = CallerFrame(sp=CALLER_SP, x29=gate.INPUT + 0xa0, x7=TABLE)
    for address, width in gate.INITIAL_CELLS.items():
        f.put(address, width, int.from_bytes(IMAGE.read(address, width), 'little'))
    for address, width, value in (
        (gate.CACHE, 1, 0), (gate.ONCE, 8, 0), (gate.GUARD, 8, 0x7a653430),
        (LIVE_RIGHT, 4, 0), (retry.TASK, 4, 0x317),
    ):
        f.put(address, width, value)
    for index in (19, 22, 27, 28, 30):
        f.seed(f'x{index}', 0x2000 + index)
    f.seed('x26', LIVE_LEFT)
    f.seed('x24', LIVE_RIGHT)
    f.step(0x100530374, 0x10053043c)
    assert [number(f.get(CALLER_SP + offset, 8)) for offset in (0x298, 0x2a0, 0x300)] == [
        LEFT, RIGHT, TABLE,
    ]

    # Separate original coefficient producer. The earlier helper result is
    # declared independently from this local return gate.
    f.step(0x10047e084, 0x10047e08c)
    f.seed('w20', PHASE_IN)
    f.seed('w22', 0x12345678)
    f.put(gate.INPUT + 4, 4, 0x12345678 ^ int(not compare_matches))
    target = f.step(0x10047e0f8, 0x10047e12c)
    assert target == (0x100636d60 if compare_matches else NO_CLASS_CALL)
    if not compare_matches:
        return f, None
    f.seed('w23', 0xa6)
    f.seed('w24', 0x0a5cd4cf)
    assert f.step(target, CALL + 4) == ENTRY
    assert number(f.read('sp')) == CALLER_SP
    assert number(f.read('x0')) == gate.INPUT
    assert number(f.read('w20')) == PHASE_NEXT
    assert f.loads[-1] == (0x100636df0, 0x1010a1640, 8)
    word = number(f.get(gate.INPUT + 4, 4))
    assert ((gate.INPUT ^ 0xe732d262) * 0xba209ef7 + word) & 0xffffffff == gate.PHASE
    return f, word


def class_profile(byte, primary_flag, outcomes):
    f, caller_word = prefix(True)
    f.seed('x30', CALL + 4)
    encoded = gate.enter(f)
    for address in (retry.PRIMARY, retry.AVP):
        for offset, width in ((4, 4), (0x14, 4), (0x18, 1), (0x28, 8)):
            f.put(address + offset, width, int.from_bytes(IMAGE.read(address + offset, width), 'little'))
    f.put(retry.PRIMARY, 1, primary_flag)
    f.put(gate.R, 1, byte)
    api_return(f, 0, 'w0')
    f.read_record_byte(0x100438534)
    f.step(0x100438538, 0x10043861c)
    target = 0x1002765f8 if byte == 0x98 else retry.FALLBACK
    branch(f, 0x10043861c, 0x1004385d4, 'x9', target)

    lookups = []
    for epoch, outcome in enumerate(outcomes):
        if target == retry.FALLBACK:
            target = retry.primary_check(f, primary_flag == 0x70)
        row, continuation = retry.lookup(f, target, outcome, epoch * 0x1000)
        target = retry.retire(f, row, continuation)
        lookups.append(row)
    if target == retry.FALLBACK:
        target = retry.primary_check(f, primary_flag == 0x70)
    assert target == retry.FINAL
    returned = retry.publish_status(f, byte, encoded)
    assert number(f.read('x30')) == CALL + 4
    assert number(f.read('w20')) == PHASE_NEXT
    target = f.step(CALL + 4, 0x100636e38)
    assert (target == ACCEPTED) == (int(returned['value'], 16) == retry.STATUS_OK)
    assert target in (NO_CLASS_CALL, ACCEPTED)
    assert number(f.get(gate.INPUT + 4, 4)) == caller_word
    return {'helper_byte': byte, 'record': hex(gate.INPUT), 'word_at_plus_four': hex(caller_word),
            'lookups': lookups, 'returned_record_field': returned,
            'continuation': hex(target), 'edges': f.edges}


def address_codec_proof():
    address = z3.BitVec('caller_address_low32', 32)
    f = CallerFrame(x29=z3.ZeroExt(32, address) + 0xa0, w25=0xba209ef7, w20=PHASE_IN)
    f.step(0x100636d60, 0x100636da8)
    word = f.read('w8')
    caller_phase = f.read('w20')
    decoded = (address ^ 0xe732d262) * 0xba209ef7 + word
    solver = z3.SolverFor('QF_BV')
    solver.set(timeout=30000)
    solver.add(z3.Or(decoded != gate.PHASE, caller_phase != PHASE_NEXT))
    assert solver.check() == z3.unsat
    return 'all u32 record-address projections decode to 0xe8d for incoming W20=0x219a'


def census():
    sections = []
    for offset, command, _ in commands(IMAGE.data, 0):
        if command == 0x19:
            for index in range(unpack_from('<I', IMAGE.data, offset + 64)[0]):
                section = offset + 72 + index * 80
                if IMAGE.data[section:section + 16].rstrip(b'\0') == b'__text':
                    sections.append(unpack_from('<QQ', IMAGE.data, section + 32))
    assert len(sections) == 1
    base, size = sections[0]
    code = IMAGE.read(base, size)
    targets, metadata = starts()
    rows = []
    pattern = pack('<II', 0xd2800011 | (0x31e8 << 5), 0xd73f0911)
    offset = code.find(pattern)
    while offset >= 0:
        if offset % 4 == 0:
            pc = base + offset + 4
            envelope = bisect_right(targets, pc) - 1
            windows = list(CS.disasm(IMAGE.read(pc - 0x60, 0x68), pc - 0x60))
            assert (windows[-2].mnemonic, windows[-2].op_str) == ('blraa', 'x8, x17')
            rows.append({'call': hex(pc),
                         'compiler_bracket': [hex(item) for item in targets[envelope:envelope + 2]],
                         'preceding_code': ''.join(insn.bytes.hex() for insn in windows),
                         'target_resolved_here': pc == CALL})
        offset = code.find(pattern, offset + 1)
    assert len(rows) == 6
    return {'section': hex(base), 'size_bytes': size, 'sha256': sha256(code).hexdigest(),
            'pattern': pattern.hex(), 'function_starts': metadata,
            'calls': rows}


def inspect():
    assert (bank(LEFT, RIGHT, 0xa), TABLE + 8 * 0xceea) == (0xea, 0x1010a1640)
    direct, _ = prefix(False)
    cases = [
        class_profile(0x99, 0x70, ('open failure',)),
        class_profile(0x99, 0x00, ()),
        class_profile(0x98, 0x70, ('open failure', 'open failure')),
    ]
    assert [case['continuation'] for case in cases] == [
        hex(NO_CLASS_CALL), hex(ACCEPTED), hex(NO_CLASS_CALL),
    ]
    assert [row['class'] for row in cases[2]['lookups']] == [
        'AvpFairPlayDriver', 'com_apple_driver_FairPlayIOKit',
    ]
    slots = FIXUP_SLOTS | {0x10104abc0, 0x10104ad90, 0x101059650, 0x1010a1640}
    return {'caller_census': census(), 'proof': address_codec_proof(),
            'prior_helper_mismatch_edges': direct.edges, 'cases': cases,
            'fixups': verify_original_fixups(slots), 'spans': list(SPANS.values()),
            'native_ipc_observed': False}


if __name__ == '__main__':
    print(json.dumps(inspect(), indent=2, sort_keys=True))
