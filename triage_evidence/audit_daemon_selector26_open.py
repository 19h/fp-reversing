#!/usr/bin/env python3
"""Check the static IOKit connection handoff to the selector 26 constructor."""

from contextlib import redirect_stdout
import json
import struct
import sys
from pathlib import Path

import z3

from audit_daemon_selector26_cleanup import landmark
from audit_daemon_selector26_record_origin import (
    CONTEXT, FOURTH, GLOBAL_ONE, GLOBAL_TWO, RECORD, SECOND, OriginFrame, trace_check,
)
from audit_daemon_selector26_return import FIXUP_SLOTS, SP, SPANS, number
from audit_userclient_fallback_metadata import solve
from daemon_receive_tools import FIXUPS, IMAGE, POOL, SOURCE, TABLE, qword, selected
from daemon_receive_tools import verify_original_fixups
from lskd_values_symbolic import resize
from resolve_kernel_collection_interfaces import commands
from verify_daemon_reader_record_payloads_publication import sha

TASK_SLOT = 0x1010a39c8
TASK_ADDEND = 0x7bf13863
TASK = 0x4000
MATCH, ITERATE, OPEN, CALLER = 0x1002b7b08, 0x10018453c, 0x100176964, 0x1001f50b0
MATCH_CALL, ITERATE_CALL, OPEN_CALL = 0x1002b7b94, 0x10018458c, 0x100176a0c
MATCH_END, ITERATE_END, OPEN_END = 0x1002b7bbc, 0x1001845c0, 0x100176a34
MATCH_ERROR, OPEN_ERROR = 0x1000bd85c, 0x1002c99a0


class OpenFrame(OriginFrame):
    def load(self, address, width):
        if width == 8 and number(address) == TASK_SLOT:
            self.loads.append((self.pc, TASK_SLOT, width))
            return resize(TASK + TASK_ADDEND, 64)
        return super().load(address, width)


def task_binding():
    data = SOURCE.read_bytes()
    at = next(off for off, command, _ in commands(data, 0) if command == 0x80000034)
    fixup_offset, = struct.unpack_from('<I', data, at + 8)
    version, _, imports, symbols, count, fmt, symfmt = struct.unpack_from(
        '<7I', data, fixup_offset)
    assert (version, fmt, symfmt) == (0, 2, 0)
    word, = struct.unpack('<Q', IMAGE.read(TASK_SLOT, 8))
    ordinal = word & 0xffffff
    assert word >> 62 == 1 and (word >> 32) & 0x7ffff == 0 and ordinal < count
    entry, addend = struct.unpack_from('<Ii', data, fixup_offset + imports + 8 * ordinal)
    start = fixup_offset + symbols + (entry >> 9)
    name = data[start:data.index(0, start)].decode()
    assert name == '_mach_task_self_' and addend == TASK_ADDEND
    assert FIXUPS[TASK_SLOT]['target'] == 'libSystem/' + name
    return {'slot': hex(TASK_SLOT), 'word': hex(word), 'symbol': name,
            'import_ordinal': ordinal, 'library_ordinal': entry & 255,
            'import_addend': hex(addend), 'instruction_bias': hex(-addend)}


def banks():
    match_pair = (qword(0x1010a44b0) - 0xfd31782, qword(0x1010a4a58) - 0xd45667)
    specifications = (
        ('matching', match_pair, 0xa, 0xcce9, TABLE, 0x1010a0d88),
        ('iterator', FOURTH, 0x6d, 0xcd19, TABLE, 0x1010a0e38),
        ('task', match_pair, 0x9a, 0x328, POOL, TASK_SLOT),
        ('open', match_pair, 0x9a, 0xcca6, TABLE, 0x1010a0b48),
        ('constructor', SECOND, 0xf3, 0xce5b, TABLE, 0x1010a13e0),
    )
    rows = {}
    for role, pair, key, additive, base, expected_slot in specifications:
        row = selected(*pair, key, additive, base)
        assert int(row['slot'], 16) == expected_slot
        rows[role] = row
    return rows


def profile(match_status, service, open_status, word):
    dictionary, main, iterator, task, connection = 0x7000, 0x117, 0x217, 0x317, 0x417
    f = OpenFrame(x1=dictionary, x20=CONTEXT, x22=GLOBAL_ONE, x26=GLOBAL_TWO, x28=TABLE,
                  x29=RECORD + 0x78, w24=0x5dee)
    f.put(GLOBAL_ONE, 4, 0x12345678)
    f.put(GLOBAL_TWO, 4, 0x98765432)
    f.put(TASK, 4, task)
    for offset, value in zip((0x28, 0x30, 0x40, 0x38), FOURTH + SECOND):
        f.put(SP + offset, 8, value)
    f.put(SP + 0x4c, 4, word)
    f.put(SP + 0x7c, 4, main)

    def api_return(value):
        for register in range(18):
            f.regs.pop(f'x{register}', None)
        f.seed('w0', value)

    def handoff():
        byte_read = (0x1001f50c0, SP + 0x4c, 4)
        assert byte_read not in f.loads
        assert f.step(CALLER, 0x1001f511c) is None
        assert byte_read in f.loads and number(f.get(SP + 0x4c, 4)) == word
        landmark(0x1001f511c, 'sturb', 'w8, [x29, #-0x78]')
        f.store(f.read('x29') - 0x78, 1, f.read('w8'), 0x1001f511c)
        assert f.step(0x1001f5120, 0x1001f517c) == 0x1004110fc
        assert number(f.read('x0')) == RECORD
        assert number(f.get(RECORD + 16, 8)) == CONTEXT
        assert number(f.get(CONTEXT + 4, 4)) == connection
        assert number(f.get(RECORD + 4, 4)) == (
            0x8934 - (RECORD ^ 0xf9d49974) * 0xda51a827) & 0xffffffff

    assert f.step(MATCH, MATCH_CALL + 4) == 'IOKit/_IOServiceGetMatchingServices'
    assert tuple(number(f.read(r)) for r in ('w0', 'x1', 'x2')) == (main, dictionary, SP + 0x78)
    if match_status == 0:
        f.put(SP + 0x78, 4, iterator)
    api_return(match_status)
    target = f.step(MATCH_CALL + 4, MATCH_END)
    assert target == (MATCH_ERROR if match_status else ITERATE)
    if target == ITERATE:
        assert f.step(ITERATE, ITERATE_CALL + 4) == 'IOKit/_IOIteratorNext'
        assert number(f.read('w0')) == iterator
        api_return(service)
        target = f.step(ITERATE_CALL + 4, ITERATE_END)
        assert target == (OPEN if service else MATCH_ERROR)
    if target == OPEN:
        assert f.step(OPEN, OPEN_CALL + 4) == 'IOKit/_IOServiceOpen'
        assert tuple(number(f.read(r)) for r in ('w0', 'w1', 'w2', 'x3')) == (
            service, task, 0, CONTEXT + 4)
        assert (0x1001769cc, TASK, 4) in f.loads
        assert number(f.get(SP + 0xc, 4)) == service
        assert number(f.read('w24')) == 0x3941
        if open_status == 0:
            f.put(CONTEXT + 4, 4, connection)
        api_return(open_status)
        target = f.step(OPEN_CALL + 4, OPEN_END)
        assert target == (OPEN_ERROR if open_status else CALLER)
    if target == CALLER:
        handoff()
    assert number(f.get(SP + 0x4c, 4)) == word
    assert all(address + width <= SP + 0x4c or SP + 0x50 <= address
               for _, address, width, _ in f.stores)
    return {'match_status': match_status, 'service': service, 'open_status': open_status,
            'incoming_word': word, 'frontier': hex(target), 'edges': f.edges,
            'source_loads': [[hex(pc), hex(addr), width] for pc, addr, width in f.loads],
            'source_stores': [[hex(pc), hex(addr), width] for pc, addr, width, _ in f.stores]}


def predicates():
    result = z3.BitVec('return_word', 32)
    cases = (
        ('matching_status', MATCH_CALL, MATCH_END, 0x5dee, 0x1b38, 0xb794, 0x5dee),
        ('iterator_service', ITERATE_CALL, ITERATE_END, 0x5dee, 0x1b38, 0x5dee, 0x5dfe),
        ('open_status', OPEN_CALL, OPEN_END, 0x3941, 0x3941 ^ 0x8e9e, 0x3942, 0x3941),
    )
    proofs = []
    for name, call, end, phase, w21, zero, nonzero in cases:
        f = OpenFrame(w0=result, w24=phase, w21=w21)
        f.step(call + 4, end - 0xc)
        expected = z3.If(result == 0, resize(zero, 32), resize(nonzero, 32))
        proof = solve(name, [], f.read('w8') != expected)
        assert proof['result'] == 'unsat'
        proofs.append(proof)
    return proofs


def report():
    cases = ((1, 0, 0, 0), (0, 0, 0, 0), (0, 0x517, 0xe00002c2, 0x100),
             (0, 0x517, 0, 0x100), (0, 0x517, 0, 0x110))
    bank_rows = banks()
    profiles = [profile(*case) for case in cases]
    return {'daemon_sha256': sha(SOURCE), 'generator_sha256': sha(Path(__file__)),
            'profiles': profiles, 'proofs': predicates(), 'banks': bank_rows,
            'task_import': task_binding(), 'trace': trace_check(),
            'source_spans': list(SPANS.values()),
            'fixups': verify_original_fixups(FIXUP_SLOTS)}


if __name__ == '__main__':
    with redirect_stdout(sys.stderr):
        result = report()
    print(json.dumps(result, indent=2))
