#!/usr/bin/env python3
"""Trace the first local buffer reads and the insertion of the second node."""

import json
from pathlib import Path
import sys
from contextlib import redirect_stdout

import z3

from audit_daemon_selector26_node import FIRST_INSERT, PROFILES, SP, node_frame, route
from audit_daemon_selector26_return import FIXUP_SLOTS, SPANS, number
from daemon_receive_tools import SOURCE, verify_original_fixups
from verify_daemon_reader_record_payloads_publication import sha

READ_PC = 0x100054958
CONSUME = (
    (READ_PC, 0x1000549b4, 0x100054998, 0x101051a58, 0xc0b6, 0x10015f344),
    (0x10015f344, 0x10015f384, 0x10015f348, 0x10103c470, 0xad0a, 0x100012ab8),
)
SECOND_INSERT = (
    (0x100012ab8, 0x100013330, 0x1000132fc, 0x10107f700, 0x051e, 0x1000de840),
    (0x1000de840, 0x1000de894, 0x1000de88c, 0x10106d630, 0xd162, 0x10007ff30),
    *FIRST_INSERT[:3],
    (0x100081d6c, 0x100081dac, 0x100081d9c, 0x10108f550, 0x65c0, 0x100013a48),
    (0x100013a48, 0x100013abc, 0x100013aa8, 0x101055b60, 0x9197, 0x1000e72c4),
)
BYTE_READS = (0x10015f354, 0x10015f360, 0x10015f370, 0x10015f37c)


def profile(words, locations):
    owner, first, buffer, second, second_buffer = locations
    frame, handoff = node_frame(words, locations)
    assert handoff['pending']['missing_byte_offsets'] == list(range(8))
    assert not any(address < SP + 0x100 and address + width > SP + 0xf8
                   for _, address, width, _ in frame.stores)
    inherited = z3.BitVec('sp_f8_live_in', 64)
    frame.put(SP + 0xf8, 8, inherited)
    before = len(frame.loads)
    start, consume = route(frame, READ_PC, CONSUME)
    assert frame.loads[before] == (READ_PC, SP + 0xf8, 8)
    assert z3.is_true(z3.simplify(frame.read('x20') == inherited + 0xc84937ac))
    assert number(frame.read('x0')) == buffer
    reads = [(pc, address - buffer, width) for pc, address, width in frame.loads[before:]
             if address < buffer + 14 and address + width > buffer]
    assert reads == [(pc, index, 1) for index, pc in enumerate(BYTE_READS)]
    assert not any(address < second_buffer + 14 and address + width > second_buffer
                   for _, address, width in frame.loads[before:])

    store_start = len(frame.stores)
    end, insertion = route(frame, start, SECOND_INSERT)
    assert end == 0x1000e72c4
    assert number(frame.get(owner, 8)) == first
    assert number(frame.get(first, 8)) == second
    assert number(frame.get(second, 8)) == 0
    assert number(frame.get(owner + 8, 8)) == second
    assert number(frame.get(second + 8, 8)) == first
    assert number(frame.get(first + 8, 8)) == 0
    assert number(frame.get(first + 24, 8)) == buffer
    assert number(frame.get(second + 24, 8)) == second_buffer
    assert [(pc, address, width, number(value))
            for pc, address, width, value in frame.stores[store_start:]
            if address in (owner, owner + 8, first, first + 8, second, second + 8)] == [
        (0x100013a68, first, 8, second), (0x100013a70, second + 8, 8, first),
        (0x100013a74, owner + 8, 8, second),
    ]
    return {'first_buffer_reads': [{'pc': hex(pc), 'offset_bytes': offset, 'width_bytes': width}
                                   for pc, offset, width in reads],
            'conditional_edges': consume + insertion,
            'terminal_pc': hex(end)}


def report():
    profiles = [profile(words, addresses) for words, addresses in PROFILES]
    assert all(profile == profiles[0] for profile in profiles)
    return {'daemon_sha256': sha(SOURCE), 'generator_sha256': sha(Path(__file__)),
            'parent_generator_sha256': sha(Path(__file__).with_name('audit_daemon_selector26_node.py')),
            'profiles': len(profiles), 'sp_f8_origin': 'unknown',
            'native_exchange_observed': False,
            'observations': profiles[0],
            'fixups': verify_original_fixups(FIXUP_SLOTS), 'source_spans': list(SPANS.values())}


if __name__ == '__main__':
    with redirect_stdout(sys.stderr):
        result = report()
    print(json.dumps(result, indent=2))
