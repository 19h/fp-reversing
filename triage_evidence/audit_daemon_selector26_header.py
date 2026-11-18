#!/usr/bin/env python3
"""Recover the ten-byte header writer immediately before the selector 26 split."""

from contextlib import redirect_stdout
import json
from pathlib import Path
import sys

import z3

from audit_daemon_selector26_callers import Caller, CONTEXT, DATA, INPUT
from audit_daemon_selector26_callers import caller, fields
from audit_daemon_selector26_node import route
from audit_daemon_selector26_return import FIXUP_SLOTS, RECORD, SP, SPANS, number
from audit_userclient_fallback_metadata import solve
from daemon_receive_tools import SOURCE, verify_original_fixups
from verify_daemon_reader_record_payloads_publication import sha

HEADER = (
    (0x1000859ec, 0x100085a60, 0x100085a2c, 0x101046b08, 0x9dfb, 0x1000fe08c),
    (0x1000fe08c, 0x1000fe3d8, 0x1000fe3d0, 0x10106d138, 0xa57c, 0x1000c62f0),
)
WRITERS = (0x1000fe0a8, 0x1000fe0c0, 0x1000fe0dc, 0x1000fe0fc, 0x1000fe150,
           0x1000fe16c, 0x1000fe308, 0x1000fe328, 0x1000fe348, 0x1000fe364)


def gate_proof():
    inherited = z3.BitVec('inherited_x22', 64)
    frame = Caller(x22=inherited)
    frame.step(0x1000fe378, 0x1000fe3c0)
    result = solve('header_exit_compare_equivalent_to_null_x22', [],
                   frame.equal != (inherited == 0))
    assert result['result'] == 'unsat'
    return result


def profile(first, buffer):
    extent = z3.BitVec('caller_extent', 64)
    size_word = z3.BitVec('saved_w19', 32)
    f = caller(extent, 0x2c if first else 0x2d)
    for reg, value in [('x0', buffer), ('x20', 0x7000), ('x22', 0), ('w24', 0x1983), ('w19', size_word)]:
        f.seed(reg, value)
    f.put(0x7000, 8, 0)
    f.put(SP + 0x90, 8, INPUT)

    terminal, edges = route(f, HEADER[0][0], HEADER)
    assert terminal == 0x1000c62f0
    assert (0x100085a14, 0x7000, 8) in f.loads
    assert (0x100085a48, SP + 0x90, 8) in f.loads
    assert number(f.read('x6')) == INPUT
    assert number(f.read('x0')) == number(f.read('x7')) == buffer
    assert number(f.read('x8')) == buffer + 10
    assert number(f.read('w10')) == 0xa4c7 and number(f.read('w11')) == 0x662a
    assert [(pc, address, width) for pc, address, width, _ in f.stores] == [
        (pc, buffer + offset, 1) for offset, pc in enumerate(WRITERS)
    ]
    assert [number(f.get(buffer + offset, 1)) for offset in range(6)] == [0, 0, 0, 0, 0x50, 0xdb]
    length = z3.Concat(*(f.get(buffer + offset, 1) for offset in range(6, 10)))
    proof = solve(f'header_length_{int(first)}_{buffer:x}', [], length != 0x37c30c43 - size_word)
    assert proof['result'] == 'unsat'

    target = f.step(terminal, 0x1000c635c)
    assert (0x1000c62f0, INPUT, 1) in f.loads
    assert number(f.get(SP + 0xa8, 8)) == buffer
    call = 0x1000f2204 if first else 0x100111754
    assert target == (0x1000f20f4 if first else 0x100111684)
    assert f.step(target, call + 4) == (0x10043a018 if first else 0x10043ee28)
    assert number(f.read('x0')) == RECORD
    assert number(f.get(RECORD + (0 if first else 24), 8)) == buffer
    assert number(f.get(RECORD + (8 if first else 16), 8)) == CONTEXT
    # Reuse the caller's established record codec on its original data placement.
    if buffer == DATA:
        record = solve(f'header_to_caller_{call:x}', [], fields(f, first, extent))
        assert record['result'] == 'unsat'
    else:
        record = None
    assert [(pc, address, width) for pc, address, width, _ in f.stores
            if buffer <= address < buffer + 10] == [(pc, buffer + i, 1) for i, pc in enumerate(WRITERS)]
    return {'data_address_fixture': hex(buffer), 'header_edges': edges,
            'caller_edges': f.edges, 'header_length_proof': proof, 'record_proof': record}


def report():
    FIXUP_SLOTS.add(0x101060830)
    proofs = [gate_proof()]
    profiles = [profile(first, buffer) for first in (True, False) for buffer in (DATA, 0x8000)]
    return {'daemon_sha256': sha(SOURCE), 'generator_sha256': sha(Path(__file__)),
            'entry_slot': '0x101060830', 'entry_origin': 'unknown',
            'native_exchange_observed': False,
            'write_sites': [hex(pc) for pc in WRITERS],
            'proofs': proofs, 'profiles': profiles,
            'fixups': verify_original_fixups(FIXUP_SLOTS), 'source_spans': list(SPANS.values())}


if __name__ == '__main__':
    with redirect_stdout(sys.stderr):
        result = report()
    print(json.dumps(result, indent=2))
