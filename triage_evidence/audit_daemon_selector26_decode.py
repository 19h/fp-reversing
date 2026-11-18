#!/usr/bin/env python3
"""Recover the local four-byte readback and its allocator continuation."""

from contextlib import redirect_stdout
import json
from pathlib import Path
import sys

import z3

from audit_daemon_selector26_node import FIRST_INSERT, PROFILES, SP, node_frame, route
from audit_daemon_selector26_readback import CONSUME, READ_PC, SECOND_INSERT
from audit_daemon_selector26_return import FIXUP_SLOTS, SPANS, number
from audit_userclient_fallback_metadata import solve
from daemon_receive_tools import SOURCE, verify_original_fixups
from verify_daemon_reader_record_payloads_publication import sha

RESTART = (
    *FIRST_INSERT[5:7],
    (0x1001e2e00, 0x1001e2e0c, 0x10002bfd8, 0x101041970, 0x7cb2, 0x1000fe5bc),
    (0x1000fe5bc, 0x1000fe608, 0x1000fe600, 0x10107bb50, 0xf6ab, 0x1000bde3c),
    (0x1000bde3c, 0x1000bde84, 0x1000bde70, 0x101056c38, 0xa551, 0x10002bfd0),
    *FIRST_INSERT[10:],
)


def consume(words, locations, symbolic=None):
    frame, _ = node_frame(words, locations)
    frame.put(SP + 0xf8, 8, z3.BitVec('incoming_sp_f8', 64))
    if symbolic is not None:
        # Replace just the input to the local arithmetic proof.
        frame.put(locations[2], 4, symbolic)
    entry, edges = route(frame, READ_PC, CONSUME)
    assert entry == 0x100012ab8
    return frame, entry, edges


def observed(words, locations):
    frame, entry, edges = consume(words, locations)
    stores = [(pc, width, number(value)) for pc, address, width, value in frame.stores
              if address < SP + 0xb8 and address + width > SP + 0xb4]
    assert stores == [(0x10001bc3c, 4, 0xff7657b9), (0x10001bc3c, 4, 0x8c74d4f5)]
    frame.step(entry, 0x1000132d4)
    decoded = number(frame.read('w8'))
    assert decoded == 0xfa88cee0
    assert number(frame.get(SP + 0xb4, 4)) == 0x8c74d4f5
    frame.step(0x1000132d4, 0x1000132fc)
    assert z3.is_false(z3.simplify(frame.equal))
    assert number(frame.read('w8')) == 0x8b02

    end, insert_edges = route(frame, entry, SECOND_INSERT)
    owner, _, _, second, _ = locations
    assert number(frame.get(owner + 8, 8)) == second
    end, restart_edges = route(frame, end, RESTART)
    assert end == 0x10001bc34
    assert frame.step(end, 0x10001bca0) == 'libSystem/_malloc'
    assert number(frame.read('x0')) == 32
    return {'consumer_edges': edges + insert_edges, 'restart_edges': restart_edges,
            'next_import': frame.edges[-1], 'next_argument_size_bytes': 32}


def equations(words, locations, index):
    input_word = z3.BitVec('local_readback_word', 32)
    frame, entry, _ = consume(words, locations, input_word)
    frame.step(entry, 0x1000132d4)
    decoded = frame.read('w8')
    constant = number(z3.substitute(decoded, (input_word, z3.BitVecVal(0, 32))))
    be32 = z3.Concat(*(z3.Extract(offset + 7, offset, input_word) for offset in range(0, 32, 8)))
    model = be32 ^ constant
    checks = [solve(f'profile_{index}_byte_reversal_and_xor', [], decoded != model)]
    frame.step(0x1000132d4, 0x1000132fc)
    expected_compare = (model ^ 0x8c74d4f5) == 0x05fe9959
    expected_index = z3.If(expected_compare, z3.BitVecVal(0x8aea, 32), z3.BitVecVal(0x8b02, 32))
    checks.append(solve(f'profile_{index}_compare_and_index', [], z3.Or(
        frame.equal != expected_compare, frame.read('w8') != expected_index)))
    assert all(check['result'] == 'unsat' for check in checks)
    return {'byte_reverse_xor': hex(constant), 'checks': checks}


def zero_word_output(words, locations):
    frame, entry, _ = consume(words, locations, z3.BitVecVal(0, 32))
    frame.step(entry, 0x1000132d4)
    return hex(number(frame.read('w8')))


def layout_controls(expected):
    crossed = [[zero_word_output(words, locations) for _, locations in PROFILES]
               for words, _ in PROFILES]
    assert all(row == expected for row in crossed)
    words, baseline = PROFILES[0]
    _, alternative = PROFILES[1]
    replacements = [zero_word_output(words, baseline[:i] + (value,) + baseline[i + 1:])
                    for i, value in enumerate(alternative)]
    assert replacements == [expected[0], expected[0], expected[1], expected[0], expected[0]]
    return {'crossed_global_and_heap_profiles': crossed, 'single_allocation_relocations': replacements}


def report():
    cases = [observed(words, locations) for words, locations in PROFILES]
    assert all(case == cases[0] for case in cases)
    models = [equations(words, locations, index) for index, (words, locations) in enumerate(PROFILES)]
    masks = [model['byte_reverse_xor'] for model in models]
    assert len(set(masks)) == len(models)
    return {'daemon_sha256': sha(SOURCE), 'generator_sha256': sha(Path(__file__)),
            'profiles': len(cases), 'sp_f8_source': 'unknown', 'native_exchange_observed': False,
            'observations': cases[0], 'equations': models, 'layout_controls': layout_controls(masks),
            'fixups': verify_original_fixups(FIXUP_SLOTS), 'source_spans': list(SPANS.values())}


if __name__ == '__main__':
    with redirect_stdout(sys.stderr):
        result = report()
    print(json.dumps(result, indent=2))
