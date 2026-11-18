#!/usr/bin/env python3
"""Lift the nonnull allocation route from the daemon's saved caller record."""

from contextlib import redirect_stdout
import json
from pathlib import Path
import sys

import z3

from audit_daemon_selector26_cleanup import landmark
from audit_daemon_selector26_record_origin import (
    ALLOCATED, CONTEXT, FP, GLOBAL_ONE, GLOBAL_TWO, OriginFrame, PHASE, RECORD,
    SECOND, THIRD, trace_check,
)
from audit_daemon_selector26_return import FIXUP_SLOTS, SP, SPANS, number
from audit_userclient_fallback_metadata import solve
from daemon_receive_tools import FIXUPS, ROOT, SOURCE, TABLE, selected, verify_original_fixups
from verify_daemon_reader_record_payloads_publication import read, sha

NODE, BUFFER = 0x20000, 0x21000


def normal_malloc_return(frame, call, size, result):
    assert frame.edges[-1]['pc'] == hex(call)
    assert frame.edges[-1]['target'] == 'libSystem/_malloc'
    assert number(frame.read('x0')) == size
    assert result and result & 15 == 0
    # Require new definitions of every volatile value consumed after the call.
    for register in (*range(19), 30):
        frame.regs.pop(f'x{register}', None)
    for flag in ('negative', 'equal', 'carry', 'overflow'):
        setattr(frame, flag, z3.Bool(f'volatile_{flag}_{call:x}'))
    frame.seed('x0', result)
    return {'pc': hex(call), 'size_bytes': size}


def constructor_frame(first, second, *, frame_type=OriginFrame, registers=None,
                      locations=(ALLOCATED, NODE, BUFFER)):
    allocated, node, buffer = locations
    incoming = z3.BitVec('incoming_sp_e0', 64)
    f = frame_type(x0=RECORD, x29=FP, **(registers or {}))
    f.put(RECORD + 16, 8, CONTEXT)
    f.put(RECORD + 4, 4, (PHASE - ((RECORD ^ 0xf9d49974) * 0xda51a827)) & 0xffffffff)
    f.put(SP + 0xe0, 8, incoming)
    f.put(GLOBAL_ONE, 8, first)
    f.put(GLOBAL_TWO, 8, second)
    assert f.step(0x100411130, 0x10041132c) == 0x10005be70
    assert f.step(0x10005be70, 0x10005bf24) == 'libSystem/_malloc'
    allocations = [normal_malloc_return(f, 0x10005bf20, 16, allocated)]
    assert tuple(number(f.get(SP + offset, 8)) for offset in (0x70, 0x68)) == THIRD

    f.step(0x10005bf24, 0x10005bfb0)
    assert tuple(number(f.get(FP - offset, 8)) for offset in (0xf8, 0x100)) == SECOND
    first_slot = TABLE + 8 * 0x6241
    assert (0x10005bf48, first_slot, 8) in f.loads
    indirect(f, 0x10005bfb0, 'x8', first_slot, 0x6ff9, 0x100015c50)
    assert f.step(0x100015c50, 0x100015c90) == 0x10002bfd0
    assert f.step(0x10002bfd0, 0x10002c010) == 0x10004e9d0
    assert number(f.read('w8')) == PHASE
    f.step(0x10004e9d0, 0x10004ea30)
    dispatch_slot = TABLE + 8 * 0x2c2a
    assert f.loads[-2:] == [(0x10004ea08, dispatch_slot, 8), (0x10004ea28, SP + 0xe0, 8)]
    indirect(f, 0x10004ea30, 'x9', dispatch_slot, 0x5530, 0x10008c8e8)
    assert number(f.read('w8')) == 0x9ea4
    assert number(f.read('w23')) == 0x8b3dc655

    f.step(0x10008c8e8, 0x10008c974)
    assert number(f.read('w10')) == 4
    assert f.step(0x10008c974, 0x10008c994) == 0x10001bc34
    assert f.step(0x10001bc34, 0x10001bca0) == 'libSystem/_malloc'
    allocations.append(normal_malloc_return(f, 0x10001bc9c, 32, node))
    assert f.step(0x10001bca0, 0x10001bcd8) == 0x100015a3c
    assert f.step(0x100015a3c, 0x100015af8) == 'libSystem/_malloc'
    allocations.append(normal_malloc_return(f, 0x100015af4, 14, buffer))
    assert f.step(0x100015af8, 0x100015b28) == 0x10005c5f4
    assert number(f.read('x22')) == node
    assert number(f.get(RECORD + 16, 8)) == CONTEXT
    assert number(f.get(SP + 0x90, 8)) == RECORD
    assert number(f.get(SP + 0x124, 4)) == PHASE
    assert number(f.get(FP - 0xc0, 8)) == 0
    assert number(f.get(FP - 0xb8, 8)) == number(f.get(SP + 0x40, 8)) == allocated
    assert not any(BUFFER <= address < BUFFER + 14 for _, address, _, _ in f.stores)
    assert [(pc, address - node, width, number(value)) for pc, address, width, value in f.stores
            if node <= address < node + 32] == [
        (0x100015a48, 0, 8, 0), (0x100015a48, 8, 8, 0),
        (0x100015aa8, 16, 4, 14), (0x100015b00, 24, 8, buffer),
    ]
    return f, allocations, incoming


def constructor_globals(first, second):
    f, allocations, incoming = constructor_frame(first, second)
    proof = solve('arbitrary_incoming_cell_preserved_through_buffer_publication',
                  [], f.get(SP + 0xe0, 8) != incoming)
    assert proof['result'] == 'unsat'
    return {'allocations': allocations, 'edges': f.edges}, proof


def indirect(frame, pc, reg, slot, modifier, target):
    landmark(pc, 'braa', f'{reg}, x17')
    assert number(frame.read(reg)) == FIXUPS[slot]['target'] == target
    assert number(frame.read('x17')) == modifier
    assert f'div=0x{modifier:X} ad=0 key=IA' in FIXUPS[slot]['annotation']
    frame.edges.append({'pc': hex(pc), 'slot': hex(slot), 'modifier': hex(modifier),
                        'target': hex(target)})


def report():
    previous = json.loads(read(ROOT / 'daemon_selector26_record_origin_audit.json'))
    digest = sha(SOURCE)
    assert digest == previous['daemon_sha256']
    profiles = [constructor_globals(*values) for values in (
        (0x12345678, 0x98765432), (0xffffffff, 0), (0, 0xffffffff))]
    assert all(profile == profiles[0][0] for profile, _ in profiles)
    banks = [selected(*pair, key, additive, TABLE) for pair, key, additive in (
        (THIRD, 0x86, 0xcbb5), (SECOND, 0xf3, 0xcbca))]
    assert all(row['inputs_checked'] == 256 and row['target'] == 'libSystem/_malloc'
               and row['slot'] == '0x10109ff58' for row in banks)
    return {'daemon_sha256': digest, 'generator_sha256': sha(Path(__file__)),
            'constructor': profiles[0][0], 'global_profiles_checked': len(profiles),
            'proofs': [profiles[0][1]], 'banks': banks, 'trace': trace_check(),
            'native_exchange_observed': False, 'fixups': verify_original_fixups(FIXUP_SLOTS),
            'source_spans': list(SPANS.values())}


if __name__ == '__main__':
    with redirect_stdout(sys.stderr):
        result = report()
    print(json.dumps(result, indent=2))
