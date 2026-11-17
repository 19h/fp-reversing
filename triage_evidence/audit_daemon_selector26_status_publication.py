#!/usr/bin/env python3
"""Verify the conditional frame-to-record handoff of the selector 26 error."""

import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

import z3

from audit_daemon_selector26_cleanup import NEXT, CleanupFrame, landmark
from audit_daemon_selector26_return import FIXUP_SLOTS, SP, SPANS, number
from audit_userclient_fallback_metadata import solve
from daemon_receive_tools import CS, FIXUPS, IMAGE, POOL, ROOT, SOURCE, TABLE
from daemon_receive_tools import verify_original_fixups
from verify_daemon_reader_record_payloads_publication import read, sha

FP = SP + 0x240
OUTPUT = 0xd000
STATUS = z3.BitVec('publication_error', 32)
PHASE = 0x8934


def frame(transient):
    f = CleanupFrame(x29=FP, x30=TABLE, x2=0x1000242f8,
                     w28=PHASE, w16=-0x7e42, w1=0x38c0,
                     w13=0x9749ae9b, w14=0x68b5fff5, w15=0x37ac)
    f.put(FP - 0xb8, 8, 0)
    f.put(SP + 0x90, 8, OUTPUT)
    f.put(SP + 0xa8, 8, transient)
    f.put(SP + 0xe8, 4, STATUS)
    f.put(OUTPUT + 8, 4, 0)
    return f


def slice_bytes(start, end):
    raw = IMAGE.read(start, end - start)
    instructions = list(CS.disasm(raw, start))
    assert len(instructions) * 4 == len(raw)
    SPANS[start, end] = {'start': hex(start), 'end_exclusive': hex(end),
                         'bytes_hex': raw.hex()}
    return instructions


def tail(f, target):
    f.step(0x100026478, 0x100026484)
    assert number(f.read('x0')) == 0 and number(f.read('x17')) == 0xf2d5
    assert number(f.read('x2')) == target


def publication(transient):
    f = frame(transient)
    assert f.step(0x1000242f8, 0x100024314) == 0x100008f88
    assert number(f.read('w23')) == 0xaf2 and number(f.read('x12')) == FP - 0xb8
    assert f.step(0x100008f88, 0x100008fbc) == 0x100026478
    slot = 0x10103f680
    assert (0x100008f94, slot, 8) in f.loads
    assert 'div=0xF2D5 ad=0 key=IA' in FIXUPS[slot]['annotation']
    tail(f, 0x100092550)
    f.step(0x100092550, 0x100092580)
    landmark(0x100092580, 'braa', 'x8, x17')
    _, result_slot, _ = f.loads[-3]
    target = FIXUPS[result_slot]['target']
    assert number(f.read('x8')) == target and number(f.read('x17')) == 0x49be
    assert 'div=0x49BE ad=0 key=IA' in FIXUPS[result_slot]['annotation']
    f.edges.append({'pc': '0x100092580', 'slot': hex(result_slot),
                    'target': hex(target), 'modifier': '0x49be'})
    assert (0x100092578, SP + 0xe8, 4) in f.loads
    assert number(f.read('x0')) == OUTPUT
    proof = solve('all_status_words_round_trip_' + ('nonnull' if transient else 'null'),
                  [], f.read('w22') != STATUS)
    if transient:
        assert target == 0x1000dda2c and number(f.read('x11')) == transient
        # Audit the call setup and compose the normal return of the indirect callee.
        f.step(0x1000dda78, 0x1000dda84)
        assert number(f.read('x0')) == transient
        f.seed('x0', z3.BitVec('indirect_return', 64))
        target = f.step(0x1000dda8c, 0x1000dda9c)
    assert target == 0x1000acc50
    f.step(0x1000acc50, 0x1000acc54)
    assert f.stores[-1][:3] == (0x1000acc50, OUTPUT + 8, 4)
    result = solve('all_status_words_published_' + ('nonnull' if transient else 'null'),
                   [], f.get(OUTPUT + 8, 4) != STATUS)
    assert proof['result'] == result['result'] == 'unsat'
    return {'transient_is_null': not transient, 'edges': f.edges, 'proofs': [proof, result]}


def report():
    source = sha(SOURCE)
    upstream_path = ROOT / 'daemon_selector26_cleanup_audit.json'
    upstream = json.loads(read(upstream_path))
    assert source == upstream['daemon_sha256']
    f = frame(0)
    tail(f, 0x1000242f8)
    landmark(0x100026484, 'braa', 'x2, x17')
    candidates = []
    for slot, row in sorted(FIXUPS.items()):
        if not (TABLE <= slot < POOL and row['kind'] == 'auth-rebase'
                and 'div=0xCA53 ad=0 key=IA' in row['annotation']):
            continue
        index = (slot - TABLE) // 8
        phase = ((index ^ 0x38c0) + 0x7e42) & 0xffffffff
        candidates.append({'phase': hex(phase), 'index': hex(index), 'slot': hex(slot),
                           'target': hex(row['target'])})
        FIXUP_SLOTS.add(slot)
    assert len(candidates) == 6 and any(row['phase'] == hex(PHASE) for row in candidates)
    setup = slice_bytes(0x1000dda2c, 0x1000dda8c)
    assert (setup[-1].mnemonic, setup[-1].op_str) == ('blraa', 'x8, x17')
    assert (setup[-2].mnemonic, setup[-2].op_str) == ('mov', 'x17, #0x46a2')
    epilogue = slice_bytes(0x1000acc54, 0x1000acc90)
    assert epilogue[-2].mnemonic == 'retab' and epilogue[-1].mnemonic == 'bl'
    fixup_candidates = [slot for slot, row in sorted(FIXUPS.items())
                        if TABLE + 8 * 0xcb96 <= slot <= TABLE + 8 * 0xcc95
                        and 'div=0x46A2 ad=0 key=IA' in row['annotation']]
    assert TABLE + 8 * 0xcc08 in fixup_candidates
    FIXUP_SLOTS.update(fixup_candidates)
    profiles = [publication(0), publication(NEXT)]
    return {'daemon_sha256': source, 'generator_sha256': sha(Path(__file__)),
            'upstream_sha256': sha(upstream_path),
            'phase_candidates': candidates,
            'transient_call_pac_compatible_slots': list(map(hex, fixup_candidates)),
            'profiles': profiles, 'phase_reaching_definition_established': False,
            'fixups': verify_original_fixups(FIXUP_SLOTS), 'source_spans': list(SPANS.values())}


if __name__ == '__main__':
    with redirect_stdout(sys.stderr):
        result = report()
    print(json.dumps(result, indent=2))
