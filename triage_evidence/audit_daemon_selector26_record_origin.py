#!/usr/bin/env python3
"""Audit the caller record, frame saves and conditional allocator setup."""

from contextlib import redirect_stdout
import json
import re
import sys
from pathlib import Path

import z3

from audit_daemon_selector26_cleanup import CleanupFrame, landmark
from audit_daemon_selector26_return import FIXUP_SLOTS, SP, SPANS, number
from audit_userclient_fallback_metadata import solve
from daemon_receive_tools import FIXUPS, IMAGE, POOL, ROOT, SOURCE, TABLE, qword, selected
from daemon_receive_tools import verify_original_fixups
from lskd_values_symbolic import resize
from verify_daemon_reader_record_payloads_publication import sha

FP = SP + 0x240
RECORD, CONTEXT, ALLOCATED = 0x8000, 0x9000, 0xa000
PHASE = 0x8934
FIRST = (0x100fc4130, 0x101031ea0)
SECOND = (0x100fc4230, 0x101031fa0)
THIRD = (0x101031da0, 0x100e99900)
FOURTH = (0x100e99a00, 0x100f4e390)
GLOBAL_ONE, GLOBAL_TWO = 0x1010b8e18, 0x1010c4670


class OriginFrame(CleanupFrame):
    def load(self, address, width):
        at = number(address)
        if width == 8 and at in FIXUPS and at >= POOL:
            self.loads.append((self.pc, at, width))
            FIXUP_SLOTS.add(at)
            return resize(qword(at), 64)
        if width == 1 and any(base <= at < base + 256 for base in FIRST + SECOND + THIRD + FOURTH):
            self.loads.append((self.pc, at, width))
            return resize(IMAGE.read(at, 1)[0], 8)
        return super().load(address, width)


def caller_field_proof():
    p = z3.BitVec('aligned_record', 64)
    f = OriginFrame(x29=p + 0x78, w24=0x3941)
    f.step(0x1001f50cc, 0x1001f5108)
    encoded = (f.read('w24') - f.read('w9')) + 0x4ff3
    g = OriginFrame(x0=p)
    g.step(0x100411240, 0x100411290)
    proof = solve('caller_record_decodes_to_phase_for_aligned_record',
                  [(p & 15) == 0], encoded + g.read('w16') != PHASE)
    assert proof['result'] == 'unsat'
    return proof


def caller_route():
    f = OriginFrame(x29=RECORD + 0x78, x28=TABLE, w24=0x3941,
                    x20=CONTEXT, x22=GLOBAL_ONE, x26=GLOBAL_TWO,
                    w25=0x7d18d723, w27=0x297027a6)
    f.put(SP + 0x4c, 4, 16)
    f.put(SP + 0x40, 8, SECOND[0])
    f.put(SP + 0x38, 8, SECOND[1])
    f.put(GLOBAL_ONE, 4, 0x12345678)
    f.put(GLOBAL_TWO, 4, 0x98765432)
    f.step(0x1001f50b0, 0x1001f511c)
    landmark(0x1001f511c, 'sturb', 'w8, [x29, #-0x78]')
    f.store(f.read('x29') - 0x78, 1, f.read('w8'), 0x1001f511c)
    assert f.step(0x1001f5120, 0x1001f517c) == 0x1004110fc
    assert number(f.read('x0')) == RECORD and number(f.get(RECORD + 16, 8)) == CONTEXT
    for status, target in ((0x8b3dc651, 0x10011c77c), (0x74c29ded, 0x1002c99a0),
                           (0x74c29cd6, 0x1002c99a0)):
        f.put(RECORD + 8, 4, status)
        assert f.step(0x1001f517c, 0x1001f51a8) == target
    return f.edges


def profile(context, allocated):
    f = OriginFrame(x0=RECORD, x29=FP)
    f.put(RECORD + 16, 8, context)
    f.put(RECORD + 4, 4, (PHASE - ((RECORD ^ 0xf9d49974) * 0xda51a827)) & 0xffffffff)
    f.put(GLOBAL_ONE, 8, 0x12345678)
    f.put(GLOBAL_TWO, 8, 0x98765432)
    # The original prologue initializes these before its first authenticated branch.
    assert f.step(0x100411130, 0x10041132c) == (0x10005be70 if context else 0x1000acc50)
    assert number(f.read('w28')) == PHASE
    assert number(f.get(FP - 0xc0, 8)) == number(f.get(FP - 0xb8, 8)) == 0
    if not context:
        f.step(0x1000acc50, 0x1000acc54)
        assert number(f.get(RECORD + 8, 4)) == 0x74c29d88
    else:
        assert f.step(0x10005be70, 0x10005bf24) == 'libSystem/_malloc'
        assert number(f.read('x0')) == 16
        assert number(f.get(SP + 0x90, 8)) == RECORD
        f.seed('x0', allocated)
        f.step(0x10005bf24, 0x10005bfb0)
        slot = TABLE + 8 * (0x6241 if allocated else 0x6246)
        target = 0x100015c50 if allocated else 0x100013334
        assert number(f.read('x8')) == FIXUPS[slot]['target'] == target
        assert 'div=0x6FF9 ad=0 key=IA' in FIXUPS[slot]['annotation']
        assert number(f.get(SP + 0x124, 4)) == PHASE
        assert (number(f.get(SP + 0xb8, 8)), number(f.get(SP + 0xc0, 8))) == FIRST
        if allocated:
            assert f.step(target, 0x100015c90) == 0x10002bfd0
            assert number(f.get(FP - 0xb8, 8)) == allocated
            assert number(f.get(allocated, 8)) == number(f.get(allocated + 8, 8)) == 0
            assert f.step(0x10002bfd0, 0x10002c010) == 0x10004e9d0
    return {'input_context_null': not context, 'allocator_result': hex(allocated), 'edges': f.edges}


def trace_check():
    trace = Path.home() / 'Downloads' / 'zut' / 'annotated-strace-rax-user.txt'
    digest = sha(trace)
    assert digest == '78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e'
    lines = trace.read_text().splitlines()
    sends = [int(match.group(1)) for line in lines
             if (match := re.search(r'\bsend bits=.*\bid=(\d+)', line))]
    assert len(sends) == 22 and sends[-1] == 2862 and 2865 not in sends
    assert 'c2 02 00 e0' in lines[1739] and 'port name=0x0' in lines[1740]
    return {'sha256': digest, 'send_ids': sends, 'open_reply_lines': [1736, 1741],
            'open_result': '0xe00002c2', 'connection_port': 0}


def report():
    proof = caller_field_proof()
    caller_edges = caller_route()
    profiles = [profile(0, 0), profile(CONTEXT, 0), profile(CONTEXT, ALLOCATED)]
    for pc, m, op in ((0x1001f512c, 'stur', 'w8, [x29, #-0x74]'),
                      (0x1001f5178, 'blraa', 'x8, x17'),
                      (0x1001f517c, 'ldur', 'w8, [x29, #-0x70]'),
                      (0x10005bfb0, 'braa', 'x8, x17')):
        landmark(pc, m, op)
    banks = [selected(*pair, key, additive, base) for pair, key, additive, base in (
        (SECOND, 0xf3, 0xce5b, TABLE), (FIRST, 0xa3, 0xcb96, TABLE),
        (FIRST, 0x4e, 0x8fb, POOL), (FOURTH, 0x6d, -0x3c, POOL),
        (SECOND, 0xf3, 0x8d7, POOL), (THIRD, 0x86, 0xcbb5, TABLE))]
    assert [row['target'] for row in banks[:2]] == ['0x1004110fc', 'libSystem/_free']
    FIXUP_SLOTS.update(int(row['slot'], 16) for row in banks)
    return {'daemon_sha256': sha(SOURCE), 'generator_sha256': sha(Path(__file__)),
            'proofs': [proof], 'profiles': profiles, 'caller_edges': caller_edges,
            'banks': banks, 'trace': trace_check(),
            'fixups': verify_original_fixups(FIXUP_SLOTS), 'source_spans': list(SPANS.values())}


if __name__ == '__main__':
    with redirect_stdout(sys.stderr):
        result = report()
    print(json.dumps(result, indent=2))
