#!/usr/bin/env python3
"""Verify the immediate callers and shared status gate of fairplayd selector 26."""

from contextlib import redirect_stdout
import json
import sys

import z3

from audit_daemon_selector26_return import KEY, RECORD, SP, SPANS, Frame, number
from audit_daemon_selector26_return import FIXUP_SLOTS
from audit_userclient_fallback_metadata import solve
from daemon_receive_tools import CS, FIXUPS, IMAGE, ROOT, SOURCE, TABLE, qword, selected
from daemon_receive_tools import verify_original_fixups
from lskd_values_symbolic import resize
from verify_daemon_reader_record_payloads_publication import read, sha

SCOPE = 'Original fairplayd common dispatch, selector 26 caller records and shared local result gate.'
FP = RECORD + 0x80
CONTEXT, DATA, INPUT, GLOBALS = 0x3000, 0x4000, 0x5000, 0x6000
STATUS = z3.BitVec('caller_record_status', 32)
DISPATCH_BYTE = z3.BitVec('caller_dispatch_byte', 8)
DISPATCH_BIAS = z3.BitVec('caller_dispatch_bias', 64)
EXTENT = z3.BitVec('caller_extent_cell', 64)
FAILURE_CONTINUATION = 0x100013334
ZERO_CONTINUATION = 0x1000acd3c
ROOT_WORDS = {0x1010a59a8, 0x1010a7fa0}
FIRST_BANK = (0x100e99800, 0x100f4e290)
SECOND_BANK = (0x101031da0, 0x100e99900)


class Caller(Frame):
    def load(self, address, width):
        at = number(address)
        if width == 1 and any(base <= at < base + 256 for base in FIRST_BANK + SECOND_BANK):
            self.loads.append((self.pc, at, width))
            return resize(IMAGE.read(at, 1)[0], 8)
        if width == 8 and at in ROOT_WORDS:
            self.loads.append((self.pc, at, width))
            FIXUP_SLOTS.add(at)
            return resize(qword(at), 64)
        return super().load(address, width)


def caller(extent, selector):
    f = Caller(x29=FP, x30=TABLE, w10=0xa4c7, x6=INPUT, x7=DATA,
               x25=z3.BitVec('caller_x25', 64), x26=GLOBALS, x27=GLOBALS + 4)
    f.put(INPUT, 1, selector)
    f.put(SP + 0x38, 8, 0)
    f.put(SP + 0x88, 8, CONTEXT)
    f.put(SP + 0x130, 8, extent)
    f.put(SP + 0x70, 8, SECOND_BANK[0])
    f.put(SP + 0x68, 8, SECOND_BANK[1])
    f.put(SP + 0x108, 8, z3.BitVec('saved_caller_object', 64))
    f.put(SP + 0x104, 4, z3.BitVec('caller_companion_word', 32))
    f.put(FP - 0xd0, 8, TABLE)
    f.put(GLOBALS, 4, 0x107)
    f.put(GLOBALS + 4, 4, 0x206)
    return f


def dispatch(first, extent):
    f = caller(extent, 0x2c if first else 0x2d)
    target = f.step(0x1000c62f0, 0x1000c635c)
    assert target == (0x1000f20f4 if first else 0x100111684)
    assert number(f.read('w20')) == number(f.read('w21')) == 0x7ef7
    call = 0x1000f2204 if first else 0x100111754
    assert f.step(target, call + 4) == (0x10043a018 if first else 0x10043ee28)
    assert number(f.read('w19')) == 0x4d3f
    assert number(f.read('x0')) == RECORD
    return f, call


def fields(f, first, extent):
    extent = resize(extent, 32)
    if first:
        key = ((RECORD ^ 0xd71b18ee ^ 0x11cd78fa) * 0x6b86592f) & 0xffffffff
        return z3.Or(f.get(RECORD, 8) != DATA, f.get(RECORD + 8, 8) != CONTEXT,
                     (f.get(RECORD + 16, 4) ^ key) + 0xf537f77b != extent,
                     (f.get(RECORD + 20, 4) ^ key) != 0xbf1d)
    key = ((RECORD ^ 0xba958aeceaae0ac9) * 0x7398180b) & 0xffffffff
    return z3.Or(f.get(RECORD + 16, 8) != CONTEXT, f.get(RECORD + 24, 8) != DATA,
                 (f.get(RECORD, 4) ^ key) + 0xbc30601d != extent,
                 f.get(RECORD + 4, 4) - key != 0xb469)


def reload_result(f, first, call, status):
    result_offset = 24 if first else 8
    # Compose the prior callee's record store and ordinary ABI return.
    f.put(RECORD + result_offset, 4, status)
    f.seed('x30', call + 4)
    f.seed('x0', z3.BitVec('opaque_callee_x0', 64))
    assert f.step(call + 4, call + 24) == 0x1000745f4
    assert f.loads[-2] == (call + 8, RECORD + result_offset, 4)
    return f.read('w16')


def continue_failure(f):
    f.step(FAILURE_CONTINUATION, 0x100013368)
    pc = 0x100013368
    raw = IMAGE.read(pc, 4)
    SPANS[pc, pc + 4] = {'start': hex(pc), 'end_exclusive': hex(pc + 4),
                         'bytes_hex': raw.hex()}
    branch = next(CS.disasm(raw, pc))
    assert (branch.mnemonic, branch.op_str) == ('braa', 'x9, x17')
    slot = 0x10105f030
    assert f.loads[-3] == (0x100013350, slot, 8)
    assert FIXUPS[slot]['target'] == number(f.read('x9')) == 0x1000c3174
    assert number(f.read('x17')) == 0x7d16
    assert 'div=0x7D16 ad=0 key=IA' in FIXUPS[slot]['annotation']
    f.edges.append({'pc': hex(pc), 'slot': hex(slot), 'target': '0x1000c3174',
                    'modifier': '0x7d16'})
    assert f.step(0x1000c3174, 0x1000c31c0) == 0x100008f88


def control_profile(first, raw_status):
    extent = 16 if first else 14
    f, call = dispatch(first, extent)
    reload_result(f, first, call, raw_status)
    target = f.step(0x1000745f4, 0x100074634)
    parked = None
    if raw_status == KEY:
        assert target == ZERO_CONTINUATION
    else:
        assert target == FAILURE_CONTINUATION
        continue_failure(f)
        target = 0x100008f88
        assert number(f.get(SP + 0xe8, 4)) == raw_status
        parked = hex(number(f.get(SP + 0xe8, 4)))
    return {'edges': f.edges, 'raw_status': hex(raw_status), 'next_pc': hex(target),
            'saved_status_stack_plus_e8': parked}


def image_checks():
    first = selected(*FIRST_BANK, 0x61, 0xcd60)
    second = selected(*SECOND_BANK, 0x86, 0xcd5f)
    collision = selected(0x100fc4230, 0x101031fa0, 0xf3, 0xcd5c)
    for row, target in zip((first, second, collision), (0x10043a018, 0x10043ee28, 0x100454f60)):
        assert row['target'] == hex(target)
    for start, end in ((0x10043a018, 0x10043a038), (0x10043ee28, 0x10043ee4c)):
        raw = IMAGE.read(start, end - start)
        SPANS[start, end] = {'start': hex(start), 'end_exclusive': hex(end),
                             'bytes_hex': raw.hex()}
    f = Caller(x22=TABLE, w8=7, w27=0xa5cd4cf)
    assert f.step(0x1000b3a38, 0x1000b3a98) == 0x100454f60
    return [first, second, collision]


def report():
    upstream = json.loads(read(ROOT / 'daemon_selector26_return_audit.json'))
    assert upstream['daemon_sha256'] == sha(SOURCE)
    banks = image_checks()
    f = caller(14, DISPATCH_BYTE)
    f.put(SP + 0x38, 8, DISPATCH_BIAS)
    f.step(0x1000c62f0, 0x1000c6348)
    proofs = [solve('all_dispatch_bytes', [], f.read('w9') != z3.If(
        DISPATCH_BYTE - resize(DISPATCH_BIAS, 8) == 0x2d,
        resize(0xa4c7, 32), resize(0xa4cb, 32)))]
    profiles = {}
    for first in (True, False):
        label = 'direct' if first else 'descriptor'
        f, call = dispatch(first, EXTENT)
        proofs.append(solve(label + '_record_fields', [], fields(f, first, EXTENT)))
        loaded = reload_result(f, first, call, STATUS)
        f.step(0x1000745f4, 0x100074628)
        proofs.append(solve(label + '_all_record_status_words', [], z3.Or(
            loaded != STATUS,
            f.read('w8') != z3.If(STATUS == KEY, resize(0x8c08, 32), resize(0x4d3f, 32)))))
        values = {name: int(words['encoded'], 16) for name, words in upstream['statuses'].items()}
        values['zero_api_status'] = KEY
        for name, status in values.items():
            profiles[label + '_' + name] = control_profile(first, status)
    f, call = dispatch(False, 14)
    reload_result(f, False, call, STATUS)
    f.seed('w23', 0xb11)
    continue_failure(f)
    proofs.append(solve('all_failure_words_preserved_in_caller_stack', [STATUS != KEY],
                        f.get(SP + 0xe8, 4) != STATUS))
    return {'scope': SCOPE, 'daemon_sha256': sha(SOURCE),
            'generator_sha256': sha(ROOT / 'audit_daemon_selector26_callers.py'),
            'dependencies': {name: sha(ROOT / name) for name in (
                'audit_daemon_selector26_return.py', 'daemon_selector26_return_audit.json',
                'daemon_receive_tools.py', 'daemon_receive_fixups.txt',
                'audit_userclient_fallback_metadata.py')},
            'banks': banks, 'fixups': verify_original_fixups(FIXUP_SLOTS),
            'source_spans': list(SPANS.values()), 'proofs': proofs, 'profiles': profiles,
            'native_exchange_observed': False, 'full_goal_complete': False}


if __name__ == '__main__':
    with redirect_stdout(sys.stderr):
        result = report()
    print(json.dumps(result, indent=2))
