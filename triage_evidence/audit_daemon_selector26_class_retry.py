#!/usr/bin/env python3
"""Replay ordinary lookup, release, fallback and status return in one frame."""

from contextlib import redirect_stdout
import json
from pathlib import Path
import re
import sys

import z3

from audit_daemon_selector26_class_gate import (
    AVP, F, INPUT, MIDDLE_BANK, PHASE, PRIMARY, R, enter, initial_frame,
)
from audit_daemon_selector26_cleanup import landmark
from audit_daemon_selector26_match_entry import (
    AVP as AVP_DECODER, CLASSES, DISPATCH, LEGACY, MAIN, api_return, branch, class_call,
)
from audit_daemon_selector26_open import (
    CALLER, ITERATE, ITERATE_CALL, ITERATE_END, MATCH, MATCH_CALL, MATCH_END,
    OPEN, OPEN_CALL, OPEN_END, TASK,
)
from audit_daemon_selector26_record_origin import FIRST, FOURTH, SECOND, OriginFrame, trace_check
from audit_daemon_selector26_return import FIXUP_SLOTS, SP, SPANS, number
from audit_userclient_fallback_metadata import solve
from daemon_receive_tools import FIXUPS, IMAGE, POOL, SOURCE, selected, verify_original_fixups
from verify_daemon_reader_record_payloads_publication import sha

FALLBACK = 0x10014ebf0
FINAL = 0x1002bfecc
NO_SERVICE = 0x1000bd85c
REJECTED = 0x1002c99a0
EXTRA = 0x10028a774
SERVICE_RELEASE = 0x1001dca60
ITERATOR_TEST = 0x1001bb4d4
ITERATOR_RELEASE = 0x100205930
RESUME = 0x1001ce7b8
RELEASE = 'IOKit/_IOObjectRelease'
STATUS_OK = 0x8b3dc651
POSTPROCESS_WORD = 0x1010c4d70


def initial_attempt(byte, primary_flag):
    f = initial_frame()
    encoded = enter(f)
    for address in (PRIMARY, AVP):
        for offset, width in ((4, 4), (0x14, 4), (0x18, 1), (0x28, 8)):
            f.put(address + offset, width, int.from_bytes(IMAGE.read(address + offset, width),
                                                         'little'))
    f.put(PRIMARY, 1, primary_flag)
    f.put(R, 1, byte)
    api_return(f, 0, 'w0')
    f.read_record_byte(0x100438534)
    f.step(0x100438538, 0x10043861c)
    entry = 0x1002765f8 if byte == 0x98 else FALLBACK
    branch(f, 0x10043861c, 0x1004385d4, 'x9', entry)
    f.put(TASK, 4, 0x317)
    assert number(f.get(F + 0x6c, 4)) == PHASE
    return f, entry, encoded


def primary_check(f, allowed):
    assert number(f.read('x20')) == PRIMARY
    f.step(FALLBACK, 0x10014ec24)
    target = 0x100289e64 if allowed else FINAL
    branch(f, 0x10014ec24, 0x10014ec1c, 'x9', target)
    return target


def constructor_return(f, result, context_bit):
    f.step(CALLER, 0x1001f511c)
    landmark(0x1001f511c, 'sturb', 'w8, [x29, #-0x78]')
    f.store(f.read('x29') - 0x78, 1, f.read('w8'), 0x1001f511c)
    assert f.step(0x1001f5120, 0x1001f517c) == 0x1004110fc
    assert number(f.read('x0')) == R and number(f.get(R + 16, 8)) == number(f.read('x20'))
    f.put(R + 8, 4, result)
    f.put(number(f.read('x20')) + 0x14, 4, context_bit)
    api_return(f, 0, 'w0')
    target = f.step(0x1001f517c, 0x1001f51a8)
    if result != STATUS_OK:
        assert target == REJECTED
        return target
    assert target == 0x10011c77c
    target = f.step(target, 0x10011c7b4)
    assert target == (REJECTED if context_bit & 0x80 else EXTRA)
    return target


def lookup(f, entry, outcome, epoch):
    word = int(entry == 0x1002765f8)
    context = AVP if word else PRIMARY
    if word:
        f.step(entry, 0x100276624)
        branch(f, 0x100276624, 0x100276608, 'x10', MAIN)
    else:
        assert f.step(entry, 0x100289eac) == MAIN
    assert number(f.read('x20')) == context and number(f.get(F + 0x4c, 4)) == word
    assert f.step(MAIN, 0x100281688) == 'IOKit/_IOMainPort'
    assert number(f.get(F + 0x70, 8)) == (FALLBACK if word else FINAL)
    main, iterator, service, connection = [value + epoch for value in (0x117, 0x217, 0x517, 0x417)]
    row = {'context': hex(context), 'word': word, 'outcome': outcome, 'class': None,
           'iterator': 0, 'service': 0, 'connection': 0, 'releases': []}
    if outcome == 'main failure':
        api_return(f, 1, 'w0')
        assert f.step(0x100281688, 0x1002816ac) == NO_SERVICE
        return row, NO_SERVICE
    f.put(F + 0x7c, 4, main)
    api_return(f, 0, 'w0')
    assert f.step(0x100281688, 0x1002816ac) == DISPATCH
    decoder = AVP_DECODER if word else LEGACY
    f.step(DISPATCH, 0x1001a1f44)
    branch(f, 0x1001a1f44, 0x1001a1eec, 'x8', decoder)
    row['class'] = class_call(f, decoder)
    call, end, _, _ = CLASSES[decoder]
    dictionary = 0 if outcome == 'null dictionary' else 0x21000
    api_return(f, dictionary, 'x0')
    target = f.step(call + 4, end)
    assert target == (MATCH if dictionary else NO_SERVICE)
    if not dictionary:
        return row, target
    assert f.step(MATCH, MATCH_CALL + 4) == 'IOKit/_IOServiceGetMatchingServices'
    assert tuple(number(f.read(r)) for r in ('w0', 'x1', 'x2')) == (main, dictionary, F + 0x78)
    if outcome == 'match failure':
        api_return(f, 1, 'w0')
        assert f.step(MATCH_CALL + 4, MATCH_END) == NO_SERVICE
        return row, NO_SERVICE
    f.put(F + 0x78, 4, iterator)
    row['iterator'] = iterator
    api_return(f, 0, 'w0')
    assert f.step(MATCH_CALL + 4, MATCH_END) == ITERATE
    assert f.step(ITERATE, ITERATE_CALL + 4) == 'IOKit/_IOIteratorNext'
    assert number(f.read('w0')) == iterator
    if outcome == 'iterator exhausted':
        api_return(f, 0, 'w0')
        assert f.step(ITERATE_CALL + 4, ITERATE_END) == NO_SERVICE
        return row, NO_SERVICE
    row['service'] = service
    api_return(f, service, 'w0')
    assert f.step(ITERATE_CALL + 4, ITERATE_END) == OPEN
    assert f.step(OPEN, OPEN_CALL + 4) == 'IOKit/_IOServiceOpen'
    assert tuple(number(f.read(r)) for r in ('w0', 'w1', 'w2', 'x3')) == (service, 0x317, 0, context + 4)
    if outcome == 'open failure':
        api_return(f, 0xe00002c2, 'w0')
        assert f.step(OPEN_CALL + 4, OPEN_END) == REJECTED
        return row, REJECTED
    row['connection'] = connection
    f.put(context + 4, 4, connection)
    api_return(f, 0, 'w0')
    assert f.step(OPEN_CALL + 4, OPEN_END) == CALLER
    status = 0x74c29ded if outcome == 'constructor failure' else STATUS_OK
    bit = 0 if outcome == 'success bit clear' else 0x80
    return row, constructor_return(f, status, bit)


def retire(f, row, target):
    context = int(row['context'], 16)
    if target == EXTRA:
        seed = int.from_bytes(IMAGE.read(POSTPROCESS_WORD, 8), 'little')
        f.put(POSTPROCESS_WORD, 8, seed)
        assert f.step(EXTRA, 0x10028a7d8) is None
        landmark(0x10028a7d8, 'sturb', 'w10, [x29, #-0x78]')
        f.store(f.read('x29') - 0x78, 1, f.read('w10'), 0x10028a7d8)
        assert f.step(0x10028a7dc, 0x10028a8b4) == 0x100902878
        assert (number(f.read('x0')), number(f.read('x1'))) == (R, F + 0x80)
        assert number(f.get(R + 16, 8)) == context
        return 0x100902878
    if target == REJECTED:
        assert f.step(target, 0x1002c99c0) == SERVICE_RELEASE
        f.step(SERVICE_RELEASE, 0x1001dcab8)
        landmark(0x1001dcab8, 'blraa', 'x8, x17')
        assert (0x1001dcaac, 0x1010a0240, 8) in f.loads
        assert number(f.read('x8')) == 0x1010a0240 and number(f.read('x17')) == 0xbe7e
        assert FIXUPS[0x1010a0240]['target'] == RELEASE
        assert number(f.read('w0')) == row['service'] != 0
        row['releases'].append({'pc': '0x1001dcab8', 'kind': 'service', 'name': row['service']})
        api_return(f, 1, 'w0')
        assert f.step(0x1001dcabc, 0x1001dcac8) == ITERATOR_TEST
    else:
        assert target == NO_SERVICE
        assert f.step(target, 0x1000bd878) == ITERATOR_TEST
    assert number(f.get(context + 0x18, 1)) == 0x20 and number(f.get(context + 0x28, 8)) == 0
    assert number(f.get(context + 4, 4)) == row['connection']
    f.step(ITERATOR_TEST, 0x1001bb518)
    assert number(f.read('x20')) == PRIMARY
    target = ITERATOR_RELEASE if row['iterator'] else RESUME
    branch(f, 0x1001bb518, 0x1001bb50c, 'x8', target)
    if target == ITERATOR_RELEASE:
        assert f.step(target, 0x100205984) == RELEASE
        assert number(f.read('w0')) == row['iterator']
        row['releases'].append({'pc': '0x100205980', 'kind': 'iterator', 'name': row['iterator']})
        api_return(f, 1, 'w0')
        assert f.step(0x100205984, 0x1002059c0) == RESUME
    f.step(RESUME, 0x1001ce7c0)
    target = FALLBACK if row['word'] else FINAL
    branch(f, 0x1001ce7c0, 0x100281654, 'x8', target)
    return target


def publish_status(f, byte, encoded):
    f.step(FINAL, 0x1002bff74)
    f.local_call(0x1002bff74, 0x1002bff68, 'x8', 0x1004156b4)
    assert number(f.read('x0')) == R
    assert number(f.get(R + 4, 4)) == encoded
    f.put(R, 1, byte)
    api_return(f, 0, 'w0')
    f.read_record_byte(0x1002bff78)
    f.step(0x1002bff7c, 0x1002bffc0)
    assert z3.is_true(z3.simplify(f.equal))
    landmark(0x1002bffc0, 'b.ne', '#0x1002bffe4')
    chosen = PRIMARY if byte == 0x99 else AVP
    assert (0x1002bff88, chosen, 1) in f.loads
    result = number(f.get(INPUT, 4))
    assert result == (0x74c29dee if number(f.get(chosen, 1)) == 0x70 else STATUS_OK)
    f.step(0x1002bffc4, 0x1002bffe4)
    assert f.return_pc == 0x1002bffe0 and number(f.read('sp')) == F + 0x150
    return {'context': hex(chosen), 'value': hex(result), 'write_pc': '0x1002bffa8'}


def run(byte, primary_flag, outcomes):
    f, target, encoded = initial_attempt(byte, primary_flag)
    rows = []
    for epoch, outcome in enumerate(outcomes):
        if target == FALLBACK:
            target = primary_check(f, primary_flag == 0x70)
        assert target in (0x1002765f8, 0x100289e64)
        row, continuation = lookup(f, target, outcome, epoch * 0x1000)
        rows.append(row)
        target = retire(f, row, continuation)
    if target == FALLBACK and primary_flag != 0x70:
        target = primary_check(f, False)
    assert target in (FINAL, 0x100902878)
    returned = publish_status(f, byte, encoded) if target == FINAL else None
    return {'initial_helper_byte': byte, 'primary_flag': primary_flag, 'lookups': rows,
            'status': returned, 'frontier': hex(target), 'edges': f.edges}


def alignment_proofs():
    rec = z3.BitVec('caller_record', 64)
    word = z3.BitVec('caller_control', 32)
    caller = OriginFrame(x29=rec + 0x78, w24=0x3941)
    caller.put(SP + 0x4c, 4, word)
    caller.step(0x1001f50b0, 0x1001f5108)
    phase_word = caller.read('w24') - caller.read('w9') + 0x4ff3
    caller.step(0x1001f510c, 0x1001f511c)
    callee = OriginFrame(x0=rec)
    callee.step(0x100411240, 0x100411290)
    bias = callee.read('w16')
    actual = z3.Extract(7, 0, caller.read('w8') - bias)
    expected = z3.Extract(7, 0, 2 * word + (word ^ 0xef) + 0x3e)
    with redirect_stdout(sys.stderr):
        return [solve('phase_at_8_byte_alignment', [rec & 7 == 0], phase_word + bias != 0x8934),
                solve('dispatch_byte_at_8_byte_alignment', [rec & 7 == 0], actual != expected)]


def trace_release_sequence():
    trace = trace_check()
    path = Path.home() / 'Downloads' / 'zut' / 'annotated-strace-rax-user.txt'
    lines = path.read_text().splitlines()
    events = []
    for line_number in (1743, 1745):
        match = re.search(r'pc=(0x[\da-f]+) _kernelrpc_mach_port_deallocate_trap'
                          r'\((\d+), (\d+)\) = (0x[\da-f]+)', lines[line_number - 1])
        assert match
        pc, task, name, status = match.groups()
        assert int(task) == 0x203 and int(status, 16) == 0
        events.append({'line': line_number, 'trap_pc': pc, 'task': hex(int(task)),
                       'name': hex(int(name)), 'result': status})
    assert [e['name'] for e in events] == ['0x1903', '0x1803']
    return {**trace, 'deallocations': events}


def report():
    outcomes = ('main failure', 'null dictionary', 'match failure', 'iterator exhausted',
                'open failure', 'constructor failure', 'success bit set')
    cases = [run(0x98, 0x70, (outcome, 'open failure')) for outcome in outcomes]
    cases.extend((run(0x99, 0x70, ('open failure',)), run(0x98, 0, ('open failure',)),
                  run(0x99, 0, ()), run(0x98, 0x70, ('success bit clear',)),
                  run(0x99, 0x70, ('success bit clear',))))
    banks = [selected(*pair, key, add) for pair, key, add in (
        (FIRST, 0x4e, 0xcb6b), (SECOND, 0xf3, 0xcc27),
        (SECOND, 0x6c, 0xcd17), (MIDDLE_BANK, 0x81, 0xce9b),
    )]
    banks.append(selected(*FOURTH, 0x9c, 0x5a3, POOL, -0x2c109e4f))
    assert [row['target'] for row in banks] == [RELEASE, RELEASE, '0x1004156b4',
                                                '0x100902878', hex(POSTPROCESS_WORD)]
    return {'daemon_sha256': sha(SOURCE), 'generator_sha256': sha(Path(__file__)),
            'profiles': cases, 'banks': banks, 'proofs': alignment_proofs(),
            'rax_open_and_release': trace_release_sequence(),
            'source_spans': list(SPANS.values()), 'fixups': verify_original_fixups(FIXUP_SLOTS)}


if __name__ == '__main__':
    print(json.dumps(report(), indent=2))
