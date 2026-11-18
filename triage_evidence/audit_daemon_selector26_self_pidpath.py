#!/usr/bin/env python3
"""Verify selector 26's self-PID path query and private result dispatch."""

import json
import subprocess

import z3

from audit_daemon_selector26_aggregate_reads import assert_equal, walk
from audit_daemon_selector26_followon_aggregate import CALL, check_followon, overlaps
from audit_daemon_selector26_helper_consumers import return_from_call
from audit_daemon_selector26_record_consumer import CS, FRONTIER, IMAGE, REPLAY, SOURCE, number, sections, sha
from daemon_receive_tools import FIXUPS, verify_original_fixups

ENTRY = 0x10043fea8
GETPID = 0x100440074
PIDPATH = 0x1004400e0
STATUS_STORE = 0x1004400fc
RETURN = 0x100440118
SELECT = 0x10064beb4
BRANCH = 0x10064bebc
SUCCESS = 0x8b3dc651
FAILURE = 0x74c29dee
GLOBAL_A, GLOBAL_B = 0x1010b6760, 0x1010c4670


def check_pidpath(fixture, data, profiles, equal, seed, pid, constant):
    _, frame, record, child, child_size = check_followon(fixture, data, profiles, equal, seed, constant)
    use_start, store_start = len(frame.loads), len(frame.stores)
    scratch = number(frame.get(record + 8, 8))
    callee_sp = number(frame.read('sp'))
    restorables = ('x19', 'x20', 'x21', 'x22', 'x23', 'x24', 'x25', 'x26', 'x29', 'x30')
    saved = tuple(frame.get(callee_sp + offset, 8) for offset in (0x48, 0x40, 0x38, 0x30, 0x28,
                                                                 0x20, 0x18, 0x10, 0x50, 0x58))
    parent_load = frame.load
    controller_reads = []

    def load(address, width):
        try:
            value = parent_load(address, width)
        except KeyError:
            at = number(address)
            assert width == 1 and constant['start'] <= at < constant['start'] + constant['size_bytes']
            return z3.BitVecVal(IMAGE.read(at, 1)[0], 8)
        if frame.pc in (0x10043ff18, 0x10043ff7c):
            controller_reads.append((number(address), width, number(value) if z3.is_expr(value) else value))
        return value

    frame.load = load
    edges, calls = [], []
    assert walk(frame, ENTRY, edges, calls) == GETPID
    assert edges == [(GETPID, 0x1010a0f70, 'libSystem/_getpid')]
    assert calls == [(GETPID, 'libSystem/_getpid', record)]
    assert [(at, width) for at, width, _ in controller_reads] == [(GLOBAL_A, 8), (GLOBAL_B, 8)]
    initial = controller_reads[0][2] ^ (callee_sp + 8) ^ controller_reads[1][2]
    mask64 = (1 << 64) - 1
    assert [(site, at, width, number(value)) for site, at, width, value in frame.stores[store_start:]] == [
        (0x10043ffb8, GLOBAL_A, 8, (initial * 0x0a5cd4cf + 0x8c2fb9df71512e5a) & mask64),
        (0x10043ffbc, GLOBAL_B, 8, ((initial ^ 0x73d046208eaed1a6) * 0x0a5cd4cf) & mask64),
    ]
    return_from_call(frame, GETPID + 4, pid)
    assert walk(frame, GETPID + 4, edges, calls) == PIDPATH
    assert edges[-1] == (PIDPATH, 0x1010a0608, 'libSystem/_proc_pidpath')
    assert calls[-1] == (PIDPATH, 'libSystem/_proc_pidpath', pid)
    assert number(frame.read('x1')) == scratch
    assert number(frame.read('w2')) == 4096
    assert scratch + 4096 == record - 1

    result = z3.BitVec('pidpath_result', 32)
    return_from_call(frame, PIDPATH + 4, z3.ZeroExt(32, result))
    assert walk(frame, PIDPATH + 4, edges, calls, stop=RETURN) == RETURN
    assert next(CS.disasm(IMAGE.read(RETURN, 4), RETURN)).mnemonic == 'retab'
    assert number(frame.read('sp')) == callee_sp + 0x60
    for register, expected in zip(restorables, saved, strict=True):
        assert_equal(frame.read(register), expected)
    assert number(frame.read('x30')) == CALL + 4
    result_fields = [(site, at - record, width, value) for site, at, width, value in frame.stores[store_start:]
                     if overlaps(at, width, record, 0x30)]
    expected = z3.If(result < 1, z3.BitVecVal(FAILURE, 32), z3.BitVecVal(SUCCESS, 32))
    assert [row[:3] for row in result_fields] == [(STATUS_STORE, 0x10, 4)]
    assert_equal(frame.get(record + 0x10, 4), expected)
    callee_loads = frame.loads[use_start:]
    assert [(site, at - record, width) for site, at, width in callee_loads
            if overlaps(at, width, record, 0x30)] == [(0x10043ffc0, 8, 8)]
    for base, size in ((child, child_size), (scratch, 4096)):
        assert not any(overlaps(at, width, base, size) for _, at, width in callee_loads)
        assert not any(overlaps(at, width, base, size) for _, at, width, _ in frame.stores[store_start:])

    assert walk(frame, CALL + 4, edges, calls, stop=SELECT) == SELECT
    assert frame.loads[-1] == (0x10064be8c, record + 0x10, 4)
    index = frame.read('w8')
    indexes = [number(z3.substitute(index, (result, z3.BitVecVal(value, 32)))) for value in (1, 0)]
    assert indexes[0] != indexes[1]
    assert_equal(index, z3.If(result < 1, z3.BitVecVal(indexes[1], 32), z3.BitVecVal(indexes[0], 32)))
    table = number(frame.read('x30'))
    routes = []
    for selected in indexes:
        offset = z3.BitVecVal(selected, 32).as_signed_long()
        slot = table + 8 * offset
        target = FIXUPS[slot]['target']
        frame.seed('w8', selected)
        assert walk(frame, SELECT, edges, calls, stop=target) == target
        assert edges[-1] == (BRANCH, slot, target)
        routes.append((slot, target))
    assert len(edges) == 4 and len(calls) == 2
    print(hex(fixture), equal, 'PID', pid, 'routes', [(hex(slot), hex(target)) for slot, target in routes],
          flush=True)
    fixups = {at for _, at, width in frame.loads[use_start:] if width == 8 and at in FIXUPS}
    return fixups, routes


def main():
    saved = json.loads(subprocess.check_output(['zstd', '-dc', str(REPLAY)]))
    assert sha(SOURCE) == saved['daemon_sha256']
    profiles = {row['class']: row for row in saved['profiles'] if row['outcome']['frontier'] == hex(FRONTIER)}
    image_sections = sections()
    data = [row for row in image_sections if row['segment'] == '__DATA']
    constant, = [row for row in image_sections if (row['segment'], row['section']) == ('__TEXT', '__const')]
    slots = set()
    routes = []
    for equal in (False, True):
        for fixture, seed, pid in ((0x98, 0, 11747), (0x99, 17, 501)):
            selected, row = check_pidpath(fixture, data, profiles, equal, seed, pid, constant)
            slots.update(selected)
            routes.append(row)
    assert all(row == routes[0] for row in routes)
    assert len(verify_original_fixups(slots)['records']) == len(slots)
    print(len(slots), 'original fixup words')


if __name__ == '__main__':
    main()
