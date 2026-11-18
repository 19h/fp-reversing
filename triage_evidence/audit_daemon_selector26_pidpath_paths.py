#!/usr/bin/env python3
"""Trace the selector 26 caller after the self-process path query."""

import json
import subprocess

import z3

from audit_daemon_selector26_aggregate_consumer import ALLOCATION_BASE, ALLOCATE, FREE, LOAD, STORE
from audit_daemon_selector26_aggregate_reads import walk
from audit_daemon_selector26_class_retry import F, R, REJECTED
from audit_daemon_selector26_followon_aggregate import FOLLOWON_BASE, overlaps
from audit_daemon_selector26_helper_consumers import return_from_call
from audit_daemon_selector26_record_consumer import CS, FRONTIER, IMAGE, REPLAY, SOURCE, number, sections, sha
from audit_daemon_selector26_self_pidpath import BRANCH, SELECT, check_pidpath
from daemon_receive_tools import verify_original_fixups

GUARD = 0x1009e572c
LENGTH = 0x1009c0494
DIRECT = (0x100943d3c, 0x1010a0ab8, 0x10043a018, 0x1002069c4)
DESCRIPTOR = (0x100915e7c, 0x1010a0ca8, 0x10043ee28, 0x100293074)
METHOD = 'IOKit/_IOConnectCallStructMethod'
PATH_NODE = 0x49000
PATH_CHILD = 0x4a000
AGGREGATE = 0x4b000
STRNLEN = 'libSystem/_strnlen'
FLAGS = ('negative', 'equal', 'carry', 'overflow')


def enter_route(state, result, route, path):
    frame, record, _, _, symbol = state
    substitution = symbol, z3.BitVecVal(result, 32)
    for key, value in frame.regs.items():
        frame.regs[key] = z3.simplify(z3.substitute(value, substitution))
    for name in FLAGS:
        setattr(frame, name, z3.simplify(z3.substitute(getattr(frame, name), substitution)))
    status = frame.get(record + 0x10, 4)
    frame.put(record + 0x10, 4, z3.simplify(z3.substitute(status, substitution)))
    scratch = number(frame.get(record + 8, 8))
    for offset, byte in enumerate(path):
        frame.put(scratch + offset, 1, byte)
    edges, calls = [], []
    slot, pc = route
    assert walk(frame, SELECT, edges, calls, stop=pc) == pc
    assert edges == [(BRANCH, slot, pc)] and not calls
    return pc, scratch, edges, calls


def check_nonpositive(state, route, result):
    frame, _, child, child_size, _ = state
    pc, scratch, edges, calls = enter_route(state, result, route, b'')
    read_start, store_start = len(frame.loads), len(frame.stores)
    first, second = FOLLOWON_BASE + 0x1000, FOLLOWON_BASE + 0x3000
    source = ALLOCATION_BASE + 0x4000
    expected = (
        (0x100a86f0c, 0x24000), (0x100942a64, first + 0x1000), (0x100a35f0c, first),
        (0x100942a64, child), (0x100a35f0c, second), (0x100945d50, FOLLOWON_BASE),
        (0x100a2fe70, 0x23000), (0x10070f118, source),
    )
    for site, pointer in expected:
        assert walk(frame, pc, edges, calls, stop=GUARD) == site
        assert calls[-1] == (site, FREE, pointer)
        pc = site + 4
        return_from_call(frame, pc)
    assert walk(frame, pc, edges, calls, stop=GUARD) == GUARD and len(calls) == len(expected)
    assert z3.is_false(z3.simplify(frame.condition('ne')))
    assert not any(overlaps(address, width, scratch, 4096) or overlaps(address, width, child, child_size)
                   for _, address, width in frame.loads[read_start:])
    statuses = [(site, number(value)) for site, at, width, value in frame.stores[store_start:]
                if at == R + 8 and width == 4]
    assert statuses == [(0x1009e5714, 0x74c29dee)]
    for first, last in ((0x1009e5730, 0x1009e5750), (0x100902ae0, 0x100902b00)):
        for pc in range(first, last + 4, 4):
            frame.step(pc, pc + 4)
        assert frame.return_pc == last
        assert number(frame.read('x30')) == (0x100902ae0 if last == 0x1009e5750 else 0x10028a8b4)
    assert number(frame.read('sp')) == F and number(frame.get(F + 0x80, 8)) == 0
    assert walk(frame, 0x10028a8b4, edges, calls, stop=REJECTED) == REJECTED
    assert len(calls) == len(expected)
    print('path failure', result, 'status stores', [(hex(site), hex(status)) for site, status in statuses],
          'edges', len(edges), flush=True)
    return edges


def check_positive(state, route, fixture_path, abi):
    frame, record, child, child_size, _ = state
    count = len(fixture_path)
    source_bytes = fixture_path + b'\0'
    pc, scratch, edges, calls = enter_route(state, count, route, source_bytes)
    start = len(frame.loads)
    store_start = len(frame.stores)
    copy, pending = [], None
    parent_load, parent_store = frame.load, frame.store

    def load(address, width):
        nonlocal pending
        value = parent_load(address, width)
        at = number(address)
        if overlaps(at, width, scratch, 4096):
            offset = at - scratch
            assert frame.pc == LOAD and width == 1 and 0 <= offset <= count and pending is None
            assert number(value) == source_bytes[offset]
            tag = z3.BitVec(f'pidpath_byte_{offset}', 8)
            pending = offset, tag
            return tag
        return value

    def store(address, width, value, site):
        nonlocal pending
        if pending is not None and site == STORE:
            offset, tag = pending
            assert number(address) == PATH_CHILD + 10 + offset and width == 1
            mask = number(z3.simplify(z3.Extract(7, 0, value) ^ tag))
            copy.append(offset)
            value = source_bytes[offset] ^ mask
            pending = None
        parent_store(address, width, value, site)

    frame.load, frame.store = load, store
    assert walk(frame, pc, edges, calls) == LENGTH
    assert calls == [(LENGTH, STRNLEN, scratch)] and number(frame.read('x1')) == 4096
    return_from_call(frame, LENGTH + 4, count)
    pc = LENGTH + 4
    for site, size, pointer in ((0x100948dd0, 32, PATH_NODE), (0x100a2fc00, count + 11, PATH_CHILD),
                               (0x100a05060, None, AGGREGATE)):
        assert walk(frame, pc, edges, calls, limit=30000) == site
        assert calls[-1][:2] == (site, ALLOCATE)
        extent = calls[-1][2]
        if size is not None:
            assert extent == size
        assert 0 < extent < 0x1000
        assert not any(overlaps(address, 1, pointer, extent) for address in frame.ram)
        pc = site + 4
        return_from_call(frame, pc, pointer)
    aggregate_size = extent
    reentry, slot, core, method = abi
    assert walk(frame, pc, edges, calls, limit=50000) == reentry, calls[-1]
    assert edges[-1] == (reentry, slot, core)
    assert calls[-1] == (reentry, core, record) and len(calls) == 5
    assert copy == list(range(count, -1, -1)) and pending is None
    assert number(frame.get(PATH_NODE + 0x18, 8)) == PATH_CHILD
    pointer_field, context_field = (0, 8) if abi == DIRECT else (24, 16)
    assert number(frame.get(record + pointer_field, 8)) == AGGREGATE
    context = number(frame.get(record + context_field, 8))
    loads = frame.loads[start:]
    assert [(at - child, width) for site, at, width in loads
            if site == 0x10091667c and overlaps(at, width, child, child_size)] == [
                (offset, 1) for offset in range(child_size - 1, -1, -1)]
    assert not any(overlaps(at, width, child, child_size) for _, at, width, _ in frame.stores[store_start:])
    frame.seed('x30', reentry + 4)
    assert next(CS.disasm(IMAGE.read(core, 4), core)).mnemonic == 'pacibsp'
    assert walk(frame, core + 4, edges, calls, limit=50000) == method, calls[-1]
    assert edges[-1] == (method, 0x1010a0640, METHOD)
    connection = number(frame.get(context + 4, 4))
    assert calls[-1] == (method, METHOD, connection) and len(calls) == 6
    assert number(frame.read('w1')) == 26
    x2, x3, x4, x5 = (number(frame.read(f'x{i}')) for i in range(2, 6))
    sp = number(frame.read('sp'))
    assert x5 == sp and x2 == x4
    if abi == DIRECT:
        assert (x2, x3) == (AGGREGATE, aggregate_size)
    else:
        assert (x2, x3) == (sp + 8, 16)
        assert (number(frame.get(x2, 8)), number(frame.get(x2 + 8, 4))) == (AGGREGATE, aggregate_size)
    assert number(frame.get(x5, 8)) == x3
    print('path positive', count, 'aggregate', aggregate_size, 'method', hex(method),
          'connection fixture', hex(connection), 'public size', x3, 'edges', len(edges), flush=True)
    return edges


def main():
    saved = json.loads(subprocess.check_output(['zstd', '-dc', str(REPLAY)]))
    assert sha(SOURCE) == saved['daemon_sha256']
    profiles = {row['class']: row for row in saved['profiles'] if row['outcome']['frontier'] == hex(FRONTIER)}
    original_sections = sections()
    data = [row for row in original_sections if row['segment'] == '__DATA']
    constant, = [row for row in original_sections if (row['segment'], row['section']) == ('__TEXT', '__const')]
    slots = set()
    for equal in (False, True):
        for fixture, seed, pid in ((0x98, 0, 11747), (0x99, 17, 501)):
            _, routes, state = check_pidpath(fixture, data, profiles, equal, seed, pid, constant)
            frame = state[0]
            regs, ram = frame.regs.copy(), frame.ram.copy()
            loads, stores = len(frame.loads), len(frame.stores)
            flags = {name: getattr(frame, name) for name in FLAGS}
            edges = check_nonpositive(state, routes[1], 0 if fixture == 0x98 else -1)
            frame.regs, frame.ram = regs, ram
            del frame.loads[loads:]
            del frame.stores[stores:]
            for name, value in flags.items():
                setattr(frame, name, value)
            edges.extend(check_positive(state, routes[0], b'/' + b'fixture/fairplayd',
                                        DIRECT if fixture == 0x98 else DESCRIPTOR))
            slots.update(slot for _, slot, _ in edges)
    assert len(verify_original_fixups(slots)['records']) == len(slots)
    print(len(slots), 'original fixup words')


if __name__ == '__main__':
    main()
