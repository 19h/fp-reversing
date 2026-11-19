#!/usr/bin/env python3
"""Check the outer legacy count gate and replay the resulting daemon return."""

import json
import struct
import subprocess

import z3

import audit_daemon_selector26_pidpath_returns as replay
from audit_iokit_sync_error_reply import (
    ARG, COUNTS, H, NDR, SP, STATUS, Slice, Sources, copyout_and_client, k, load, reply_fields,
    resize,
)
from kernel_vm_mig_tools import Image

BAD_ARGUMENT = 0xe00002c2
METHOD = k(0x846b710)
HANDLER = k(0xa504034)
EXTENTS = (16, 272, 288)


def instruction(src, address, mnemonic, operands):
    insn = src.insn(address)
    assert (insn.mnemonic, insn.op_str) == (mnemonic, operands)


def prove(facts, bad):
    solver = z3.Solver()
    solver.add(*facts)
    assert solver.check() == z3.sat
    solver.add(z3.Or(*bad))
    assert solver.check() == z3.unsat


def check_adapter(src):
    _, member, adjustment, flags, count_in, count_out = struct.unpack(
        '<QQQQQQ', src.kernel.read(METHOD, 48))
    image = Image()
    assert image.k.sha256 == src.kernel.sha256
    pointer = image.pointer(METHOD + 8)
    assert int(pointer['target'], 16) == HANDLER and int(pointer['raw'], 16) == member
    assert int(image.pointer(k(0x846b838))['target'], 16) == METHOD
    assert (adjustment, flags, count_in, count_out) == (0, 3, 16, 16)
    base = 0xc565000
    for offset, mnemonic, operands in (
        (0x170, 'ldr', 'x8, [x0, #0x20]'),
        (0x174, 'mov', 'w9, #-1'),
        (0x178, 'cmp', 'x8, x9'),
        (0x17c, 'mov', 'w19, w3'),
        (0x180, 'ccmp', 'x8, x19, #4, ne'),
        (0x188, 'ldr', 'x10, [x20, #0x28]'),
        (0x190, 'cmp', 'x10, x9'),
        (0x1a0, 'ldr', 'x9, [x5]'),
        (0x1a4, 'cmp', 'x9, x10'),
        (0x1dc, 'mov', 'w21, #0x2c2'),
        (0x1e0, 'movk', 'w21, #0xe000, lsl #16'),
        (0x20c, 'blraa', 'x8, x16'),
        (0x2c0, 'mov', 'x0, x21'),
        (0x2d4, 'retab', ''),
        (0x3b4, 'braa', 'x17, x7'),
    ):
        instruction(src, k(base + offset), mnemonic, operands)
    for origin, operation, target in (
        (0x184, 'b.ne', k(base + 0x1dc)),
        (0x194, 'b.ne', k(base + 0x1a0)),
        (0x1a8, 'b.ne', k(base + 0x24c)),
        (0x238, 'bl', k(0xc4babac)),
        (0x248, 'b', k(base + 0x2c0)),
    ):
        src.edge(k(base + origin), operation, target)
    for extent in (15, 16, 17, *EXTENTS[1:]):
        gate = Slice(src, [('x0', METHOD), ('x20', METHOD), ('x3', extent), ('x5', COUNTS)],
                     [(METHOD + 0x20, 8, count_in), (METHOD + 0x28, 8, count_out),
                      (COUNTS, 8, 16)])
        gate.run_slice(k(base + 0x170), k(base + 0x184))
        assert z3.is_true(z3.simplify(gate.condition('ne') == (extent != 16)))
        if extent == 16:
            gate.run_slice(k(base + 0x188), k(base + 0x194))
            assert z3.is_true(z3.simplify(gate.condition('ne')))
            gate.run_slice(k(base + 0x1a0), k(base + 0x1a8))
            assert z3.is_true(z3.simplify(gate.condition('eq')))
    for capacity in (15, 17, 0x100000010):
        gate = Slice(src, [('x10', count_out), ('x5', COUNTS)], [(COUNTS, 8, capacity)])
        gate.run_slice(k(base + 0x1a0), k(base + 0x1a8))
        assert z3.is_true(z3.simplify(gate.condition('ne')))


def check_request_geometry(src):
    src.edge(0x184e77e2c, 'b.hi', 0x184e77e3c)
    instruction(src, 0x184e77ff8, 'str', 'w22, [x26, #0x28]')
    instruction(src, 0x184e7801c, 'str', 'w8, [x28, #0x3c]')
    for extent, size in zip(EXTENTS, (100, 356, 372), strict=True):
        wrapper = Slice(src, [('x5', extent), ('x4', ARG), ('x11', extent)])
        wrapper.run_slice(0x184e77d98, 0x184e77da0)
        assert z3.is_true(z3.simplify(wrapper.read('x4') == ARG))
        wrapper.run_slice(0x184e77e28, 0x184e77e2c)
        assert z3.is_false(z3.simplify(wrapper.condition('hi')))
        mig = Slice(src, [('w22', extent), ('w25', 0), ('sp', SP)])
        mig.run_slice(0x184e77fd0, 0x184e77fe8)
        mig.run_slice(0x184e77ffc, 0x184e78000)
        assert z3.is_true(z3.simplify(mig.read('w22') == size))


def check_reply(src):
    # The mismatch arm leaves the caller's capacity cell unchanged under normal calls.
    src.edge(k(0xc562fec), 'bl', k(0xc565154))
    src.edge(k(0xc5708dc), 'bl', k(0xc566e4c))
    src.edge(0x184e77e68, 'b.hi', 0x184e77e74)
    src.edge(0x184e77e70, 'b', 0x184e77e78)
    rejected = Slice(src)
    rejected.run_slice(k(0xc5651dc), k(0xc5651e4))
    rejected.run_slice(k(0xc5652c0), k(0xc5652c4))
    ndr = int.from_bytes(src.kernel.read(NDR, 8), 'little')
    for extent in EXTENTS[1:]:
        legacy = Slice(src, [('x0', rejected.read('x0')), ('sp', SP), ('x22', ARG + 0x60), ('w21', BAD_ARGUMENT)],
                       [(SP + 0x10, 8, extent)])
        legacy.run_slice(k(0xc562ff0), k(0xc563008))
        src.edge(k(0xc5708a0), 'b', k(0xc5708bc))
        dispatch = Slice(src, [('x0', legacy.read('x0'))])
        dispatch.run_slice(k(0xc5708bc), k(0xc5708c0))
        dispatch.run_slice(k(0xc5708e0), k(0xc5708e4))
        src.edge(k(0xc570ba0), 'bl', k(0xc5707ec))
        impl = Slice(src, [('x0', dispatch.read('x0')), ('sp', SP), ('x27', COUNTS),
                           ('x28', ARG + 0x34), ('x21', 0), ('x22', 0)],
                     [(SP + 0x80, 4, 0), (SP + 0x90, 4, extent), (SP + 0xa0, 4, 0),
                      (SP + 0x20, 8, H + 0x2c)])
        impl.run_slice(k(0xc570ba4), k(0xc570bc8))
        src.edge(k(0xc570bc8), 'cbz', k(0xc570bec))
        src.edge(k(0xc570bec), 'cbz', k(0xc5709a8))
        impl.run_slice(k(0xc5709a8), k(0xc5709ac))
        reply, reply_bad = reply_fields(src, impl.read('x0'), ndr)
        pack_bad, result, guards, _, _, simple = copyout_and_client(src, reply)
        wrapper = Slice(src, [('x0', result), ('x19', COUNTS), ('x29', SP)],
                        [(COUNTS, 8, extent), (SP - 0x14, 4, extent)])
        wrapper.run_slice(0x184e77e60, 0x184e77e68)
        capacity_branch_bad = wrapper.condition('hi')
        wrapper.run_slice(0x184e77e6c, 0x184e77e70)
        wrapper.run_slice(0x184e77e78, 0x184e77e7c)
        prove([STATUS == BAD_ARGUMENT, simple], [
            legacy.get(ARG + 0x60, 4) != extent, impl.get(H + 0x2c, 4) != extent,
            impl.get(COUNTS, 4) != 0, impl.get(ARG + 0x34, 8) != 0,
            *reply_bad, *pack_bad, *guards, capacity_branch_bad,
            wrapper.read('x0') != BAD_ARGUMENT, wrapper.get(COUNTS, 8) != extent,
        ])
        print(f'{extent} B: short reply 2965 preserves {BAD_ARGUMENT:#x} and capacity')


def check_daemon():
    saved = json.loads(subprocess.check_output(['zstd', '-dc', str(replay.REPLAY)]))
    assert replay.sha(replay.SOURCE) == saved['daemon_sha256']
    profiles = {row['class']: row for row in saved['profiles']
                if row['outcome']['frontier'] == hex(replay.FRONTIER)}
    sections = replay.sections()
    data = [row for row in sections if row['segment'] == '__DATA']
    constant, = [row for row in sections if (row['segment'], row['section']) == ('__TEXT', '__const')]
    bindings, extents = {}, set()
    for equal in (False, True):
        _, routes, state = replay.check_pidpath(0x98, data, profiles, equal, 0, 11747, constant)
        frame, record, *_ = state
        _, extent = replay.check_positive(state, routes[0], replay.FIXTURE_PATH, replay.DIRECT)
        result, slot, target, edges = replay.replay_return(
            frame, record, replay.DIRECT, extent, BAD_ARGUMENT, extent, 0, False)
        assert (result, slot, target) == (0x6b3dc493, 0x101047988, 0x10065f430)
        extents.add(extent)
        bindings.update((address, destination) for _, address, destination in edges)
        print(f'{extent} B: daemon stores {result:#x} and branches to {target:#x}')
    assert extents == set(EXTENTS[1:])
    words = replay.verify_original_fixups(bindings)['records']
    assert {int(word['address'], 16): int(word['decoded_target'], 16)
            for word in words} == bindings
    print(f'{len(words)} original daemon fixup words match the replay targets')


def check_trace():
    trace = load('zut_trace_decoded.json')
    assert trace['send_count'] == 22 and '2865' not in trace['send_ids']
    opened, = (pair for pair in trace['pairs'] if pair['send_id'] == 2862)
    assert opened['reply_id'] == 2962
    reply, = (event for event in trace['events'] if event['line'] == opened['reply_line'])
    assert reply['id'] == 2962 and int(reply['open_result'], 16) == BAD_ARGUMENT
    port, = reply['descriptors']
    assert port['kind'] == 'port' and int(port['name'], 16) == 0


if __name__ == '__main__':
    source = Sources()
    check_trace()
    check_adapter(source)
    check_request_geometry(source)
    check_reply(source)
    check_daemon()
