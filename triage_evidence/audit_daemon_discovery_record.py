#!/usr/bin/env python3
"""Correlate the discovery cleanup branch with original record and lock-adapter sites."""

from hashlib import sha256
import json

import z3

from audit_daemon_class_status_route import verify
from audit_daemon_discovery_cleanup import CleanupProbe, NULL_STOP, ar
from audit_daemon_discovery_owner import FRAME, OWNER, REQUEST
from audit_daemon_selector26_return import Frame, SPANS
from daemon_receive_tools import IMAGE, selected, verify_original_fixups

RECORD = FRAME + 0xe480
STATE = FRAME + 0xe500
LOCK_OWNER = FRAME + 0xe680
LOCK = FRAME + 0xe780
STATUS = 0x8b3dc651
ENTRY = 0x10080a4d0
CALL = 0x10057b484
ADAPTER = 0x1004423f8
LEFT, RIGHT = 0x100fc4130, 0x101031ea0


def source():
    word = z3.BitVec('record_word', 32)
    frame = Frame(sp=FRAME, x9=RECORD, w10=word, w12=0xbc5f)
    frame.step(0x100530250, 0x100530318)
    for slot, field in ((0x55e8, 0), (0x2828, 8), (0x8588, 0x10),
                        (0x6fb8, 0x20), (0x27f0, 0x28), (0x73c8, 0x30),
                        (0x11c8, 0x40), (0x2120, 0x48)):
        verify(frame.get(FRAME + slot, 8) == RECORD + field)
    verify(z3.And(*(frame.get(RECORD + offset, 8) == 0 for offset in (0, 0x10, 0x20, 0x30, 0x40))))
    verify(z3.And(*(frame.get(RECORD + offset, 4) == word for offset in (0x18, 0x28, 0x38, 0x48))))

    field = z3.BitVec('pointer_field', 64)
    frame = Frame(sp=FRAME, w9=0x25e9)
    frame.put(FRAME + 0x6fb8, 8, RECORD + 0x20)
    frame.put(RECORD + 0x20, 8, field)
    frame.step(0x10080a4b8, 0x10080a4f0)
    verify(frame.read('w19') == 0xabf8)
    verify(frame.read('w8') == z3.If(field == 0, z3.BitVecVal(0x25fe, 32), 0x25e9))

    frame = Frame(sp=FRAME, x28=LOCK_OWNER)
    frame.step(0x100606554, 0x100606558)
    verify(frame.read('x8') == LOCK_OWNER + 8)
    frame.put(FRAME + 0x1888, 8, LOCK_OWNER + 8)
    frame.put(LOCK_OWNER + 8, 8, field)
    phase = z3.BitVec('phase', 32)
    frame.seed('w27', phase)
    frame.step(0x10057b3c4, 0x10057b41c)
    verify(frame.get(REQUEST, 8) == field)
    key = ((REQUEST ^ 0xeaae0ac9) * 0x7398180b) & 0xffffffff
    verify(frame.get(REQUEST + 8, 4) + key == phase + 0x7413)
    return {'bit_vector_checks': 15, 'spans': list(SPANS.values())}


def replay(field, *, probe=None, lock=LOCK):
    if probe is None:
        probe = CleanupProbe()
    probe.run_cleanup(OWNER, False)
    assert probe.u.reg_read(ar.UC_ARM64_REG_PC) == NULL_STOP
    assert probe.reg(9) == 0x25e9 and probe.reg(19) == 0xabf8
    first = len(probe.branch_slots)
    saved_cpu = probe.u.context_save()
    probe.setreg(9, RECORD)
    probe.setreg(12, 0xbc5f)
    probe.setreg(20, STATE)
    probe.put(STATE, 8, RECORD + 0x28)
    probe.put(FRAME + 0x5478, 8, STATE)
    probe.put(FRAME + 0x1314, 4, 0)
    probe.u.emu_start(0x1007fd788, 0x100530318, count=120)
    assert probe.u.reg_read(ar.UC_ARM64_REG_PC) == 0x100530318
    producer = probe.branch_slots[-1]
    assert producer['target'] == '0x100530250'
    assert probe.memory_word(FRAME + 0x7908) == STATE
    assert probe.memory_word(FRAME + 0x6fb8) == RECORD + 0x20
    assert probe.memory_word(RECORD + 0x20) == 0
    assert probe.memory_word(RECORD + 0x28, 4) == STATUS
    if field:
        probe.put(RECORD + 0x20, 8, field)
    probe.setreg(19, STATE)
    probe.u.emu_start(0x1006171b0, 0x1006171b8, count=3)
    assert probe.memory_word(FRAME + 0x5900) == STATE + 0x100
    probe.setreg(28, LOCK_OWNER)
    probe.put(LOCK_OWNER + 8, 8, lock)
    probe.u.emu_start(0x100606554, 0x1006065dc, count=40)
    assert probe.memory_word(FRAME + 0x1888) == LOCK_OWNER + 8
    probe.put(FRAME + 0x968, 8, LEFT)
    probe.put(FRAME + 0x960, 8, RIGHT)
    probe.u.context_restore(saved_cpu)

    probe.u.emu_start(ENTRY, CALL, count=1200)
    assert probe.u.reg_read(ar.UC_ARM64_REG_PC) == CALL
    assert probe.reg(0) == REQUEST and probe.reg(8) == ADAPTER and probe.reg(17) == 0x6aa4
    assert probe.memory_word(REQUEST) == lock
    assert probe.reg(27) == 0x2e80
    edges = probe.branch_slots[first + 1:]
    assert edges[0]['target'] == ('0x1005b1320' if field else '0x1004cfca0')
    assert edges[-1]['target'] == '0x10057b3c4'
    assert not probe.output_accesses
    return {'field': hex(field), 'producer_edge': producer, 'continuation_edges': edges,
            'endpoint': hex(CALL), 'prepared_record': {
                'address': hex(REQUEST), 'word_at_0': hex(lock),
                'word_at_8': hex(probe.memory_word(REQUEST + 8, 4)),
                'phase_w27': hex(probe.reg(27))}}


def inspect():
    proof = source()
    profiles = [replay(field) for field in (0, STATE)]
    target = selected(LEFT, RIGHT, 0xa3, 0xcb31)
    assert target['target'] == hex(ADAPTER)
    slots = {int(target['slot'], 16), 0x10108a330, 0x1010982f0}
    for profile in profiles:
        slots.add(int(profile['producer_edge']['fixup_slot'], 16))
        slots.update(int(edge['fixup_slot'], 16) for edge in profile['continuation_edges'])
    return {'image_sha256': sha256(IMAGE.data).hexdigest(), 'source': proof,
            'profiles': profiles, 'adapter_bank': target, 'fixups': verify_original_fixups(slots)}


if __name__ == '__main__':
    print(json.dumps(inspect(), indent=2, sort_keys=True))
