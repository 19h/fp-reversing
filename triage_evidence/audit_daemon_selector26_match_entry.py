#!/usr/bin/env python3
"""Audit the two original class-matching predecessors of the IOKit open fragment."""

import json
from pathlib import Path

from audit_daemon_selector26_cleanup import landmark
from audit_daemon_selector26_open import (
    ITERATE, ITERATE_CALL, ITERATE_END, MATCH, MATCH_CALL, MATCH_END, OPEN, OPEN_CALL,
    OPEN_END, TASK, OpenFrame,
)
from audit_daemon_selector26_record_origin import (
    CONTEXT, FIRST, FOURTH, GLOBAL_ONE, GLOBAL_TWO, RECORD, SECOND,
)
from audit_daemon_selector26_return import CS, FIXUP_SLOTS, SP, SPANS, number
from daemon_receive_tools import FIXUPS, IMAGE, POOL, SOURCE, TABLE
from daemon_receive_tools import selected, verify_original_fixups
from verify_daemon_reader_record_payloads_publication import sha

MAIN = 0x100281608
DISPATCH = 0x1001a1eb4
LEGACY = 0x1000799c0
AVP = 0x1002816ec
MATCH_SLOT = 0x1010a0c28
MAIN_BANK = (0x100e99700, 0x100f4e190)

CLASSES = {
    LEGACY: (0x100079bf0, 0x100079c18, 31, b'com_apple_driver_FairPlayIOKit\0'),
    AVP: (0x100281890, 0x1002818b8, 18, b'AvpFairPlayDriver\0'),
}
CLASS_DATA = {
    LEGACY: (0x1010b5f58, 0x100f981f0),
    AVP: (0x1010b7818, 0x100f8a201),
}
IMAGE_BYTES = tuple((pointer, CLASSES[entry][2]) for entry, (_, pointer) in CLASS_DATA.items())
IMAGE_BYTES += tuple((base, 256) for base in MAIN_BANK)


class MatchFrame(OpenFrame):
    def load(self, address, width):
        address_value = number(address)
        if width == 1 and any(base <= address_value < base + size
                              for base, size in IMAGE_BYTES):
            self.loads.append((self.pc, address_value, width))
            return IMAGE.read(address_value, 1)[0]
        return super().load(address, width)


def api_return(frame, value, register):
    for index in range(18):
        frame.regs.pop(f'x{index}', None)
    frame.seed(register, value)


def branch(frame, pc, load_pc, register, expected):
    landmark(pc, 'braa', f'{register}, x17')
    _, slot, width = next(load for load in reversed(frame.loads) if load[0] == load_pc)
    assert width == 8 and number(frame.read(register)) == FIXUPS[slot]['target'] == expected
    modifier = number(frame.read('x17'))
    assert FIXUPS[slot]['annotation'] == f'(div=0x{modifier:04X} ad=0 key=IA)'
    frame.edges.append({'pc': hex(pc), 'slot': hex(slot), 'target': hex(expected),
                        'modifier': hex(modifier)})


def class_call(frame, entry):
    call, _, size, expected = CLASSES[entry]
    cursor = entry
    for insn in CS.disasm(IMAGE.read(entry, call - entry), entry):
        if insn.mnemonic != 'sturb':
            continue
        frame.step(cursor, insn.address)
        assert insn.op_str.endswith("]") and "[x29, #-" in insn.op_str
        source = insn.reg_name(insn.operands[0].reg)
        dest = frame.address(insn, insn.operands[1])
        landmark(insn.address, 'sturb', insn.op_str)
        frame.store(dest, 1, frame.read(source), insn.address)
        cursor = insn.address + 4
    frame.step(cursor, call)
    landmark(call, 'blraa', 'x8, x17')
    assert frame.loads[-1][1:] == (MATCH_SLOT, 8)
    assert number(frame.read('x17')) == 0x83b
    assert FIXUPS[MATCH_SLOT]['annotation'] == '(div=0x083B ad=0 key=IA)'
    assert FIXUPS[MATCH_SLOT]['target'] == 'IOKit/_IOServiceMatching'
    arg = number(frame.read('x0'))
    sp = number(frame.read('sp'))
    record = number(frame.read('x29')) - 0x78
    assert arg == (record - 31 if entry == LEGACY else sp + 0x97)
    class_bytes = bytes(number(frame.get(arg + offset, 1)) for offset in range(size))
    assert class_bytes == expected
    selected_cell, pointer = CLASS_DATA[entry]
    assert any(address == selected_cell and width == 8 for _, address, width in frame.loads)
    assert all(any(address == pointer + offset and width == 1 for _, address, width in frame.loads)
               for offset in range(size))
    return class_bytes[:-1].decode()


def profile(word, main_status, dictionary):
    f = MatchFrame(x20=CONTEXT, x22=GLOBAL_ONE, x26=GLOBAL_TWO,
                   x28=TABLE, x29=RECORD + 0x78, w8=0xe5e)
    f.put(GLOBAL_ONE, 4, 0x12345678)
    f.put(GLOBAL_TWO, 4, 0x98765432)
    f.put(SP + 0x10, 8, CONTEXT)
    f.put(SP + 0x6c, 4, 0xe8d)
    for offset, value in zip((0x60, 0x58, 0x40, 0x38), FIRST + SECOND):
        f.put(SP + offset, 8, value)
    if word == 0:
        assert f.step(0x100289e64, 0x100289eac) == MAIN
    else:
        f.step(0x1002765f8, 0x100276624)
        branch(f, 0x100276624, 0x100276608, 'x10', MAIN)
    writer = 0x100289e64 if word == 0 else 0x100276610
    assert number(f.get(SP + 0x4c, 4)) == word
    assert f.step(MAIN, 0x100281688) == 'IOKit/_IOMainPort'
    assert (number(f.read('w0')), number(f.read('x1'))) == (0, SP + 0x7c)
    assert number(f.get(SP + 0x78, 8)) == 0
    main = 0x117
    if main_status == 0:
        f.put(SP + 0x7c, 4, main)
    api_return(f, main_status, 'w0')
    target = f.step(0x100281688, 0x1002816ac)
    class_name = None
    if not main_status:
        assert target == DISPATCH
        entry = AVP if word else LEGACY
        f.step(DISPATCH, 0x1001a1f44)
        branch(f, 0x1001a1f44, 0x1001a1eec, 'x8', entry)
        assert (number(f.get(SP + 0x28, 8)), number(f.get(SP + 0x30, 8))) == FOURTH
        assert number(f.read('w19')) == number(f.read('w23')) == 0x5a55
        class_name = class_call(f, entry)
        call, end, _, _ = CLASSES[entry]
        api_return(f, dictionary, 'x0')
        target = f.step(call + 4, end)
        assert target == (MATCH if dictionary else 0x1000bd85c)
        assert number(f.read('x1')) == dictionary and number(f.read('w24')) == 0x5dee
        assert number(f.get(SP + 0x7c, 4)) == main
    else:
        assert target == 0x1000bd85c
    stores = [(pc, width, number(value)) for pc, address, width, value in f.stores
              if address < SP + 0x50 and SP + 0x4c < address + width]
    assert stores == [(writer, 4, word)]
    assert number(f.read('sp')) == SP and number(f.read('x20')) == CONTEXT
    if target == MATCH:
        target = open_handoff(f, word, main, dictionary)
    return {'control_word': word, 'reaching_store': hex(writer), 'main_status': main_status,
            'dictionary': hex(dictionary), 'class': class_name, 'frontier': hex(target),
            'edges': f.edges, 'class_calls': [] if class_name is None else [
                {'pc': hex(CLASSES[entry][0]), 'slot': hex(MATCH_SLOT), 'modifier': '0x83b'}],
            'stores': [[hex(pc), hex(address), width] for pc, address, width, _ in f.stores]}


def open_handoff(frame, word, main, dictionary):
    iterator, service, task = 0x217, 0x517, 0x317
    frame.put(TASK, 4, task)
    assert frame.step(MATCH, MATCH_CALL + 4) == 'IOKit/_IOServiceGetMatchingServices'
    assert tuple(number(frame.read(r)) for r in ('w0', 'x1', 'x2')) == (
        main, dictionary, SP + 0x78)
    frame.put(SP + 0x78, 4, iterator)
    api_return(frame, 0, 'w0')
    assert frame.step(MATCH_CALL + 4, MATCH_END) == ITERATE
    assert frame.step(ITERATE, ITERATE_CALL + 4) == 'IOKit/_IOIteratorNext'
    assert number(frame.read('w0')) == iterator
    api_return(frame, service, 'w0')
    assert frame.step(ITERATE_CALL + 4, ITERATE_END) == OPEN
    assert frame.step(OPEN, OPEN_CALL + 4) == 'IOKit/_IOServiceOpen'
    assert tuple(number(frame.read(r)) for r in ('w0', 'w1', 'w2', 'x3')) == (
        service, task, 0, CONTEXT + 4)
    frame.put(CONTEXT + 4, 4, 0x417)
    api_return(frame, 0, 'w0')
    target = frame.step(OPEN_CALL + 4, OPEN_END)
    assert target == 0x1001f50b0 and number(frame.read('w24')) == 0x3941
    frame.step(target, 0x1001f50c4)
    assert number(frame.read('w9')) == word
    assert [(pc, width) for pc, address, width, _ in frame.stores
            if address < SP + 0x50 and SP + 0x4c < address + width] == [
        (0x100276610 if word else 0x100289e64, 4)]
    return target


def report():
    cases = [profile(word, status, dictionary)
             for word in (0, 1) for status, dictionary in ((0, 0x7000), (0, 0), (1, 0))]
    banks = [
        selected(*FIRST, 0xa3, 0xcce1),
        selected(*SECOND, 0xe4, 0xe37, POOL, -0x7b6f428e),
        selected(*MAIN_BANK, 0x81, 0x7bc, POOL, -0x1ea9005e),
        selected(*FOURTH, 0x54, 0xccf1),
        selected(*FOURTH, 0x78, 0xcd06),
    ]
    assert [row['target'] for row in banks] == [
        'IOKit/_IOMainPort', '0x1010b5f58', '0x1010b7818',
        'IOKit/_IOServiceMatching', 'IOKit/_IOServiceMatching']
    return {'daemon_sha256': sha(SOURCE), 'generator_sha256': sha(Path(__file__)),
            'profiles': cases, 'banks': banks, 'source_spans': list(SPANS.values()),
            'fixups': verify_original_fixups(FIXUP_SLOTS)}


if __name__ == '__main__':
    print(json.dumps(report(), indent=2))
