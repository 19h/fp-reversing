#!/usr/bin/env python3
"""Replay the original phase, cached sysctl and first IOKit class decision."""

import json
from pathlib import Path

import z3

from audit_daemon_selector26_cleanup import landmark
from audit_daemon_selector26_match_entry import MAIN, MatchFrame, api_return, branch
from audit_daemon_selector26_record_origin import FIRST, FOURTH, SECOND
from audit_daemon_selector26_return import FIXUP_SLOTS, SPANS, number
from daemon_receive_tools import FIXUPS, IMAGE, POOL, SOURCE, TABLE, selected
from daemon_receive_tools import verify_original_fixups
from recover_daemon_object_clock import sections
from verify_daemon_reader_record_payloads_publication import sha

F = 0x11000
R = F + 0xc8
INPUT = 0x12000
GUARD = 0x13000
SEED = 0x1010c4670
CACHE = 0x1010c5740
ONCE = 0x1010c8248
PRIMARY = 0x1010b63a0
AVP = 0x1010b5d90
BLOCK = 0x1010399d8
NAME = 0x100ecc5c0
PHASE = 0xe8d
ALT_BANK = (0x100e99800, 0x100f4e290)
MIDDLE_BANK = (0x100e99700, 0x100f4e190)
INITIAL_CELLS = {
    SEED: 8, 0x1010b65f8: 8, 0x1010b8028: 8, 0x1010b9080: 8,
    0x1010b6608: 8, PRIMARY: 1, AVP: 1,
}


class GateFrame(MatchFrame):
    def load(self, address, width):
        at = number(address)
        if at == 0x1010b1e18 and width == 8:
            assert FIXUPS[at]['target'] == 'libSystem/___stack_chk_guard'
            self.loads.append((self.pc, at, width))
            return GUARD
        if all(at + offset in self.ram for offset in range(width)):
            self.loads.append((self.pc, at, width))
            return self.get(at, width)
        if width == 1 and any(base <= at < base + 256 for base in ALT_BANK + MIDDLE_BANK):
            self.loads.append((self.pc, at, width))
            return IMAGE.read(at, width)[0]
        try:
            return super().load(address, width)
        except KeyError as exc:
            raise AssertionError((hex(self.pc), hex(at), width)) from exc

    def read_record_byte(self, pc):
        landmark(pc, 'ldurb', 'w8, [x29, #-0x78]')
        self.pc = pc
        self.seed('w8', self.load(self.read('x29') - 0x78, 1))

    def local_call(self, pc, load_pc, register, target):
        landmark(pc, 'blraa', f'{register}, x17')
        _, slot, width = next(load for load in self.loads if load[0] == load_pc)
        modifier = number(self.read('x17'))
        assert width == 8 and number(self.read(register)) == FIXUPS[slot]['target'] == target
        assert FIXUPS[slot]['annotation'] == f'(div=0x{modifier:04X} ad=0 key=IA)'
        self.edges.append({'pc': hex(pc), 'slot': hex(slot), 'target': hex(target),
                           'modifier': hex(modifier)})


def initial_frame():
    frame = GateFrame(sp=F + 0x150, x0=INPUT)
    for index in range(19, 31):
        frame.seed(f'x{index}', 0x2000 + index)
    for at, width in INITIAL_CELLS.items():
        frame.put(at, width, int.from_bytes(IMAGE.read(at, width), 'little'))
    frame.put(CACHE, 1, 0)
    frame.put(ONCE, 8, 0)
    frame.put(GUARD, 8, 0x7a653430)
    frame.put(INPUT + 4, 4, PHASE - ((INPUT ^ 0xe732d262) * 0xba209ef7))
    return frame


def enter(frame):
    landmark(0x1004382b4, 'pacibsp', '')
    frame.step(0x1004382b8, 0x100438530)
    frame.local_call(0x100438530, 0x100438524, 'x8', 0x1004156b4)
    assert number(frame.read('sp')) == F and number(frame.read('x29')) == F + 0x140
    assert number(frame.read('x0')) == R and number(frame.read('w27')) == PHASE
    assert number(frame.read('x28')) == TABLE and number(frame.read('x26')) == SEED
    return number(frame.get(R + 4, 4))


def enter_byte_helper(record_word, once):
    # Run the two original prefixes on adjacent ABI frames. The first passes
    # its private record at SP+0x10 to the second with the original encoded word.
    frame = initial_frame()
    frame.seed('sp', F)
    frame.seed('x0', R)
    frame.put(R + 4, 4, record_word)
    frame.put(ONCE, 8, once)
    landmark(0x1004156b4, 'pacibsp', '')
    frame.step(0x1004156b8, 0x100415910)
    frame.local_call(0x100415910, 0x100415904, 'x8', 0x10044f9c8)
    assert number(frame.read('x0')) == F - 0x30
    landmark(0x10044f9c8, 'pacibsp', '')
    frame.step(0x10044f9cc, 0x10044fc30)
    target = 0x10035a43c if once == -1 else 0x10032f5f0
    branch(frame, 0x10044fc30, 0x10044fc28, 'x13', target)
    return frame, target


def once_callback(result, value):
    frame = initial_frame()
    frame.seed('sp', F)
    landmark(0x10043dd24, 'pacibsp', '')
    frame.step(0x10043dd28, 0x10043df88)
    landmark(0x10043df88, 'blraa', 'x8, x17')
    assert (0x10043df10, 0x1010a0628, 8) in frame.loads
    assert number(frame.read('x8')) == 0x1010a0628
    assert number(frame.read('x17')) == 0x686b
    assert FIXUPS[0x1010a0628]['target'] == 'libSystem/_sysctlbyname'
    args = [number(frame.read(f'x{i}')) for i in range(5)]
    assert args == [NAME, F - 0x70 + 0x14, F - 0x70 + 8, 0, 0]
    assert number(frame.get(args[1], 4)) == 0 and number(frame.get(args[2], 8)) == 4
    if not result:
        frame.put(args[1], 4, value)
    api_return(frame, result, 'w0')
    target = frame.step(0x10043df8c, 0x10043dfb8)
    assert target == (0x10028cc50 if result else 0x100130ae0)
    if not result:
        frame.step(target, 0x100130b44)
        branch(frame, 0x100130b44, 0x100130b3c, 'x8', 0x10028cc50)
    stores = [(pc, width) for pc, at, width, _ in frame.stores if at == CACHE]
    assert stores == ([] if result else [(0x100130b30, 1)])
    assert number(frame.get(CACHE, 1)) == (0 if result else int(value != 0))
    frame.step(0x10028cc50, 0x10028cc6c)
    assert frame.return_pc == 0x10028cc68 and number(frame.read('sp')) == F
    return number(frame.get(CACHE, 1)), frame.edges


def helper_byte(record_word, once, cached):
    frame, entry = enter_byte_helper(record_word, once)
    if once == -1:
        frame.step(entry, 0x10035a444)
        branch(frame, 0x10035a444, 0x10035a43c, 'x8', 0x100360938)
    else:
        frame.step(entry, 0x10032f688)
        landmark(0x10032f688, 'blraa', 'x9, x17')
        assert (0x10032f650, 0x1010a12e8, 8) in frame.loads
        assert number(frame.read('x9')) == 0x1010a12e8
        assert number(frame.read('x17')) == 0x6007
        assert (number(frame.read('x0')), number(frame.read('x1'))) == (ONCE, BLOCK)
        assert FIXUPS[BLOCK + 16]['target'] == 0x10043dd24
        frame.put(CACHE, 1, cached)
        api_return(frame, 0, 'w0')
        frame.step(0x10032f68c, 0x10032f694)
        branch(frame, 0x10032f694, 0x10032f68c, 'x8', 0x100360938)
    frame.put(CACHE, 1, cached)
    frame.step(0x100360938, 0x1003609d8)
    assert number(frame.read('sp')) == F - 0x40
    frame.step(0x100415914, 0x100415930)
    assert z3.is_true(z3.simplify(frame.equal))
    landmark(0x100415930, 'b.ne', '#0x100415944')
    frame.step(0x100415934, 0x100415944)
    assert frame.return_pc == 0x100415940 and number(frame.read('sp')) == F
    result = number(frame.get(R, 1))
    assert result == ((cached & 0x89) ^ 0x99)
    return result, frame.edges


def class_route(byte, primary, avp):
    frame = initial_frame()
    enter(frame)
    frame.put(R, 1, byte)
    frame.put(PRIMARY, 1, primary)
    frame.put(AVP, 1, avp)
    api_return(frame, 0, 'w0')
    frame.read_record_byte(0x100438534)
    frame.step(0x100438538, 0x10043861c)
    assert [number(frame.get(F + off, width)) for off, width in
            ((0x60, 8), (0x58, 8), (0x40, 8), (0x38, 8),
             (0x10, 8), (0x50, 8), (0x6c, 4))] == [*FIRST, *SECOND, AVP, PRIMARY, PHASE]
    entry = 0x1002765f8 if byte != 0x99 and avp == 0x70 else 0x10014ebf0
    branch(frame, 0x10043861c, 0x1004385d4, 'x9', entry)
    if entry == 0x10014ebf0:
        frame.step(entry, 0x10014ec24)
        entry = 0x100289e64 if primary == 0x70 else 0x1002bfecc
        branch(frame, 0x10014ec24, 0x10014ec1c, 'x9', entry)
    word = None
    if entry == 0x1002765f8:
        frame.step(entry, 0x100276624)
        branch(frame, 0x100276624, 0x100276608, 'x10', MAIN)
        assert number(frame.read('x20')) == AVP
        word = 1
    elif entry == 0x100289e64:
        assert frame.step(entry, 0x100289eac) == MAIN
        assert number(frame.read('x20')) == PRIMARY
        word = 0
    if word is not None:
        assert number(frame.get(F + 0x4c, 4)) == word
    return {'helper_byte': byte, 'primary': primary, 'avp': avp,
            'entry': hex(entry), 'control_word': word, 'edges': frame.edges}


def report():
    encoded = enter(initial_frame())
    assert IMAGE.read(NAME, 20) == b'kern.hv_vmm_present\0'
    common = next(s for s in sections() if (s['segment'], s['section']) == ('__DATA', '__common'))
    assert int(common['flags'], 16) & 0xff == 1
    assert common['start'] <= CACHE < ONCE < ONCE + 8 <= common['start'] + common['size_bytes']
    assert IMAGE.read(PRIMARY, 1) == IMAGE.read(AVP, 1) == b'\x70'
    assert FIXUPS[0x1010a1640]['target'] == 0x1004382b4
    assert FIXUPS[BLOCK]['target'] == 'libSystem/__NSConcreteGlobalBlock'
    cases = []
    for status, value in ((0, 0), (0, 1), (0, 0xffffffff), (1, 0)):
        cache, callback_edges = once_callback(status, value)
        cold, cold_edges = helper_byte(encoded, 0, cache)
        warm, warm_edges = helper_byte(encoded, -1, cache)
        assert cold == warm == 0x99 ^ cache
        cases.append({'query_status': status, 'query_value': value, 'cache': cache,
                      'helper_byte': cold, 'callback_edges': callback_edges,
                      'cold_edges': cold_edges, 'warm_edges': warm_edges})
    routes = [class_route(byte, primary, avp)
              for byte in (0x99, 0x98) for primary in (0x70, 0) for avp in (0x70, 0)]
    banks = [selected(*pair, key, add, base, bias) for pair, key, add, base, bias in (
        (FIRST, 0xa3, 0xcd2c, TABLE, 0),
        (SECOND, 0xf3, 0x8d7, POOL, -0x2f3b2e12),
        (MIDDLE_BANK, 0x56, 0xce70, TABLE, 0),
        (FOURTH, 0x6d, 0xcdaf, TABLE, 0),
        (FOURTH, 0xd7, 0xcc5b, TABLE, 0),
        (FIRST, 0xa3, 0x1164, POOL, -0x2d25cba6),
        (FOURTH, 0x9c, 0xa0f, POOL, -0xdedfa73),
        (ALT_BANK, 0x61, 0xa24, POOL, -0xdedfa73),
        (ALT_BANK, 0x61, 0x47c, POOL, -0x05e4033b),
        (SECOND, 0xe4, 0x4f1, POOL, -0x4a02fcce),
    )]
    assert [row['target'] for row in banks] == [
        '0x1004156b4', hex(TABLE), '0x10044f9c8', 'libSystem/_dispatch_once',
        'libSystem/_sysctlbyname', hex(NAME), hex(CACHE), hex(CACHE), hex(AVP), hex(PRIMARY)]
    slots = FIXUP_SLOTS | {BLOCK, BLOCK + 16, 0x1010a1640}
    return {'daemon_sha256': sha(SOURCE), 'generator_sha256': sha(Path(__file__)),
            'phase': hex(PHASE), 'name': 'kern.hv_vmm_present',
            'cases': cases, 'routes': routes, 'banks': banks,
            'source_spans': list(SPANS.values()), 'fixups': verify_original_fixups(slots)}


if __name__ == '__main__':
    print(json.dumps(report(), indent=2))
