#!/usr/bin/env python3
"""Verify the pinned fairplayd cached-lock gate in a private, bounded model."""

import json

import z3

from audit_archived_iokit_open_retirement import TRACE_SHA, trace_record
from audit_daemon_selector26_return import Frame, SPANS
from daemon_receive_tools import FIXUPS, IMAGE, SOURCE, TABLE, bank, qword
from daemon_receive_tools import verify_original_fixups
from daemon_rpc502_probe import HALT, STACK, Probe, ar

SP = STACK + 0x70000
RECORD = SP + 0xc20
HEAP = STACK + 0x10000
ONCE = 0x1010c67e0
CACHE = 0x1010c6820
BLOCK = 0x101039c10
CALLBACK_RETURN = HALT + 4
STATUS = 0x8b3dc651
NULL_STATUS = 0x74c29d88
CLASS_CALLER = 0x100636d60
CLASS_ENTRY = 0x1004382b4
NO_CLASS = 0x1006340c8
PREDECESSOR_OTHER = 0x1004c620c

IMPORTS = {
    '_dispatch_once': (0x10002c18c, (ONCE, BLOCK)),
    '_malloc': (0x1003010ec, (200,)),
    '_pthread_rwlock_init': (0x1003184c8, (HEAP, 0)),
    '_free': (0x100254368, (HEAP,)),
    '_pthread_rwlock_wrlock': (0x10019eed0, (HEAP,)),
}


class GateProbe(Probe):
    def __init__(self):
        self.reads = []
        self.record_stores = []
        self.slots = set()
        super().__init__()

    def memory_word(self, address, width=8):
        return int.from_bytes(self.u.mem_read(address, width), 'little')

    def read_hook(self, u, access, address, size, value, user):
        if size == 8 and address in FIXUPS:
            self.reads.append((u.reg_read(ar.UC_ARM64_REG_PC), address))
            self.slots.add(address)
        super().read_hook(u, access, address, size, value, user)

    def write_hook(self, u, access, address, size, value, user):
        if RECORD <= address < RECORD + 16:
            self.record_stores.append({
                'pc': hex(u.reg_read(ar.UC_ARM64_REG_PC)), 'offset_bytes': address - RECORD,
                'size_bytes': size, 'value': hex(value & ((1 << (size * 8)) - 1)),
            })
        super().write_hook(u, access, address, size, value, user)

    def finish_import(self, return_pc, value):
        for register in range(18):
            self.setreg(register, 0x40b00000 ^ (register << 10) ^ self.clobber)
        self.setreg(0, value)
        self.setreg(30, return_pc)
        self.u.reg_write(ar.UC_ARM64_REG_PC, return_pc)

    def hook(self, u, pc, size, user):
        if pc in (CLASS_ENTRY, NO_CLASS, PREDECESSOR_OTHER):
            self.stop('source_boundary', pc=hex(pc), argument=hex(self.reg(0)),
                      sp=hex(u.reg_read(ar.UC_ARM64_REG_SP)))
            return
        if pc == 0x10047df94:
            assert tuple(self.reg(i) for i in (7, 20, 22)) == (TABLE, 0x219a, STATUS)
        if pc == CLASS_CALLER:
            assert self.memory_word(RECORD + 4, 4) == STATUS
        if pc == CALLBACK_RETURN:
            self.u.mem_write(ONCE, b'\xff' * 8)
            self.finish_import(self.once_return, 0)
            return
        if pc in self.imports:
            name = self.imports[pc]
            assert name.startswith('libSystem/') and name.split('/', 1)[1] in IMPORTS, name
            name = name.split('/', 1)[1]
            call, arguments = IMPORTS[name]
            assert self.reg(30) == call + 4
            assert tuple(self.reg(index) for index in range(len(arguments))) == arguments
            self.records.append({'kind': 'modeled_import', 'name': name, 'pc': hex(call),
                                 'args': [hex(arg) for arg in arguments]})
            if name == '_dispatch_once':
                assert self.memory_word(ONCE) == 0
                self.once_return = self.reg(30)
                self.setreg(0, BLOCK)
                self.setreg(30, CALLBACK_RETURN)
                assert self.memory_word(BLOCK + 16) == qword(BLOCK + 16) == 0x1004116b4
                u.reg_write(ar.UC_ARM64_REG_PC, self.memory_word(BLOCK + 16))
                return
            result = {'_malloc': self.allocation, '_pthread_rwlock_init': self.init_result,
                      '_free': 0, '_pthread_rwlock_wrlock': self.lock_result}[name]
            self.records[-1]['model_result'] = hex(result)
            self.finish_import(self.reg(30), result)
            return
        before = len(self.pac)
        super().hook(u, pc, size, user)
        if len(self.pac) > before and 'target' in self.pac[-1]:
            item = self.pac[-1]
            target = int(item['target'], 16)
            name = self.imports.get(target, target)
            modifier = int(item['modifier'], 16)
            candidates = [(load_pc, slot) for load_pc, slot in self.reads
                          if FIXUPS[slot]['target'] == name and FIXUPS[slot]['annotation'] ==
                          f'(div=0x{modifier:04X} ad=0 key=IA)']
            assert candidates, (item, self.reads[-3:])
            load_pc, slot = candidates[-1]
            self.branch_slots.append(dict(item, target=hex(name) if isinstance(name, int) else name,
                                          load_pc=hex(load_pc), fixup_slot=hex(slot)))
            self.reads.clear()

    def run_case(self, name, allocation, init_result=0, lock_result=0, clobber=0,
                 marker=0, context=HEAP):
        self.allocation, self.init_result, self.lock_result = allocation, init_result, lock_result
        self.clobber = clobber
        self.stop_reason = None
        self.records, self.record_stores, self.writes, self.pac, self.branch_slots = [], [], [], [], []
        self.reads.clear()
        initial = [self.memory_word(address) for address in (ONCE, CACHE)]
        self.u.reg_write(ar.UC_ARM64_REG_SP, SP + 0xcd0)
        self.setreg(30, HALT)
        self.u.emu_start(0x100559b7c, 0x100559c80, count=400)
        assert self.u.reg_read(ar.UC_ARM64_REG_SP) == SP
        assert self.reg(29) - 0xa0 == RECORD
        assert tuple(self.reg(i) for i in (16, 15, 26, 24)) == (
            0x100fc4130, 0x101031ea0, 0x1010b8de0, 0x1010c4670,
        )
        self.setreg(7, TABLE)
        self.u.emu_start(0x100530374, 0x100530464, count=400)
        offsets = (0x2d0, 0x2c8, 0x290, 0x288, 0x300, 0x2f0, 0x2f8)
        bank_frame = dict(zip(map(hex, offsets), [self.memory_word(SP + off) for off in offsets]))
        assert tuple(bank_frame.values()) == (
            0x100fc4230, 0x101031fa0, 0x100fc4130, 0x101031ea0, TABLE, 0x1010b8de0,
            0x1010c4670,
        )
        for register, value in {9: 0x65a1, 11: marker, 19: context}.items():
            self.setreg(register, value)
        self.u.emu_start(0x100639894, 0, count=20000)
        assert self.stop_reason == 'source_boundary'
        assert self.u.reg_read(ar.UC_ARM64_REG_SP) == SP
        return {'case': name, 'initial_once_and_cache': list(map(hex, initial)),
                'final_once_and_cache': [hex(self.memory_word(addr)) for addr in (ONCE, CACHE)],
                'reaching_marker': hex(marker), 'reaching_context': hex(context),
                'bank_and_dispatch_frame': {k: hex(v) for k, v in bank_frame.items()},
                'sequence': self.records, 'record_stores': self.record_stores,
                'image_writes': self.writes, 'edges': self.branch_slots}


def original_codecs():
    projection = z3.BitVec('record_address_low32', 32)
    common = z3.BitVec('equal_address_term', 32)
    aligned = projection & 7 == 0

    def prove(condition, result):
        solver = z3.SolverFor('QF_BV')
        solver.set(timeout=30000)
        solver.add(condition, z3.Not(result))
        assert solver.check() == z3.unsat

    frame = Frame(x29=z3.ZeroExt(32, projection) + 0xa0, w20=0x219a)
    frame.step(0x10047df94, 0x10047dfe8)
    caller = frame.read('w10')
    frame.seed('w10', common)
    frame.step(0x10047dfe8, 0x10047dff4)
    encoded = frame.read('w9')
    frame.seed('w19', projection)
    frame.step(0x1004186d4, 0x100418708)
    callee = frame.read('w15')
    prove(aligned, caller == callee)
    prove(projection == 2, caller != callee)
    frame.seed('w15', common)
    frame.step(0x100418708, 0x10041870c)
    prove(True, encoded ^ frame.read('w17') == 0x5ca8)

    frame.seed('w25', projection)
    frame.step(0x10047e05c, 0x10047e08c)
    caller = frame.read('w9')
    frame.seed('w9', common)
    frame.step(0x10047e08c, 0x10047e098)
    encoded = frame.read('w9')
    frame.step(0x100412bac, 0x100412bdc)
    callee = frame.read('w15')
    prove(aligned, caller == callee)
    prove(projection == 4, caller != callee)
    prove(True, common * frame.read('w16') + encoded == 0xc491)
    return {'assumptions': ['W20=0x219a', 'P is 8 B aligned'],
            'decoded_phases': ['0x5ca8', '0xc491'], 'misaligned_controls_bytes': [2, 4],
            'proof_queries': 6, 'spans': list(SPANS.values())}


def verify_case(case, imports, output, target):
    calls = [row['name'] for row in case['sequence'] if row['kind'] == 'modeled_import']
    assert calls == imports, case
    assert case['sequence'][-1]['pc'] == hex(target), case
    writes = {int(row['pc'], 16): row for row in case['record_stores']}
    if output is None:
        assert not writes
        return
    assert (writes[0x10008730c]['offset_bytes'], writes[0x10008730c]['size_bytes']) == (0, 8)
    assert (writes[0x10003cdbc]['offset_bytes'], writes[0x10003cdbc]['size_bytes']) == (4, 4)
    assert int(writes[0x10003cdbc]['value'], 16) == output
    ptr = 0 if output == NULL_STATUS else HEAP
    assert int(writes[0x10008730c]['value'], 16) == ptr
    assert int(writes[0x10047e09c]['value'], 16) == ptr
    assert case['final_once_and_cache'] == ['0xffffffffffffffff', hex(ptr)]
    publication = [row for row in case['image_writes'] if int(row['address'], 16) == CACHE]
    if ptr and '_pthread_rwlock_init' in calls:
        assert publication == [{'pc': '0x10030a254', 'address': hex(CACHE),
                                'size': 8, 'value': hex(ptr)}]
    else:
        assert not publication
    if target == CLASS_ENTRY:
        assert case['sequence'][-1]['argument'] == hex(RECORD)
        assert case['edges'][-1]['site'] == '0x100636dfc'


def inspect():
    success = GateProbe()
    alloc_fail, init_fail, null_context, marker_matches = [GateProbe() for _ in range(4)]
    assert IMAGE.read(ONCE, 8) == IMAGE.read(CACHE, 8) == bytes(8)
    cases = [
        (success.run_case('cold_initialized', HEAP), 3, STATUS, CLASS_ENTRY),
        (success.run_case('warm_lock_error', 0, lock_result=5, clobber=0xff), 1, STATUS, CLASS_ENTRY),
        (alloc_fail.run_case('cold_allocation_failed', 0), 2, NULL_STATUS, NO_CLASS),
        (alloc_fail.run_case('warm_null', 0), 0, NULL_STATUS, NO_CLASS),
        (init_fail.run_case('cold_initialization_failed', HEAP, init_result=22), 4, NULL_STATUS, NO_CLASS),
        (null_context.run_case('null_context', 0, context=0), 0, None, PREDECESSOR_OTHER),
        (marker_matches.run_case('incoming_marker_matches', 0, marker=STATUS), 0, None, PREDECESSOR_OTHER),
    ]
    for case, profile, word, target in cases:
        once_allocate = ['_dispatch_once', '_malloc']
        patterns = [[], ['_pthread_rwlock_wrlock'], once_allocate,
                    once_allocate + ['_pthread_rwlock_init', '_pthread_rwlock_wrlock'],
                    once_allocate + ['_pthread_rwlock_init', '_free']]
        verify_case(case, patterns[profile], word, target)

    probes = (success, alloc_fail, init_fail, null_context, marker_matches)
    slots = set().union(*(probe.slots for probe in probes)) | {BLOCK, BLOCK + 16, BLOCK + 24}
    plain_imports = {slot for slot in slots if FIXUPS[slot]['kind'] == 'bind'}
    assert plain_imports == {0x1010b1e18}
    assert FIXUPS[0x1010b1e18]['target'] == 'libSystem/___stack_chk_guard'
    archive = trace_record(SOURCE.with_name('annotated-strace-rax-user.txt'))
    source_ranges = ((0x100559b7c, 0x100559c80), (0x100530374, 0x100530464),
                     (0x100639894, 0x100639910), (0x10047df94, 0x10047e12c),
                     (0x10019eed4, 0x10019eee8), (0x10003cdbc, 0x10003cdd4))
    return {
        'profiles': [case for case, _, _, _ in cases],
        'fixups': verify_original_fixups(slots - plain_imports),
        'stack_guard_import': {'slot': '0x1010b1e18', 'target': FIXUPS[0x1010b1e18]['target'],
                               'word_hex': IMAGE.read(0x1010b1e18, 8).hex()},
        'codec_proof': original_codecs(),
        'source_spans': [{'start': hex(lo), 'end_exclusive': hex(hi),
                          'bytes_hex': IMAGE.read(lo, hi - lo).hex()} for lo, hi in source_ranges],
        'bank_checks': [
            {'left': hex(left), 'right': hex(right), 'key': hex(key),
             'value': hex(bank(left, right, key)), 'inputs': 256}
            for left, right, key in ((0x100fc4230, 0x101031fa0, 0x6c),
                                    (0x100fc4130, 0x101031ea0, 0xa3))
        ],
        'archive': {'sha256': TRACE_SHA, 'evidence': archive, 'native_gate_join_established': False},
        'image_sha256': '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e',
        'native_pac_or_import_execution': False,
    }


if __name__ == '__main__':
    print(json.dumps(inspect(), indent=2, sort_keys=True))
