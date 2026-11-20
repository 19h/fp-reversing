#!/usr/bin/env python3
"""Trace the stored lock pointer across the pinned fairplayd class lifecycle."""

import json

import z3

from audit_archived_iokit_open_retirement import trace_record
from audit_daemon_class_lock_gate import (
    CACHE, CLASS_ENTRY, GateProbe, HEAP, NO_CLASS, RECORD, SP,
)
from audit_daemon_selector26_open import task_binding
from audit_daemon_selector26_return import Frame, SPANS
from daemon_receive_tools import FIXUPS, IMAGE, SOURCE, TABLE, verify_original_fixups
from daemon_rpc502_probe import Probe, STACK, ar

PRIMARY = 0x1010b63a0
AVP = 0x1010b5d90
CONTEXT_SKIP = 0x10053ec30
CLEANUP = 0x100523d74
FINAL = 0x1006220ec
TASK_NAME = 0x317
MAIN_NAME = 0x117
DICTIONARY = STACK + 0x20000
TASK_IMPORT = 'libSystem/_mach_task_self_'
IOKIT_SIGNATURES = {
    '_IOMainPort': (0x100281684, 2),
    '_IOServiceMatching': ((0x100079bf0, 0x100281890), 1),
    '_IOServiceGetMatchingServices': (0x1002b7b94, 3),
    '_IOIteratorNext': (0x10018458c, 1),
    '_IOServiceOpen': (0x100176a0c, 4),
    '_IOObjectRelease': ((0x1001dcab8, 0x100205980), 1),
}
SAVED_EDGES = {
    0x1001ce7c0: (0x100281654, 0x100281658, 0x1001ce7b8, 0x70),
    0x1004b1340: (0x100631030, 0x100631034, 0x1004b1338, 0x558),
}


class ReleaseProbe(GateProbe):
    def __init__(self, env, primary, outcome, unlock_result):
        self.outcome = outcome
        self.unlock_result = unlock_result
        self.attempt = 0
        self.owners = {}
        self.saved = {}
        self.roots = {}
        super().__init__()
        self.u.mem_write(0x1010c8248, b'\xff' * 8)
        self.u.mem_write(0x1010c5740, bytes([env]))
        self.u.mem_write(PRIMARY, bytes([primary]))
        self.u.mem_write(self.import_addresses[TASK_IMPORT], TASK_NAME.to_bytes(4, 'little'))
        self.data_import_values.append({'name': TASK_IMPORT})
        assert self.memory_word(AVP, 1) == 0x70

    def read_hook(self, u, access, address, size, value, user):
        pc = u.reg_read(ar.UC_ARM64_REG_PC)
        if pc in (0x100281654, 0x100631030):
            assert size == 8 and address in FIXUPS
            self.roots[pc] = address
        super().read_hook(u, access, address, size, value, user)

    def write_hook(self, u, access, address, size, value, user):
        pc = u.reg_read(ar.UC_ARM64_REG_PC)
        for branch, (producer, store, _, off) in SAVED_EDGES.items():
            if pc == store:
                assert size == 8 and address == u.reg_read(ar.UC_ARM64_REG_SP) + off
                slot = self.roots[producer]
                assert FIXUPS[slot]['target'] == value
                self.saved[branch] = (producer, store, slot, address, value)
        super().write_hook(u, access, address, size, value, user)

    def saved_branch(self, u, pc, size, user):
        producer, store, slot, address, value = self.saved[pc]
        _, _, reload, off = SAVED_EDGES[pc]
        assert address == u.reg_read(ar.UC_ARM64_REG_SP) + off
        assert self.memory_word(address) == value == self.reg(8)
        Probe.hook(self, u, pc, size, user)
        entry = self.pac[-1]
        assert FIXUPS[slot]['annotation'] == f"(div=0x{int(entry['modifier'], 16):04X} ad=0 key=IA)"
        self.branch_slots.append(dict(entry, fixup_slot=hex(slot), load_pc=hex(reload),
                                      producer_pc=hex(producer), store_pc=hex(store)))
        self.reads.clear()

    def iokit_return(self, name, pc, args):
        if name == '_IOMainPort':
            assert args == (0, SP - 0x150 + 0x7c)
            if self.outcome == 'main_failure':
                return 1
            self.u.mem_write(args[1], MAIN_NAME.to_bytes(4, 'little'))
            return 0
        if name == '_IOServiceMatching':
            self.attempt += 1
            label = bytes(self.u.mem_read(args[0], 31)).split(b'\0', 1)[0].decode()
            assert label == ('AvpFairPlayDriver' if pc == 0x100281890
                             else 'com_apple_driver_FairPlayIOKit')
            assert not self.owners
            self.records[-1]['class'] = label
            return DICTIONARY
        iterator = 0x217 + 4 * (self.attempt - 1)
        service = 0x517 + 4 * (self.attempt - 1)
        if name == '_IOServiceGetMatchingServices':
            assert args == (MAIN_NAME, DICTIONARY, SP - 0x150 + 0x78)
            self.u.mem_write(args[2], iterator.to_bytes(4, 'little'))
            self.owners[iterator] = 'iterator'
            return 0
        if name == '_IOIteratorNext':
            assert args == (iterator,) and self.owners[iterator] == 'iterator'
            if self.outcome == 'iterator_exhausted':
                return 0
            self.owners[service] = 'service'
            return service
        if name == '_IOServiceOpen':
            context = AVP if self.reg(20) == AVP else PRIMARY
            assert self.reg(20) == context and self.owners[service] == 'service'
            assert args == (service, TASK_NAME, 0, context + 4)
            assert self.memory_word(context + 4, 4) == 0
            return 0xe00002c2
        assert name == '_IOObjectRelease'
        kind = 'service' if pc == 0x1001dcab8 else 'iterator'
        assert args == ((service if kind == 'service' else iterator),)
        assert self.owners.pop(args[0]) == kind
        return 0

    def hook(self, u, pc, size, user):
        if pc == FINAL:
            assert self.reg(21) == self.memory_word(SP + 0x62c, 4)
            self.stop('source_boundary', pc=hex(pc), stored_status=hex(self.reg(21)),
                      saved_outer_phase=hex(self.reg(24)))
            return
        if pc in (CLASS_ENTRY, NO_CLASS, CONTEXT_SKIP, CLEANUP, 0x100523ed0, 0x1004ba4d4):
            assert not self.owners
            self.records.append({'kind': 'source_checkpoint', 'pc': hex(pc),
                                 'phase': hex(self.reg(19) & 0xffffffff),
                                 'record_u32': hex(self.memory_word(RECORD, 4)),
                                 'record_pointer': hex(self.memory_word(RECORD + 8)),
                                 'context': hex(self.reg(20)) if pc == 0x1004ba4d4 else None})
            if pc in (CLASS_ENTRY, NO_CLASS):
                Probe.hook(self, u, pc, size, user)
                return
        if pc in SAVED_EDGES:
            self.saved_branch(u, pc, size, user)
            return
        if pc in self.imports:
            namespace, name = self.imports[pc].split('/', 1)
            return_pc = self.reg(30)
            call = return_pc - 4
            if namespace == 'IOKit':
                sites, count = IOKIT_SIGNATURES[name]
                assert call in (sites if isinstance(sites, tuple) else (sites,))
                args = tuple(self.reg(i) for i in range(count))
                self.records.append({'kind': 'modeled_import', 'name': name, 'pc': hex(call),
                                     'args': list(map(hex, args))})
                result = self.iokit_return(name, call, args)
                self.records[-1]['model_result'] = hex(result)
                self.finish_import(return_pc, result)
                return
            if name == '_pthread_rwlock_unlock':
                assert call == 0x1000db668 and not self.owners
                lock = self.reg(0)
                acquire, = [row for row in self.records if row.get('name') == '_pthread_rwlock_wrlock']
                assert lock == HEAP == self.memory_word(CACHE) == int(acquire['args'][0], 16)
                self.records.append({'kind': 'modeled_import', 'name': name, 'pc': hex(call),
                                     'args': [hex(lock)], 'model_result': hex(self.unlock_result)})
                self.finish_import(return_pc, self.unlock_result)
                return
        super().hook(u, pc, size, user)


def codecs():
    p = z3.BitVec('p', 32)
    equal_term = z3.BitVec('equal_term', 32)

    def verify(condition, proposition):
        solver = z3.SolverFor('QF_BV')
        solver.set(timeout=30000)
        solver.add(condition, z3.Not(proposition))
        assert solver.check() == z3.unsat

    f = Frame(x29=z3.ZeroExt(32, p) + 0xa0, w19=0x5a82)
    f.step(CLEANUP, 0x100523dc8)
    getter_caller = f.read('w9')
    f.seed('w9', equal_term)
    f.step(0x100523dc8, 0x100523dd0)
    getter_encoded = f.read('w8')
    f.seed('w19', p)
    f.step(0x1004186d4, 0x100418708)
    verify(p & 7 == 0, getter_caller == f.read('w15'))
    f.seed('w15', equal_term)
    f.step(0x100418708, 0x10041870c)
    verify(True, getter_encoded ^ f.read('w17') == 0x5ca8)

    f.seed('w19', 0x5a82)
    f.seed('w24', p)
    f.step(0x100523e34, 0x100523e6c)
    unlock_caller = f.read('w10')
    f.seed('w10', equal_term)
    f.step(0x100523e6c, 0x100523e70)
    f.step(0x100523e74, 0x100523e7c)
    unlock_encoded = f.read('w8')
    f.seed('w19', p)
    f.step(0x100423b64, 0x100423b94)
    verify(p & 7 == 0, unlock_caller == f.read('w15'))
    f.seed('w15', equal_term)
    f.step(0x100423b94, 0x100423b98)
    verify(True, unlock_encoded ^ f.read('w15') == 0xb645)

    return {'entry_w19': '0x5a82', 'alignment_bytes': 8, 'queries': 4,
            'phases': ['0x5ca8', '0xb645'], 'original_spans': list(SPANS.values())}


def inspect():
    cases = []
    slots = set()
    configurations = (
        ('primary_open_failed', 0, 0x70, HEAP, 'open_failure', 0, 0),
        ('avp_and_primary_failed', 1, 0x70, HEAP, 'open_failure', 0, 0),
        ('class_skipped', 0, 0, HEAP, 'open_failure', 0, 0),
        ('main_port_failed', 0, 0x70, HEAP, 'main_failure', 0, 0),
        ('iterator_exhausted', 0, 0x70, HEAP, 'iterator_exhausted', 0, 0),
        ('null_cache', 0, 0x70, 0, 'open_failure', 0, 0),
        ('lock_and_unlock_error_controls', 0, 0x70, HEAP, 'open_failure', 5, 22),
    )
    for name, env, primary, allocation, outcome, lock, unlock in configurations:
        probe = ReleaseProbe(env, primary, outcome, unlock)
        result = probe.run_case(name, allocation, lock_result=lock)
        assert not probe.owners
        slots.update(probe.slots)
        sequence = result['sequence']
        imports = [row for row in sequence if row['kind'] == 'modeled_import']
        release_sites = [row['pc'] for row in imports if row['name'] == '_IOObjectRelease']
        paired = ['0x1001dcab8', '0x100205980']
        wanted = {
            'primary_open_failed': paired, 'avp_and_primary_failed': paired * 2,
            'class_skipped': [], 'main_port_failed': [], 'null_cache': [],
            'iterator_exhausted': ['0x100205980'], 'lock_and_unlock_error_controls': paired,
        }[name]
        assert release_sites == wanted
        cache_copies = [row for row in result['record_stores'] if row['pc'] == '0x10008730c']
        assert [int(row['value'], 16) for row in cache_copies] == [allocation, allocation]
        assert [row['name'] for row in imports].count('_dispatch_once') == 1
        private = [row for row in sequence if row.get('pc') == '0x100523ed0']
        expected_cleanup = 0x118cb413 if allocation else 0xeb6c70cc
        assert len(private) == 1 and int(private[0]['record_u32'], 16) == expected_cleanup
        assert sequence[-1]['pc'] == hex(FINAL)
        assert sequence[-1]['stored_status'] == hex(
            0x74c29dba if name == 'class_skipped' else 0x74c29dee if allocation else 0x74c29d88
        )
        names = [row['name'] for row in imports]
        if name == 'class_skipped':
            assert all(row['name'] not in IOKIT_SIGNATURES for row in imports)
            context_writes = [row for row in result['image_writes']
                              if 0x1004ba4d4 <= int(row['pc'], 16) <= 0x1004ba524]
            assert len(context_writes) == 9
            assert context_writes[:2] == [
                {'pc': '0x1004ba4d4', 'address': hex(PRIMARY), 'size': 1, 'value': '0x70'},
                {'pc': '0x1004ba4e8', 'address': hex(PRIMARY + 4),
                 'size': 4, 'value': '0x82da5774'},
            ]
        if allocation:
            assert names[-1] == '_pthread_rwlock_unlock'
            assert names.count('_pthread_rwlock_wrlock') == 1
        else:
            assert all('rwlock' not in item for item in names)
        result['model_environment_cache_byte'] = env
        result['model_primary_context_byte'] = primary
        cases.append(result)

    data_bind_slots = {slot for slot in slots if FIXUPS[slot]['kind'] == 'bind'}
    assert {FIXUPS[slot]['target'] for slot in data_bind_slots} == {
        'libSystem/___stack_chk_guard', TASK_IMPORT,
    }
    source_spans = ((0x1004ba4c0, 0x1004ba554), (0x100523d74, 0x100523f00),
                    (0x100423b98, 0x100423c30), (0x1000db660, 0x1000db680),
                    (0x1000f7554, 0x1000f756c), (0x1006220cc, 0x1006220ec))
    return {
        'profiles': cases,
        'codecs': codecs(),
        'fixups': verify_original_fixups(slots - data_bind_slots),
        'source_spans': [{'start': hex(lo), 'end_exclusive': hex(hi),
                          'bytes_hex': IMAGE.read(lo, hi - lo).hex()} for lo, hi in source_spans],
        'task_port_binding': task_binding(),
        'modeled_data_bind_slots': [{'slot': hex(slot), 'target': FIXUPS[slot]['target'],
                                     'raw_word_hex': IMAGE.read(slot, 8).hex()}
                                    for slot in sorted(data_bind_slots)],
        'archived_trace': trace_record(SOURCE.with_name('annotated-strace-rax-user.txt')),
        'native_lock_lifetime_or_archived_caller_observed': False,
    }


if __name__ == '__main__':
    print(json.dumps(inspect(), indent=2, sort_keys=True))
