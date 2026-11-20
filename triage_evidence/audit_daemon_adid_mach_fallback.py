#!/usr/bin/env python3
"""Verify original fairplayd's selected legacy ADID transport, with private API returns."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import struct
import subprocess

from unicorn import arm64_const as ar
import z3

from audit_daemon_adid_reply_reader import IMPORTS
from audit_daemon_adid_request_origin import BUFFER, CLIENT, DICT, MODELS, P, QUEUE, RECORD
from audit_daemon_adid_request_origin import Replay, reference
from audit_daemon_iokit_native_registry import daemon_slices
from audit_archived_iokit_open_retirement import GUEST_MESSAGE, TRACE_SHA
from audit_live_fairplay_adid_ipc import ACTIVATE, ARM64E, PAYLOAD, POOL, PROVIDER_SHA, QUEUE as QUEUE_BANK
from audit_live_fairplay_adid_ipc import TABLE, TYPED
from daemon_receive_tools import FIXUPS, IMAGE, SOURCE, selected, verify_original_fixups
import recover_daemon_environment_outputs as environment


CACHE = 0x1010ca318
SERVICE = 0x101033900
WRAPPER = 0x100de9f08
BOOTSTRAP = P + 0x58000
NDR = P + 0x58008
REPLY_OBJECT = P + 0x59000
RESPONSE_DATA = P + 0x5a000
NDR_BYTES = bytes.fromhex('0000000001000000')
INVALID_DEST = 0x10000003
LOOKUP = 0x100e2320c
FIRST = 0x100e23104
RETRY = 0x100e232dc
MACH = 0x100de9fac
END_SUCCESS_RETRY = 0x100e23324
WRAPPER_IMPORTS = {
    0x100de9f54: (0x100e2ab50, '_mig_get_reply_port'),
    MACH: (0x100e2aaf0, '_mach_msg'),
    0x100de9fe0: (0x100e2ab60, '_mig_put_reply_port'),
    0x100dea044: (0x100e2ab30, '_mig_dealloc_reply_port'),
}
BOOTSTRAP_NAME, LOOKUP_NAME, REPLY_NAME = 0x103, 0x6a03, 0x507
PROFILES = (
    ('cold_lookup_and_retry_error', 0, INVALID_DEST, 0, 0x10000004),
    ('warm_other_transport_error', 0x6903, 0x10000004, None, None),
    ('warm_lookup_rejected', 0x6903, INVALID_DEST, 5, None),
    ('warm_retry_still_invalid', 0x6903, INVALID_DEST, 0, INVALID_DEST),
    ('cold_lookup_and_success_reply', 0, INVALID_DEST, 0, 0),
)
ERROR_RETURNS = {
    'cold_lookup_and_retry_error': 0xffff5028,
    'warm_other_transport_error': 0xffff5028,
    'warm_lookup_rejected': 0xffff5027,
    'warm_retry_still_invalid': 0xffff5027,
}


class Fallback(Replay):
    def __init__(self, parent, prefix, profile):
        super().__init__(parent['configuration'], parent)
        self.prefix = prefix
        self.label, self.cached, self.first_status, self.lookup_status, self.retry_status = profile
        self.hops = []
        self.wire = []
        self.release_order = []
        self.frees = []
        self.slot_reads = []
        self.lookups = []
        self.status_gate = None
        self.ensure(CACHE, 4)
        self.u.mem_write(CACHE, struct.pack('<I', self.cached))
        for slot, target in ((0x1010b1858, BOOTSTRAP), (0x1010b1e10, NDR), (0x1010b1e38, 0)):
            self.ensure(slot, 8)
            self.u.mem_write(slot, struct.pack('<Q', target))
        self.fixture(BOOTSTRAP, struct.pack('<I', BOOTSTRAP_NAME))
        self.fixture(NDR, NDR_BYTES)

    def return_value(self, pc, result):
        self.flush()
        pattern = self.caller_configuration['pattern']
        for j in range(18):
            self.set(j, (0x129a571e97bfa023 * (j + 1)) ^ pattern)
        self.u.reg_write(ar.UC_ARM64_REG_NZCV, (pattern & 15) << 28)
        if result is not None:
            self.set(0, result)
        self.set(30, pc + 4)
        self.u.reg_write(ar.UC_ARM64_REG_PC, pc + 4)

    def slot_for(self, pc, target, modifier):
        self.flush()
        for row in reversed(self.reads[-32:]):
            slot = int(row['address'], 16)
            rec = FIXUPS.get(slot)
            if rec and rec['target'] == target and rec['annotation'] == f'(div=0x{modifier:04X} ad=0 key=IA)':
                self.slot_reads.append(slot)
                return hex(slot)
        raise AssertionError((hex(pc), target, modifier))

    def wire_request(self, pc):
        ptr, options, sendsz, recvcap, reply, timeout, notify = (self.reg(j) for j in range(7))
        frame = self.register('sp')
        assert (ptr, options, sendsz, recvcap, reply, timeout, notify) == (frame, 3, 56, 64, REPLY_NAME, 0, 0)
        source = self.snapshot(frame, sendsz)
        assert source['known_mask_hex'][:8] == '01' * 4 and source['known_mask_hex'][16:] == '01' * 48
        bits, _, remote, local, voucher, mid, count, payload, flags, size, ndr, repeated = struct.unpack(
            '<7IQII8sI', bytes.fromhex(source['bytes_hex']))
        hop = self.hops[-1]
        assert (bits, remote, local, voucher, mid, count) == (0x80001513, hop['destination'], REPLY_NAME, 0, 1200, 1)
        assert (payload, flags, size, ndr, repeated) == (BUFFER, 0x01000100, 20, NDR_BYTES, 20)
        data = self.snapshot(payload, size)
        assert data == self.request['buffer'] and data == self.prefix['request']['buffer']
        status = self.first_status if len(self.hops) == 1 else self.retry_status
        self.wire.append(dict(emission=hex(pc), bits=hex(bits), remote=hex(remote), local=hex(local),
                              voucher=hex(voucher), identifier=mid, descriptor_count=count, flags=hex(flags),
                              inline_send_bytes=sendsz, receive_capacity_bytes=recvcap, ool_extent_bytes=size,
                              repeated_extent_bytes=repeated, ndr_hex=ndr.hex(), status=hex(status),
                              payload_sha256=sha256(bytes.fromhex(data['bytes_hex'])).hexdigest()))
        if status == 0:
            # This reply exists only in the emulator. The application bytes are opaque.
            response = struct.pack('<7IQII8sI', 0x80001200, 56, 0, REPLY_NAME, 0, 1300, 1,
                                   RESPONSE_DATA, 0x01000100, 4, NDR_BYTES, 4)
            self.fixture(ptr, response)
        return status

    def wrapper_import(self, pc, insn):
        stub, name = WRAPPER_IMPORTS[pc]
        assert (insn.mnemonic, insn.op_str) == ('bl', '#' + hex(stub))
        assert self.hops
        if name == '_mig_get_reply_port':
            result = REPLY_NAME
        elif name == '_mach_msg':
            result = self.wire_request(pc)
        else:
            assert self.reg(0) == REPLY_NAME
            self.wire[-1]['reply_cache_operation'] = name
            result = None
        return self.return_value(pc, result)

    def code(self, u, pc, size, data):
        raw = bytes(u.mem_read(pc, size))
        insn = next(self.cs.disasm(raw, pc))
        if pc in WRAPPER_IMPORTS:
            assert raw == IMAGE.read(pc, 4)
            return self.wrapper_import(pc, insn)
        if pc == 0x100e23158:
            assert self.reg(20) == 0xb9 and self.reg(27) == 0x3c2e08d2
            self.status_gate = hex(self.reg(9))
            assert self.status_gate == ('0x100e2315c' if self.first_status == INVALID_DEST else '0x100e23324')
        if pc == END_SUCCESS_RETRY and self.retry_status == 0:
            frame = self.register('sp')
            assert struct.unpack('<Q', bytes(u.mem_read(frame + 0x188, 8))) == (RESPONSE_DATA,)
            assert struct.unpack('<I', bytes(u.mem_read(frame + 0x19c, 4))) == (4,)
            assert self.reg(0) == 0
            return self.stop('after_legacy_transport_reply_outputs')
        if pc not in MODELS and insn.mnemonic == 'blraa':
            target_reg, modifier_reg = insn.op_str.split(', ')
            target, modifier = self.register(target_reg), self.register(modifier_reg)
            x0, x1, x2, x3, x4 = (self.reg(j) for j in range(5))
            symbol = IMPORTS.get(target)
            if target == WRAPPER:
                assert pc in (FIRST, RETRY) and modifier == 0x57e4 and raw == IMAGE.read(pc, 4)
                slot = self.slot_for(pc, target, modifier)
                frame = self.register('sp')
                assert (x1, x2, x3, x4) == (BUFFER, 20, frame + 0x188, frame + 0x19c)
                assert x0 == (self.cached if pc == FIRST else LOOKUP_NAME)
                assert any(row['pc'] == hex(0x100e23080 if pc == FIRST else 0x100e23274)
                           and row['address'] == hex(CACHE) for row in self.reads[-40:])
                self.hops.append(dict(pc=hex(pc), slot=slot, destination=x0, request_ool_bytes=x2,
                                      output_offsets_from_parent_sp=['0x188', '0x19c']))
            elif symbol:
                assert raw == IMAGE.read(pc, 4)
                self.slot_for(pc, symbol, modifier)
                if pc == 0x100e21718:
                    assert (symbol, x0, x1) == ('libSystem/_xpc_connection_send_message_with_reply_sync', CLIENT, DICT)
                    assert len(self.visits) == self.prefix['source_visits']
                    words = b''.join(int(row['pc'], 16).to_bytes(8, 'little') + bytes.fromhex(row['bytes_hex'])
                                     for row in self.visits)
                    assert sha256(words).hexdigest() == self.prefix['ordered_source_words_sha256']
                    result = REPLY_OBJECT
                elif pc == 0x100e21770:
                    assert (symbol, x0) == ('libSystem/_xpc_get_type', REPLY_OBJECT)
                    result = self.callee_address('_xpc_type_error')
                elif symbol == 'libSystem/_xpc_release':
                    self.release_order.append((hex(pc), x0))
                    result = None
                elif symbol == 'libSystem/_free':
                    self.frees.append((hex(pc), x0))
                    result = None
                elif pc == LOOKUP:
                    assert (symbol, x0, x1, x2) == ('libSystem/_bootstrap_look_up', BOOTSTRAP_NAME, SERVICE, CACHE)
                    assert bytes(u.mem_read(x1, 15)) == b'com.apple.adid\0'
                    assert self.lookup_status is not None
                    self.lookups.append(dict(pc=hex(pc), service='com.apple.adid', namespace=hex(x0),
                                             cache_address=hex(x2), status=self.lookup_status,
                                             output=None if self.lookup_status else hex(LOOKUP_NAME)))
                    if self.lookup_status == 0:
                        u.mem_write(x2, struct.pack('<I', LOOKUP_NAME))
                    result = self.lookup_status
                else:
                    return super().code(u, pc, size, data)
                return self.return_value(pc, result)
        return super().code(u, pc, size, data)

    def audit(self):
        state = self.run()
        retry = self.lookup_status == 0
        assert self.prefix_rechecked and len(self.lookups) == int(self.lookup_status is not None)
        assert len(self.wire) == len(self.hops) == 1 + int(retry)
        if retry:
            assert self.wire[0]['payload_sha256'] == self.wire[1]['payload_sha256']
        assert self.release_order == [(hex(a), b) for a, b in (
            (0x100e22df0, QUEUE), (0x100e22e40, CLIENT), (0x100e22f08, DICT), (0x100e22fac, REPLY_OBJECT))]
        if self.retry_status == 0:
            assert state['boundary']['pc'] == hex(END_SUCCESS_RETRY) and self.reg(0) == 0
        else:
            assert state['boundary']['pc'] == hex(environment.RETURN)
            assert self.frees == [(hex(0x100e24fdc), BUFFER), (hex(0x100e2507c), RECORD)]
            assert self.reg(0) & 0xffffffff == ERROR_RETURNS[self.label]
        cache, = struct.unpack('<I', bytes(self.u.mem_read(CACHE, 4)))
        assert cache == (LOOKUP_NAME if retry else self.cached)
        return dict(profile=self.label, configuration=self.caller_configuration, initial_cache=hex(self.cached),
                    final_cache=hex(cache), legacy_calls=self.hops, lookups=self.lookups, wire=self.wire,
                    releases=self.release_order, frees=self.frees, boundary=state['boundary']['pc'],
                    w0=hex(self.reg(0) & 0xffffffff), status_gate_target=self.status_gate,
                    source_visits=len(state['source_visits']))


def provider_record(binary, launchd_plist):
    blob, = [blob for cpu, subtype, blob in daemon_slices(binary.read_bytes()) if (cpu, subtype) == ARM64E]
    assert sha256(blob).hexdigest() == PROVIDER_SHA
    imports = subprocess.check_output(['xcrun', 'dyld_info', '-arch', 'arm64e', '-imports', str(binary)], text=True)
    symbols = set(re.findall(r'^\s+0x[\da-fA-F]+\s+(_\S+)\s+', imports, flags=re.M))
    suspect = {name for name in symbols if re.match(r'^_(?:mach_msg|mach_msg2|mig_|bootstrap_)', name)}
    assert '_xpc_connection_create_mach_service' in symbols and not suspect
    services = json.loads(subprocess.check_output(
        ['plutil', '-extract', 'MachServices', 'json', '-o', '-', str(launchd_plist)]))
    assert services == {'com.apple.adid': True}
    return dict(arm64e_sha256=PROVIDER_SHA, direct_mach_mig_bootstrap_imports=sorted(suspect), mach_services=services)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('provider', type=Path)
    parser.add_argument('launchd_plist', type=Path)
    parser.add_argument('archived_trace', type=Path)
    args = parser.parse_args()
    archive = args.archived_trace.read_bytes()
    assert sha256(archive).hexdigest() == TRACE_SHA
    guest_ids = [int(match[8]) for row in archive.decode().splitlines()
                 if (match := GUEST_MESSAGE.fullmatch(row))]
    assert guest_ids and not {1200, 1300}.intersection(guest_ids)
    stubs = subprocess.check_output(
        ['xcrun', 'llvm-objdump', '--macho', '--indirect-symbols', str(SOURCE)], text=True)
    for stub, name in WRAPPER_IMPORTS.values():
        assert re.search(rf'^0x{stub:016x}\s+\d+\s+{name}$', stubs, flags=re.M)
    parents = [row for row in reference('daemon_environment_outputs_checks')['cases']
               if row['configuration']['kind'] == 'caller' and row['boundary']['pc'] == '0x100e1ea4c']
    prefixes = [row for row in reference('daemon_adid_request_origin_audit')['cases']
                if row['prefix_rechecked'] and row['request']]
    assert len(parents) == len(prefixes) == 8
    cases, slots = [], set()
    for parent in parents:
        prefix, = [row for row in prefixes if row['configuration'] == parent['configuration']]
        for profile in PROFILES:
            run = Fallback(parent, prefix, profile)
            cases.append(run.audit())
            slots.update(run.slot_reads)

    banks = [
        selected(*ACTIVATE, 0xa0, -0x94, POOL),
        selected(*TYPED, 0x6a, 0xa97, TABLE),
        selected(*PAYLOAD, 0xaa, 0xa98, TABLE),
        selected(*PAYLOAD, 0xaa, 0xa3c, TABLE),
        selected(*TYPED, 0x6a, -0x49, POOL),
        selected(*QUEUE_BANK, 0x3e, 0xa4b, TABLE),
    ]
    assert [row['target'] for row in banks] == [
        hex(CACHE), hex(WRAPPER), 'libSystem/_bootstrap_look_up', hex(WRAPPER),
        'libSystem/_bootstrap_port', hex(WRAPPER)]
    status = z3.BitVec('status', 32)
    encoded = (status ^ 0xadef2fef) + ((status << 1) & 0x5bde5fde) + 0x7e3ed827 + 0xb9
    solver = z3.Solver()
    solver.add((encoded == 0x3c2e08d2) != (status == INVALID_DEST))
    assert solver.check() == z3.unsat
    print(json.dumps(dict(source_sha256=sha256(SOURCE.read_bytes()).hexdigest(), cases=cases, banks=banks,
                          verified_authenticated_fixups=verify_original_fixups(slots),
                          invalid_destination_predicate_counterexample='unsat',
                          provider=provider_record(args.provider, args.launchd_plist),
                          archived_trace=dict(sha256=TRACE_SHA, parsed_guest_message_records=len(guest_ids),
                                              adid_legacy_messages=0),
                          native_ipc_executed=False), sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
