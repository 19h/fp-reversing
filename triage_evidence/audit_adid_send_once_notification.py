#!/usr/bin/env python3
"""Audit retirement of the ordinary ADID legacy reply right and fairplayd's ID 71 handler."""

import argparse
import json
from pathlib import Path
import re
import struct
import subprocess

from audit_adid_legacy_mach_receive import Evidence, cached_image, symbol
from audit_archived_iokit_open_retirement import GUEST_MESSAGE, HOST_RECEIVE, TRACE_SHA
from audit_daemon_adid_mach_fallback import (
    BUFFER, CACHE as DESTINATION_CACHE, END_SUCCESS_RETRY, Fallback, IMAGE,
    INVALID_DEST, LOOKUP_NAME, RECORD, REPLY_NAME, Replay, SOURCE, reference,
)
from audit_daemon_iokit_native_registry import PINNED_DAEMON_SHA, command, digest
from audit_live_fairplay_reply_rights import compiler_ranges
from audit_live_iokit_mach_transport import CACHE_UUID, dyld_uuid
from audit_live_kext_selector26 import Collection, IDENTITIES
from bootpolicy_cache_reader import Cache


NOTIFICATION = 71
DESTROY = 0x100dea0dc
SERVICE_NAME_FIXTURE = 0x6903


def audit_kernel(path):
    image = Collection(path, IDENTITIES[1])
    kernel_uuid = image.entries['com.apple.kernel']['uuid']
    boot_identity = subprocess.check_output(
        ['kmutil', 'inspect', '--show-kernel-uuid-only'], stderr=subprocess.STDOUT
    ).decode().lower()
    assert kernel_uuid in boot_identity
    limits = compiler_ranges(image)
    evidence = Evidence(image.read)
    rows = {}
    for index, name, argc, words, handler in (
        (18, b'_kernelrpc_mach_port_deallocate_trap', 2, 2, 0xfffffe000bd23738),
        (24, b'_kernelrpc_mach_port_construct_trap', 4, 5, 0xfffffe000bd23c98),
        (47, b'mach_msg2_trap', 8, 16, 0xfffffe000bd25630),
    ):
        entry = 0xfffffe0007f07018 + 24 * index
        name_ptr = image.pointer(0xfffffe0007f07c18 + 8 * index)
        func_ptr = image.pointer(entry + 8)
        munger_ptr = image.pointer(entry + 16)
        assert evidence.record(entry, 2) == bytes((argc, words))
        assert evidence.record(int(name_ptr['target'], 16), len(name) + 1) == name + b'\0'
        assert (int(func_ptr['target'], 16), func_ptr['diversity'], func_ptr['auth']) == (handler, '0x307a', 1)
        assert handler in limits and int(munger_ptr['target'], 16) in limits
        rows[-index] = dict(name=name.decode(), argument_count=argc, word_count=words,
                            name_pointer=name_ptr, handler_pointer=func_ptr, munger_pointer=munger_ptr)
    evidence.check((
        (0xfffffe000bebfba4, 'sub', 'x20, x9, w8, sxtw'),
        (0xfffffe000bebfbb0, 'add', 'x8, x20, x20, lsl #1'),
        (0xfffffe000bebfbb4, 'lsl', 'x8, x8, #3'),
        (0xfffffe000bebfbb8, 'adrp', 'x9, #0xfffffe0007f07000'),
        (0xfffffe000bebfbbc, 'add', 'x9, x9, #0x18'),
        (0xfffffe000bebfbd4, 'ldr', 'x22, [x23, #8]'),
        (0xfffffe000bebfcc4, 'mov', 'x17, #0x307a'),
        (0xfffffe000bebfcc8, 'blraa', 'x22, x17'),
        (0xfffffe000bf517e0, 'ldr', 'w8, [x0, #4]'),
        (0xfffffe000bf517e4, 'str', 'x8, [x0, #8]'),
        (0xfffffe000bd23754, 'bl', '#0xfffffe000bd433e4'),
        (0xfffffe000bd2375c, 'ldr', 'x16, [x0, #0x318]'),
        (0xfffffe000bd2376c, 'autda', 'x16, x17'),
        (0xfffffe000bd23790, 'ldr', 'w1, [x19, #8]'),
        (0xfffffe000bd237a0, 'b', '#0xfffffe000bd26434'),
        (0xfffffe000bd26468, 'bl', '#0xfffffe000bd1ae28'),
        (0xfffffe000bd2646c, 'cbnz', 'w0, #0xfffffe000bd264ac'),
        (0xfffffe000bd2648c, 'b', '#0xfffffe000bd1bbf0'),
        (0xfffffe000bd1bc18, 'ldr', 'w23, [x2, #8]'),
        (0xfffffe000bd1bc1c, 'and', 'w8, w23, #0x1f0000'),
        (0xfffffe000bd1bc2c, 'cmp', 'w8, #0x40, lsl #12'),
        (0xfffffe000bd1bc34, 'b.eq', '#0xfffffe000bd1bc90'),
        (0xfffffe000bd1bca0, 'autda', 'x16, x17'),
        (0xfffffe000bd1bd3c, 'bl', '#0xfffffe000bd1b514'),
        (0xfffffe000bd1bd40, 'tbnz', 'w0, #0, #0xfffffe000bd1bdb4'),
        (0xfffffe000bd1bd4c, 'str', 'wzr, [x22, #0xc]'),
        (0xfffffe000bd1b550, 'tst', 'w8, #7'),
        (0xfffffe000bd1b554, 'b.eq', '#0xfffffe000bd1b560'),
        (0xfffffe000bd1b558, 'mov', 'w0, #0'),
        (0xfffffe000bd1beb0, 'bl', '#0xfffffe000bd04c9c'),
        (0xfffffe000bd1beb8, 'bl', '#0xfffffe000bd5323c'),
        (0xfffffe000bd1bebc, 'mov', 'x0, x21'),
        (0xfffffe000bd1bec0, 'bl', '#0xfffffe000bd110f4'),
        (0xfffffe000bd110f8, 'str', 'wzr, [x0, #0x3c]'),
        (0xfffffe000bd11100, 'ands', 'w8, w8, #7'),
        (0xfffffe000bd11104, 'b.eq', '#0xfffffe000bd11144'),
        (0xfffffe000bd11108, 'cmp', 'w8, #2'),
        (0xfffffe000bd1110c, 'b.hi', '#0xfffffe000bd11134'),
        (0xfffffe000bd1112c, 'cmp', 'x16, x8'),
        (0xfffffe000bd11130, 'b.eq', '#0xfffffe000bd111c4'),
        (0xfffffe000bd11134, 'ldrh', 'w8, [x0, #0x38]'),
        (0xfffffe000bd11138, 'mov', 'w9, #0xfffe'),
        (0xfffffe000bd11140, 'b.lo', '#0xfffffe000bd11148'),
        (0xfffffe000bd11144, 'b', '#0xfffffe000bd186a0'),
        (0xfffffe000bd1116c, 'bl', '#0xfffffe000bd52a0c'),
        (0xfffffe000bd11180, 'mov', 'w8, #0x12'),
        (0xfffffe000bd11188, 'str', 'x19, [sp, #8]'),
        (0xfffffe000bd11190, 'ldr', 'd0, [x8, #0xd20]'),
        (0xfffffe000bd11194, 'str', 'd0, [sp, #0x18]'),
        (0xfffffe000bd1119c, 'mov', 'w1, #0x20'),
        (0xfffffe000bd111a4, 'movk', 'w2, #5, lsl #16'),
        (0xfffffe000bd111b0, 'bl', '#0xfffffe000bd3d4d0'),
        (0xfffffe000bd111c4, 'b', '#0xfffffe000bd3d1cc'),
        (0xfffffe000bd3d1e8, 'str', 'w9, [x0, #0x8c]'),
        (0xfffffe000bd186a0, 'pacibsp', ''),
        (0xfffffe000bd3d510, 'bl', '#0xfffffe000bd0e880'),
        (0xfffffe000bd3d520, 'bl', '#0xfffffe000bd0eacc'),
        (0xfffffe000bd3d578, 'bl', '#0xfffffe000bd0effc'),
        (0xfffffe000bd0f1f8, 'add', 'x0, x20, #0x28'),
        (0xfffffe000bd0f208, 'bl', '#0xfffffe000bd0fbf0'),
        (0xfffffe000bd23d24, 'bl', '#0xfffffe000bd27fac'),
        (0xfffffe000bd23d38, 'bl', '#0xfffffe000bec09cc'),
    ))
    assert struct.unpack('<II', evidence.record(0xfffffe000700dd20, 8)) == (0, NOTIFICATION)
    for start in (0xfffffe000bd110f4, 0xfffffe000bd3d1cc, 0xfffffe000bd186a0,
                  0xfffffe000bd3d4d0, 0xfffffe000bd23738, 0xfffffe000bd26434, 0xfffffe000bd1bbf0):
        evidence.record(start, limits[start][1] - start)
    return {'sha256': image.digest, 'uuid': kernel_uuid, 'traps': rows, 'source': evidence.windows}


def audit_library():
    cache = Cache()
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    kernel = cached_image(cache, 'libsystem_kernel.dylib', '780a6c1f-be02-34cc-84dd-00e05f61c89b')
    for name, entry in (
        ('_mach_msg_destroy', 0x180549bbc), ('_mach_port_deallocate', 0x18054a06c),
        ('__kernelrpc_mach_port_deallocate_trap', 0x180548ac8),
        ('__kernelrpc_mach_port_deallocate', 0x18056d928), ('_mig_get_reply_port', 0x180548f00),
        ('_mach_port_construct', 0x180549e9c), ('_mig_put_reply_port', 0x18054e1d8),
    ):
        symbol(kernel, name, entry)
    evidence = Evidence(cache.read)
    evidence.check((
        (0x180549e08, 'b', '#0x18054a06c'),
        (0x18054a084, 'bl', '#0x180548ac8'),
        (0x180548ac8, 'mov', 'x16, #-0x12'),
        (0x180548acc, 'svc', '#0x80'),
        (0x18054a094, 'b.ne', '#0x18054a0bc'),
        (0x18054a0b8, 'b', '#0x18056d928'),
        (0x18056d990, 'mov', 'x4, #0xc8600000000'),
        (0x18056d99c, 'bl', '#0x18055b918'),
        (0x180548f18, 'ldr', 'w0, [x19, #0x10]'),
        (0x180548f20, 'cbnz', 'w0, #0x180548f5c'),
        (0x180548f2c, 'add', 'x8, x8, #0xdc0'),
        (0x180548f4c, 'bl', '#0x180549e9c'),
        (0x180548f58, 'str', 'x0, [x19, #0x10]'),
        (0x180549ec0, 'bl', '#0x180548b10'),
        (0x180548b10, 'mov', 'x16, #-0x18'),
        (0x180548b14, 'svc', '#0x80'),
        (0x18054e1d8, 'ret', ''),
    ))
    assert struct.unpack('<6I', evidence.record(0x18057edc0, 16) + bytes(8)) == (0x1000, 0, 0, 0, 0, 0)
    return {'shared_cache_uuid': cache.uuid, 'libkernel_uuid': kernel.uuid, 'source': evidence.windows}


class NotificationReplay(Fallback):
    def __init__(self, parent, prefix, message_id, retry):
        status = INVALID_DEST if retry else 0
        super().__init__(parent, prefix, ('notification', SERVICE_NAME_FIXTURE, status,
                                         0 if retry else None, 0 if retry else None))
        self.message_id = message_id
        self.destroy = []
        self.reply_helpers = []

    def reply_bytes(self):
        return struct.pack('<6I', 0x1200, 24, 0, REPLY_NAME, 0, self.message_id)

    def code(self, u, pc, size, data):
        if pc == DESTROY:
            assert bytes(u.mem_read(pc, size)) == IMAGE.read(pc, size)
            reply = bytes(u.mem_read(self.reg(0), len(self.reply_bytes())))
            assert reply == self.reply_bytes()
            word = self.reg(21) & 0xffffffff
            status, = struct.unpack('<i', struct.pack('<I', word))
            self.destroy.append({'pc': hex(pc), 'bytes': reply.hex(), 'signed_status': status})
            return self.return_value(pc, None)
        if pc in (0x100de9fe0, 0x100dea044):
            self.reply_helpers.append(hex(pc))
        if pc == END_SUCCESS_RETRY and self.retry_status == 0:
            # This retry returned a transport success with a notification.
            # The earlier audit's stop here assumes a successful 1300 parse.
            return Replay.code(self, u, pc, size, data)
        return super().code(u, pc, size, data)

    def audit_notification(self, retry):
        state = self.run()
        assert self.prefix_rechecked
        assert state['boundary']['pc'] == '0x100701a7c' and self.reg(0) & 0xffffffff == 0xffff5028
        assert len(self.destroy) == 1
        assert self.destroy[0]['signed_status'] == (-308 if self.message_id == NOTIFICATION else -301)
        assert self.frees == [('0x100e24fdc', BUFFER), ('0x100e2507c', RECORD)]
        assert len(self.lookups) == int(retry) and len(self.wire) == 1 + int(retry)
        assert self.reply_helpers == (['0x100de9fe0'] if retry else [])
        cache, = struct.unpack('<I', self.u.mem_read(DESTINATION_CACHE, 4))
        assert cache == (LOOKUP_NAME if retry else SERVICE_NAME_FIXTURE)
        return dict(control=self.caller_configuration, message_id=self.message_id, retry=retry,
                    wrapper_destroy=self.destroy[0], final_w0=hex(self.reg(0) & 0xffffffff),
                    original_visits=len(state['source_visits']), cache=hex(cache),
                    wire=self.wire, lookups=self.lookups, reply_helpers=self.reply_helpers,
                    frees=self.frees, helper_cut=state['boundary']['pc'])


def audit_daemon():
    assert digest(SOURCE.read_bytes()) == PINNED_DAEMON_SHA
    indirect = command('xcrun', 'llvm-objdump', '--macho', '--indirect-symbols', str(SOURCE)).decode()
    assert re.search(r'^0x0000000100e2ab10\s+\d+\s+_mach_msg_destroy$', indirect, flags=re.M)
    evidence = Evidence(IMAGE.read)
    evidence.check((
        (0x100de9f98, 'mov', 'w1, #3'),
        (0x100de9fac, 'bl', '#0x100e2aaf0'),
        (0x100de9ffc, 'cbnz', 'w21, #0x100dea040'),
        (0x100dea000, 'ldr', 'w8, [sp, #0x14]'),
        (0x100dea004, 'cmp', 'w8, #0x47'),
        (0x100dea008, 'b.eq', '#0x100dea060'),
        (0x100dea060, 'mov', 'w21, #-0x134'),
        (0x100dea064, 'b', '#0x100dea0d8'),
        (0x100dea068, 'mov', 'w21, #-0x12d'),
        (DESTROY, 'bl', '#0x100e2ab10'),
    ))
    evidence.record(0x100de9f08, 0x1e8)
    parents = [row for row in reference('daemon_environment_outputs_checks')['cases']
               if row['configuration']['kind'] == 'caller' and row['boundary']['pc'] == '0x100e1ea4c']
    prefixes = [row for row in reference('daemon_adid_request_origin_audit')['cases']
                if row['prefix_rechecked'] and row['request']]
    assert len(parents) == len(prefixes) == 8
    cases = []
    for parent in parents:
        prefix, = (row for row in prefixes if row['configuration'] == parent['configuration'])
        for message_id in (NOTIFICATION, 72):
            for retry in (False, True):
                cases.append(NotificationReplay(parent, prefix, message_id, retry).audit_notification(retry))
    return {'sha256': PINNED_DAEMON_SHA, 'source': evidence.windows, 'cases': cases}


def sdk_audit():
    assertions = b"""
#include <mach/mach.h>
#include <mach/mig_errors.h>
#include <mach/notify.h>
#include <stddef.h>
_Static_assert(MIG_SERVER_DIED == -308, "server died");
_Static_assert(MIG_REPLY_MISMATCH == -301, "different reply ID");
_Static_assert(MACH_NOTIFY_SEND_ONCE == 71, "send-once ID");
_Static_assert(MACH_PORT_TYPE_SEND_ONCE == 0x40000, "namespace type");
_Static_assert(MACH_MSG_TYPE_MOVE_SEND_ONCE == 18, "notification disposition");
_Static_assert(MPO_REPLY_PORT == 0x1000, "reply construction");
_Static_assert(offsetof(mach_send_once_notification_t, trailer) == 24, "header-only notification");
_Static_assert(sizeof(mach_send_once_notification_t) == 44, "notification including format-0 trailer");
"""
    subprocess.run(['xcrun', 'clang', '-x', 'c', '-fsyntax-only', '-'],
                   input=assertions, check=True)
    return assertions.decode().strip().splitlines()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('current_collection', type=Path)
    parser.add_argument('annotated_rax_trace', type=Path)
    args = parser.parse_args()
    assert command('sw_vers', '-buildVersion').decode().strip() == '26C5035r'
    trace = args.annotated_rax_trace.read_bytes()
    assert digest(trace) == TRACE_SHA
    lines = trace.decode().splitlines()
    guest = [int(m[8]) for line in lines if (m := GUEST_MESSAGE.fullmatch(line))]
    host = [int(m[1]) for line in lines if (m := HOST_RECEIVE.search(line))]
    assert guest and host and not {71, 1200, 1300}.intersection(guest + host)
    result = dict(build='26C5035r', kernel=audit_kernel(args.current_collection),
                  library=audit_library(), daemon=audit_daemon(), sdk=sdk_audit(),
                  archived_trace=dict(sha256=TRACE_SHA, guest_count=len(guest), host_receives=len(host)),
                  native_notification_delivery='unknown',
                  scope='Original code and private receive outcomes. No native IPC sent.')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
