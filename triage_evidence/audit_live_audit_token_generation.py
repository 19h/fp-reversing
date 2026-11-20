#!/usr/bin/env python3
"""Recover the task token's installed kernel path and check exec generation changes."""

import argparse
import ctypes as C
import errno
import json
import os
from pathlib import Path
import select
import struct
import subprocess
import sys

from audit_live_adid_peer_entitlement import (
    AuditToken, TASK_AUDIT_TOKEN, TOKEN_WORDS, TaskQuery, bind, checked_instructions,
)
from audit_live_arcade_registration_reply import rebuild_registry
from audit_live_fairplay_client_entitlements import BUILD, CS_OPS_CDHASH, CS_OPS_STATUS, identity, process
from audit_live_kext_selector26 import Collection, IDENTITIES

MACH_TABLE = 0xfffffe0007f07018
MACH_NAMES = 0xfffffe0007f07c18
BSD_TABLE = 0xfffffe0007f39230
BSD_NAMES = 0xfffffe000cb1b0e8
TASK_INFO = 3405
CAT = '/bin/cat'


def table_row(image, index, name, table, name_table, mach=False):
    row = table + 24 * index
    name_pointer = image.pointer(name_table + 8 * index)
    expected = name.encode() + b'\0'
    assert image.read(int(name_pointer['target'], 16), len(expected)) == expected
    pointer = image.pointer(row + (8 if mach else 0))
    assert (pointer['auth'], pointer['key'], pointer['diversity']) == (
        1, 0, '0x307a' if mach else '0xbcad')
    return {'index': index, 'name': name, 'handler': pointer,
            'record_bytes': image.read(row, 24).hex(), 'name_pointer': name_pointer}


def switch_target(image, table, base, index):
    displacement, = struct.unpack('<i', image.read(table + 4 * index, 4))
    return base + displacement


def kernel_route(collection):
    image = Collection(collection, IDENTITIES[1])
    mach = table_row(image, 44, 'task_name_for_pid', MACH_TABLE, MACH_NAMES, mach=True)
    plain = table_row(image, 169, 'csops', BSD_TABLE, BSD_NAMES)
    qualified = table_row(image, 170, 'csops_audittoken', BSD_TABLE, BSD_NAMES)
    assert [row['handler']['target'] for row in (mach, plain, qualified)] == [
        '0xfffffe000c312f60', '0xfffffe000c30e510', '0xfffffe000c30f25c']
    assert struct.unpack('<3B', bytes.fromhex(mach['record_bytes'])[:3]) == (3, 3, 0)
    assert struct.unpack('<IhH', bytes.fromhex(plain['record_bytes'])[16:]) == (1, 4, 16)
    assert struct.unpack('<IhH', bytes.fromhex(qualified['record_bytes'])[16:]) == (1, 5, 20)

    registry = rebuild_registry(image)
    task, = (row for row in registry['subsystems'] if row['start'] <= TASK_INFO < row['end_exclusive'])
    subsystem = int(task['pointer']['target'], 16)
    assert (subsystem, task['start'], task['end_exclusive']) == (0xfffffe0007e74bf8, 3400, 3466)
    routine_offset = 40 + (TASK_INFO - task['start']) * 32
    routine = image.pointer(subsystem + routine_offset)
    assert (routine['target'], routine['auth'], routine['diversity']) == ('0xfffffe000bddf07c', 1, '0x3a83')
    reply_descriptors, max_reply = struct.unpack('<II', image.read(subsystem + routine_offset + 16, 8))
    assert (reply_descriptors, max_reply) == (0, 424)
    assert switch_target(image, 0xfffffe000bd911c4, 0xfffffe000bd8fcbc, TASK_AUDIT_TOKEN - 1) == 0xfffffe000bd9048c
    assert switch_target(image, 0xfffffe000c30f168, 0xfffffe000c30e92c, 0) == 0xfffffe000c30ea50
    assert switch_target(image, 0xfffffe000c30f168, 0xfffffe000c30e92c, 16) == 0xfffffe000c30ed44
    assert image.named('_copyin') == 0xfffffe000bebfe58
    assert image.named('_copyout') == 0xfffffe000bec09cc
    assert image.named('_proc_find') == 0xfffffe000c3076b4
    assert image.named('_proc_pidversion') == 0xfffffe000c30812c

    instructions = checked_instructions(image.read, (
        (0xfffffe000bf4503c, 'adrp x8, #0xfffffe0007f07000'),
        (0xfffffe000bf45040, 'add x8, x8, #0x18'),
        (0xfffffe000bf45048, 'ldr x8, [x1, #8]!'),
        (0xfffffe000c48a954, 'adrp x9, #0xfffffe0007f39000'),
        (0xfffffe000c48a958, 'add x9, x9, #0x230'),
        (0xfffffe000c48a95c, 'add x23, x9, x8, lsl #3'),
        (0xfffffe000c48ab0c, 'mov x17, #0xbcad'), (0xfffffe000c48ab10, 'blraa x8, x17'),
        (0xfffffe000c312f84, 'ldr w0, [x0]'), (0xfffffe000c312f88, 'ldr w20, [x8, #8]'),
        (0xfffffe000c312f8c, 'ldr x19, [x8, #0x10]'), (0xfffffe000c312fd4, 'bl #0xfffffe000c3076b4'),
        (0xfffffe000c313168, 'mov w2, #3'), (0xfffffe000c31316c, 'bl #0xfffffe000c63fd84'),
        (0xfffffe000c3131b4, 'mov w1, #3'), (0xfffffe000c3131bc, 'bl #0xfffffe000bd41a4c'),
        (0xfffffe000c313264, 'bl #0xfffffe000bd11bd8'), (0xfffffe000c313208, 'bl #0xfffffe000bec09cc'),
        (0xfffffe000bd3c678, 'add w8, w8, #0x64'), (0xfffffe000bd3c724, 'blraa x8, x17'),
        (0xfffffe000bddf08c, 'cmp w8, #0x30'), (0xfffffe000bddf0bc, 'ldr w9, [x1, #0xc]'),
        (0xfffffe000bddf0c4, 'csel w8, w9, w8, lo'), (0xfffffe000bddf0cc, 'ldr x0, [x0, #8]'),
        (0xfffffe000bddf0d0, 'ldr w1, [x1, #8]'), (0xfffffe000bddf0dc, 'bl #0xfffffe000bd917c4'),
        (0xfffffe000bddf128, 'add w8, w8, #0x30'), (0xfffffe000bddf12c, 'str w8, [x20, #4]'),
        (0xfffffe000bd91818, 'mov w2, #0xc'), (0xfffffe000bd91820, 'bl #0xfffffe000bd41ef4'),
        (0xfffffe000bd91834, 'bl #0xfffffe000bd8fbec'), (0xfffffe000bd8fc94, 'sub w16, w23, #1'),
        (0xfffffe000bd8fcb8, 'ldrsw x16, [x17, x16, lsl #2]'),
        (0xfffffe000bd90494, 'cmp w8, #8'), (0xfffffe000bd904a4, 'bl #0xfffffe000bd912a8'),
        (0xfffffe000bd9090c, 'mov w8, #8'),
        (0xfffffe000bd912ac, 'ldr x16, [x0, #0x320]'), (0xfffffe000bd912bc, 'autda x16, x17'),
        (0xfffffe000bd912e0, 'ldr w8, [x16, #0x18]'), (0xfffffe000bd912e4, 'str w8, [x1, #0x14]'),
        (0xfffffe000bd912f0, 'ldr w8, [x16, #0x1c]'), (0xfffffe000bd912f4, 'str w8, [x1, #0x1c]'),
        (0xfffffe000bd0f208, 'bl #0xfffffe000bd0fbf0'),
        (0xfffffe000c30e524, 'mov x4, #0'), (0xfffffe000c30e528, 'b #0xfffffe000c30e52c'),
        (0xfffffe000c30f260, 'ldr x4, [x1, #0x20]'), (0xfffffe000c30f264, 'cbz x4, #0xfffffe000c30f27c'),
        (0xfffffe000c30f278, 'b #0xfffffe000c30e52c'), (0xfffffe000c30f27c, 'mov w0, #0x16'),
        (0xfffffe000c30e5fc, 'bl #0xfffffe000c3076b4'), (0xfffffe000c30e618, 'ldr w21, [x19, #0x60]'),
        (0xfffffe000c30e638, 'ldr x1, [x19, #0x18]'), (0xfffffe000c3081a4, 'ldr w0, [x1, #0x18]'),
        (0xfffffe000c30e6bc, 'ldr w28, [x1, #0x18]'), (0xfffffe000c30e6c8, 'mov w2, #0x20'),
        (0xfffffe000c30e6cc, 'bl #0xfffffe000bebfe58'), (0xfffffe000c30e6d4, 'ldr w8, [sp, #0x54]'),
        (0xfffffe000c30e6d8, 'mov w26, #3'), (0xfffffe000c30e6dc, 'cmp w8, w21'),
        (0xfffffe000c30e6e0, 'b.ne #0xfffffe000c30e738'), (0xfffffe000c30e6e4, 'ldr w8, [sp, #0x5c]'),
        (0xfffffe000c30e6e8, 'cmp w8, w28'), (0xfffffe000c30e6f8, 'b.ne #0xfffffe000c30e738'),
        (0xfffffe000c30e72c, 'bl #0xfffffe000c642f30'), (0xfffffe000c30e93c, 'cmp x27, #8'),
        (0xfffffe000c30ed78, 'bl #0xfffffe000c367558'), (0xfffffe000c30ed98, 'bl #0xfffffe000c30f1b4'),
    ))
    return {
        'collection_sha256': image.digest, 'kernel_uuid': IDENTITIES[1][1], 'instructions': instructions,
        'mach_row_44': mach, 'bsd_rows': [plain, qualified], 'task_subsystem': task,
        'task_info': {'request_id': TASK_INFO, 'reply_id': TASK_INFO + 100, 'routine': routine,
                      'maximum_internal_reply_bytes': max_reply, 'reply_descriptors': reply_descriptors},
    }


def task_token(query, pid):
    name = C.c_uint32()
    status = query.name_for_pid(query.self_port, pid, C.byref(name))
    assert status == 0 and name.value
    token, count = AuditToken(), C.c_uint32(TOKEN_WORDS)
    try:
        status = query.task_info(name.value, TASK_AUDIT_TOKEN, C.byref(token), C.byref(count))
        assert status == 0 and count.value == TOKEN_WORDS and token.words[5] == pid
    finally:
        status = query.deallocate(query.self_port, name.value)
        assert status == 0
    return token


def queries(syscall, pid, token, wanted, matches):
    result = {}
    for selector, fmt, key in ((CS_OPS_STATUS, '<I', 'status_flags'), (CS_OPS_CDHASH, '20s', 'cdhash')):
        fill = b'\xa5' * struct.calcsize(fmt)
        buffer = C.create_string_buffer(fill, len(fill))
        C.set_errno(0)
        status = syscall(pid, selector, buffer, len(buffer), C.byref(token))
        observed = (status, C.get_errno())
        if matches:
            assert observed == (0, 0)
            value, = struct.unpack(fmt, buffer.raw)
            assert (value.hex() if isinstance(value, bytes) else hex(value)) == wanted[key]
        else:
            assert observed == (-1, errno.ESRCH) and buffer.raw == fill
        result[key] = {'return': observed[0], 'errno': observed[1], 'output_width_bytes': len(buffer),
                       'unchanged': buffer.raw == fill}
    return result


CHILD = '''
import os
import sys

os.write(1, b'before\\n')
assert os.read(0, 1) == b'x'
if sys.argv[1] == 'same':
    action = 'import os; os.write(1, os.read(0, 6)); os.read(0, 1)'
    os.execv(sys.executable, [sys.executable, '-B', '-c', action])
os.execv(sys.argv[2], [sys.argv[2]])
'''


def read_marker(pipe, expected):
    observed = bytearray()
    while len(observed) < len(expected):
        assert select.select([pipe], [], [], 5)[0], 'Timed out waiting for the controlled child'
        part = os.read(pipe.fileno(), len(expected) - len(observed))
        assert part, 'The controlled child exited before producing its marker'
        observed.extend(part)
    assert observed == expected


def exec_observation(mode):
    system = C.CDLL(None, use_errno=True)
    syscall = bind(system, 'csops_audittoken', C.c_int, C.c_int, C.c_uint, C.c_void_p,
                   C.c_size_t, C.POINTER(AuditToken))
    query = TaskQuery()
    with subprocess.Popen([sys.executable, '-B', '-c', CHILD, mode, CAT], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, bufsize=0) as child:
        pid = child.pid
        read_marker(child.stdout, b'before\n')
        before = identity(pid)
        _, initial_uid, initial_executable = process(pid)
        assert initial_uid == os.geteuid() and initial_executable == process(os.getpid())[2]
        before_token = task_token(query, pid)
        initial = queries(syscall, pid, before_token, before, matches=True)
        child.stdin.write(b'xafter\n')
        read_marker(child.stdout, b'after\n')
        after = identity(pid)
        _, uid, executable = process(pid)
        assert child.poll() is None and uid == os.geteuid()
        if mode == 'same':
            assert executable == initial_executable
        else:
            assert executable.name == Path(CAT).name
            signing = subprocess.check_output(['codesign', '-d', '--arch', 'arm64e', '--verbose=4', CAT],
                                             stderr=subprocess.STDOUT, text=True)
            assert f"CDHash={after['cdhash']}" in signing.splitlines()
        assert (before['cdhash'] == after['cdhash']) == (mode == 'same')
        after_token = task_token(query, pid)
        assert before_token.words[:7] == after_token.words[:7]
        assert before_token.words[7] != after_token.words[7]
        stale = queries(syscall, pid, before_token, after, matches=False)
        fresh = queries(syscall, pid, after_token, after, matches=True)
        assert after == identity(pid)
        child.stdin.close()
        assert child.wait(timeout=5) == 0
    return {'same_executable': mode == 'same', 'cdhash_changed': before['cdhash'] != after['cdhash'],
            'only_token_word_7_changed': True, 'before_exec': initial,
            'after_exec_with_original_token': stale, 'after_exec_with_current_token': fresh}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    args = parser.parse_args()
    assert os.geteuid() != 0
    assert subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip() == BUILD
    assert subprocess.check_output(['sysctl', '-n', 'kern.uuid'], text=True).strip().lower() == IDENTITIES[1][1]
    result = {'build': BUILD, 'kernel': kernel_route(args.collection),
              'exec_observations': [exec_observation('same'), exec_observation('different')]}
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
