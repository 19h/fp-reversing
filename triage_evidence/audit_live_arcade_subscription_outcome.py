#!/usr/bin/env python3
"""Audit the original Arcade upcall request scalar and reply consumer."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

from audit_live_arcade_registration import HANDOFF, SUBSCRIPTION, archive_audit
from audit_live_fairplay_reply_rights import compiler_ranges
from audit_live_kext_selector26 import Collection, IDENTITIES
from audit_live_kext_selector26_transfer import words

TERMINATE = 0xfffffe000bd86d1c
THREAD_TASK = 0xfffffe000bdc68b8


def audit(image, trace):
    anchors = (
        (0xfffffe000bd29988, 'mrs', 'x19, tpidr_el1'),
        (0xfffffe000bd299bc, 'str', 'x8, [sp, #0x10]'),
        (0xfffffe000bd29a20, 'mov', 'w25, #1'),
        (0xfffffe000bd29a88, 'ldr', 'x0, [x22, #0xe18]'),
        (0xfffffe000bd29c2c, 'ldr', 'x27, [x0, #0x18]'),
        (0xfffffe000bd29c54, 'mov', 'x0, x27'),
        (0xfffffe000bd29c94, 'ldr', 'x3, [x27, #0x5a0]'),
        (0xfffffe000bd29c98, 'str', 'w25, [sp, #0x24]'),
        (0xfffffe000bd29ca0, 'add', 'x4, sp, #0x24'),
        (0xfffffe000bd29cb4, 'mov', 'x26, x0'),
        (0xfffffe000bd29cdc, 'mov', 'x0, x28'),
        (0xfffffe000bd29ce4, 'cmn', 'w26, #0x134'),
        (0xfffffe000bd29cf4, 'b.eq', '#0xfffffe000bd29a38'),
        (0xfffffe000bd29cf8, 'mov', 'w8, #3'),
        (0xfffffe000bd29cfc, 'movk', 'w8, #0x1000, lsl #16'),
        (0xfffffe000bd29d00, 'cmp', 'w26, w8'),
        (0xfffffe000bd29d04, 'b.ne', '#0xfffffe000bd29dc4'),
        (0xfffffe000bd29d08, 'mov', 'x0, x27'),
        (0xfffffe000bd29d1c, 'b', '#0xfffffe000bd29a38'),
        (0xfffffe000bd29d5c, 'mov', 'w26, #5'),
        (0xfffffe000bd29d84, 'mov', 'x0, x19'),
        (0xfffffe000bd29dc4, 'cbnz', 'w26, #0xfffffe000bd29d60'),
        (0xfffffe000bd29dc8, 'ldr', 'w8, [sp, #0x24]'),
        (0xfffffe000bd29dcc, 'cmp', 'w8, #1'),
        (0xfffffe000bd29dd0, 'b.eq', '#0xfffffe000bd29d84'),
        (0xfffffe000bd29dd4, 'b', '#0xfffffe000bd29da4'),
        (0xfffffe000bdda2ac, 'mov', 'x19, x4'),
        (0xfffffe000bdda304, 'str', 'x3, [sp, #0x40]'),
        (0xfffffe000bdda318, 'adrp', 'x8, #0xfffffe000700d000'),
        (0xfffffe000bdda31c, 'ldr', 'd0, [x8, #0xee0]'),
        (0xfffffe000bdda320, 'str', 'd0, [sp, #0x18]'),
        (0xfffffe000bdda328, 'mov', 'w1, #0x48'),
        (0xfffffe000bdda32c, 'mov', 'w2, #0x38'),
        (0xfffffe000bdda340, 'cbnz', 'w0, #0xfffffe000bdda3c0'),
        (0xfffffe000bdda344, 'ldr', 'w8, [sp, #0x1c]'),
        (0xfffffe000bdda348, 'cmp', 'w8, #0x47'),
        (0xfffffe000bdda34c, 'b.eq', '#0xfffffe000bdda394'),
        (0xfffffe000bdda350, 'mov', 'w9, #0xf083'),
        (0xfffffe000bdda354, 'cmp', 'w8, w9'),
        (0xfffffe000bdda358, 'b.ne', '#0xfffffe000bdda39c'),
        (0xfffffe000bdda360, 'tbnz', 'w8, #0x1f, #0xfffffe000bdda3ac'),
        (0xfffffe000bdda364, 'ldr', 'w8, [sp, #4]'),
        (0xfffffe000bdda368, 'cmp', 'w8, #0x30'),
        (0xfffffe000bdda36c, 'b.eq', '#0xfffffe000bdda3a4'),
        (0xfffffe000bdda370, 'cmp', 'w8, #0x2c'),
        (0xfffffe000bdda374, 'b.ne', '#0xfffffe000bdda3ac'),
        (0xfffffe000bdda378, 'ldr', 'w8, [sp, #0x28]'),
        (0xfffffe000bdda37c, 'ldr', 'x9, [sp, #8]'),
        (0xfffffe000bdda380, 'cmp', 'x9, #0'),
        (0xfffffe000bdda384, 'ccmp', 'w8, #0, #4, eq'),
        (0xfffffe000bdda388, 'mov', 'w9, #-0x12c'),
        (0xfffffe000bdda38c, 'csel', 'w8, w8, w9, ne'),
        (0xfffffe000bdda394, 'mov', 'w8, #-0x134'),
        (0xfffffe000bdda39c, 'mov', 'w8, #-0x12d'),
        (0xfffffe000bdda3a4, 'ldr', 'x8, [sp, #8]'),
        (0xfffffe000bdda3a8, 'cbz', 'x8, #0xfffffe000bdda3e8'),
        (0xfffffe000bdda3ac, 'mov', 'w8, #-0x12c'),
        (0xfffffe000bdda3e8, 'ldr', 'w8, [sp, #0x28]'),
        (0xfffffe000bdda3ec, 'cbnz', 'w8, #0xfffffe000bdda3b0'),
        (0xfffffe000bdda3f0, 'mov', 'w0, #0'),
        (0xfffffe000bdda3f4, 'ldr', 'w8, [sp, #0x2c]'),
        (0xfffffe000bdda3f8, 'str', 'w8, [x19]'),
        (0xfffffe000bdc6930, 'ldr', 'x0, [x1, #0x28]'),
        (0xfffffe000bd86d34, 'mov', 'x20, x0'),
        (0xfffffe000bd86d38, 'mrs', 'x19, tpidr_el1'),
        (0xfffffe000bd86d4c, 'cmp', 'x20, x0'),
        (0xfffffe000bd86e3c, 'ldclr', 'w9, w8, [x8]'),
        (0xfffffe000bd86e40, 'strb', 'wzr, [x20, #0x14]'),
        (0xfffffe000bd86e50, 'ldr', 'x21, [x24, #0x50]!'),
        (0xfffffe000bd86e64, 'ldr', 'x21, [x21, #0x410]'),
    )
    for pc, opcode, operands in anchors:
        image.instruction(pc, opcode, operands)

    calls = {
        0xfffffe000bd29c28: 0xfffffe000bdc5f78,
        0xfffffe000bd29cb0: SUBSCRIPTION,
        0xfffffe000bd29ce0: image.named('_ipc_port_release_send'),
        0xfffffe000bd29d0c: image.named('_vm_map_copy_discard'),
        0xfffffe000bd29d88: THREAD_TASK,
        0xfffffe000bd29da0: TERMINATE,
        0xfffffe000bdda33c: 0xfffffe000bd3d8d4,
        0xfffffe000bdda3b8: 0xfffffe000bd3dd30,
        0xfffffe000bd86d40: THREAD_TASK,
        0xfffffe000bd86e48: 0xfffffe000bd3ef5c,
        0xfffffe000bd86e60: 0xfffffe000bd9fa44,
        0xfffffe000bd86e74: image.named('_get_bsdtask_info'),
        0xfffffe000bd86e7c: image.named('_proc_pid'),
    }
    for site, target in calls.items():
        assert image.branch(site, 'bl') == target

    literal = 0xfffffe000700dee0
    voucher, request_id = struct.unpack('<II', image.read(literal, 8))
    assert (voucher, request_id) == (0, 61471)
    bounds = compiler_ranges(image)
    functions = {}
    for role, start in {'handoff': HANDOFF, 'subscription_client': SUBSCRIPTION,
                        'current_thread_task': THREAD_TASK, 'task_termination': TERMINATE}.items():
        ordinal, end = bounds[start]
        instructions = words(image, start, end - start)
        assert len(instructions) * 4 == end - start
        functions[role] = {'start': hex(start), 'end_exclusive': hex(end), 'ordinal': ordinal,
                           'sha256': sha256(image.read(start, end - start)).hexdigest(),
                           'instructions': instructions}

    return {'identity': IDENTITIES[1], 'fileset_sha256': sha256(image.data).hexdigest(),
            'request_literal': hex(literal), 'request_id': request_id, 'reply_id': request_id + 100,
            'instruction_assertions': len(anchors), 'functions': functions,
            'direct_calls': {hex(site): hex(target) for site, target in calls.items()},
            'archived_trace': archive_audit(trace), 'native_exchange_observed': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('annotated_trace', type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(Collection(args.collection, IDENTITIES[1]), args.annotated_trace), indent=2))
