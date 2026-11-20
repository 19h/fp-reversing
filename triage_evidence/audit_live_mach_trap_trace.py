#!/usr/bin/env python3
"""Audit the installed Mach trap trace ABI and compare retained IOKit controls."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess

from audit_live_adid_peer_entitlement import checked_instructions
from audit_live_audit_token_generation import MACH_NAMES, MACH_TABLE, table_row
from audit_live_iokit_open_owner import BUILD
from audit_live_kext_selector26 import Collection, IDENTITIES


TRAP_INDEX = 47
BASE_EVENT = 0x010c0000
TRANSPORT_CONTROL = Path(__file__).with_name('live_iokit_mach_headers_audit.json.zst')

CHECKS = {
    'trap_index_and_argument_copy': (
        (0xfffffe000bec606c, 'bl #0xfffffe000bebfb50'),
        (0xfffffe000bebfb94, 'ldr w8, [x19, #0x88]'),
        (0xfffffe000bebfba4, 'sub x20, x9, w8, sxtw'),
        (0xfffffe000bebfbb0, 'add x8, x20, x20, lsl #1'),
        (0xfffffe000bebfbb4, 'lsl x8, x8, #3'),
        (0xfffffe000bebfbb8, 'adrp x9, #0xfffffe0007f07000'),
        (0xfffffe000bebfbbc, 'add x9, x9, #0x18'),
        (0xfffffe000bebfbc4, 'add x23, x9, w8, sxtw'),
        (0xfffffe000bebfbd4, 'ldr x22, [x23, #8]'),
        (0xfffffe000bebfbf0, 'ldrb w8, [x23]'),
        (0xfffffe000bebfc28, 'lsl x2, x8, #3'),
        (0xfffffe000bebfc2c, 'add x0, sp, #0x20'),
        (0xfffffe000bebfc30, 'add x1, x19, #8'),
        (0xfffffe000bebfc34, 'bl #0xfffffe000c697810'),
    ),
    'trap_entry_and_exit_records': (
        (0xfffffe000bebfc7c, 'adrp x24, #0xfffffe000cbd8000'),
        (0xfffffe000bebfc80, 'ldrb w8, [x24, #0x758]'),
        (0xfffffe000bebfc84, 'tbnz w8, #0, #0xfffffe000bebfd14'),
        (0xfffffe000bebfd14, 'mov w0, #1'),
        (0xfffffe000bebfd18, 'movk w0, #0x10c, lsl #16'),
        (0xfffffe000bebfd1c, 'bfi w0, w20, #2, #0xe'),
        (0xfffffe000bebfd20, 'ldp x1, x2, [sp, #0x20]'),
        (0xfffffe000bebfd24, 'ldp x3, x4, [sp, #0x30]'),
        (0xfffffe000bebfd28, 'bl #0xfffffe000c2b75a4'),
        (0xfffffe000bebfd2c, 'b #0xfffffe000bebfc88'),
        (0xfffffe000bebfcc0, 'add x0, sp, #0x20'),
        (0xfffffe000bebfcc4, 'mov x17, #0x307a'),
        (0xfffffe000bebfcc8, 'blraa x22, x17'),
        (0xfffffe000bebfccc, 'mov x21, x0'),
        (0xfffffe000bebfcd4, 'tbnz w8, #0, #0xfffffe000bebfd58'),
        (0xfffffe000bebfd58, 'mov w8, #1'),
        (0xfffffe000bebfd5c, 'movk w8, #0x10c, lsl #16'),
        (0xfffffe000bebfd60, 'bfi w8, w20, #2, #0xe'),
        (0xfffffe000bebfd64, 'sxtw x1, w21'),
        (0xfffffe000bebfd68, 'add w0, w8, #1'),
        (0xfffffe000bebfd6c, 'mov x2, #0'),
        (0xfffffe000bebfd70, 'mov x3, #0'),
        (0xfffffe000bebfd74, 'mov x4, #0'),
        (0xfffffe000bebfd78, 'bl #0xfffffe000c2b75a4'),
    ),
    'mach_msg2_packed_fields': (
        (0xfffffe000bd25668, 'ldp x24, x25, [x0, #0x10]'),
        (0xfffffe000bd2566c, 'ldp x20, x8, [x0, #0x20]'),
        (0xfffffe000bd2587c, 'lsr x10, x25, #0x20'),
        (0xfffffe000bd25880, 'stp w25, w10, [sp, #0x38]'),
        (0xfffffe000bd25884, 'lsr x10, x20, #0x20'),
        (0xfffffe000bd25888, 'stp w20, w10, [sp, #0x40]'),
        (0xfffffe000bd2596c, 'lsr x7, x8, #0x20'),
        (0xfffffe000bd25980, 'bl #0xfffffe000bd253d8'),
    ),
    'mach_receive_continuation': (
        (0xfffffe000bd25034, 'bl #0xfffffe000bd24b70'),
        (0xfffffe000bd25038, 'bl #0xfffffe000bec9a0c'),
        (0xfffffe000bd255fc, 'b #0xfffffe000bd24b70'),
        (0xfffffe000bec9a2c, 'sxtw x8, w0'),
        (0xfffffe000bec9a30, 'str x8, [x16, #8]'),
        (0xfffffe000bec9a54, 'ldr w9, [x16, #0x88]'),
        (0xfffffe000bec9a58, 'tbnz w8, #0, #0xfffffe000bec9a60'),
        (0xfffffe000bec9a60, 'neg w8, w9, lsl #2'),
        (0xfffffe000bec9a64, 'and w8, w8, #0xfffc'),
        (0xfffffe000bec9a68, 'mov w9, #2'),
        (0xfffffe000bec9a6c, 'movk w9, #0x10c, lsl #16'),
        (0xfffffe000bec9a70, 'mov w1, w0'),
        (0xfffffe000bec9a74, 'orr w0, w8, w9'),
        (0xfffffe000bec9a78, 'mov x2, #0'),
        (0xfffffe000bec9a7c, 'mov x3, #0'),
        (0xfffffe000bec9a80, 'mov x4, #0'),
        (0xfffffe000bec9a84, 'bl #0xfffffe000c2b75a4'),
    ),
    'trace_thread_identity': (
        (0xfffffe000c2b75a8, 'mrs x8, tpidr_el1'),
        (0xfffffe000c2b75b0, 'ldr x5, [x8, #0x510]'),
        (0xfffffe000c2b75b4, 'mov x6, #0'),
        (0xfffffe000c2b75b8, 'b #0xfffffe000c2b8178'),
    ),
}


def check_trace_decoder():
    environment = {**os.environ, 'LC_ALL': 'C'}
    begin = BASE_EVENT | (TRAP_INDEX << 2) | 1
    end = BASE_EVENT | (TRAP_INDEX << 2) | 2
    assert (begin, end) == (0x010c00bd, 0x010c00be)
    decoded = subprocess.check_output(['/usr/bin/ktrace', 'decode', hex(begin), hex(end)],
                                      text=True, env=environment)
    fields = re.findall(r'^\s*debugid: (0x[\da-f]+) \(([^)]+)\)\n.*?^function: (\w+)',
                        decoded, re.M | re.S)
    assert [(int(code, 16), name, phase) for code, name, phase in fields] == [
        (begin, 'MSC_mach_msg2_trap', 'start'), (end, 'MSC_mach_msg2_trap', 'end')]
    state = subprocess.run(['/usr/bin/ktrace', 'info'], capture_output=True, text=True,
                           check=False, env=environment)
    return {'records': fields, 'ktrace_info_exit_status': state.returncode,
            'ktrace_info_errmsg_eremote': 'Too many levels of remote in path' in state.stderr}


def check_transport_control():
    raw = subprocess.check_output(['zstd', '-dcq', TRANSPORT_CONTROL])
    captured = json.loads(raw)
    assert (captured['build'], captured['kernel_uuid'].lower()) == (BUILD, IDENTITIES[1][1])
    records = []
    for exchange in captured['exchanges']:
        request = exchange['request']
        reply = exchange['reply']
        assert len(bytes.fromhex(exchange['request_bytes'])) == request['size_bytes']
        assert len(bytes.fromhex(exchange['reply_bytes'])) == reply['size_bytes']
        # Read the two original contiguous u32 pairs as LP64 event arguments.
        size_and_bits, names = struct.unpack_from('<QQ', bytes.fromhex(exchange['request_bytes']))
        mask = (1 << 32) - 1
        assert (size_and_bits & mask, size_and_bits >> 32) == (request['bits'], request['size_bytes'])
        assert (names & mask, names >> 32) == (request['remote'], request['local'])
        options = int(exchange['options'], 16)
        assert options & 3 == 3
        assert request['local'] == reply['local']
        assert request['id'] + 100 == reply['id'] and exchange['transport_result'] == 0
        records.append({'operation': exchange['operation'], 'request_id_from_buffer': request['id'],
                        'reply_id_from_buffer': reply['id'], 'arg2_options': hex(options),
                        'arg3_size_and_bits': hex(size_and_bits), 'arg4_names': hex(names),
                        'arg1_exit_transport_result': exchange['transport_result']})
    assert [record['request_id_from_buffer'] for record in records] == [205, 2877, 2881, 2802, 2862]
    reply = bytes.fromhex(captured['exchanges'][-1]['reply_bytes'])
    connection, = struct.unpack_from('<I', reply, 28)
    application_status, = struct.unpack_from('<I', reply, 48)
    assert (connection, application_status) == (0, 0xe00002c2)
    return {'receipt_payload_sha256': hashlib.sha256(raw).hexdigest(),
            'derived_from_prior_control_headers': records, 'open_connection': connection,
            'open_application_status': hex(application_status)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    args = parser.parse_args()
    assert subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip() == BUILD
    assert subprocess.check_output(['sysctl', '-n', 'kern.uuid'], text=True).strip().lower() == IDENTITIES[1][1]
    image = Collection(args.collection, IDENTITIES[1])
    trap = table_row(image, TRAP_INDEX, 'mach_msg2_trap', MACH_TABLE, MACH_NAMES, mach=True)
    assert (trap['handler']['target'], bytes.fromhex(trap['record_bytes'])[:3]) == (
        '0xfffffe000bd25630', b'\x08\x10\x00')
    assert image.named('_kernel_debug') == 0xfffffe000c2b75a4
    assert image.named('_kdebug_enable') == 0xfffffe000cbd8758
    receipt = {'macos_build': BUILD, 'collection_sha256': image.digest,
               'kernel_uuid': IDENTITIES[1][1], 'trap_record': trap,
               'instruction_checks': {name: checked_instructions(image.read, checks)
                                      for name, checks in CHECKS.items()},
               'decoder_and_status': check_trace_decoder(),
               'prior_native_control': check_transport_control()}
    print(json.dumps(receipt, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
