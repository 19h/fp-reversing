#!/usr/bin/env python3
"""Audit the archived check-in voucher and its installed library producers."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import struct
import subprocess

from audit_adid_legacy_mach_receive import Evidence, cached_image, symbol, veneer
from audit_archived_iokit_open_retirement import (
    GUEST_MESSAGE, HOST_SEND, RAX_COMMIT, TRACE_SHA, decode_guest, verified_record,
)
from audit_live_iokit_mach_transport import CACHE_UUID, clean_pointer, dyld_uuid
from bootpolicy_cache_reader import CS, Cache


def archive(path):
    raw = path.read_bytes()
    assert sha256(raw).hexdigest() == TRACE_SHA
    lines = raw.decode().splitlines()
    assert len(lines) == 1748
    req, request = decode_guest(lines, 1489, 'send', (0x1513, 40, 0xc03, 0x507, 0, 412))
    rep, reply = decode_guest(lines, 1494, 'received', (0x1200, 36, 0, 0x507, 0, 512))
    assert struct.unpack_from('<ii', request, 32) == (-1, 1)
    assert struct.unpack_from('<i', reply, 32) == (4,)
    assert not rep['descriptors']
    thread = req['thread']
    assert lines[1487] == f'[{thread}] pc=0x180547b54 host_self_trap() = 0xc03'
    assert lines[1492] == f'[{thread}] mig host_get_special_port(412) = KERN_INVALID_ARGUMENT'
    assert lines[1497] == (
        f'[{thread}] pc=0x180547c20 mach_msg2_trap(0x16fdfce70, 0x200000003, '
        '0x2800001513, 0x50700000c03, 0x19c00000000, 0x50700000000, 48, 0) = 0x0'
    )
    creation = re.fullmatch(
        rf'\[{thread}\] pc=0x180547cb0 host_create_mach_voucher_trap'
        r'\(3075, (0x[0-9a-f]+), 16, (0x[0-9a-f]+)\) = 0x0', lines[1498],
    )
    assert creation and creation.groups() == ('0x185550970', '0x16fdfcf3c')
    assert 3075 == int(req['remote'], 16)
    assert [n for n, line in enumerate(lines, 1) if 'host_create_mach_voucher_trap(' in line] == [1499]
    checkins = []
    for start, width, name in (
        (1500, 172, 'com.apple.unfreed'), (1541, 172, 'com.apple.fairplayd'),
        (1575, 168, 'com.apple.fpsd'), (1609, 176, 'com.apple.arcade.fpsd'),
        (1643, 172, 'com.apple.fpsd.sim'),
    ):
        sent, body = decode_guest(lines, start, 'send', (0x80131513, width, 0x707, 0xb03, 0xd03, 0x400000ce))
        received, incoming = decode_guest(lines, start + 16, 'received', (0x80001200, 72, 0, 0xb03, 0, 0x20000000))
        assert sent['thread'] == received['thread'] == thread
        assert sent['descriptors'] == [{'kind': 'port', 'offset': 28, 'name': '0x707', 'disposition': 19}]
        assert len(received['descriptors']) == 1 and received['descriptors'][0]['disposition'] == 16
        assert name.encode() + b'\0' in body[40:]
        host_send = verified_record(lines, start + 13, HOST_SEND,
                                    ('1073742030', str(width), '1', '0x400000000', '0x80b', '0xc03', '0x0'))
        checkins.append({'service': name, 'guest_send': sent, 'guest_reply': received,
                         'guest_voucher': hex(struct.unpack_from('<I', body, 16)[0]),
                         'guest_reply_voucher': hex(struct.unpack_from('<I', incoming, 16)[0]),
                         'host_send_annotation': host_send})
    all_vouchers = [n for n, line in enumerate(lines, 1)
                    if (match := GUEST_MESSAGE.fullmatch(line)) and int(match[7], 16)]
    assert all_vouchers == [row['guest_send']['line'] for row in checkins]
    return {'sha256': TRACE_SHA, 'lookup': [req, rep], 'voucher_trap': lines[1498], 'checkins': checkins}


def cache_contract():
    cache = Cache()
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    xpc = cached_image(cache, 'libxpc.dylib', '94e40b03-44c5-3636-aa1a-c64a5d6b6bbb')
    dispatch = cached_image(cache, 'libdispatch.dylib', '435a06f9-1bc8-3282-8663-b6418c44a05e')
    kernel = cached_image(cache, 'libsystem_kernel.dylib', '780a6c1f-be02-34cc-84dd-00e05f61c89b')
    evidence = Evidence(cache.read)
    functions = {}
    for image, names in (
        (xpc, {0x184be84d8: '__xpc_pipe_routine', 0x184be925c: '__xpc_pipe_mach_msg'}),
        (dispatch, {0x1855b9c3c: '__dispatch_get_mach_host_port', 0x1855b9c74: '__dispatch_mach_host_port_init',
                    0x1855bb6d8: '__voucher_task_mach_voucher_init', 0x1855bc9a0: '_voucher_mach_msg_set',
                    0x1855bcc4c: '__voucher_init'}),
        (kernel, {0x180549a54: '_host_get_special_port', 0x180549e0c: '_host_create_mach_voucher'}),
    ):
        for address, name in names.items():
            symbol(image, name, address)
            functions[hex(address)] = {'name': name, **image.function(address)}
    bindings = {}
    for pc, branch, stub, name, target in (
        (0x184be8610, 'bl', 0x18806d470, '_voucher_mach_msg_set', 0x180549a34),
        (0x184be9290, 'bl', 0x18806d230, '_mach_msg', 0x180548f94),
        (0x1855b9c8c, 'bl', 0x18806cf20, '_mach_host_self', 0x180549a50),
        (0x1855b9ca0, 'bl', 0x188079b00, '_host_get_special_port', 0x180549a54),
        (0x1855b9cc8, 'bl', 0x18806cf40, '_mach_port_deallocate', 0x18054a06c),
        (0x1855bb700, 'bl', 0x18808c610, '_host_create_mach_voucher', 0x180549e0c),
        (0x1855bcc54, 'b', 0x18808c490, '___libkernel_voucher_init', 0x180549154),
    ):
        evidence.check([(pc, branch, f'#{stub:#x}')])
        bindings[hex(pc)] = veneer(cache, evidence, stub, kernel, name, target)

    evidence.check([
        (0x184be85b4, 'mov', 'x24, x0'),
        (0x184be8668, 'mov', 'x1, x26'),
        (0x184be8678, 'bl', '#0x184be925c'),
        (0x180549154, 'adrp', 'x8, #0x1ed902000'),
        (0x180549158, 'str', 'x0, [x8, #0x898]'),
        (0x180549a38, 'ldr', 'x8, [x8, #0x898]'),
        (0x180549a3c, 'ldr', 'x1, [x8, #8]'),
        (0x180549a40, 'cbz', 'x1, #0x180549a48'),
        (0x180549a44, 'braaz', 'x1'),
        (0x1855bcc4c, 'adrp', 'x0, #0x1e24a7000'),
        (0x1855bcc50, 'add', 'x0, x0, #0x4d0'),
        (0x1855bc9d0, 'cbz', 'x0, #0x1855bc9dc'),
        (0x1855bc9ec, 'b.ne', '#0x1855bca3c'),
        (0x1855bca3c, 'bl', '#0x1855d04d4'),
        (0x1855d04d8, 'add', 'x0, x0, #0x928'),
        (0x1855d04dc, 'adrp', 'x16, #0x1855bb000'),
        (0x1855d04e0, 'add', 'x16, x16, #0x6d8'),
        (0x1855d04e4, 'paciza', 'x16'),
        (0x1855d04e8, 'b', '#0x1855a922c'),
        (0x1855a9234, 'b', '#0x18559859c'),
        (0x1855bb6e8, 'bl', '#0x1855b9c3c'),
        (0x1855b9c64, 'bl', '#0x1855cfc80'),
        (0x1855cfc88, 'adrp', 'x16, #0x1855b9000'),
        (0x1855cfc8c, 'add', 'x16, x16, #0xc74'),
        (0x1855cfc94, 'b', '#0x1855a922c'),
        (0x1855b9c90, 'mov', 'x19, x0'),
        (0x1855b9c94, 'add', 'x3, sp, #0xc'),
        (0x1855b9c98, 'mov', 'w1, #-1'),
        (0x1855b9c9c, 'mov', 'w2, #1'),
        (0x1855b9cb4, 'cbnz', 'w0, #0x1855b9cf8'),
        (0x1855b9cd8, 'ldr', 'w19, [sp, #0xc]'),
        (0x1855b9cdc, 'cbz', 'w19, #0x1855b9d10'),
        (0x1855b9ce4, 'str', 'w19, [x8, #0xb00]'),
        (0x1855b9cf8, 'cmp', 'w20, #4'),
        (0x1855b9cfc, 'b.eq', '#0x1855b9cdc'),
        (0x1855b9d08, 'bl', '#0x1855ca2f8'),
        (0x1855b9d14, 'bl', '#0x1855cfc98'),
        (0x1855cfcbc, 'brk', '#1'),
        (0x1855cb480, 'brk', '#1'),
        (0x180549a50, 'b', '#0x180548b4c'),
        (0x180548b50, 'svc', '#0x80'),
        (0x180549a80, 'stp', 'w1, w2, [sp, #0x20]'),
        (0x180549acc, 'bl', '#0x18055b918'),
        (0x180548c1c, 'svc', '#0x80'),
        (0x180549b24, 'ldr', 'w8, [sp, #0x20]'),
        (0x180549b34, 'cmp', 'w9, #0'),
        (0x180549b38, 'csel', 'w20, w8, w20, eq'),
        (0x180549b94, 'str', 'w8, [x19]'),
        (0x1855b9c50, 'ldr', 'w0, [x8, #0xb00]'),
        (0x1855bb6f0, 'adrp', 'x1, #0x1855d2000'),
        (0x1855bb6f4, 'add', 'x1, x1, #0x970'),
        (0x1855bb6f8, 'sub', 'x3, x29, #4'),
        (0x1855bb6fc, 'mov', 'w2, #0x10'),
        (0x180549e30, 'bl', '#0x180548ca8'),
        (0x180548ca8, 'mov', 'x16, #-0x46'),
        (0x180548cac, 'svc', '#0x80'),
        (0x1855bb710, 'ldur', 'w8, [x29, #-4]'),
        (0x1855bb718, 'add', 'x9, x9, #0x934'),
        (0x1855bb71c, 'str', 'w8, [x9]'),
        (0x1855bb724, 'add', 'x9, x9, #0x930'),
        (0x1855bb728, 'str', 'w8, [x9]'),
        (0x1855bc9f8, 'ldr', 'w0, [x8]'),
        (0x1855bca18, 'str', 'w0, [x19, #0x10]'),
        (0x1855bca1c, 'mov', 'w9, #0x130000'),
        (0x1855bca20, 'orr', 'w8, w8, w9'),
        (0x1855bca24, 'str', 'w8, [x19]'),
    ])
    table = clean_pointer(cache.pointer(0x1e24a74d8))
    assert table['authenticated'] and int(table['target'], 0) == 0x1855bc9a0
    assert evidence.record(0x1e24a74d0, 8) == struct.pack('<Q', 3)
    recipe = evidence.record(0x1855d2970, 16)
    assert struct.unpack('<4I', recipe) == (3, 610, 0, 0)
    symbol(dispatch, '__dispatch_mach_host_port', 0x1ed95db00)
    symbol(dispatch, '__voucher_default_task_mach_voucher', 0x1ed95d934)
    symbol(dispatch, '__voucher_task_mach_voucher', 0x1ed95d930)
    return {'cache_uuid': cache.uuid, 'image_uuids': [xpc.uuid, dispatch.uuid, kernel.uuid],
            'functions': functions, 'veneer_bindings': bindings, 'voucher_set_table_member': table,
            'recipe_hex': recipe.hex(), 'instruction_and_data_windows': evidence.windows}


def baseline_comparison(current, archived, root):
    old_record = (root / 'rpc700_endpoint_inventory_source.json').read_bytes()
    old = json.loads(old_record)
    assert old['cache_uuid'] == '2bd06591-e751-3e84-963f-b08dab6af23a'
    body = old['caller_functions']['0x185537c74']
    programs = {int(row['ea'], 0): (row['mnemonic'], row['operands']) for row in body['instructions']}
    assert programs[0x185537c98] == ('mov', 'w1, #-1')
    assert programs[0x185537c9c] == ('mov', 'w2, #1')
    assert programs[0x185537ca0] == ('bl', '#0x188079af0')
    assert programs[0x185537cf8] == ('cmp', 'w20, #4')
    assert programs[0x185537cfc] == ('b.eq', '#0x185537cdc')
    assert programs[0x185537ce4] == ('str', 'w19, [x8, #0xbc0]')
    ins, = CS.disasm(bytes.fromhex(body['bytes'])[44:48], 0x185537ca0)
    assert (ins.mnemonic, ins.op_str) == programs[0x185537ca0]
    assert 0x1855b9ca0 - 0x185537ca0 == 0x82000
    logged_recipe = int(re.search(r'host_create_mach_voucher_trap\(3075, (0x[0-9a-f]+)', archived['voucher_trap'])[1], 0)
    assert 0x1855d2970 - logged_recipe == 0x82000
    assert 0x180548b54 - 0x180547b54 == 0x180548c20 - 0x180547c20 == 0x180548cb0 - 0x180547cb0 == 0x1000
    return {'baseline_cache_uuid': old['cache_uuid'], 'baseline_receipt_sha256': sha256(old_record).hexdigest(),
            'installed_cache_uuid': current['cache_uuid'], 'dispatch_call_and_recipe_deltas': '0x82000',
            'kernel_trap_return_pc_deltas': '0x1000'}


def bridge_source(repo):
    checks = {
        'bridge/translate.rs': (
            r'if let Some\(v\) = m.voucher.take\(\) \{\s*kmsg::release\(proc, \[v\]\);',
            r'let mut buf = vec!\[0u8; HEADER_SIZE \+ m.body.len\(\)\];',
            r'let hb = bits::set\(remote_disp, local_disp, 0, m.bits & bits::COMPLEX\);',
            r'buf\[12\.\.16\].*\n\s*buf\[20\.\.24\]',
            r'if bits::voucher\(hbits\) != 0 && voucher != host::NULL \{\s*host::deallocate\(voucher\);',
            r'voucher: None,\s*voucher_name: 0,',
        ),
        'mig/host.rs': (r'HOST_GET_SPECIAL_PORT => \{\s*req.simple\(40\)\?;\s*Err\(kr::KERN_INVALID_ARGUMENT\)',),
        'syscall/mach/voucher.rs': (
            r'KObject::Host \| KObject::HostPriv',
            r'ctx.proc.vouchers.canonical\(a\);\s*ctx.proc.insert_send\(&port\)',
            r'ctx.write_u32\(out, name\)',
        ),
        'mach/voucher.rs': (r'pub const BANK_CREATE: u32 = 610;', r'\(cmd::BANK_CREATE, _\) => Bank::DefaultTask,'),
    }
    result = {}
    for name, patterns in checks.items():
        path = 'src/user/darwin/' + name
        raw = subprocess.check_output(['git', '-C', repo, 'show', f'{RAX_COMMIT}:{path}'])
        code = raw.decode()
        matches = [re.search(pattern, code) for pattern in patterns]
        assert all(matches), name
        result[path] = {'sha256': sha256(raw).hexdigest(),
                        'checked_lines': [code.count('\n', 0, match.start()) + 1 for match in matches]}
    return {'revision': RAX_COMMIT, 'files': result}


def sdk_contract():
    sdk = subprocess.check_output(['xcrun', '--show-sdk-path'], text=True).strip()
    source = b"""
#include <stddef.h>
#include <mach/host_special_ports.h>
#include <mach/kern_return.h>
#include <mach/mach_voucher_types.h>
#include <mach/message.h>
_Static_assert(HOST_PORT == 1, "host slot");
_Static_assert(HOST_LOCAL_NODE == -1, "local node");
_Static_assert(KERN_INVALID_ARGUMENT == 4, "routine status");
_Static_assert(MIG_REPLY_MISMATCH == -301, "routine status");
_Static_assert(MACH_VOUCHER_ATTR_KEY_BANK == 3, "recipe key");
_Static_assert(sizeof(mach_voucher_attr_recipe_data_t) == 16, "recipe size");
_Static_assert(offsetof(mach_voucher_attr_recipe_data_t, content) == 16, "recipe content");
_Static_assert(offsetof(mach_msg_header_t, msgh_voucher_port) == 16, "voucher field");
_Static_assert(MACH_MSG_TYPE_COPY_SEND == 19, "voucher disposition");
"""
    subprocess.run(['xcrun', 'clang', '-isysroot', sdk, '-include', 'mach/mig_errors.h',
                    '-fsyntax-only', '-x', 'c', '-'], input=source, check=True)
    return {'assertions': 9, 'source_sha256': sha256(source).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    parser.add_argument('rax_source', type=Path)
    args = parser.parse_args()
    archived = archive(args.trace)
    current = cache_contract()
    print(json.dumps({'archive': archived, 'current': current,
                      'comparison': baseline_comparison(current, archived, Path(__file__).resolve().parent),
                      'bridge_source': bridge_source(args.rax_source), 'sdk': sdk_contract()}, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
