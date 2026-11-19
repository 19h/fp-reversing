#!/usr/bin/env python3
"""Bind normal FairPlay receive-right check-in to current images and archived observations."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import struct

from analyze_zut_trace import decode_descriptors
from audit_daemon_iokit_native_registry import command
from audit_fairplay_live_slice_identity import installed_slices
from audit_live_fairplay_adid_ipc import ThinView
from audit_live_host_special_publication import LAUNCHD_UUID, windows
from audit_live_iokit_mach_transport import CACHE_UUID, LIBKERNEL, Cache, Dylib, dyld_uuid
from audit_live_rpc700_publication import running_identity

ROOT = Path(__file__).resolve().parent
NAMES = ('com.apple.unfreed', 'com.apple.fairplayd', 'com.apple.fpsd',
         'com.apple.arcade.fpsd', 'com.apple.fpsd.sim')
LIBXPC_UUID = '94e40b03-44c5-3636-aa1a-c64a5d6b6bbb'


def launchd(path):
    identity = running_identity({'pid': 1}, path, installed_slices(path))
    selected = identity['matched_slice']
    assert selected['uuid'] == LAUNCHD_UUID
    begin = selected['file_offset_bytes']
    blob = path.read_bytes()[begin:begin + selected['slice_size_bytes']]
    assert sha256(blob).hexdigest() == selected['sha256']
    image = ThinView(blob)
    indirect = command('otool', '-arch', selected['arch'], '-Iv', str(path)).decode()
    imports = {int(pc, 16): name for pc, name in re.findall(
        r'^\s*(0x[0-9a-fA-F]+)\s+\d+\s+(\S+)\s*$', indirect, re.M)}
    expected = {
        0x10005f564: '_xpc_dictionary_expects_reply',
        0x10005f5f4: '_xpc_dictionary_get_string',
        0x10005f604: '_xpc_dictionary_get_uint64',
        0x10005f554: '_xpc_dictionary_create_reply',
        0x10005f784: '_xpc_mach_send_get_right',
        0x10005f674: '_xpc_dictionary_set_mach_recv',
        0x10005f7e4: '_xpc_release',
        0x10005e474: '_mach_port_unguard',
        0x10005f7c4: '_xpc_pipe_routine_reply',
    }
    assert {site: imports[site] for site in expected} == expected
    table, relative = 0x10005a538, 0x10002e238
    raw = image.read(table, 12 * 4)
    cases = [relative + delta for delta in struct.unpack('<12i', raw)]
    assert cases[206 - 200] == 0x10002e2e0
    for pc, mnemonic, operands in (
        (0x10002d428, 'adrp', 'x16, #0x10002e000'),
        (0x10002d42c, 'add', 'x16, x16, #0x16c'),
        (0x10002d438, 'mov', 'w0, #5'),
        (0x10002d43c, 'bl', '#0x100045950'),
        (0x1000459f0, 'str', 'x20, [x9, x8, lsl #3]'),
        (0x1000459f4, 'str', 'w19, [x0, x8, lsl #2]'),
        (0x10002e214, 'sub', 'w16, w22, #0xc8'),
        (0x10002e218, 'cmp', 'w16, #0xb'),
        (0x10002e22c, 'adrp', 'x17, #0x10005a000'),
        (0x10002e230, 'add', 'x17, x17, #0x538'),
        (0x10002e234, 'ldrsw', 'x16, [x17, x16, lsl #2]'),
        (0x10002e238, 'adr', 'x17, #0x10002e238'),
        (0x10002e2f4, 'bl', '#0x100038178'),
        (0x100046610, 'ldr', 'x10, [x10, #0xa00]'),
        (0x100046614, 'ldr', 'w11, [x10, x9, lsl #2]'),
        (0x10004671c, 'ldr', 'x8, [x8, #0x9f8]'),
        (0x100046728, 'add', 'x3, sp, #0x18'),
        (0x100046738, 'blraaz', 'x8'),
        (0x10004677c, 'adrp', 'x1, #0x100075000'),
        (0x1000467e0, 'ldr', 'x0, [sp, #0x18]'),
        (0x1000467e4, 'bl', '#0x10005f7c4'),
        (0x1000381bc, 'bl', '#0x10005f5f4'),
        (0x1000381d4, 'bl', '#0x10005f604'),
        (0x1000381e4, 'eor', 'x3, x8, #1'),
        (0x1000381e8, 'add', 'x5, sp, #8'),
        (0x100038200, 'bl', '#0x100059644'),
        (0x10003820c, 'cbnz', 'w0, #0x100038250'),
        (0x100038214, 'bl', '#0x10005f554'),
        (0x100038224, 'bl', '#0x10005f784'),
        (0x100038228, 'mov', 'x2, x0'),
        (0x100038238, 'bl', '#0x10005f674'),
        (0x100038240, 'bl', '#0x10005f7e4'),
        (0x100038244, 'str', 'x20, [x19]'),
        (0x100059a08, 'bl', '#0x100046e5c'),
        (0x100059a44, 'bl', '#0x100047380'),
        (0x100059a4c, 'str', 'x0, [x24]'),
        (0x1000473b0, 'b', '#0x10005cb70'),
        (0x10005cb8c, 'ldr', 'x8, [x0, #0x68]'),
        (0x100046ea0, 'bl', '#0x100046c48'),
        (0x100046f00, 'ldr', 'x2, [x19, #0x70]'),
        (0x100046f14, 'bl', '#0x10005e474'),
    ):
        image.instruction(pc, mnemonic, operands)
    for address, value in ((0x10006afa5, b'name\0'), (0x100070178, b'flags\0'),
                           (0x10006b71d, b'port\0')):
        assert image.read(address, len(value)) == value
    spans = {
        'register': (0x10002d428, 0x18),
        'store_registered_interface': (0x1000459e4, 0x1c),
        'dispatcher': (0x10002e16c, 0x1b4),
        'handler': (0x100038178, 0xf4),
        'find_group': (0x1000465fc, 0x30),
        'dispatch_and_emit': (0x100046718, 0xe4),
        'endpoint_return': (0x1000599fc, 0x54),
        'endpoint_getter': (0x100047380, 0x34),
        'activation': (0x100046e5c, 0xc0),
    }
    return dict(pid1=identity, imports={hex(pc): name for pc, name in expected.items()},
                table=hex(table), table_bytes=raw.hex(), cases=list(map(hex, cases)),
                windows=windows(image.read, spans))


def libxpc():
    cache = Cache()
    assert cache.uuid == dyld_uuid() == CACHE_UUID
    path, = [row['path'] for row in cache.images if Path(row['path']).name == 'libxpc.dylib']
    library = Dylib(cache, path)
    assert library.uuid == LIBXPC_UUID
    entries = {
        '_bootstrap_check_in': 0x184bc5884,
        '_bootstrap_check_in3': 0x184bc58d8,
        '__xpc_interface_routine': 0x184bb66f0,
        '__xpc_pipe_pack_message': 0x184bb6b0c,
        '__xpc_pipe_routine': 0x184be84d8,
        '__xpc_pipe_mach_msg': 0x184be925c,
        '_xpc_pipe_routine_reply': 0x184be8ad8,
        '__xpc_send_serializer': 0x184bc8294,
        '_xpc_dictionary_set_mach_recv': 0x184bcf130,
        '__xpc_mach_recv_serialize': 0x184bcf250,
        '__xpc_serializer_append_port': 0x184bb9bfc,
        '__xpc_mach_recv_deserialize': 0x184bc2c3c,
        '_xpc_mach_recv_extract_right': 0x184bc2cc8,
    }
    functions = {}
    instructions = {}
    for label, pc in entries.items():
        assert label in [row['name'] for row in library.symbols_at(pc)]
        body = library.function(pc)
        assert len(body['instructions']) * 4 == len(bytes.fromhex(body['bytes']))
        instructions.update({int(row['ea'], 16): (row['mnemonic'], row['operands'])
                             for row in body['instructions']})
        functions[label] = body
    for site, expected in {
        0x184bc58ac: ('bl', '#0x184bc58d8'),
        0x184bc5924: ('cmp', 'w8, #1'),
        0x184bc59d0: ('mov', 'w0, #5'),
        0x184bc59d4: ('mov', 'w1, #0xce'),
        0x184bc59e4: ('bl', '#0x184bb66f0'),
        0x184bc5a08: ('add', 'x16, x16, #0xcc8'),
        0x184bc5a0c: ('paciza', 'x16'),
        0x184bc5a1c: ('str', 'w0, [x20]'),
        0x184bc5b04: ('cmp', 'w8, #0x1f6'),
        0x184bb67e4: ('bl', '#0x184be84d8'),
        0x184be8598: ('bl', '#0x184bb6b0c'),
        0x184be8678: ('bl', '#0x184be925c'),
        0x184bb6b98: ('mov', 'w8, #0x40000000'),
        0x184bb6bb4: ('mov', 'w24, #0x20000000'),
        0x184be8b18: ('bl', '#0x184bb6b0c'),
        0x184be8b2c: ('bl', '#0x184bc8294'),
        0x184bc8310: ('bl', '#0x184be925c'),
        0x184be9290: ('bl', '#0x18806d230'),
        0x184bcf188: ('stp', 'w21, w21, [x22, #0x18]'),
        0x184bcf268: ('swp', 'w10, w4, [x9]'),
        0x184bcf294: ('mov', 'w5, #0x10'),
        0x184bcf298: ('bl', '#0x184bb9bfc'),
        0x184bc2c58: ('mov', 'w1, #0x10'),
        0x184bc2d00: ('swp', 'w9, w0, [x8]'),
    }.items():
        assert instructions[site] == expected, (hex(site), instructions[site])
    mach = Dylib(cache, LIBKERNEL).exports['_mach_msg']['address']
    stub_pc = 0x18806d230
    stub = windows(cache.read, {'mach_msg': (stub_pc, 16)})['mach_msg']
    rows = stub['instructions']
    assert [row[1] for row in rows] == ['adrp', 'add', 'ldr', 'braa']
    slot = sum(int(row[2].split('#')[-1], 16) for row in rows[:2])
    pointer = cache.pointer(slot)
    assert pointer['authenticated'] and int(pointer['target'], 16) == mach
    return dict(cache_uuid=cache.uuid, libxpc_uuid=library.uuid, functions=functions,
                mach_msg_stub=stub, mach_msg_binding={k: v for k, v in pointer.items() if k != 'path'})


def trace(path):
    raw = path.read_bytes()
    digest = sha256(raw).hexdigest()
    assert digest == '78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e'
    lines = raw.decode().splitlines()
    archive = json.loads(command('zstd', '-dcq', str(ROOT / 'bootstrap_checkin_handoff_source.json.zst')))
    pairs = archive['trace']['pairs']
    assert len(pairs) == len(NAMES)
    observed = []
    for index, (name, pair) in enumerate(zip(NAMES, pairs, strict=True)):
        for kind in ('request', 'reply'):
            packet = pair[kind]
            first, last = packet['line'], packet['hex_end_line']
            original = bytearray()
            for line in lines[first:last]:
                row = re.search(r'\]\s+([0-9a-f]{4,})\s+((?:[0-9a-f]{2}\s+)+)\|', line)
                assert row and int(row[1], 16) == len(original)
                original.extend(bytes.fromhex(row[2]))
            bits, length, remote, local, voucher, mid = struct.unpack_from('<6I', original)
            assert bytes(original[:length]).hex() == packet['message_hex']
            assert (bits, length, remote, local, voucher, mid) == (
                packet['bits'], packet['size_bytes'], int(packet['remote'], 16),
                int(packet['local'], 16), int(packet['voucher'], 16), packet['id'])
            assert decode_descriptors(original[:length], bits) == packet['descriptors']
        request, reply = (pair[kind] for kind in ('request', 'reply'))
        assert (request['id'], reply['id']) == (0x400000ce, 0x20000000)
        assert reply['local'] == request['local']
        assert name.encode() + b'\0' in bytes.fromhex(request['message_hex'])
        descriptor, = reply['descriptors']
        assert descriptor['disposition'] == 16
        port = int(descriptor['name'], 16)
        # Limit the member search to this check-in episode.
        end = pairs[index + 1]['request']['line'] if index + 1 < len(pairs) else reply['line'] + 64
        insertion = re.compile(rf'mach_port_insert_member_trap\(515, {port}, (\d+)\) = 0x0$')
        (line_number, port_set), = [(i + 1, int(m[1])) for i in range(reply['line'], end - 1)
                                    if (m := insertion.search(lines[i]))]
        assert port_set == 0x1003
        observed.append(dict(service=name, request_line=request['line'], reply_line=reply['line'],
                             insertion_line=line_number, port_set=hex(port_set), receive_name=hex(port),
                             request_hex=request['message_hex'], reply_hex=reply['message_hex']))
    return dict(sha256=digest, matched_pairs=observed, scope='historical emulator guest names')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('launchd', type=Path)
    parser.add_argument('annotated_trace', type=Path)
    args = parser.parse_args()
    build = command('sw_vers', '-buildVersion').decode().strip()
    assert build == '26C5035r'
    print(json.dumps(dict(build=build, launchd=launchd(args.launchd), libxpc=libxpc(),
                          trace=trace(args.annotated_trace), native_checkin_observed=False), indent=2))
