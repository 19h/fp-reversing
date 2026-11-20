#!/usr/bin/env python3
"""Read-only source audit of the installed ADID listener and Mach 1200 route."""

from hashlib import sha256
import json
import plistlib
from pathlib import Path
import re
import struct
import subprocess

from audit_daemon_iokit_native_registry import command
from audit_fairplay_live_slice_identity import installed_slices
from audit_live_fairplay_adid_ipc import PROVIDER_SHA, ThinView, provider
from audit_live_host_special_publication import LAUNCHD_UUID
from audit_live_iokit_mach_transport import CACHE_UUID, clean_pointer, dyld_uuid
from audit_live_rpc700_publication import running_identity
from bootpolicy_cache_reader import CS, Cache, Dylib


class Evidence:
    def __init__(self, reader):
        self.read = reader
        self.windows = {}

    def record(self, address, size):
        raw = self.read(address, size)
        self.windows[f'{address:#x}/{size}'] = raw.hex()
        return raw

    def check(self, rows):
        for address, mnemonic, operands in rows:
            instruction, = CS.disasm(self.record(address, 4), address)
            assert (instruction.mnemonic, instruction.op_str) == (mnemonic, operands), address

    def span(self, begin, end, transfers):
        raw = self.record(begin, end - begin)
        decoded = tuple(CS.disasm(raw, begin))
        assert len(decoded) * 4 == len(raw)
        found = {i.address: i.op_str for i in decoded
                 if i.mnemonic in ('bl', 'b', 'braa', 'braaz', 'blr', 'blraa', 'blraaz')}
        assert found == transfers, (begin, found)


def cached_image(cache, basename, uuid):
    row, = (row for row in cache.images if Path(row['path']).name == basename)
    image = Dylib(cache, row['path'])
    assert image.uuid == uuid, basename
    return image


def symbol(image, name, address):
    assert name in {row['name'] for row in image.symbols_at(address)}, (name, address)


def veneer(cache, evidence, pc, image, name, address):
    ins = tuple(CS.disasm(evidence.record(pc, 16), pc))
    page = re.fullmatch(r'x17, #(0x[0-9a-f]+)', ins[0].op_str)
    offset = re.fullmatch(r'x17, x17, #(0x[0-9a-f]+)', ins[1].op_str)
    assert [i.mnemonic for i in ins] == ['adrp', 'add', 'ldr', 'braa']
    assert page and offset and ins[2].op_str == 'x16, [x17]' and ins[3].op_str == 'x16, x17'
    slot = int(page[1], 16) + int(offset[1], 16)
    pointer = clean_pointer(cache.pointer(slot))
    assert pointer['authenticated'] and int(pointer['target'], 16) == address
    symbol(image, name, address)
    return {'name': name, 'image_uuid': image.uuid, 'pointer': pointer}


def launchd_audit():
    path = Path('/sbin/launchd')
    identity = running_identity({'pid': 1}, path, installed_slices(path))
    match = identity['matched_slice']
    assert match['uuid'] == LAUNCHD_UUID
    start = match['file_offset_bytes']
    blob = path.read_bytes()[start:start + match['slice_size_bytes']]
    assert sha256(blob).hexdigest() == match['sha256']
    evidence = Evidence(ThinView(blob).read)
    evidence.check((
        (0x10002d420, 'mov', 'w0, #3'),
        (0x10002d414, 'add', 'x16, x16, #0xc60'),
        (0x10002d424, 'bl', '#0x100045950'),
        (0x10002d438, 'mov', 'w0, #5'),
        (0x10002d42c, 'add', 'x16, x16, #0x16c'),
        (0x10002d43c, 'bl', '#0x100045950'),
        (0x1000459f0, 'str', 'x20, [x9, x8, lsl #3]'),
        (0x10002dca0, 'sub', 'w16, w21, #0x320'),
        (0x10002dcc0, 'add', 'x17, x17, #0x46c'),
        (0x10002dcc4, 'ldrsw', 'x16, [x17, x16, lsl #2]'),
        (0x10002dcc8, 'adr', 'x17, #0x10002dcc8'),
        (0x10002e214, 'sub', 'w16, w22, #0xc8'),
        (0x10002e230, 'add', 'x17, x17, #0x538'),
        (0x10002e234, 'ldrsw', 'x16, [x17, x16, lsl #2]'),
        (0x10002e238, 'adr', 'x17, #0x10002e238'),
        (0x10002e044, 'bl', '#0x1000326c0'),
        (0x100032738, 'bl', '#0x10005f5f4'),
        (0x100032794, 'bl', '#0x100059644'),
        (0x1000327a8, 'bl', '#0x10005f554'),
        (0x1000327b8, 'bl', '#0x10005f784'),
        (0x1000327cc, 'bl', '#0x10005f674'),
        (0x100032aa4, 'str', 'x22, [x19]'),
        (0x10002e290, 'bl', '#0x10003826c'),
        (0x100038324, 'bl', '#0x10005f5f4'),
        (0x1000383dc, 'bl', '#0x100059b3c'),
        (0x100038444, 'mov', 'x21, x0'),
        (0x100038458, 'mov', 'w1, #1'),
        (0x10003845c, 'bl', '#0x100047380'),
        (0x100038470, 'bl', '#0x10005f6d4'),
        (0x100038494, 'str', 'x20, [x19]'),
        (0x1000467e4, 'bl', '#0x10005f7c4'),
    ))
    routes = {}
    for interface, routine, base_id, table, relative, expected in (
        (3, 805, 800, 0x10005a46c, 0x10002dcc8, 0x10002e030),
        (5, 207, 200, 0x10005a538, 0x10002e238, 0x10002e27c),
    ):
        delta, = struct.unpack('<i', evidence.record(table + 4 * (routine - base_id), 4))
        assert relative + delta == expected
        routes[f'{interface}/{routine}'] = hex(expected)
    for address, literal in ((0x10006afa5, b'name\0'), (0x10006b71d, b'port\0')):
        assert evidence.record(address, len(literal)) == literal
    indirect = command('otool', '-arch', match['arch'], '-Iv', str(path)).decode()
    imports = {int(pc, 16): name for pc, name in re.findall(
        r'^\s*(0x[0-9a-fA-F]+)\s+\d+\s+(\S+)\s*$', indirect, re.M)}
    checked = {
        0x10005f554: '_xpc_dictionary_create_reply',
        0x10005f5f4: '_xpc_dictionary_get_string',
        0x10005f674: '_xpc_dictionary_set_mach_recv',
        0x10005f6d4: '_xpc_dictionary_set_value',
        0x10005f784: '_xpc_mach_send_get_right',
        0x10005f7c4: '_xpc_pipe_routine_reply',
    }
    assert {pc: imports[pc] for pc in checked} == checked
    return {'uuid': match['uuid'], 'sha256': match['sha256'], 'cdhash': match['codesign_cdhash'],
            'routes': routes, 'bindings': {hex(pc): name for pc, name in checked.items()},
            'source': evidence.windows}


def layout_audit():
    source = b"""
#include <mach/mach.h>
#include <mach/mig_errors.h>
#include <stddef.h>
_Static_assert(offsetof(mach_msg_header_t, msgh_remote_port) == 8, "reply name");
_Static_assert(offsetof(mach_msg_header_t, msgh_id) == 20, "message ID");
_Static_assert(offsetof(mach_msg_audit_trailer_t, msgh_audit) == 20, "audit token");
_Static_assert(sizeof(mach_msg_audit_trailer_t) == 52, "audit size");
_Static_assert(MACH_MSG_TYPE_PORT_SEND_ONCE == 18, "received send-once");
_Static_assert(MACH_MSG_OOL_DESCRIPTOR == 1, "OOL descriptor");
_Static_assert(MIG_BAD_ID == -303, "reply status");
"""
    subprocess.run(['xcrun', 'clang', '-x', 'c', '-fsyntax-only', '-'],
                   input=source, check=True)
    return {'sdk_version': command('xcrun', '--show-sdk-version').decode().strip(),
            'assertions': source.decode().strip().splitlines()}


def notification_rows(cache, evidence, xpc):
    rows = {}
    expected = ('', '__Xmach_notify_port_deleted', '', '', '',
                '__Xmach_notify_port_destroyed', '__Xmach_notify_no_senders',
                '__Xmach_notify_send_once', '__Xmach_notify_dead_name')
    for message_id, name in enumerate(expected, 64):
        slot = 0x1e240c818 + 40 * message_id - 0x9f8
        raw = evidence.record(slot, 8)
        present = raw != bytes(8)
        assert present == bool(name)
        if present:
            pointer = clean_pointer(cache.pointer(slot))
            assert pointer['authenticated']
            symbol(xpc, name, int(pointer['target'], 16))
            rows[message_id] = {'name': name, 'pointer': pointer}
        else:
            rows[message_id] = {'empty_slot': hex(slot)}

    modulus = 1 << 32
    # cmn produces carry precisely when (id - 73) modulo 2^32 is in the
    # final nine values. Adding 73 and reducing puts those values at 64..72.
    accepted = tuple((low + 73) % modulus for low in range(modulus - 9, modulus))
    assert accepted == tuple(rows)
    controls = (0, 63, *accepted, 73, 1200, 1300, 0x7fffffff, 0x80000000, 0xffffffff)
    for value in controls:
        adds_with_carry = (value - 73) % modulus + 9 >= modulus
        assert adds_with_carry == (value in rows), value
    return {'rows': rows, 'carry_control_ids': controls, 'domain_bits': 32}


def main():
    assert command('sw_vers', '-buildVersion').decode().strip() == '26C5035r'
    adid_path = Path('/System/Library/PrivateFrameworks/CoreADI.framework/adid')
    launch_plist = Path('/System/Library/LaunchDaemons/com.apple.adid.plist').read_bytes()
    launch_config = plistlib.loads(launch_plist)
    assert launch_config['Program'] == str(adid_path)
    assert 'com.apple.adid' in launch_config['MachServices']
    adid = provider(adid_path)
    assert adid['sha256'] == PROVIDER_SHA
    cache = Cache()
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    xpc = cached_image(cache, 'libxpc.dylib', '94e40b03-44c5-3636-aa1a-c64a5d6b6bbb')
    dispatch = cached_image(cache, 'libdispatch.dylib', '435a06f9-1bc8-3282-8663-b6418c44a05e')
    kernel = cached_image(cache, 'libsystem_kernel.dylib', '780a6c1f-be02-34cc-84dd-00e05f61c89b')
    pthread = cached_image(cache, 'libsystem_pthread.dylib', '37f8fd20-72d4-385d-8d3c-d21cda4dd94b')
    asl = cached_image(cache, 'libsystem_asl.dylib', '452b60ab-6b94-332f-b4dd-91022043a57b')
    bsm = cached_image(cache, 'libbsm.0.dylib', 'ccdec355-884e-36f6-a571-7291f637b936')
    evidence = Evidence(cache.read)
    bindings = {}
    for pc, image, name, target in (
        (0x1880876b0, dispatch, '_dispatch_mach_create_4libxpc', 0x1855af8f8),
        (0x1880876a0, dispatch, '_dispatch_mach_connect', 0x1855afa54),
        (0x188087710, dispatch, '_dispatch_mach_msg_get_msg', 0x1855b34a8),
        (0x18806c9b0, dispatch, '_dispatch_once', 0x185598570),
        (0x18806d240, kernel, '_mach_msg_destroy', 0x180549bbc),
        (0x18806d270, kernel, '_mach_port_insert_right', 0x18054b17c),
        (0x18806cf50, kernel, '_mach_port_mod_refs', 0x180549320),
        (0x1880879e0, kernel, '_mach_port_set_attributes', 0x18054b6f8),
        (0x1880879b0, kernel, '_mach_port_guard', 0x18054bbcc),
        (0x18806cb80, pthread, '_pthread_setspecific', 0x180588d4c),
        (0x18806cb60, pthread, '_pthread_key_create', 0x1805883a0),
        (0x18806e260, asl, '_syslog$DARWIN_EXTSN', 0x18771c37c),
    ):
        bindings[hex(pc)] = veneer(cache, evidence, pc, image, name, target)
    for image, name, address in (
        (xpc, '_xpc_connection_create_mach_service', 0x184bbbc94),
        (xpc, '_xpc_connection_activate', 0x184bbc0c0),
        (xpc, '__xpc_connection_mach_event', 0x184bbdfa0),
        (xpc, '__xpc_connection_pass2mig', 0x184bc6900),
        (xpc, '__xpc_connection_init', 0x184bbc4a8),
        (xpc, '__xpc_connection_check_in', 0x184bba4e0),
        (xpc, '_bootstrap_look_up', 0x184bc16b0),
        (xpc, '_bootstrap_look_up3', 0x184bb91b8),
        (xpc, '_xpc_mach_recv_extract_right', 0x184bc2cc8),
        (xpc, '____xpc_connection_pass2mig_block_invoke', 0x184bda374),
        (bsm, '_audit_token_to_pid', 0x206c3f720),
        (kernel, '_mach_msg_destroy_port', 0x180549d00),
        (kernel, '_mach_port_deallocate', 0x18054a06c),
        (kernel, '_mach_vm_deallocate', 0x18054a7a4),
        (dispatch, '__dispatch_mach_msg_invoke', 0x1855b1da4),
    ):
        symbol(image, name, address)
    once = clean_pointer(cache.pointer(0x1e240cbb0))
    assert once['authenticated'] and int(once['target'], 16) == 0x184bda374
    evidence.check((
        (0x184bbbcb0, 'mov', 'w0, #0'),
        (0x184bbbcb4, 'bl', '#0x184bce224'),
        (0x184bbbcbc, 'tbnz', 'w19, #0, #0x184bbbce0'),
        (0x184bbbce4, 'orr', 'w8, w8, #8'),
        (0x184bbbd14, 'strh', 'w8, [x20, #0x108]'),
        (0x184bce244, 'mov', 'x20, x0'),
        (0x184bce25c, 'cbz', 'w20, #0x184bce278'),
        (0x184bce278, 'adrp', 'x16, #0x184bbd000'),
        (0x184bce27c, 'add', 'x16, x16, #0xfa0'),
        (0x184bce280, 'paciza', 'x16'),
        (0x184bce284, 'mov', 'x3, x16'),
        (0x184bce290, 'mov', 'x2, x19'),
        (0x184bce294, 'bl', '#0x1880876b0'),
        (0x184bce298, 'str', 'x0, [x19, #0xa8]'),
        (0x1855af8fc, 'b', '#0x1855af6d0'),
        (0x1855af6f0, 'mov', 'x23, x3'),
        (0x1855af82c, 'pacib', 'x16, x17'),
        (0x1855af838, 'stp', 'x16, x22, [x0, #0x28]'),
        (0x1855b1f14, 'ldp', 'x16, x0, [x23, #0x28]!'),
        (0x1855b1f24, 'autib', 'x16, x17'),
        (0x1855b1f40, 'mov', 'x4, x16'),
        (0x1855b1f74, 'mov', 'x1, x20'),
        (0x1855b1f78, 'mov', 'x2, x19'),
        (0x1855b1f80, 'bl', '#0x1855af5d8'),
        (0x1855af5e4, 'blraaz', 'x4'),
        (0x184bbc11c, 'b', '#0x184bbc15c'),
        (0x184bbc37c, 'bl', '#0x184bbc4a8'),
        (0x184bbc570, 'tbnz', 'w8, #3, #0x184bbc5c8'),
        (0x184bbc6c0, 'add', 'x1, x1, #0x2da'),
        (0x184bbc6c4, 'mov', 'w2, #6'),
        (0x184bbc6d0, 'add', 'x1, x1, #0x2df'),
        (0x184bbc6d8, 'mov', 'x2, #0'),
        (0x184bbc6e4, 'add', 'x1, x1, #0x555'),
        (0x184bbc6f8, 'add', 'x1, x1, #0x81c'),
        (0x184bbc710, 'mov', 'w0, #3'),
        (0x184bbc714, 'mov', 'w1, #0x325'),
        (0x184bbc724, 'bl', '#0x184bb66f0'),
        (0x184bbc728, 'cbz', 'w0, #0x184bbc7e8'),
        (0x184bbc7f0, 'add', 'x1, x1, #0x159'),
        (0x184bbc800, 'add', 'x16, x16, #0xcc8'),
        (0x184bbc804, 'paciza', 'x16'),
        (0x184bbc810, 'bl', '#0x184be5bf8'),
        (0x184bbc814, 'str', 'w0, [x19, #0x44]'),
        (0x184bc2d00, 'swp', 'w9, w0, [x8]'),
        (0x184bbc880, 'bl', '#0x1880879e0'),
        (0x184bbc898, 'bl', '#0x1880879b0'),
        (0x184bbc970, 'tbnz', 'w8, #3, #0x184bbca60'),
        (0x184bbca74, 'mov', 'w3, #0x14'),
        (0x184bbca78, 'bl', '#0x18806d270'),
        (0x184bbca84, 'str', 'w8, [x19, #0x4c]'),
        (0x184bbca34, 'bl', '#0x184bba4e0'),
        (0x184bba50c, 'ldr', 'x0, [x20, #0xa8]'),
        (0x184bba510, 'ldr', 'w1, [x20, #0x44]'),
        (0x184bba514, 'ldr', 'w2, [x20, #0x4c]'),
        (0x184bba53c, 'b', '#0x1880876a0'),
        (0x184bc16e0, 'bl', '#0x184bb91b8'),
        (0x184bb9210, 'b.ne', '#0x184bb9288'),
        (0x184bb92e4, 'mov', 'w0, #5'),
        (0x184bb92e8, 'mov', 'w1, #0xcf'),
        (0x184bb92f8, 'bl', '#0x184bb66f0'),
        (0x184bb9338, 'bl', '#0x184bba268'),
        (0x184bb9350, 'mov', 'w2, #0'),
        (0x184bb9354, 'mov', 'w3, #1'),
        (0x184bb9358, 'bl', '#0x18806cf50'),
        (0x184bb9368, 'str', 'w27, [x20]'),
        (0x184bbe048, 'cmp', 'x21, #2'),
        (0x184bbe04c, 'b.eq', '#0x184bbe2ec'),
        (0x184bbe2f4, 'bl', '#0x188087710'),
        (0x184bbe2f8, 'mov', 'w9, #0x3fffffff'),
        (0x184bbe2fc, 'ldr', 'w8, [x0, #0x14]'),
        (0x184bbe304, 'b.gt', '#0x184bbe358'),
        (0x184bbe308, 'mov', 'w9, #0x10000000'),
        (0x184bbe310, 'b.eq', '#0x184bbe3d0'),
        (0x184bbe314, 'mov', 'w9, #0x20000000'),
        (0x184bbe31c, 'b.eq', '#0x184bbe6fc'),
        (0x184bbe320, 'mov', 'w9, #0x30000000'),
        (0x184bbe328, 'b.eq', '#0x184bbe3d0'),
        (0x184bbe32c, 'b', '#0x184bbe4ac'),
        (0x184bbe4b4, 'bl', '#0x184bc6900'),
        (0x184bbe4b8, 'b', '#0x184bbe700'),
        (0x184bbe710, 'bl', '#0x184be6af0'),
        (0x184bbe744, 'retab', ''),
        (0x184bc6938, 'bl', '#0x188087710'),
        (0x184bc6940, 'ldr', 'w8, [x0, #4]'),
        (0x184bc6944, 'add', 'x8, x8, #3'),
        (0x184bc6948, 'and', 'x8, x8, #0x1fffffffc'),
        (0x184bc694c, 'add', 'x9, x0, x8'),
        (0x184bc6950, 'ldr', 'w8, [x9, #0x28]'),
        (0x184bc6954, 'cbz', 'w8, #0x184bc6980'),
        (0x184bc697c, 'b', '#0x18806d240'),
        (0x184bc69ac, 'ldr', 'w9, [x19, #8]'),
        (0x184bc69b0, 'mov', 'w10, #0x24'),
        (0x184bc69b8, 'ldr', 'w8, [x19, #0x14]'),
        (0x184bc69bc, 'add', 'w10, w8, #0x64'),
        (0x184bc69c8, 'str', 'w10, [sp, #0x28]'),
        (0x184bc69cc, 'sub', 'w9, w8, #0x49'),
        (0x184bc69d0, 'cmn', 'w9, #9'),
        (0x184bc69d4, 'b.lo', '#0x184bc6a10'),
        (0x184bc69d8, 'mov', 'w9, #0x28'),
        (0x184bc69dc, 'umull', 'x9, w8, w9'),
        (0x184bc69e0, 'sub', 'x9, x9, #0x9f8'),
        (0x184bc69e8, 'add', 'x10, x10, #0x818'),
        (0x184bc69ec, 'ldr', 'x9, [x10, x9]'),
        (0x184bc69fc, 'blraaz', 'x9'),
        (0x184bc6a20, 'mov', 'w9, #-0x12f'),
        (0x184bc6a24, 'str', 'w9, [sp, #0x34]'),
        (0x184bc6a64, 'retab', ''),
        (0x184bc6a90, 'bl', '#0x18806c9b0'),
        (0x184bda3a4, 'bl', '#0x18806cb60'),
        (0x206c3f720, 'ldr', 'w0, [x0, #0x14]'),
        (0x180549bdc, 'ldr', 'w0, [x0, #8]'),
        (0x180549be0, 'and', 'w1, w20, #0x1f'),
        (0x180549be4, 'bl', '#0x180549d00'),
        (0x180549bf4, 'tbnz', 'w20, #0x1f, #0x180549c0c'),
        (0x180549c0c, 'ldr', 'w20, [x19, #0x18]'),
        (0x180549c18, 'add', 'x19, x19, #0x1c'),
        (0x180549c24, 'lsr', 'w9, w8, #0x18'),
        (0x180549c74, 'cmp', 'w9, #1'),
        (0x180549c7c, 'tst', 'w8, #0xff'),
        (0x180549c84, 'ldr', 'w2, [x19, #0xc]'),
        (0x180549c88, 'cbnz', 'w2, #0x180549cd0'),
        (0x180549cd0, 'ldr', 'x1, [x19]'),
        (0x180549cd8, 'bl', '#0x18054a7a4'),
        (0x180549d30, 'sub', 'w8, w1, #0x11'),
        (0x180549d34, 'cmp', 'w8, #2'),
        (0x180549d44, 'b', '#0x180549de8'),
        (0x180549e08, 'b', '#0x18054a06c'),
    ))
    evidence.span(0x184bc6958, 0x184bc6980, {0x184bc697c: '#0x18806d240'})
    evidence.span(0x184bc6a10, 0x184bc6a68, {
        0x184bc6a38: '#0x18806e260', 0x184bc6a40: '#0x18806d240',
        0x184bc6a4c: '#0x18806cb80',
    })
    evidence.span(0x184bbe2ec, 0x184bbe330, {
        0x184bbe2f4: '#0x188087710', 0x184bbe32c: '#0x184bbe4ac',
    })
    for address, value in (
        (0x184c002da, b'type\0'), (0x184c002df, b'handle\0'),
        (0x184bfc555, b'flags\0'), (0x184c0081c, b'name\0'), (0x184c00159, b'port\0'),
        (0x184bfb69b, b'MIG demux failed. This message ID is invalid: 0x%x\0'),
    ):
        assert evidence.record(address, len(value)) == value

    report = {'build': '26C5035r', 'cache_uuid': cache.uuid,
              'image_uuids': {Path(image.path).name: image.uuid
                              for image in (xpc, dispatch, kernel, pthread, asl, bsm)},
              'adid': adid, 'service_plist_sha256': sha256(launch_plist).hexdigest(),
              'launchd': launchd_audit(), 'bindings': bindings, 'once_block': once,
              'notification_demux': notification_rows(cache, evidence, xpc),
              'sdk': layout_audit(), 'cache_source': evidence.windows,
              'scope': 'Installed source and image identity. No IPC sent.'}
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
