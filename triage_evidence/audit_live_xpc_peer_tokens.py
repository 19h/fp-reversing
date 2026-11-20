#!/usr/bin/env python3
"""Verify installed XPC audit metadata routing and an anonymous two-process exchange."""

from hashlib import sha256
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

from audit_fairplay_native_xpc_observation import inventory
from audit_live_adid_peer_entitlement import checked_instructions
from audit_live_fairplay_adid_ipc import PROVIDER_SHA, ThinView, bindings
from audit_live_fairplay_client_entitlements import BUILD, identity, process, signed_blobs
from audit_live_iokit_mach_transport import CACHE_UUID, dyld_uuid
from audit_live_xpc_log_sites import LIBXPC, connect_stub
from bootpolicy_cache_reader import Cache, Dylib


FUNCTIONS = {
    0x184bb80ec: '_xpc_receive_mach_msg',
    0x184bb85f4: '__xpc_graph_unpack_impl',
    0x184bb8b64: '_xpc_dictionary_get_audit_token',
    0x184bbd44c: '_xpc_connection_send_message_with_reply_sync',
    0x184bbddfc: '__xpc_connection_unpack_message',
    0x184bbdfa0: '__xpc_connection_mach_event',
    0x184bbffb8: '__xpc_connection_call_event_handler',
    0x184bc17d8: '__xpc_connection_handle_async_reply',
    0x184bc6820: '_xpc_dictionary_create_reply',
    0x184bc8f58: '_xpc_connection_get_audit_token',
    0x184bda15c: '__xpc_connection_check_peer_requirement',
    0x184be8cac: '_xpc_pipe_receive',
}

SITES = {
    'application_receive': (
        (0x184bbe3fc, 'bl #0x184bbddfc'),
        (0x184bbe410, 'bl #0x184bbffb8'),
        (0x184bc0020, 'mov x1, x19'),
        (0x184bc0024, 'blraa x8, x16'),
        (0x184bbd6cc, 'bl #0x184bbddfc'),
        (0x184bc1914, 'bl #0x184bbddfc'),
        (0x184bbde40, 'bl #0x184bda15c'),
        (0x184bbde44, 'tbz w0, #0, #0x184bbde74'),
        (0x184bbdf28, 'bl #0x184bb80ec'),
    ),
    'peer_requirement': (
        (0x184bda194, 'ldr w8, [x0, #0x18]'),
        (0x184bda198, 'cmp w8, #2'),
        (0x184bda19c, 'b.ne #0x184bda1e4'),
        (0x184bda1bc, 'ldr w8, [x19, #0x7c]'),
        (0x184bda1c0, 'ldr w9, [x22, #0x28]'),
        (0x184bda1c8, 'b.ne #0x184bda23c'),
        (0x184bda1cc, 'ldr w23, [x19, #0x84]'),
        (0x184bda1d0, 'ldr w22, [x22, #0x30]'),
        (0x184bda1e0, 'b.ne #0x184bda244'),
        (0x184bda1e4, 'ldr x8, [x19, #0xf0]'),
    ),
    'receive_record': (
        (0x184bb816c, 'ldp w9, w8, [x19, #4]'),
        (0x184bb8170, 'str wzr, [x19, #8]'),
        (0x184bb8198, 'stp w8, wzr, [sp, #0x10]'),
        (0x184bb81ac, 'add x8, x9, #3'),
        (0x184bb81b0, 'and x8, x8, #0x1fffffffc'),
        (0x184bb81b4, 'add x9, x19, x8'),
        (0x184bb81b8, 'ldur q0, [x9, #0x14]'),
        (0x184bb81bc, 'ldur q1, [x9, #0x24]'),
        (0x184bb81c0, 'stp q0, q1, [sp, #0x30]'),
        (0x184be8d20, 'bl #0x184bb80ec'),
        (0x184be8d98, 'mov w25, #0xa06'),
        (0x184be8d9c, 'movk w25, #0x300, lsl #16'),
    ),
    'dictionary_token': (
        (0x184bb8858, 'and w8, w8, #0xfffffffc'),
        (0x184bb885c, 'orr w8, w8, #1'),
        (0x184bb8860, 'str w8, [x0, #0x1c]'),
        (0x184bb88e4, 'tbz w22, #0, #0x184bb8910'),
        (0x184bb88ec, 'stur q0, [x20, #0x58]'),
        (0x184bb8900, 'ldp q0, q1, [x19, #0x20]'),
        (0x184bb8904, 'stur q0, [x20, #0x78]'),
        (0x184bb8908, 'stur q1, [x20, #0x88]'),
        (0x184bb8b94, 'ldr w8, [x20, #0x1c]'),
        (0x184bb8b98, 'and w8, w8, #3'),
        (0x184bb8ba8, 'ldur q0, [x20, #0x78]'),
        (0x184bb8bac, 'ldur q1, [x20, #0x88]'),
        (0x184bb8bbc, 'ldur q0, [x20, #0x58]'),
        (0x184bb8bc0, 'ldur q1, [x20, #0x68]'),
        (0x184bb8bc4, 'stp q0, q1, [x19]'),
        (0x184bb8bcc, 'movi v0.2d, #0xffffffffffffffff'),
        (0x184bb8bd0, 'stp q0, q0, [x19]'),
        (0x184bb8bd4, 'str wzr, [x19, #0x14]'),
    ),
    'reply_creation': (
        (0x184bc685c, 'cmp w8, #1'),
        (0x184bc6860, 'b.ne #0x184bc68c8'),
        (0x184bc6864, 'mov x21, x19'),
        (0x184bc6868, 'ldr x8, [x21, #0x58]!'),
        (0x184bc686c, 'cbz x8, #0x184bc68c8'),
        (0x184bc6894, 'orr w8, w8, #2'),
        (0x184bc6898, 'str w8, [x0, #0x1c]'),
        (0x184bc689c, 'ldr q0, [x21]'),
        (0x184bc68a0, 'str q0, [x0, #0x60]'),
        (0x184bc68a4, 'ldr x8, [x21, #0x10]'),
        (0x184bc68a8, 'str x8, [x0, #0x70]'),
        (0x184bc68ac, 'stp xzr, xzr, [x21]'),
        (0x184bc68b0, 'str xzr, [x21, #0x10]'),
        (0x184bc68b4, 'ldr x0, [x19, #0x70]'),
        (0x184bc68c0, 'str x0, [x20, #0x58]'),
    ),
    'connection_token': (
        (0x184bbdf34, 'cmn w8, #1'),
        (0x184bbdf38, 'b.eq #0x184bbdf74'),
        (0x184bbdf48, 'add x21, x19, x8'),
        (0x184bbdf4c, 'add x0, x20, #0x58'),
        (0x184bbdf54, 'bl #0x18806cad0'),
        (0x184bbdf58, 'ldur q0, [x21, #0x14]'),
        (0x184bbdf5c, 'ldur q1, [x21, #0x24]'),
        (0x184bbdf60, 'stur q1, [x20, #0x78]'),
        (0x184bbdf64, 'stur q0, [x20, #0x68]'),
        (0x184bbdf6c, 'bl #0x18806cae0'),
        (0x184bc8f70, 'add x0, x0, #0x58'),
        (0x184bc8f78, 'bl #0x18806cad0'),
        (0x184bc8f7c, 'ldur q0, [x20, #0x68]'),
        (0x184bc8f80, 'ldur q1, [x20, #0x78]'),
        (0x184bc8f84, 'stp q0, q1, [x19]'),
        (0x184bc8fa4, 'b #0x18806cae0'),
    ),
}


def installed_transport():
    cache = Cache()
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    xpc = Dylib(cache, LIBXPC)
    assert xpc.uuid == '94e40b03-44c5-3636-aa1a-c64a5d6b6bbb'
    for address, name in FUNCTIONS.items():
        assert name in {row['name'] for row in xpc.symbols_at(address)}
    for address in (0x184bb8b64, 0x184bbd44c, 0x184bc6820, 0x184bc8f58, 0x184be8cac):
        assert xpc.exports[FUNCTIONS[address]]['address'] == address
    platform = Dylib(cache, '/usr/lib/system/libsystem_platform.dylib')
    locks = [
        connect_stub(cache, 0x18806cad0, platform, '_os_unfair_lock_lock_with_options'),
        connect_stub(cache, 0x18806cae0, platform, '_os_unfair_lock_unlock'),
    ]
    return {
        'cache_uuid': cache.uuid,
        'libxpc_uuid': xpc.uuid,
        'functions': {name: hex(pc) for pc, name in FUNCTIONS.items()},
        'locking_bindings': locks,
        'instructions': {step: checked_instructions(cache.read, checks)
                         for step, checks in SITES.items()},
    }


def installed_adid():
    pid, = inventory()['adid']
    start, euid, path = process(pid)
    live_identity = identity(pid)
    _, source = signed_blobs(path, live_identity)
    row = source['slice']
    with path.open('rb') as stream:
        stream.seek(row['file_offset_bytes'])
        image = stream.read(row['slice_size_bytes'])
    assert sha256(image).hexdigest() == row['sha256'] == PROVIDER_SHA
    assert row['uuid'] == '4d24325f-3529-39b1-bbf8-64bbcf406049'
    slot = 0x1002d8a18
    binding = bindings(path, '-arch', 'arm64e')[slot]
    assert binding == 'auth-bind libSystem/_xpc_dictionary_get_audit_token (div=0xD178 ad=0 key=IA)'
    instructions = checked_instructions(ThinView(image).read, (
        (0x1000aa4b0, 'ldr x8, [x22, w8, uxtw #3]'),
        (0x1000aa4b4, 'add x1, sp, #0x60'),
        (0x1000aa4b8, 'mov x0, x20'),
        (0x1000aa4bc, 'mov x17, #0xd178'),
        (0x1000aa4c0, 'blraa x8, x17'),
    ))
    assert live_identity == identity(pid) and (start, euid, path) == process(pid)
    return {'uuid': row['uuid'], 'slice_sha256': row['sha256'], 'slot': hex(slot),
            'binding': binding, 'instructions': instructions}


def probe():
    source = Path(__file__).with_name('xpc_peer_audit_probe.c')
    with TemporaryDirectory() as temporary:
        program = Path(temporary) / 'xpc-peer-audit-probe'
        subprocess.run(['xcrun', '--sdk', 'macosx', 'clang', '-std=c17', '-Wall', '-Wextra',
                        '-Werror', '-fblocks', '-o', program, source], check=True)
        result = json.loads(subprocess.check_output([program], timeout=18))
    assert result == {
        'separate_processes': True,
        'bootstrap_token_pairs': 1,
        'connection_token_pairs': 2,
        'dictionary_and_peer_tokens_match': True,
        'task_info_tokens_match': True,
        'request_token_survives_reply_creation': True,
        'unattached_dictionary_has_default_token': True,
    }
    return {'source': source.name, 'source_sha256': sha256(source.read_bytes()).hexdigest(),
            'observed': result}


def main():
    assert subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip() == BUILD
    receipt = {'macos_build': BUILD, 'transport': installed_transport(), 'adid': installed_adid(),
               'anonymous_probe': probe()}
    print(json.dumps(receipt, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
