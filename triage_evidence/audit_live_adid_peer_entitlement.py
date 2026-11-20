#!/usr/bin/env python3
"""Compare the live ADID peer entitlement using kernel exports and task tokens."""

import ctypes as C
from hashlib import sha256
import json
import os
from pathlib import Path
import plistlib
import struct
import subprocess

from audit_fairplay_native_xpc_observation import inventory
from audit_live_fairplay_adid_ipc import PROVIDER_SHA, ThinView
from audit_live_fairplay_client_entitlements import BUILD, identity, process, read_blob, signed_blobs
from audit_live_iokit_mach_transport import CACHE_UUID, clean_pointer, dyld_uuid
from bootpolicy_cache_reader import CS, Cache, Dylib

SECURITY = '/System/Library/Frameworks/Security.framework/Versions/A/Security'
COREFOUNDATION = '/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation'
LIBKERNEL = '/usr/lib/system/libsystem_kernel.dylib'
LIBBSM = '/usr/lib/libbsm.0.dylib'
LIBCE = '/usr/lib/libCoreEntitlements.dylib'
KEY = 'adi-client'
UTF8 = 0x08000100
TASK_AUDIT_TOKEN = 15
TOKEN_WORDS = 8


class AuditToken(C.Structure):
    _fields_ = [('words', C.c_uint32 * TOKEN_WORDS)]


def bind(library, name, result, *arguments):
    function = getattr(library, name)
    function.restype = result
    function.argtypes = arguments
    return function


class TaskQuery:
    def __init__(self):
        system, security, cf = C.CDLL(None), C.CDLL(SECURITY), C.CDLL(COREFOUNDATION)
        u32, ptr = C.c_uint32, C.c_void_p
        self.self_port = u32.in_dll(system, 'mach_task_self_').value
        self.name_for_pid = bind(system, 'task_name_for_pid', C.c_int, u32, C.c_int, C.POINTER(u32))
        self.task_info = bind(system, 'task_info', C.c_int, u32, C.c_int, ptr, C.POINTER(u32))
        self.deallocate = bind(system, 'mach_port_deallocate', C.c_int, u32, u32)
        self.make_task = bind(security, 'SecTaskCreateWithAuditToken', ptr, ptr, AuditToken)
        self.copy_value = bind(security, 'SecTaskCopyValueForEntitlement', ptr, ptr, ptr, C.POINTER(ptr))
        self.make_string = bind(cf, 'CFStringCreateWithCString', ptr, ptr, C.c_char_p, u32)
        self.get_type = bind(cf, 'CFGetTypeID', C.c_ulong, ptr)
        self.string_type = bind(cf, 'CFStringGetTypeID', C.c_ulong)
        self.equal = bind(cf, 'CFEqual', C.c_ubyte, ptr, ptr)
        self.release = bind(cf, 'CFRelease', None, ptr)

    def read(self, pid, expected_value):
        name = C.c_uint32()
        status = self.name_for_pid(self.self_port, pid, C.byref(name))
        result = {'task_name_status': status, 'task_name_returned': bool(name.value)}
        if status != 0:
            assert not name.value
            return result
        assert name.value
        token, words = AuditToken(), C.c_uint32(TOKEN_WORDS)
        try:
            task_status = self.task_info(name.value, TASK_AUDIT_TOKEN, C.byref(token), C.byref(words))
            assert task_status == 0 and words.value == TOKEN_WORDS and token.words[5] == pid
            result.update(task_info_status=task_status, token_words=words.value, token_pid_matches=True)
        finally:
            release_status = self.deallocate(self.self_port, name.value)
            assert release_status == 0
        result['task_name_reference_released'] = True

        task = self.make_task(None, token)
        key = self.make_string(None, KEY.encode(), UTF8)
        error, value, expected = C.c_void_p(), None, None
        try:
            assert task and key
            value = self.copy_value(task, key, C.byref(error))
            assert not error.value
            result.update(sec_task_value_present=bool(value), sec_task_error_present=False)
            if expected_value is None:
                assert not value
            else:
                assert value and self.get_type(value) == self.string_type()
                expected = self.make_string(None, expected_value.encode(), UTF8)
                assert expected and self.equal(value, expected)
                result.update(sec_task_type='CFString', sec_task_matches_live_export=True)
            return result
        finally:
            for object_ref in (expected, value, error.value, key, task):
                if object_ref:
                    self.release(object_ref)


def tlv(view, pos):
    assert pos + 2 <= len(view)
    tag, length = view[pos:pos + 2]
    assert tag & 0x1f != 0x1f
    pos += 2
    if length & 0x80:
        width = length & 0x7f
        assert 1 <= width <= 4 and pos + width <= len(view) and view[pos] != 0
        length = int.from_bytes(view[pos:pos + width], 'big')
        assert length >= 128
        pos += width
    end = pos + length
    assert end <= len(view)
    return tag, view[pos:end], end


def der_fields(blob):
    view = memoryview(blob)[8:]
    tag, wrapper, end = tlv(view, 0)
    assert tag == 0x70 and end == len(view)
    tag, version, pos = tlv(wrapper, 0)
    assert tag == 0x02 and version == b'\x01'
    tag, entries, end = tlv(wrapper, pos)
    assert tag == 0xb0 and end == len(wrapper)
    result = {}
    pos = 0
    while pos < len(entries):
        tag, entry, pos = tlv(entries, pos)
        assert tag == 0x30
        tag, key, value_start = tlv(entry, 0)
        assert tag == 0x0c
        value_tag, value, end = tlv(entry, value_start)
        text = bytes(key).decode('utf-8')
        assert end == len(entry) and text not in result
        result[text] = (value_tag, value)
    return result


def checked_instructions(read, expected):
    result = {}
    for pc, asm in expected:
        insn, = CS.disasm(read(pc, 4), pc)
        assert f'{insn.mnemonic} {insn.op_str}'.strip() == asm, hex(pc)
        result[hex(pc)] = {'instruction': asm, 'bytes': insn.bytes.hex()}
    return result


def framework_route():
    cache = Cache()
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    security, kernel, cf, bsm, ce = (Dylib(cache, path) for path in (
        SECURITY, LIBKERNEL, COREFOUNDATION, LIBBSM, LIBCE))
    assert security.uuid == '8125dd3c-bf42-3b79-9173-ce7e200f0eca'
    assert kernel.uuid == '780a6c1f-be02-34cc-84dd-00e05f61c89b'
    for image, name, pc in (
        (security, '_SecTaskCreateWithAuditToken', 0x1851e0fa4),
        (security, '_SecTaskCopyValueForEntitlement', 0x1851e12a4),
        (kernel, '_csops_audittoken', 0x1805495b4),
        (kernel, '_task_name_for_pid', 0x180548bf4),
        (kernel, '_task_info', 0x180549398),
    ):
        assert image.exports[name]['address'] == pc
    bindings = {}
    for pc, image, name in (
        (0x188088960, bsm, '_audit_token_to_au32'),
        (0x188089fc0, kernel, '_csops_audittoken'),
        (0x188072f00, cf, '_CFDataCreateWithBytesNoCopy'),
        (0x188088e60, ce, '_CEQueryContextToCFDictionary'),
        (0x188073100, cf, '_CFDictionaryGetValue'),
        (0x188073790, cf, '_CFRetain'),
    ):
        ops = list(CS.disasm(cache.read(pc, 16), pc))
        assert [op.mnemonic for op in ops] == ['adrp', 'add', 'ldr', 'braa']
        slot = sum(int(op.op_str.rsplit('#', 1)[-1], 16) for op in ops[:2])
        pointer = cache.pointer(slot)
        assert pointer['authenticated'] and pointer['chain_membership_verified']
        assert image.exports[name]['address'] == int(pointer['target'], 16)
        bindings[hex(pc)] = {**clean_pointer(pointer), 'symbol': name}
    instructions = checked_instructions(cache.read, (
        (0x1851e0fd8, 'ldp q0, q1, [x19]'), (0x1851e0fdc, 'stp q0, q1, [x0, #0x10]'),
        (0x1851e12dc, 'ldrb w8, [x20, #0x30]'), (0x1851e12ec, 'bl #0x1851e1330'),
        (0x1851e12f4, 'ldr x0, [x20, #0x38]'), (0x1851e1300, 'bl #0x188073100'),
        (0x1851e1310, 'bl #0x188073790'), (0x1851e1250, 'bl #0x188088960'),
        (0x1851e1258, 'add x4, x19, #0x10'), (0x1851e1268, 'bl #0x188089fc0'),
        (0x1851e1428, 'mov w1, #0x10'), (0x1851e142c, 'mov w3, #8'),
        (0x1851e1430, 'bl #0x1851e11f4'), (0x1851e14d8, 'cmp w8, #0x22'),
        (0x1851e14e4, 'rev w22, w8'), (0x1851e15bc, 'mov w1, #0x10'),
        (0x1851e15c4, 'mov x3, x22'), (0x1851e15c8, 'bl #0x1851e11f4'),
        (0x1851e15f8, 'sub w2, w22, #8'), (0x1851e1608, 'add x1, x21, #8'),
        (0x1851e160c, 'bl #0x188072f00'), (0x1851e1618, 'bl #0x1851b67e8'),
        (0x1851e167c, 'bl #0x188088e60'), (0x1805495b4, 'mov x16, #0xaa'),
        (0x1805495b8, 'svc #0x80'), (0x180548bf4, 'mov x16, #-0x2c'),
        (0x180548bf8, 'svc #0x80'), (0x18054942c, 'bl #0x180548f00'),
        (0x18054943c, 'stp w22, w0, [sp, #0x10]'), (0x180549468, 'mov x4, #0xd4d00000000'),
        (0x180549474, 'bl #0x18055b918'), (0x1805494b4, 'cmp w8, #0xdb1'),
        (0x180549568, 'add w9, w2, #0x28'), (0x1805495a4, 'bl #0x180548ef0'),
    ))
    assert struct.unpack('<II', cache.read(0x18057e410, 8)) == (0x1513, 40)
    assert struct.unpack('<II', cache.read(0x18057e9c8, 8)) == (0, 3405)
    return {'cache_uuid': cache.uuid, 'security_uuid': security.uuid, 'libkernel_uuid': kernel.uuid,
            'instructions': instructions, 'bindings': bindings,
            'task_info': {'request_id': 3405, 'reply_id': 3505, 'request_header_bits': '0x1513',
                          'request_bytes': 40, 'audit_token_reply_bytes': 72}}


def observe():
    assert os.geteuid() != 0
    assert subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip() == BUILD
    prior = json.loads(subprocess.check_output(['zstd', '-dcq', Path(__file__).with_name(
        'fairplay_native_xpc_observation.json.zst')]))
    assert prior['macos_build'] == BUILD
    before = inventory()
    query = TaskQuery()
    self_result = query.read(os.getpid(), None)
    assert self_result['task_name_status'] == 0
    clients = []
    adid_instructions = None
    for name, processes in before.items():
        for pid in sorted(processes):
            start, euid, path = process(pid)
            assert path.name == name and path.is_relative_to('/System/Library')
            observed = identity(pid)
            signed, source = signed_blobs(path, observed)
            xml, _ = read_blob(pid, 7, 0xfade7171)
            der, der_receipt = read_blob(pid, 16, 0xfade7172)
            assert xml and xml.find(b'\0', 8) == len(xml) - 1 and der == signed[7]
            fields = der_fields(der)
            dictionary = plistlib.loads(xml[8:-1])
            assert set(fields) == set(dictionary)
            value = dictionary.get(KEY)
            if name == 'akd':
                assert isinstance(value, str) and value.isascii() and value.isdecimal()
                assert fields[KEY] == (0x0c, value.encode())
            else:
                assert KEY not in dictionary
            security = query.read(pid, value)
            if euid == os.geteuid():
                assert security['task_name_status'] == 0
            else:
                assert security['task_name_status'] == 5
            assert observed == identity(pid) and (start, euid, path) == process(pid)
            if name == 'adid':
                row = source['slice']
                with path.open('rb') as stream:
                    stream.seek(row['file_offset_bytes'])
                    image = stream.read(row['slice_size_bytes'])
                assert sha256(image).hexdigest() == row['sha256'] == PROVIDER_SHA
                adid_instructions = checked_instructions(ThinView(image).read, (
                    (0x1001690fc, 'mov x17, #0xec8b'), (0x100169100, 'blraa x8, x17'),
                    (0x1001691c4, 'mov x17, #0x55b0'), (0x1001691c8, 'blraa x8, x17'),
                    (0x1001691cc, 'cmp x0, #0'), (0x1001691f0, 'braa x8, x17'),
                ))
            clients.append({
                'name': name, 'pid': pid, 'matches_prior_pid_and_start': (
                    processes[pid] == prior['process_inventory'][name]),
                'image_uuid': source['slice']['uuid'], 'live_identity': observed,
                'observer_uid_matches': euid == os.geteuid(), 'live_der_receipt': der_receipt,
                'live_der_matches_cd_bound_slot': True, 'xml_and_der_key_sets_equal': True,
                'adi_client_present': KEY in fields, 'adi_client_der_tag': fields[KEY][0] if value else None,
                'adi_client_is_decimal_string': value is not None, 'security': security,
            })
    assert before == inventory() and adid_instructions is not None
    assert sum(row['name'] == 'akd' and row['matches_prior_pid_and_start']
               and row['security']['sec_task_matches_live_export'] for row in clients) == 1
    return {'build': BUILD, 'prior_log_window_utc': [prior['start_utc'], prior['end_utc']],
            'adid_instructions': adid_instructions, 'framework_route': framework_route(),
            'clients': clients, 'self_control': self_result}


if __name__ == '__main__':
    print(json.dumps(observe(), indent=2, sort_keys=True))
