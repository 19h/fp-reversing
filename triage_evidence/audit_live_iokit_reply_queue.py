#!/usr/bin/env python3
"""Trace ordinary IOKit reply-port construction and measure reply queue use."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import ctypes
import json
from pathlib import Path
import struct
import subprocess

from audit_live_iokit_main_port import BUILD, mig_record
from audit_live_iokit_mach_transport import CACHE_UUID, IOKIT, LIBKERNEL, dyld_uuid, record_windows
from audit_live_iokit_matching import SERVICE_CLASS
from audit_live_iokit_mig_reply_port import INVALID_NAME, RECEIVE_RIGHT, TYPE_RECEIVE
from audit_live_kext_selector26 import Collection, IDENTITIES
from bootpolicy_cache_reader import CS, Cache, Dylib

RECEIVE_STATUS = 2
STATUS_WORDS = (
    'port_set_count', 'sequence', 'make_send_count', 'queue_limit', 'queued_messages',
    'send_once_rights', 'has_send_rights', 'port_deleted_request', 'no_senders_request', 'flags',
)


def kernel(image):
    trap = 0xfffffe0007f07018 + 24 * 24
    assert image.read(trap, 2) == bytes((4, 5))
    handler = image.pointer(trap + 8)
    assert (handler['target'], handler['auth'], handler['diversity']) == (
        '0xfffffe000bd23c98', 1, '0x307a')
    name = image.pointer(0xfffffe0007f07c18 + 8 * 24)
    expected_name = b'_kernelrpc_mach_port_construct_trap\0'
    assert image.read(int(name['target'], 16), len(expected_name)) == expected_name
    subsystem = 0xfffffe0007e73b08
    assert struct.unpack('<4I', image.read(subsystem + 8, 16)) == (3200, 3243, 576, 0)
    fallback = mig_record(image, subsystem, 3200, 3231, 0xfffffe000bdcf6fc, (5, 0, 0, 48))

    checks = (
        (0xfffffe000bebfba4, 'sub', 'x20, x9, w8, sxtw'),
        (0xfffffe000bebfbb0, 'add', 'x8, x20, x20, lsl #1'),
        (0xfffffe000bebfbb4, 'lsl', 'x8, x8, #3'),
        (0xfffffe000bebfbb8, 'adrp', 'x9, #0xfffffe0007f07000'),
        (0xfffffe000bebfbbc, 'add', 'x9, x9, #0x18'),
        (0xfffffe000bebfbd4, 'ldr', 'x22, [x23, #8]'),
        (0xfffffe000bebfcc8, 'blraa', 'x22, x17'),
        (0xfffffe000bd23cb0, 'ldr', 'w0, [x0]'),
        (0xfffffe000bd23cb8, 'bl', '#0xfffffe000bd433e4'),
        (0xfffffe000bd23cd0, 'ldr', 'x0, [x19, #8]'),
        (0xfffffe000bd23cd8, 'mov', 'w2, #0x18'),
        (0xfffffe000bd23cdc, 'bl', '#0xfffffe000bebfe58'),
        (0xfffffe000bd23cf8, 'ldr', 'x16, [x20, #0x318]'),
        (0xfffffe000bd23d08, 'autda', 'x16, x17'),
        (0xfffffe000bd23d18, 'ldr', 'x2, [x19, #0x10]'),
        (0xfffffe000bd23d20, 'sub', 'x3, x29, #0x14'),
        (0xfffffe000bd23d24, 'bl', '#0xfffffe000bd27fac'),
        (0xfffffe000bd23d28, 'cbnz', 'w0, #0xfffffe000bd23d48'),
        (0xfffffe000bd23d2c, 'ldr', 'x1, [x19, #0x18]'),
        (0xfffffe000bd23d34, 'mov', 'w2, #4'),
        (0xfffffe000bd23d38, 'bl', '#0xfffffe000bec09cc'),
        (0xfffffe000bdcf720, 'cmp', 'w8, #1'),
        (0xfffffe000bdcf72c, 'cmp', 'w8, #0x44'),
        (0xfffffe000bdcf738, 'cmp', 'w8, #1'),
        (0xfffffe000bdcf744, 'cmp', 'w8, #0x18'),
        (0xfffffe000bdcf7d0, 'bl', '#0xfffffe000bd27fac'),
        (0xfffffe000bdcf834, 'mov', 'w8, #0x30'),
        (0xfffffe000bd2802c, 'and', 'w8, w8, #0x1fc00'),
        (0xfffffe000bd28030, 'and', 'w9, w8, #0xffffdfff'),
        (0xfffffe000bd28088, 'cmp', 'w9, #1, lsl #12'),
        (0xfffffe000bd2808c, 'b.eq', '#0xfffffe000bd280a4'),
        (0xfffffe000bd280ac, 'ldr', 'x16, [x17, #0x58]!'),
        (0xfffffe000bd280b4, 'autda', 'x16, x17'),
        (0xfffffe000bd28134, 'cmp', 'w9, #1, lsl #12'),
        (0xfffffe000bd2813c, 'mov', 'w8, #0xa'),
        (0xfffffe000bd28140, 'strb', 'w8, [sp]'),
        (0xfffffe000bd2814c, 'mov', 'w25, #0xc'),
        (0xfffffe000bd2817c, 'strb', 'w25, [sp]'),
        (0xfffffe000bd28180, 'mov', 'w8, #0x28'),
        (0xfffffe000bd28188, 'adrp', 'x9, #0xfffffe0007e6e000'),
        (0xfffffe000bd2818c, 'add', 'x9, x9, #0xb70'),
        (0xfffffe000bd28194, 'ldr', 'x24, [x10, #0x10]'),
        (0xfffffe000bd2843c, 'mov', 'w25, #0xa'),
        (0xfffffe000bd28440, 'b', '#0xfffffe000bd28180'),
        (0xfffffe000bd28308, 'ubfx', 'w3, w24, #4, #1'),
        (0xfffffe000bd2830c, 'ldr', 'x22, [sp]'),
        (0xfffffe000bd28320, 'bl', '#0xfffffe000bd14ef4'),
        (0xfffffe000bd28330, 'tbz', 'w8, #1, #0xfffffe000bd28348'),
        (0xfffffe000bd283a8, 'tbnz', 'w8, #0, #0xfffffe000bd283c4'),
        (0xfffffe000bd283b0, 'str', 'x19, [x21, #0x78]'),
        (0xfffffe000bd14f60, 'bl', '#0xfffffe000bd041e8'),
        (0xfffffe000bd14fd0, 'ands', 'w27, w26, #1'),
        (0xfffffe000bd14fd4, 'mov', 'w8, #0x30000'),
        (0xfffffe000bd14fd8, 'mov', 'w9, #0x20000'),
        (0xfffffe000bd14fdc, 'csel', 'w28, w9, w8, eq'),
        (0xfffffe000bd15000, 'bl', '#0xfffffe000bd15064'),
        (0xfffffe000bd1501c, 'bl', '#0xfffffe000bd134ac'),
        (0xfffffe000bd15028, 'str', 'w21, [x22]'),
        (0xfffffe000bd15030, 'str', 'x19, [x8]'),
        (0xfffffe000bd15108, 'str', 'xzr, [x0, #0x28]'),
        (0xfffffe000bd1510c, 'mov', 'w9, #5'),
        (0xfffffe000bd15110, 'strh', 'w9, [x0, #0x3a]'),
        (0xfffffe000bd15114, 'str', 'xzr, [x0, #0x40]'),
        (0xfffffe000bd15118, 'str', 'w5, [x0, #0x34]'),
        (0xfffffe000bd15144, 'str', 'w9, [x0]'),
        (0xfffffe000bd1359c, 'str', 'x17, [x21]'),
        (0xfffffe000bd135a4, 'orr', 'w9, w22, w23'),
        (0xfffffe000bd135ac, 'str', 'w8, [x21, #8]'),
    )
    for pc, mnemonic, operands in checks:
        image.instruction(pc, mnemonic, operands)
    labels = {}
    for value, expected in ((10, 'reply port'), (11, 'special reply port'), (12, 'weak reply port')):
        row = 0xfffffe0007e6eb70 + 40 * value
        pointer = image.pointer(row)
        raw = expected.encode() + b'\0'
        assert image.read(int(pointer['target'], 16), len(raw)) == raw
        labels[value] = {'policy_row': hex(row), 'name_binding': pointer, 'name': expected}
    assert image.read(0xfffffe00070109e0, 16) == bytes.fromhex('01010000000000000000000000000000')
    return {
        'kernel_uuid': IDENTITIES[1][1], 'fileset_sha256': image.digest,
        'trap': {'selector': -24, 'handler': handler, 'name': name, 'argument_count': 4},
        'fallback_rpc': fallback, 'installed_policy_labels': labels,
        'instruction_checks': [[hex(pc), mnemonic, operands] for pc, mnemonic, operands in checks],
        'windows': record_windows(image.read, (
            (0xfffffe000bebfba4, 0x130), (0xfffffe000bd23c98, 0xbc),
            (0xfffffe000bdcf6fc, 0x160), (0xfffffe000bd27fac, 0x56c),
            (0xfffffe000bd14ef4, 0x170), (0xfffffe000bd15064, 0x128),
            (0xfffffe000bd134ac, 0x160), (0xfffffe00070109e0, 16),
            (0xfffffe0007e6ed00, 120),
        )),
    }


def library():
    cache = Cache()
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    image = Dylib(cache, LIBKERNEL)
    assert image.uuid == '780a6c1f-be02-34cc-84dd-00e05f61c89b'
    assert image.exports['_mach_port_construct']['address'] == 0x180549e9c
    checks = (
        (0x180548f4c, 'bl #0x180549e9c'), (0x180548f58, 'str x0, [x19, #0x10]'),
        (0x180549ec0, 'bl #0x180548b10'), (0x180549ec4, 'mov w8, #3'),
        (0x180549ec8, 'movk w8, #0x1000, lsl #16'), (0x180549ecc, 'cmp w0, w8'),
        (0x180549ed0, 'b.ne #0x180549f04'), (0x180549f00, 'b #0x18056efbc'),
        (0x180548b10, 'mov x16, #-0x18'), (0x180548b14, 'svc #0x80'),
        (0x18056efe4, 'stur x1, [sp, #0x1c]'), (0x18056efec, 'ldr d0, [x8, #0x770]'),
        (0x18056eff0, 'stur d0, [sp, #0x24]'), (0x18056f000, 'stur x2, [sp, #0x34]'),
        (0x18056f034, 'movk x2, #0x3c, lsl #32'), (0x18056f044, 'mov x4, #0xc9f00000000'),
        (0x18056f050, 'bl #0x18055b918'), (0x18056f08c, 'cmp w8, #0xd03'),
    )
    for pc, expected in checks:
        insn, = CS.disasm(cache.read(pc, 4), pc)
        assert f'{insn.mnemonic} {insn.op_str}' == expected
    options = cache.read(0x18057edc0, 16)
    assert options == struct.pack('<4I', 0x1000, 0, 0, 0)
    assert cache.read(0x18057e770, 8) == bytes.fromhex('0001000118000000')
    return {'cache_uuid': cache.uuid, 'libkernel_uuid': image.uuid,
            'options_literal': options.hex(),
            'instruction_checks': {hex(pc): expected for pc, expected in checks},
            'windows': record_windows(cache.read, (
                (0x180548f00, 0x94), (0x180549e9c, 0x78), (0x180548b10, 12),
                (0x18056efbc, 0xe8), (0x18057e770, 8), (0x18057edc0, 16),
            ))}


def observe():
    assert subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip() == BUILD
    assert subprocess.check_output(['sysctl', '-n', 'kern.uuid'], text=True).strip().lower() == IDENTITIES[1][1]
    mach, io = ctypes.CDLL(LIBKERNEL), ctypes.CDLL(IOKIT)
    u32 = ctypes.c_uint32
    out = ctypes.POINTER(u32)
    status = ctypes.c_int

    def bind(lib, symbol, result, *args):
        function = getattr(lib, symbol)
        function.restype, function.argtypes = result, args
        return function

    task = u32.in_dll(mach, 'mach_task_self_').value
    get = bind(mach, 'mig_get_reply_port', u32)
    retire = bind(mach, 'mig_dealloc_reply_port', None, u32)
    attributes = bind(mach, 'mach_port_get_attributes', status, u32, u32, status, out, out)
    port_type = bind(mach, 'mach_port_type', status, u32, u32, out)
    refs = bind(mach, 'mach_port_get_refs', status, u32, u32, status, out)
    deallocate = bind(mach, 'mach_port_deallocate', status, u32, u32)
    io_main = bind(io, 'IOMainPort', status, u32, out)
    matching = bind(io, 'IOServiceMatching', ctypes.c_void_p, ctypes.c_char_p)
    match = bind(io, 'IOServiceGetMatchingServices', status, u32, ctypes.c_void_p, out)
    next_service = bind(io, 'IOIteratorNext', u32, u32)
    release = bind(io, 'IOObjectRelease', status, u32)

    def snapshot(name):
        value = u32()
        assert port_type(task, name, ctypes.byref(value)) == 0 and value.value == TYPE_RECEIVE
        assert refs(task, name, RECEIVE_RIGHT, ctypes.byref(value)) == 0 and value.value == 1
        words = (u32 * len(STATUS_WORDS))()
        count = u32(len(words))
        assert attributes(task, name, RECEIVE_STATUS, words, ctypes.byref(count)) == 0
        assert count.value == len(words)
        return dict(zip(STATUS_WORDS, words, strict=True))

    phases = []
    with ThreadPoolExecutor(max_workers=1) as pool:
        observer = pool.submit(get).result(timeout=10)
        try:
            previous = get()
            retire(previous)
            name = get()

            def sample(phase):
                assert get() == name
                phase_status = pool.submit(snapshot, name).result(timeout=10)
                phases.append(dict(phase_status, phase=phase))

            main, iterator = u32(), u32()
            service = 0
            try:
                assert name and observer and len({previous, name, observer}) == 3
                sample('new_receive_right')
                sample('observer_control')
                try:
                    assert io_main(0, ctypes.byref(main)) == 0 and main.value
                    sample('IOMainPort')
                    criteria = matching(SERVICE_CLASS.encode())
                    assert criteria and match(main.value, criteria, ctypes.byref(iterator)) == 0 and iterator.value
                    sample('IOServiceGetMatchingServices')
                    service = next_service(iterator.value)
                    assert service
                    sample('IOIteratorNext')
                finally:
                    release_results = [release(handle) for handle in (service, iterator.value) if handle]
                    if main.value:
                        release_results.append(deallocate(task, main.value))
                    assert all(result == 0 for result in release_results)
                sample('released_discovery_rights')
            finally:
                retire(name)
            value = u32()
            after = port_type(task, name, ctypes.byref(value))
            assert after == INVALID_NAME
        finally:
            pool.submit(retire, observer).result(timeout=10)
    assert [phase['sequence'] for phase in phases] == [0, 0, 2, 3, 4, 4], phases
    expected = dict.fromkeys(STATUS_WORDS, 0)
    del expected['sequence']
    expected['queue_limit'] = 5
    assert all({key: phase[key] for key in expected} == expected for phase in phases)
    return {'build': BUILD, 'kernel_uuid': IDENTITIES[1][1], 'service_class': SERVICE_CLASS,
            'observer_has_distinct_mig_receive_right': True, 'receive_right_type': hex(TYPE_RECEIVE),
            'receive_user_refs_per_sample': 1, 'phases': phases, 'right_release_results': release_results,
            'post_retirement_lookup_status': after}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('--observe', action='store_true')
    args = parser.parse_args()
    result = {'kernel': kernel(Collection(args.collection, IDENTITIES[1])), 'libkernel': library()}
    if args.observe:
        result['verifier_process'] = observe()
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
