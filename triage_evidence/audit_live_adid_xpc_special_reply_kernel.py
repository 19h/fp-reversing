#!/usr/bin/env python3
"""Verify the user special reply trap and synchronous Mach2 receive from source bytes."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess

from audit_adid_legacy_mach_receive import Evidence, cached_image, veneer
from audit_archived_iokit_open_retirement import TRACE_SHA
from audit_live_fairplay_reply_rights import compiler_ranges
from audit_live_iokit_mach_transport import CACHE_UUID, dyld_uuid
from audit_live_kext_selector26 import Collection, IDENTITIES
from bootpolicy_cache_reader import CS, Cache


def kernel(path):
    image = Collection(path, IDENTITIES[1])
    boot = subprocess.check_output(['kmutil', 'inspect', '--show-kernel-uuid-only'],
                                   stderr=subprocess.STDOUT).decode().lower()
    assert IDENTITIES[1][1] in boot
    bounds = compiler_ranges(image)
    evidence = Evidence(image.read)
    traps = {}
    for index, name, counts, handler in (
        (47, b'mach_msg2_trap', b'\x08\x10', 0xfffffe000bd25630),
        (50, b'thread_get_special_reply_port', b'\0\0', 0xfffffe000bd40b94),
    ):
        entry = 0xfffffe0007f07018 + 24 * index
        identity = image.pointer(0xfffffe0007f07c18 + 8 * index)
        pointer = image.pointer(entry + 8)
        assert evidence.record(entry, 2) == counts
        assert evidence.record(int(identity['target'], 16), len(name) + 1) == name + b'\0'
        assert (int(pointer['target'], 16), pointer['auth'], pointer['diversity']) == (
            handler, 1, '0x307a')
        traps[-index] = {'name': name.decode(), 'counts': list(counts), 'pointer': pointer}
    functions = {}
    for start in (
        0xfffffe000bd40b94, 0xfffffe000bd14ef4, 0xfffffe000bd15064, 0xfffffe000bd134ac,
        0xfffffe000bd164ac, 0xfffffe000bd40d08, 0xfffffe000bd25630, 0xfffffe000bd253d8,
        0xfffffe000bd10cb0, 0xfffffe000bd112a0, 0xfffffe000bd16e24,
    ):
        _, end = bounds[start]
        raw = evidence.record(start, end - start)
        assert sum(i.size for i in CS.disasm(raw, start)) == len(raw)
        functions[hex(start)] = {'end': hex(end), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
    evidence.check([
        (0xfffffe000bd40bac, 'mrs', 'x19, tpidr_el1'),
        (0xfffffe000bd40bb4, 'ldr', 'x16, [x19, #0x450]'),
        (0xfffffe000bd40bc4, 'autda', 'x16, x17'),
        (0xfffffe000bd40bdc, 'bl', '#0xfffffe000bd1401c'),
        (0xfffffe000bd40be0, 'str', 'xzr, [x20]'),
        (0xfffffe000bd40bec, 'mov', 'w2, #4'),
        (0xfffffe000bd40bf4, 'bl', '#0xfffffe000bd164ac'),
        (0xfffffe000bd40c00, 'ldaddl', 'w8, w8, [x0]'),
        (0xfffffe000bd1650c, 'str', 'xzr, [x19, #0x40]'),
        (0xfffffe000bd40c14, 'bl', '#0xfffffe000bdc68b8'),
        (0xfffffe000bd40c18, 'ldr', 'x16, [x0, #0x318]'),
        (0xfffffe000bd40c28, 'autda', 'x16, x17'),
        (0xfffffe000bd40c44, 'add', 'x4, sp, #4'),
        (0xfffffe000bd40c48, 'add', 'x5, sp, #8'),
        (0xfffffe000bd40c4c, 'mov', 'w1, #0x10b'),
        (0xfffffe000bd40c50, 'mov', 'x2, #0'),
        (0xfffffe000bd40c54, 'mov', 'w3, #1'),
        (0xfffffe000bd40c58, 'bl', '#0xfffffe000bd14ef4'),
        (0xfffffe000bd40c60, 'mov', 'w0, #0'),
        (0xfffffe000bd40c64, 'cbnz', 'w8, #0xfffffe000bd40cd0'),
        (0xfffffe000bd40c70, 'ldadd', 'w21, w9, [x0]'),
        (0xfffffe000bd40ca8, 'str', 'x9, [x19, #0x450]'),
        (0xfffffe000bd40cb8, 'str', 'x17, [x8, #0x40]'),
        (0xfffffe000bd40ccc, 'ldr', 'w0, [sp, #4]'),
        (0xfffffe000bd14f60, 'bl', '#0xfffffe000bd041e8'),
        (0xfffffe000bd14fd0, 'ands', 'w27, w26, #1'),
        (0xfffffe000bd14fd4, 'mov', 'w8, #0x30000'),
        (0xfffffe000bd14fd8, 'mov', 'w9, #0x20000'),
        (0xfffffe000bd14fdc, 'csel', 'w28, w9, w8, eq'),
        (0xfffffe000bd15000, 'bl', '#0xfffffe000bd15064'),
        (0xfffffe000bd1501c, 'bl', '#0xfffffe000bd134ac'),
        (0xfffffe000bd15028, 'str', 'w21, [x22]'),
        (0xfffffe000bd15030, 'str', 'x19, [x8]'),
        (0xfffffe000bd15118, 'str', 'w5, [x0, #0x34]'),
        (0xfffffe000bd15138, 'str', 'x17, [x0, #0x48]'),
        (0xfffffe000bd15140, 'bfi', 'w9, w8, #8, #8'),
        (0xfffffe000bd15144, 'str', 'w9, [x0]'),
        (0xfffffe000bd15164, 'tbz', 'w4, #0, #0xfffffe000bd15170'),
        (0xfffffe000bd1516c, 'stur', 'd0, [x0, #0x84]'),
        (0xfffffe000bd135a4, 'orr', 'w9, w22, w23'),
        (0xfffffe000bd135ac, 'str', 'w8, [x21, #8]'),
        (0xfffffe000bd40d64, 'ldr', 'x21, [x8, #0x348]'),
        (0xfffffe000bd40d88, 'mov', 'w2, #0x10b'),
        (0xfffffe000bd40d94, 'mov', 'w5, #1'),
        (0xfffffe000bd40d98, 'bl', '#0xfffffe000bd15064'),
        (0xfffffe000bd40db8, 'str', 'x20, [x19, #0x3f0]'),
        (0xfffffe000bd2574c, 'tbnz', 'w27, #1, #0xfffffe000bd257bc'),
        (0xfffffe000bd2596c, 'lsr', 'x7, x8, #0x20'),
        (0xfffffe000bd25970, 'tst', 'x27, #0x4000'),
        (0xfffffe000bd25974, 'csel', 'w4, wzr, w25, eq'),
        (0xfffffe000bd25980, 'bl', '#0xfffffe000bd253d8'),
        (0xfffffe000bd25458, 'bl', '#0xfffffe000bd10cb0'),
        (0xfffffe000bd2548c, 'cbz', 'w27, #0xfffffe000bd25580'),
        (0xfffffe000bd25490, 'ldr', 'x16, [x19, #0x450]'),
        (0xfffffe000bd254a0, 'autda', 'x16, x17'),
        (0xfffffe000bd254a4, 'cmn', 'w27, #1'),
        (0xfffffe000bd254a8, 'b.eq', '#0xfffffe000bd254d0'),
        (0xfffffe000bd254ac, 'cmp', 'x16, x26'),
        (0xfffffe000bd254b0, 'b.ne', '#0xfffffe000bd254d0'),
        (0xfffffe000bd254d8, 'ldaddl', 'w8, w8, [x0]'),
        (0xfffffe000bd254e0, 'mov', 'w23, #0x4007'),
        (0xfffffe000bd254e4, 'movk', 'w23, #0x1000, lsl #16'),
        (0xfffffe000bd25514, 'bl', '#0xfffffe000bd112a0'),
        (0xfffffe000bd112e8, 'tbz', 'w9, #0x10, #0xfffffe000bd112f8'),
        (0xfffffe000bd25524, 'cbnz', 'w0, #0xfffffe000bd2557c'),
        (0xfffffe000bd2555c, 'mov', 'w2, #0'),
        (0xfffffe000bd25560, 'bl', '#0xfffffe000bd16e24'),
        (0xfffffe000bd2556c, 'ldaddl', 'w8, w8, [x0]'),
        (0xfffffe000bd16ecc, 'cmp', 'w8, #0xb'),
        (0xfffffe000bd16ed8, 'tst', 'w8, #0x7000'),
        (0xfffffe000bd16f8c, 'ldadd', 'w9, w9, [x0]'),
        (0xfffffe000bd16fb8, 'str', 'x17, [x20, #0x58]'),
        (0xfffffe000bd16fc4, 'orr', 'w8, w8, #0x1000'),
        (0xfffffe000bd16fc8, 'str', 'w8, [x20, #0x10]'),
        (0xfffffe000bd255a4, 'str', 'x26, [x19, #0x398]'),
        (0xfffffe000bd255a8, 'str', 'x21, [x19, #0x390]'),
        (0xfffffe000bd255b0, 'add', 'x0, x26, #0x10'),
        (0xfffffe000bd255c4, 'bl', '#0xfffffe000bd10370'),
    ])
    assert evidence.record(0xfffffe0007e6ed30, 2) == b'\x40\0'
    publication = {
        flag: {'type_bits': 0x30000 if flag else 0x20000, 'send_urefs': flag}
        for flag in (0, 1)
    }
    return {'sha256': image.digest, 'kernel_uuid': IDENTITIES[1][1], 'kext_uuid': IDENTITIES[1][2],
            'trap_rows': traps, 'functions': functions, 'windows': evidence.windows,
            'namespace_publication_by_flag': publication, 'trap_50_allocation_flag': 1}


def userspace():
    cache = Cache()
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    libkernel = cached_image(cache, 'libsystem_kernel.dylib', '780a6c1f-be02-34cc-84dd-00e05f61c89b')
    dispatch = cached_image(cache, 'libdispatch.dylib', '435a06f9-1bc8-3282-8663-b6418c44a05e')
    evidence = Evidence(cache.read)
    bindings = {
        'special_port': veneer(cache, evidence, 0x188087d50, libkernel, '_thread_get_special_reply_port',
                               0x180548c3c),
        'receive': veneer(cache, evidence, 0x18806d230, libkernel, '_mach_msg', 0x180548f94),
    }
    evidence.check([
        (0x1855b0bec, 'bl', '#0x188087d50'),
        (0x1855b0c7c, 'ldr', 'w19, [x8, #0x5c]'),
        (0x1855b0d08, 'orr', 'w10, w9, #0x4000'),
        (0x1855b0d10, 'csel', 'w26, w10, w9, lo'),
        (0x1855b0d14, 'csel', 'w27, w19, wzr, lo'),
        (0x1855b0d3c, 'mov', 'w2, #0'),
        (0x1855b0d44, 'mov', 'x4, x24'),
        (0x1855b0d4c, 'mov', 'x6, x27'),
        (0x1855b0d50, 'bl', '#0x18806d230'),
        (0x180548c3c, 'mov', 'x16, #-0x32'),
        (0x180548c40, 'svc', '#0x80'),
        (0x180548fa8, 'bl', '#0x180551848'),
        (0x180551964, 'mov', 'w9, #0x4003'),
        (0x18055196c, 'mov', 'w10, #0x4002'),
        (0x180551974, 'b.ne', '#0x18055197c'),
        (0x180551978, 'str', 'w24, [x20, #8]'),
        (0x1805519ac, 'ldr', 'x3, [x20, #8]'),
        (0x1805519ec, 'orr', 'x5, x13, x10, lsl #32'),
        (0x180551a24, 'bl', '#0x18055b918'),
        (0x18055b960, 'bl', '#0x180548c18'),
        (0x180548c18, 'mov', 'x16, #-0x2f'),
        (0x180548c1c, 'svc', '#0x80'),
    ])
    return {'cache_uuid': cache.uuid, 'image_uuids': [dispatch.uuid, libkernel.uuid],
            'bindings': bindings, 'windows': evidence.windows}


def sdk():
    constants = {'MACH_RCV_MSG': 2, 'MACH_SEND_MSG': 1, 'MACH_RCV_SYNC_WAIT': 0x4000,
                 'MACH_RCV_INVALID_NOTIFY': 0x10004007, 'MACH_PORT_TYPE_RECEIVE': 0x20000,
                 'MACH_PORT_TYPE_SEND': 0x10000}
    source = ['#include <mach/message.h>', '#include <mach/port.h>']
    source.extend(f'_Static_assert({name} == {value:#x}, "{name}");' for name, value in constants.items())
    subprocess.run(['xcrun', 'clang', '-arch', 'arm64e', '-x', 'c', '-fsyntax-only', '-'],
                   input='\n'.join(source), text=True, check=True)
    return constants


def archive(path):
    raw = path.read_bytes()
    assert sha256(raw).hexdigest() == TRACE_SHA
    lines = raw.decode().splitlines()
    constructor = re.compile(
        r'\[(0x[0-9a-f]+)\] pc=(0x[0-9a-f]+) thread_get_special_reply_port\(\) = (0x[0-9a-f]+)')
    creators = [(i, match.groups()) for i, line in enumerate(lines, 1)
                if (match := constructor.fullmatch(line))]
    (line, (thread, pc, name)), = creators
    assert (line, pc, name) == (1487, '0x180547c44', '0xb03')
    trap = re.compile(r'\[(' + re.escape(thread) +
                      r')\] pc=(0x[0-9a-f]+) mach_msg2_trap\(([^)]+)\) = (0x[0-9a-f]+)')
    rows = []
    for i, line_text in enumerate(lines, 1):
        match = trap.fullmatch(line_text)
        if not match:
            continue
        args = [int(field.strip(), 0) for field in match[3].split(',')]
        if args[4] >> 32 != 0x400000ce:
            continue
        assert args[1] & 3 == 3 and args[3] & 0xffffffff == 0x707
        assert args[3] >> 32 == args[5] >> 32 == int(name, 16)
        rows.append({'line': i, 'options': hex(args[1]), 'header_names': hex(args[3]),
                     'receive_name': name, 'result': match[4]})
    assert [row['line'] for row in rows] == [1514, 1526, 1555, 1567, 1589, 1601, 1623, 1635, 1657, 1669]
    assert [row['result'] for row in rows] == ['0x80000001', '0x0'] * 5
    return {'sha256': TRACE_SHA, 'constructor': {'line': line, 'pc': pc, 'name': name},
            'bootstrap_traps': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('trace', type=Path)
    args = parser.parse_args()
    result = {'kernel': kernel(args.collection), 'userspace': userspace(),
              'sdk': sdk(), 'archive': archive(args.trace)}
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
