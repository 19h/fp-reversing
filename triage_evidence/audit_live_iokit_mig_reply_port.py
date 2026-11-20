#!/usr/bin/env python3
"""Verify the IOKit MIG reply-name cache and census the archived guest headers."""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import ctypes
import hashlib
import json
from pathlib import Path
from queue import Queue
import re
import struct
import subprocess
from threading import Event

from audit_live_iokit_discovery import TRACE_SHA256, installed_discovery
from audit_live_iokit_mach_transport import CACHE_UUID, IOKIT, LIBKERNEL, clean_pointer, dyld_uuid, record_windows
from audit_live_iokit_main_port import BUILD
from audit_live_kext_selector26 import IDENTITIES
from bootpolicy_cache_reader import CS, Cache, Dylib

GUEST_HEADER = re.compile(
    r'^\[([^]]+)\]\s+(send|received) bits=(0x[0-9a-f]+) size=(\d+) '
    r'remote=(0x[0-9a-f]+) local=(0x[0-9a-f]+) voucher=(0x[0-9a-f]+) id=(\d+)'
)
HEXDUMP = re.compile(r'^\[[^]]+\]     ([0-9a-f]{4})  (.*?)  \|')
MESSAGES = (205, 2877, 2881, 2802, 2862)
RECEIVE_RIGHT = 1
TYPE_RECEIVE = 0x20000
INVALID_NAME = 15


def installed():
    discovery = installed_discovery()
    cache = Cache()
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    kernel = Dylib(cache, LIBKERNEL)
    assert kernel.uuid == '780a6c1f-be02-34cc-84dd-00e05f61c89b'
    for name, pc in (
        ('_mig_get_reply_port', 0x180548f00),
        ('_mig_put_reply_port', 0x18054e1d8),
        ('_mig_dealloc_reply_port', 0x18054bf58),
        ('_mach_init', 0x18054ec04),
        ('_mach_reply_port', 0x180548b28),
        ('_mach_port_construct', 0x180549e9c),
        ('_mach_port_mod_refs', 0x180549320),
        ('_mach_port_deallocate', 0x18054a06c),
    ):
        assert name in {row['name'] for row in kernel.symbols_at(pc)}

    sites = (
        (0x180548f14, 'mrs x19, tpidrro_el0'),
        (0x180548f18, 'ldr w0, [x19, #0x10]'),
        (0x180548f20, 'cbnz w0, #0x180548f5c'),
        (0x180548f24, 'str xzr, [sp, #0x10]'),
        (0x180548f28, 'adrp x8, #0x18057e000'),
        (0x180548f2c, 'add x8, x8, #0xdc0'),
        (0x180548f30, 'ldr q0, [x8]'),
        (0x180548f34, 'str q0, [sp]'),
        (0x180548f38, 'adrp x8, #0x1ed902000'),
        (0x180548f3c, 'ldr w0, [x8, #0x920]'),
        (0x180548f40, 'mov x1, sp'),
        (0x180548f44, 'sub x3, x29, #0x14'),
        (0x180548f48, 'mov x2, #0'),
        (0x180548f4c, 'bl #0x180549e9c'),
        (0x180548f50, 'cbnz w0, #0x180548f6c'),
        (0x180548f54, 'ldur w0, [x29, #-0x14]'),
        (0x180548f58, 'str x0, [x19, #0x10]'),
        (0x180548f68, 'retab'),
        (0x180548f90, 'brk #1'),
        (0x18054ec20, 'bl #0x18054ec3c'),
        (0x18054ec54, 'bl #0x180548b28'),
        (0x18054ec58, 'adrp x8, #0x1ed902000'),
        (0x18054ec5c, 'str w0, [x8, #0x8b4]'),
        (0x18054e1d8, 'ret'),
        (0x18054bf6c, 'mrs x21, tpidrro_el0'),
        (0x18054bf70, 'ldr w20, [x21, #0x10]'),
        (0x18054bf74, 'cbz w20, #0x18054bfc0'),
        (0x18054bf78, 'adrp x8, #0x1ed902000'),
        (0x18054bf7c, 'ldr w8, [x8, #0x8b4]'),
        (0x18054bf80, 'cmp w8, w20'),
        (0x18054bf84, 'b.eq #0x18054bfc0'),
        (0x18054bf8c, 'str x8, [x21, #0x10]'),
        (0x18054bf94, 'ldr w0, [x22, #0x920]'),
        (0x18054bf98, 'mov x1, x20'),
        (0x18054bf9c, 'mov w2, #1'),
        (0x18054bfa0, 'mov w3, #-1'),
        (0x18054bfa4, 'bl #0x180549320'),
        (0x18054bfa8, 'cmp w19, w20'),
        (0x18054bfac, 'b.eq #0x18054bfbc'),
        (0x18054bfb8, 'bl #0x18054a06c'),
        (0x18054bfbc, 'str xzr, [x21, #0x10]'),
        (0x184ebdc20, 'bl #0x188076d50'),
        (0x184ebdc30, 'stp w21, w0, [sp, #8]'),
        (0x184ebdc6c, 'bl #0x188088af0'),
        (0x184ebdca0, 'bl #0x188076d60'),
        (0x184ebdcf0, 'bl #0x188076d40'),
    )
    for pc, expected in sites:
        instruction, = CS.disasm(cache.read(pc, 4), pc)
        assert f'{instruction.mnemonic} {instruction.op_str}'.strip() == expected, hex(pc)
    slots = {}
    for veneer, slot, target in (
        (0x188076d60, 0x1e20f3a08, 0x18054e1d8),
        (0x188076d40, 0x1e20f39e0, 0x18054bf58),
    ):
        words = list(CS.disasm(cache.read(veneer, 16), veneer))
        assert [insn.mnemonic for insn in words] == ['adrp', 'add', 'ldr', 'braa']
        assert [insn.op_str for insn in words[2:]] == ['x16, [x17]', 'x16, x17']
        assert slot == sum(int(insn.op_str.split('#')[-1], 16) for insn in words[:2])
        binding = clean_pointer(cache.pointer(slot))
        assert binding['authenticated'] and binding['chain_membership_verified']
        assert int(binding['target'], 16) == target
        slots[hex(veneer)] = binding
    literal = cache.read(0x18057edc0, 16)
    assert literal == struct.pack('<4I', 0x1000, 0, 0, 0)
    assert struct.unpack_from('<I', cache.read(0x184f98ad0, 4)) == (0x80001513,)
    return {
        'uuids': discovery['uuids'],
        'thread_slot_offset_bytes': 16, 'bootstrap_sentinel_cell': '0x1ed9028b4',
        'options_bytes': (literal + bytes(8)).hex(),
        'instruction_assertions': {hex(pc): expected for pc, expected in sites},
        'open_cleanup_bindings': slots,
        'windows': record_windows(cache.read, (
            (0x180548f00, 0x94), (0x18054bf58, 0x78), (0x18054ec04, 0x5c),
            (0x18054e1d8, 4), (0x18057edc0, 16), (0x184ebdc20, 0x140),
            (0x184f98ad0, 4), (0x188076d40, 0x30),
        )),
    }


def archived(trace):
    raw = trace.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == TRACE_SHA256
    lines = raw.decode().splitlines()
    headers = []
    for line, text in enumerate(lines, 1):
        marked = GUEST_HEADER.match(text)
        if marked is None:
            continue
        thread, direction, *fields = marked.groups()
        assert thread == '0x2de300001'
        dump = bytearray()
        for index in range(line, len(lines)):
            chunk = HEXDUMP.match(lines[index])
            if chunk is None:
                break
            assert int(chunk[1], 16) == len(dump)
            dump.extend(bytes.fromhex(chunk[2]))
        words = struct.unpack_from('<6I', dump)
        assert words == tuple(int(field, 0) for field in fields)
        assert 24 <= words[1] <= len(dump)
        headers.append((line, direction, words, bytes(dump[:words[1]])))
    assert len(headers) == 44
    pairs = []
    for index in range(0, len(headers), 2):
        tx_line, tx, send, _ = headers[index]
        rx_line, rx, receive, reply_bytes = headers[index + 1]
        end = headers[index + 2][0] - 1 if index + 2 < len(headers) else len(lines)
        bits, size, destination, name, voucher, request = send
        rx_bits, rx_size, remote, rx_name, rx_voucher, reply = receive
        assert (tx, rx) == ('send', 'received')
        assert (bits & 0xffff, rx_bits & 0xffff) == (0x1513, 0x1200)
        assert (remote, rx_name, rx_voucher) == (0, name, 0)
        assert reply == (536870912 if request == 1073742030 else request + 100)
        trap = next(i for i in range(rx_line, end) if 'mach_msg2_trap(' in lines[i])
        trap_text = lines[trap]
        assert 'pc=0x180547c20 ' in trap_text and trap_text.endswith(' = 0x0')
        args = trap_text.split('mach_msg2_trap(', 1)[1].split(')', 1)[0]
        _, options, x2, x3, x4, x5, _, _ = [int(field.strip(), 0) for field in args.split(',')]
        assert options & 3 == 3
        assert (x2, x3, x4, x5 >> 32) == (
            size << 32 | bits, name << 32 | destination, request << 32 | voucher, name)
        pair = {
            'send_line': tx_line, 'receive_line': rx_line, 'completed_trap_line': trap + 1,
            'request_id': request, 'reply_id': reply,
            'guest_destination': hex(destination), 'guest_reply_name': hex(name),
            'request_header_bits': hex(bits), 'reply_header_bits': hex(rx_bits),
            'request_size_bytes': size, 'reply_size_bytes': rx_size, 'send_voucher': hex(voucher),
        }
        if request == 205:
            assert 'mig host_get_io_main(205) = KERN_SUCCESS' in lines[rx_line - 2]
            pair['guest_mig_handler_line'] = rx_line - 1
        if request in MESSAGES[1:]:
            bridge_send, bridge_receive = lines[rx_line - 3:rx_line - 1]
            assert bridge_send.startswith(f'rax-user: bridge: sent id {request} (')
            assert bridge_send.endswith('reply 0x1603: 0x0')
            assert bridge_receive.startswith(f'rax-user: bridge: received id {reply} (')
            assert bridge_receive.endswith('on host 0x1603')
            pair['bridge_reply'] = {'name': '0x1603', 'line_numbers': [rx_line - 2, rx_line - 1]}
        if request == 2862:
            assert rx_size == 52 and struct.unpack_from('<II', reply_bytes, 24) == (1, 0)
            result, = struct.unpack_from('<I', reply_bytes, 48)
            assert result == 0xe00002c2
            pair.update(returned_connection='0x0', provider_result=hex(result))
        pairs.append(pair)
    counts = Counter(row['guest_reply_name'] for row in pairs)
    assert counts == {'0x603': 1, '0x507': 16, '0xb03': 5}
    assert tuple(row['request_id'] for row in pairs[-5:]) == MESSAGES
    assert all(row['guest_reply_name'] == '0x507' for row in pairs[-5:])
    startup = {}
    for number, text in enumerate(lines, 1):
        match = re.search(r' mach_reply_port\(\) = (0x[0-9a-f]+)$', text)
        if match:
            startup[number] = match[1]
    assert startup == {2: '0x303', 1126: '0x403'}
    assert '_kernelrpc_mach_port_construct_trap(' in lines[1135] and lines[1135].endswith(' = 0x0')
    assert '_kernelrpc_mach_port_construct_trap(' in lines[1149] and lines[1149].endswith(' = 0x0')
    assert 'bsdthread_register(' in lines[1150]
    return {
        'trace_sha256': TRACE_SHA256, 'guest_thread': '0x2de300001',
        'observed_header_count': len(headers), 'reply_name_pair_counts': dict(counts),
        'mach_reply_port_returns': startup, 'nearby_construct_lines': [1136, 1150],
        'construct_output_names_observed': False, 'guest_pairs': pairs,
    }


def observe():
    assert subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip() == BUILD
    assert subprocess.check_output(['sysctl', '-n', 'kern.uuid'], text=True).strip().lower() == IDENTITIES[1][1]
    assert dyld_uuid() == CACHE_UUID
    kernel, iokit = ctypes.CDLL(LIBKERNEL), ctypes.CDLL(IOKIT)
    name_type = ctypes.c_uint32
    name_out = ctypes.POINTER(name_type)

    def bind(library, symbol, result, *arguments):
        function = getattr(library, symbol)
        function.argtypes = arguments
        function.restype = result
        return function

    task = name_type.in_dll(kernel, 'mach_task_self_').value
    getter = bind(kernel, 'mig_get_reply_port', name_type)
    put = bind(kernel, 'mig_put_reply_port', None, name_type)
    retire = bind(kernel, 'mig_dealloc_reply_port', None, name_type)
    port_type = bind(kernel, 'mach_port_type', ctypes.c_int, name_type, name_type, name_out)
    refs = bind(kernel, 'mach_port_get_refs', ctypes.c_int, name_type, name_type, ctypes.c_int, name_out)
    main = bind(iokit, 'IOMainPort', ctypes.c_int, name_type, name_out)
    release = bind(kernel, 'mach_port_deallocate', ctypes.c_int, name_type, name_type)
    ready, proceed = Queue(), Event()

    def worker():
        first = getter()
        try:
            second = getter()
            put(first)
            third = getter()
            main_name = name_type()
            assert main(0, ctypes.byref(main_name)) == 0 and main_name.value
            assert release(task, main_name.value) == 0
            fourth = getter()
            ready.put((first, second, third, fourth))
            assert proceed.wait(timeout=15)
        finally:
            retire(first)
        retired_status = port_type(task, first, ctypes.byref(name_type()))
        replacement = getter()
        retire(replacement)
        assert replacement and replacement != first
        replacement_status = port_type(task, replacement, ctypes.byref(name_type()))
        return retired_status, replacement_status

    with ThreadPoolExecutor(max_workers=2) as pool:
        jobs = [pool.submit(worker) for _ in range(2)]
        try:
            names = [ready.get(timeout=15) for _ in jobs]
            assert all(group[0] and len(set(group)) == 1 for group in names)
            assert names[0][0] != names[1][0]
            for (first, _, _, _) in names:
                value = name_type()
                assert port_type(task, first, ctypes.byref(value)) == 0 and value.value == TYPE_RECEIVE
                assert refs(task, first, RECEIVE_RIGHT, ctypes.byref(value)) == 0 and value.value == 1
        finally:
            proceed.set()
        results = [status for job in jobs for status in job.result(timeout=15)]
    assert results == [INVALID_NAME] * 4
    return {
        'build': BUILD, 'kernel_uuid': IDENTITIES[1][1], 'cache_uuid': CACHE_UUID,
        'simultaneous_worker_count': len(jobs), 'distinct_live_receive_names': len(names),
        'getter_calls_before_retirement_per_worker': 4, 'main_port_acquisition_per_worker': True,
        'per_worker_name_unchanged_across_get_put_and_io_main': True,
        'receive_type': hex(TYPE_RECEIVE), 'receive_ref_count_per_original_name': 1,
        'different_replacement_name_per_worker': True, 'post_retirement_port_type_statuses': results,
        'post_retirement_checks_before_thread_exit': True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    parser.add_argument('--observe', action='store_true')
    args = parser.parse_args()
    result = {'installed': installed(), 'archived': archived(args.trace)}
    if args.observe:
        result['verifier_process'] = observe()
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
