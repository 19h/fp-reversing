#!/usr/bin/env python3
"""Verify the installed kernel's MIG trace IDs for ordinary IOKit traffic."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import struct
import subprocess

from audit_live_adid_peer_entitlement import checked_instructions
from audit_live_arcade_registration_reply import BUCKETS, rebuild_registry
from audit_live_fairplay_client_entitlements import BUILD
from audit_live_kext_selector26 import Collection, IDENTITIES, commands, macho, mig_map, string


SANDBOX = 'com.apple.security.sandbox'
SANDBOX_UUID = '333049ce-6805-3ffe-9225-302a1ccb80ff'
INDEX_TABLE = 0xfffffe0007d3cee4
INDEX_COUNT = 355
SETTER = 0xfffffe000c31250c
LOGGER = 0xfffffe000c2b75a4
SELECTED = {205: 5, 2802: 55, 2816: 69, 2862: 114, 2865: 117, 2881: 133,
            3405: 195, 51471: 347}


def sandbox_table(image):
    for offset, command, _ in commands(image.data, 0):
        if command != 0x80000035:
            continue
        _, entry, name_offset, _ = struct.unpack_from('<QQII', image.data, offset + 8)
        if string(image.data, offset + name_offset) == SANDBOX:
            sandbox = macho(image.data, entry, SANDBOX)
            break
    else:
        raise ValueError('Sandbox fileset entry missing')
    assert sandbox['uuid'] == SANDBOX_UUID
    assert any(section['address'] <= INDEX_TABLE
               and INDEX_TABLE + 4 * INDEX_COUNT <= section['address'] + section['size']
               for section in sandbox['sections'])
    symtab, count, strings, string_size = sandbox['symtab']
    init_names = []
    for index in range(count):
        name, kind, _, _, address = struct.unpack_from('<IBBHQ', image.data, symtab + index * 16)
        if address == 0xfffffe000b7ec458 and name and kind & 0x0e == 0x0e and not kind & 0xe0:
            assert name < string_size
            init_names.append(string(image.data, strings + name))
    assert '_hook_policy_init' in init_names
    pointer = image.pointer(0xfffffe0008a95b58)
    assert (int(pointer['target'], 16), pointer['auth'], pointer['key'], pointer['address_diversity'],
            pointer['diversity']) == (SETTER, 1, 0, 1, '0x0')
    checked = checked_instructions(image.read, (
        (0xfffffe000b7ed9fc, 'cbnz w0, #0xfffffe000b7eddb0'),
        (0xfffffe000b7eda00, 'mov x19, #0'),
        (0xfffffe000b7eda04, 'adrp x20, #0xfffffe0007d3c000'),
        (0xfffffe000b7eda08, 'add x20, x20, #0xee4'),
        (0xfffffe000b7eda0c, 'ldr w1, [x20, x19, lsl #2]'),
        (0xfffffe000b7eda10, 'mov w0, #2'),
        (0xfffffe000b7eda14, 'mov x2, x19'),
        (0xfffffe000b7eda18, 'bl #0xfffffe000b82b9b0'),
        (0xfffffe000b7eda1c, 'add x19, x19, #1'),
        (0xfffffe000b7eda20, 'cmp x19, #0x163'),
        (0xfffffe000b7eda24, 'b.ne #0xfffffe000b7eda0c'),
        (0xfffffe000b82b9b0, 'adrp x17, #0xfffffe0008a95000'),
        (0xfffffe000b82b9b4, 'add x17, x17, #0xb58'),
        (0xfffffe000b82b9b8, 'ldr x16, [x17]'),
        (0xfffffe000b82b9bc, 'braa x16, x17'),
    ))
    raw = image.read(INDEX_TABLE, 4 * INDEX_COUNT)
    ids = struct.unpack(f'<{INDEX_COUNT}I', raw)
    assert len(set(ids)) == INDEX_COUNT
    return {'uuid': SANDBOX_UUID, 'setter_pointer': pointer, 'table': hex(INDEX_TABLE),
            'table_sha256': sha256(raw).hexdigest(), 'message_ids_by_filter_index': ids,
            'instructions': checked}


def dispatch(image, ids):
    assert image.named('_proc_set_syscall_filter_index') == SETTER
    assert image.named('_kernel_debug') == LOGGER
    assert image.named('_kdebug_enable') == 0xfffffe000cbd8758
    assert image.named('_thread_tid') == 0xfffffe000bd9eab4
    assert BUCKETS == 0xfffffe0007e68ab8
    registry = rebuild_registry(image)
    populated = set()
    for subsystem in registry['subsystems']:
        start = subsystem['start']
        base = int(subsystem['pointer']['target'], 16)
        populated.update(mid for mid in range(start, subsystem['end_exclusive'])
                         if any(image.read(base + 40 + 32 * (mid - start), 8)))
    assert len(populated) == 358
    assert set(ids) <= populated and populated.difference(ids) == {2408, 2409, 2410}
    checked = checked_instructions(image.read, (
        (0xfffffe000c679d94, 'mov w17, #-1'),
        (0xfffffe000c679e7c, 'str w6, [x19]'),
        (0xfffffe000c679ea4, 'str w17, [x19, #4]'),
        (0xfffffe000c312510, 'cmp w0, #2'),
        (0xfffffe000c312514, 'b.ne #0xfffffe000c312598'),
        (0xfffffe000c312534, 'adrp x12, #0xfffffe0007e68000'),
        (0xfffffe000c312538, 'add x12, x12, #0xab8'),
        (0xfffffe000c312568, 'ldr w15, [x14]'),
        (0xfffffe000c312584, 'cmp w1, w15'),
        (0xfffffe000c312588, 'ccmp x8, #0, #4, eq'),
        (0xfffffe000c31258c, 'b.ne #0xfffffe000c3125a0'),
        (0xfffffe000c3125a4, 'str w2, [x14, #4]'),
        (0xfffffe000bd3c22c, 'ldr w28, [x22, #0x1c]'),
        (0xfffffe000bd3c24c, 'adrp x12, #0xfffffe0007e68000'),
        (0xfffffe000bd3c250, 'add x12, x12, #0xab8'),
        (0xfffffe000bd3c284, 'cmp w28, w14'),
        (0xfffffe000bd3c68c, 'ldr w23, [x24, #4]'),
        (0xfffffe000bd3c6c8, 'mov x1, x28'),
        (0xfffffe000bd3c6cc, 'mov x2, x23'),
        (0xfffffe000bd3c6d8, 'cbz w0, #0xfffffe000bd3c6fc'),
        (0xfffffe000bd3c6f8, 'b #0xfffffe000bd3c734'),
        (0xfffffe000bd3c6fc, 'adrp x28, #0xfffffe000cbd8000'),
        (0xfffffe000bd3c700, 'ldrb w8, [x28, #0x758]'),
        (0xfffffe000bd3c704, 'tbnz w8, #0, #0xfffffe000bd3c898'),
        (0xfffffe000bd3c708, 'ldr x8, [x24, #8]'),
        (0xfffffe000bd3c724, 'blraa x8, x17'),
        (0xfffffe000bd3c728, 'ldrb w8, [x28, #0x758]'),
        (0xfffffe000bd3c730, 'tbnz w8, #0, #0xfffffe000bd3c8b8'),
        (0xfffffe000bd3c898, 'lsl w8, w23, #2'),
        (0xfffffe000bd3c89c, 'orr w0, w8, #0xff000001'),
        (0xfffffe000bd3c8b0, f'bl #{LOGGER:#x}'),
        (0xfffffe000bd3c8b4, 'b #0xfffffe000bd3c708'),
        (0xfffffe000bd3c8b8, 'mov w8, #2'),
        (0xfffffe000bd3c8bc, 'movk w8, #0xff00, lsl #16'),
        (0xfffffe000bd3c8c0, 'orr w0, w8, w23, lsl #2'),
        (0xfffffe000bd3c8d4, f'bl #{LOGGER:#x}'),
        (0xfffffe000bd3c8d8, 'b #0xfffffe000bd3c734'),
        (0xfffffe000c2b75a8, 'mrs x8, tpidr_el1'),
        (0xfffffe000c2b75b0, 'ldr x5, [x8, #0x510]'),
        (0xfffffe000c2b75b8, 'b #0xfffffe000c2b8178'),
        (0xfffffe000bd9eabc, 'ldr x0, [x0, #0x510]'),
        *((start + (reg - 1) * 4, f'mov x{reg}, #0')
          for start in (0xfffffe000bd3c8a0, 0xfffffe000bd3c8c4) for reg in range(1, 5)),
    ))
    routines = mig_map(image)['routines']
    assert routines[2865]['stub']['target'] == '0xfffffe000be8152c'
    return {'collection_sha256': image.digest, 'kernel_uuid': IDENTITIES[1][1],
            'registry_without_sandbox_index': sorted(populated.difference(ids)),
            'iokit_routines': {mid: routines[mid]['stub'] for mid in (2816, 2862, 2865)},
            'instructions': checked}


def event_ids(value):
    base = 0xff000000 | ((value << 2) & 0xffffffff)
    return base | 1, base | 2


def trace_observation(ids):
    table = Path('/usr/share/misc/trace.codes').read_bytes()
    catalog = {int(code, 16): label for code, label in
               re.findall(r'^\s*(0[xX][0-9a-fA-F]+)[ \t]+(\S+)', table.decode(), re.M)}
    assert {mid: ids.index(mid) for mid in SELECTED} == SELECTED
    events = {}
    decode = {}
    for mid, assigned in SELECTED.items():
        begin, end = event_ids(assigned)
        events[mid] = {'filter_index': assigned, 'start': hex(begin), 'end': hex(end),
                       'emitted_code_catalog_label': catalog.get(begin & ~3),
                       'message_number_catalog_label': catalog.get(event_ids(mid)[0] & ~3)}
        decode.update({begin: 'start', end: 'end'})
    assert events[2816]['emitted_code_catalog_label'] == 'MSG_mach_notify_port_destroyed'
    assert events[2865]['message_number_catalog_label'] == 'MSG_io_connect_method'
    assert events[2865]['emitted_code_catalog_label'] is None
    sentinel = event_ids(-1)
    assert sentinel == (0xfffffffd, 0xfffffffe)
    decode.update(dict(zip(sentinel, ('start', 'end'), strict=True)))
    environment = {**os.environ, 'LC_ALL': 'C'}
    decoded = subprocess.check_output(['/usr/bin/ktrace', 'decode', *(hex(x) for x in decode)],
                                      text=True, env=environment)
    actual = re.findall(r'^\s*debugid: (0x[0-9a-f]+)[^\n]*\n.*?^function: (\w+)',
                        decoded, re.M | re.S)
    assert {int(value, 16): phase for value, phase in actual} == decode
    state = subprocess.run(['/usr/bin/ktrace', 'info'], capture_output=True, text=True,
                           check=False, env=environment)
    return {'catalog_sha256': sha256(table).hexdigest(), 'selected_events': events,
            'initial_sentinel_emitter_arguments': [hex(x) for x in sentinel],
            'local_decoder_checked_codes': len(decode),
            'ktrace_info_exit_status': state.returncode,
            'ktrace_info_errmsg_eremote': 'Too many levels of remote in path' in state.stderr}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    args = parser.parse_args()
    assert subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip() == BUILD
    assert subprocess.check_output(['sysctl', '-n', 'kern.uuid'], text=True).strip().lower() == IDENTITIES[1][1]
    loaded = subprocess.check_output(['kmutil', 'showloaded'], text=True)
    sandbox, = (line for line in loaded.splitlines() if f'{SANDBOX} (' in line)
    assert SANDBOX_UUID in sandbox.lower()
    image = Collection(args.collection, IDENTITIES[1])
    assigned = sandbox_table(image)
    ids = assigned['message_ids_by_filter_index']
    result = {'macos_build': BUILD, 'sandbox': assigned, 'kernel': dispatch(image, ids),
              'diagnostic_tools': trace_observation(ids)}
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
