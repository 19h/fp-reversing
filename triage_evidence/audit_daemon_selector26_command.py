#!/usr/bin/env python3
"""Tie the selector 26 command scalar to the pinned FairPlayIOKit dispatcher."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path

from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc
from unicorn.arm64_const import (
    UC_ARM64_REG_SP, UC_ARM64_REG_W3, UC_ARM64_REG_W9, UC_ARM64_REG_W19,
    UC_ARM64_REG_W23, UC_ARM64_REG_W24, UC_ARM64_REG_W30, UC_ARM64_REG_X2,
    UC_ARM64_REG_X4, UC_ARM64_REG_X7, UC_ARM64_REG_X8, UC_ARM64_REG_X10,
    UC_ARM64_REG_X11, UC_ARM64_REG_X17,
)

from audit_daemon_selector26_request_bytes import archive, archived_avp, selector_requests, sha
from audit_daemon_selector26_record_consumer import CS, IMAGE
from audit_live_fairplay_connection_retirement import verify_fixup
from audit_live_fairplay_context_lifecycle import CODE_DELTA, POOL, POOL_ROOTS, TABLE, replay_proof
from audit_live_fairplay_entry import verify_layout
from audit_live_kext_selector26 import Collection, IDENTITIES
from kext_port_tools import IMAGE as KEXT_ORIGINAL, POOL as ORIGINAL_POOL, qword

COMMAND_KEY = 0x744b91e8
COMMAND_TYPE = 0x9777
STATUS_KEY = 0x31ae0066
COPY_PC = 0x1009166b8
FIRST = 0x88594abe
SECOND = 0x73eba01e
PHASE = 0x7795e642
TOKEN = 0x886a1ca3
PARENT_SHA = '2e1a288a55f811522c497d0d3e27ba670779e912b5f8ca81352d12dcb67fc82f'
CHECKS_SHA = '7e2e2dbd07769720d56219865aeb60ee9ed62695dd63bd5d79551ad3f228925e'
PROOFS_SHA = '7a552ddbb31ca2c1fd3f1c3bade719bdc30ad1b6218358d46240459a1a89323c'
ADID_SHA = 'a772a272208ccf9e9dce79dae31505084509bafc71377e9c71a0a9cb18dcf89b'
READER_SHA = '83c8787a3213a9e08cf0f415069c2876177008b640451d79f5c9364fbbcff273'
PROOFS = {
    'nonnull_container_requests_command_tag_with_exact_result_cell_keys_and_continuation',
    'matching_command_node_returns_success_to_caller_node_reader',
    'command_scalar_type_a129_requires_exact_four_byte_length',
    'command_scalar_four_payload_bytes_publish_encoded_value_and_cursor_fourteen',
    'decoded_command_first_selects_exact_direct_edge',
    'first_command_retains_container_clears_hash_outputs_and_selects_previous_reader',
    'decoded_command_second_selects_exact_direct_edge',
    'second_command_entry_saves_container_at_distinct_context_cell',
    'decoded_command_other_selects_exact_direct_edge',
}


def audit_daemon():
    packets, avp_rows, _ = archived_avp()
    prior, prior_sha = archive('daemon_selector26_request_bytes_audit')
    assert prior_sha == PARENT_SHA
    command_cases = []

    def observe(frame, blob, case):
        key = int.from_bytes(blob[:4], 'big')
        field_type = int.from_bytes(blob[4:6], 'big')
        size = int.from_bytes(blob[6:10], 'big')
        assert (key, field_type, size) == (COMMAND_KEY, COMMAND_TYPE, 4)
        assert case['coverage']['last_writer_runs'][0]['pc'] == hex(COPY_PC)
        assert case['coverage']['last_writer_runs'][0]['end'] >= 14
        command_cases.append({
            'class': case['class'], 'equal_predecessor': case['equal_predecessor'],
            'aggregate_size': len(blob), 'aggregate_sha256': sha(blob),
            'method_call_pc': case['method_call_pc'], 'last_writer_pc': hex(COPY_PC),
            'command_record': blob[:14].hex(),
            'command_scalar': f'{int.from_bytes(blob[10:14], "big"):08x}',
        })

    replayed, fixup_count = selector_requests(packets, avp_rows, observe)
    assert replayed == prior['cases'] and fixup_count == prior['verified_fixups']
    return command_cases, prior_sha, fixup_count


def copy_instructions():
    sites = ((0x10091667c, 'ldrb', 'w17, [x17]'),
             (0x1009166a8, 'eor', 'w17, w2, w17'),
             (COPY_PC, 'strb', 'w17, [x15], #0xffffffffffffffff'))
    rows = []
    for pc, mnemonic, operands in sites:
        word, = CS.disasm(IMAGE.read(pc, 4), pc)
        assert (word.mnemonic, word.op_str) == (mnemonic, operands)
        rows.append({'pc': hex(pc), 'word': word.bytes.hex(), 'instruction': f'{mnemonic} {operands}'})
    return rows


def callback_bank(image, checks):
    rule, = checks['bank_rules']
    read_banks = []
    fixups = []
    for name, offset in (('left', 0x458), ('right', 0x638)):
        target, _, bias = POOL_ROOTS[offset]
        source = qword(ORIGINAL_POOL + offset) + bias
        assert source == int(rule[name], 16)
        archived = bytes.fromhex(checks['banks'][rule[name + '_name']]['bytes_hex'])
        installed = image.read(target + bias, 256)
        assert KEXT_ORIGINAL.read(source, 256) == archived == installed
        fixups.append(verify_fixup(image, POOL + offset, target))
        read_banks.append(installed)
    left, right = read_banks
    key, constant = (int(rule[name], 16) for name in ('key', 'constant'))
    assert all(byte ^ right[left[byte] ^ key] == constant for byte in range(256))
    slot_offset = 8 * (constant + int(rule['additive'], 16))
    slot = POOL + slot_offset
    pointer = image.pointer(slot)
    assert pointer['auth'] == 0
    target = int(pointer['target'], 16) - 4
    assert target == 0xfffffe0008492780
    fixups.append(verify_fixup(image, slot, target + 4))
    assert int.from_bytes(image.read(target + 40, 8), 'little') == (32 << 32) | 0x64
    for offset, raw in ((16, b'site.FPTTLVNode\0'), (32, b'1121\0')):
        data = int(image.pointer(target + offset)['target'], 16)
        fixups.append(verify_fixup(image, target + offset, data))
        assert image.read(data, len(raw)) == raw
    return {'bank_inputs': 256, 'index': slot_offset // 8, 'descriptor': hex(target),
            'type': 'site.FPTTLVNode', 'size': 32, 'fixups': fixups}


def reader_source(image):
    checks, digest = archive('userclient_input_reader_checks')
    assert digest == READER_SHA
    span, = (row for row in checks['spans'] if row['label'] == 'reader_request')
    word, = (row for row in checks['transfers'] if row['ea'] == span['end_exclusive'])
    start = int(span['start'], 16)
    end = int(span['end_exclusive'], 16)
    raw = bytes.fromhex(span['bytes_hex'] + word['bytes_hex'])
    assert raw == KEXT_ORIGINAL.read(start, len(raw)) == image.read(start + CODE_DELTA, len(raw))
    reader = {'start': start - 4 + CODE_DELTA, 'end': end + CODE_DELTA,
              'word_count': len(raw) // 4}
    image.instruction(reader['start'], 'bti', 'j')
    image.instruction(reader['end'], 'braa', 'x8, x17')
    reader['fixups'] = {}
    for index in (0x133, 0x2c4):
        row, = (row for row in checks['branch_pointers'] if row['index'] == index)
        target = int(row['target'], 16) + CODE_DELTA
        image.instruction(target, 'bti', 'j')
        reader['fixups'][index] = verify_fixup(image, TABLE + index*8, target, row['diversity'])
    return reader


def replay_dispatch(image, spans, transfers, reader, scalar, provider):
    gate = spans['command_gate']['start']
    first = spans['first_command']['start']
    second = spans['second_command_entry']['start']
    unsupported = spans['unsupported']['start']
    cleanup = spans['cleanup_gate']['start'] - 4
    first_branch = spans['first_command']['end']
    second_end = spans['second_command_entry']['end']
    code_base = gate & ~0xfff
    base = 0x100000

    def guest(pc):
        return base + pc - code_base

    context, workspace, frame, table = (0x200000, 0x202000, 0x204000, 0x206000)
    emulator = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    emulator.mem_map(base, 0x20000)
    emulator.mem_map(context, 0x10000)
    allowed = set()
    for label in ('command_gate', 'first_command', 'second_command_entry', 'unsupported'):
        start, end = (spans[label][k] for k in ('start', 'end'))
        emulator.mem_write(guest(start), image.read(start, end-start))
        allowed.update(range(start, end, 4))
    start, end = reader['start'], reader['end']
    emulator.mem_write(guest(start), image.read(start, end-start))
    allowed.update(range(start, end, 4))
    for reg, value in ((UC_ARM64_REG_SP, frame), (UC_ARM64_REG_X2, context), (UC_ARM64_REG_X4, workspace),
                       (UC_ARM64_REG_X7, table), (UC_ARM64_REG_W19, PHASE),
                       (UC_ARM64_REG_W24, 0x7795e3ce),
                       (UC_ARM64_REG_W3, TOKEN), (UC_ARM64_REG_W30, STATUS_KEY)):
        emulator.reg_write(reg, value)
    encoded = scalar ^ STATUS_KEY
    emulator.mem_write(workspace + 0xcf0, encoded.to_bytes(4, 'little'))
    emulator.mem_write(frame + 0x738, provider.to_bytes(8, 'little'))
    output_cells = (context + 0x128, workspace + 0xaa8)
    for offset, cell in zip((0xd8, 0x478), output_cells, strict=True):
        emulator.mem_write(frame + offset, cell.to_bytes(8, 'little'))
    container = 0x50fa
    emulator.mem_write(context + 0x600, container.to_bytes(8, 'little'))
    first_cases = {0x8c4: 0xfffffe000a63dd80 + CODE_DELTA, 0x8ed: cleanup}
    for index, target in first_cases.items():
        assert int(transfers[hex(TABLE + 8*index)]['target'], 16) == target
        emulator.mem_write(table + 8*index, target.to_bytes(8, 'little'))
    reader_target = int(reader['fixups'][0x2c4]['target'], 16)
    emulator.mem_write(table + 8*0x2c4, reader_target.to_bytes(8, 'little'))
    visited = []
    stops = {first_branch, second_end, cleanup, reader['end']}

    def step(uc, address, width, _):
        pc = code_base + address - base
        assert width == 4 and pc in (allowed | stops)
        visited.append(pc)
        if pc in stops:
            uc.emu_stop()

    emulator.hook_add(UC_HOOK_CODE, step)
    emulator.emu_start(guest(gate), base + 0x20000, count=70)
    status = emulator.reg_read(UC_ARM64_REG_W23)
    reader_request = None
    if scalar == FIRST:
        assert first in visited and second not in visited and unsupported not in visited
        assert visited[-1] == first_branch
        assert image.branch(gate + 16, 'b.eq') == first
        image.instruction(first_branch, 'braa', 'x8, x17')
        selector = 0x8c4 if provider else 0x8ed
        target = emulator.reg_read(UC_ARM64_REG_X8)
        assert target == first_cases[selector] and emulator.reg_read(UC_ARM64_REG_X17) == 0x9fd7
        assert bytes(emulator.mem_read(context + 0x4b0, 8)) == container.to_bytes(8, 'little')
        assert status == 0xce515bbf
        if provider:
            assert target == reader['start']
            emulator.emu_start(guest(target), base + 0x20000, count=25)
            assert visited[-1] == reader['end']
            encoded_key = emulator.reg_read(UC_ARM64_REG_W9)
            assert encoded_key == 0x2685a3ce and encoded_key ^ STATUS_KEY == 0x172ba3a8
            assert emulator.reg_read(UC_ARM64_REG_W24) == 0x133
            assert emulator.reg_read(UC_ARM64_REG_X8) == reader_target
            assert emulator.reg_read(UC_ARM64_REG_X17) == 0x73ed
            assert tuple(emulator.reg_read(reg) for reg in (UC_ARM64_REG_X10, UC_ARM64_REG_X11)) == output_cells
            reader_request = {'branch_pc': hex(reader['end']), 'encoded_key': hex(encoded_key),
                              'raw_key': hex(encoded_key ^ STATUS_KEY), 'entry': hex(reader_target),
                              'saved_resume_target': reader['fixups'][0x133]['target']}
    elif scalar == SECOND:
        assert first not in visited and second in visited and unsupported not in visited
        assert visited[-1] == second_end and status == 0x9dc
        assert bytes(emulator.mem_read(context + 0x3a8, 8)) == container.to_bytes(8, 'little')
        target = second
    else:
        assert first not in visited and second not in visited and unsupported in visited
        assert visited[-1] == cleanup and status == 0xce515bb7
        assert image.branch(gate + 32, 'b.ne') == unsupported
        target = cleanup
    return {'decoded': f'{scalar:08x}', 'encoded': f'{encoded:08x}', 'provider_nonzero': bool(provider),
            'continuation': hex(target), 'terminal_cut': hex(visited[-1]), 'w23': hex(status),
            'reader_request': reader_request,
            'visits': list(map(hex, visited))}


def audit_kext(path, daemon):
    checks, checks_sha = archive('userclient_command_dispatch_checks')
    proofs, proofs_sha = archive('userclient_command_dispatch_audit')
    adid, adid_sha = archive('adid_iokit_contracts')
    assert (checks_sha, proofs_sha, adid_sha) == (CHECKS_SHA, PROOFS_SHA, ADID_SHA)
    assert checks['kernel_collection_sha256'] == IDENTITIES[0][0]
    assert COMMAND_KEY ^ STATUS_KEY == int(checks['command_field']['requested_encoded_tag_u32'], 16)
    assert COMMAND_TYPE ^ 0x365e == int(checks['command_field']['transformed_type_u16'], 16)
    adid_command = adid['method26_packet_records'][0]
    assert (int(adid_command['raw_key_be32'], 16), int(adid_command['tag_u16'], 16),
            adid_command['payload_size_bytes']) == (COMMAND_KEY, COMMAND_TYPE, 4)
    assert int(adid_command['payload_bytes'], 16) == SECOND
    image = Collection(path, IDENTITIES[1])
    source = {'container': checks['function_container'], 'spans': checks['spans'],
              'branch_pointers': checks['branch_pointers']}
    layout = verify_layout(image, {'selector26_command': source})
    spans = {}
    for row in source['spans']:
        old = int(row['start'], 16)
        raw = bytes.fromhex(row['bytes_hex'])
        assert raw == KEXT_ORIGINAL.read(old, len(raw))
        spans[row['label']] = {'start': old + CODE_DELTA, 'end': old + CODE_DELTA + len(raw)}
    changes = [change for span in layout['spans']['selector26_command'] for change in span['changes']]
    assert [(int(row['address'], 16), row['mnemonic'], row['operands']) for row in changes] == [
        (0xfffffe000a6a3cdc, 'adrp', 'x10, #0xfffffe0008488000'),
        (0xfffffe000a6a3ce0, 'add', 'x10, x10, #0x9a0')]
    for transfer in checks['transfers']:
        pc = int(transfer['ea'], 16)
        raw = bytes.fromhex(transfer['bytes_hex'])
        assert raw == KEXT_ORIGINAL.read(pc, 4) == image.read(pc + CODE_DELTA, 4)
    selected = [row for row in proofs['source_proofs'] if row['label'] in PROOFS]
    assert {row['label'] for row in selected} == PROOFS
    with ThreadPoolExecutor(max_workers=4) as pool:
        rechecks = list(pool.map(replay_proof, selected))
    inputs = {int(row['command_scalar'], 16) for row in daemon}
    reader = reader_source(image)
    models = {(scalar, provider): replay_dispatch(image, spans, layout['branch_fixups'], reader, scalar, provider)
              for scalar in sorted(inputs | {FIRST, SECOND, 0}) for provider in (0, 1)}
    for row in daemon:
        scalar = int(row['command_scalar'], 16)
        row['conditional_continuations'] = {
            'provider_null': models[scalar, 0]['continuation'],
            'provider_nonnull': models[scalar, 1]['continuation'],
        }
    return {'collection_identity': IDENTITIES[1], 'layout': layout, 'proof_rechecks': rechecks,
            'callback_bank': callback_bank(image, checks), 'replays': list(models.values()),
            'reader_binding': reader,
            'archived_adid_command_scalar': adid_command['payload_bytes'],
            'unchanged_terminal_transfers': len(checks['transfers']),
            'pinned_kext_checks_sha256': checks_sha, 'pinned_kext_proofs_sha256': proofs_sha}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('receipt', type=Path)
    args = parser.parse_args()
    cases, parent, fixups = audit_daemon()
    result = {'daemon_cases': cases, 'parent_receipt_sha256': parent, 'daemon_fixups_verified': fixups,
              'daemon_copy_instructions': copy_instructions(), 'kext': audit_kext(args.collection, cases),
              'native_transaction_observed': False}
    args.receipt.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
