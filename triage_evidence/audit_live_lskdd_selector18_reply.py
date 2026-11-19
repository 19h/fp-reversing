#!/usr/bin/env python3
"""Check selector 18's installed kernel reply fields and offline daemon result handling."""

import argparse
import json
from pathlib import Path

from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_W0, UC_ARM64_REG_W22

from audit_live_kext_selector26 import Collection, IDENTITIES, method_map
from audit_live_lskdd_selector18_connection import (
    CONTEXT, SHA, ThinView, bindings, daemon_slices, replay, selected_identity, window,
)

U32 = 0xffffffff
KERNEL_METHOD = 0xfffffe000a54586c
REPLY_FIELDS = {0x0c: 'provider count', 0x10: 'second provider count', 0xc14: 'provider status'}
DAEMON_READS = {
    0x1005647dc: 0xc14,
    0x1005d9e94: 0x0c,
    0x1005d5fc8: 0x10,
}
PUBLISH = 0x1005b3410
RETURN = 0x1005b344c
KERNEL_CHECKS = (
    (0x80, 'add', 'x3, x19, #0x14'),
    (0x84, 'add', 'x5, x19, #0xc'),
    (0x88, 'add', 'x6, x19, #0x10'),
    (0x94, 'mov', 'w4, #0xc00'),
    (0xa0, 'blraa', 'x9, x17'),
    (0xa4, 'str', 'w0, [x19, #0xc14]'),
    (0xa8, 'cbz', 'w0, #0xfffffe000a54591c'),
    (0xac, 'stur', 'wzr, [x19, #0xc]'),
    (0xd4, 'mov', 'w8, #-0x27'),
    (0xd8, 'str', 'w8, [x19, #0xc14]'),
    (0xdc, 'str', 'wzr, [x19, #0xc]'),
    (0xe0, 'mov', 'w0, #0'),
)
CASES = (
    ('outer-error', 0xe00002c2, 0, 0, 0, 0x2edf8807, ()),
    ('mapping-failure', 0, 0xffffffd9, 0, 0, 0x2ee02e84, (0xc14,)),
    ('provider-error', 0, 0xffff5966, 0, 0, 0x2edf8811, (0xc14,)),
    ('zero-first-count', 0, 0, 0, 0, 0x2ee02eab, (0xc14, 0x0c)),
    ('nonzero-first-count', 0, 0, 3072, 0, 0x2edf880f, (0xc14, 0x0c, 0x10)),
    ('nonzero-both-counts', 0, 0, 3072, 3072, 0x2edf880f, (0xc14, 0x0c, 0x10)),
)


def check_kernel(path):
    image = Collection(path, IDENTITIES[1])
    method = method_map(image)['methods'][18]
    assert method['count_in'] == method['count_out'] == 3096
    assert method['member']['target'] == hex(0xfffffe000a544f54)
    symbols = image.names(KERNEL_METHOD)
    assert any('ProcessEncryptedData' in symbol for symbol in symbols)
    for offset, mnemonic, operands in KERNEL_CHECKS:
        image.instruction(KERNEL_METHOD + offset, mnemonic, operands)
    return dict(identity=IDENTITIES[1], method=method, handler=hex(KERNEL_METHOD), symbols=symbols,
                instructions=window(image, KERNEL_METHOD + 0x80, KERNEL_METHOD + 0xe4))


def check_case(image, fixups, case):
    name, outer, provider, first, second, expected_status, expected_reads = case
    reads = []
    context_status = []
    final_w0 = []

    def method_reply(cpu, args):
        _, _, _, _, output, count_cell = args

        def read(_, _access, address, size, _value, _data):
            pc = cpu.reg_read(UC_ARM64_REG_PC)
            assert address != count_cell
            assert pc in DAEMON_READS and address - output == DAEMON_READS[pc] and size == 4
            reads.append(address - output)

        def stop(_, address, _size, _data):
            if address == PUBLISH:
                context_status.append(cpu.reg_read(UC_ARM64_REG_W22))
            elif address == RETURN:
                assert int.from_bytes(cpu.mem_read(CONTEXT + 0x30, 4), 'little') == expected_status
                final_w0.append(cpu.reg_read(UC_ARM64_REG_W0))
                cpu.emu_stop()

        cpu.hook_add(UC_HOOK_MEM_READ, read, begin=output, end=output + 3095)
        cpu.hook_add(UC_HOOK_MEM_READ, read, begin=count_cell, end=count_cell + 7)
        cpu.hook_add(UC_HOOK_CODE, stop, begin=PUBLISH, end=RETURN)
        if outer == 0:
            for offset, value in zip(REPLY_FIELDS, (first, second, provider), strict=True):
                cpu.mem_write(output + offset, value.to_bytes(4, 'little'))
            cpu.mem_write(count_cell, (3096).to_bytes(8, 'little'))
        return outer

    trace = replay(image, fixups, 0x403, method_reply)
    assert tuple(reads) == expected_reads, (name, reads)
    assert context_status == [expected_status] and len(final_w0) == 1
    return dict(case=name, outer_return=hex(outer), provider_status=hex(provider),
                first_count=first, second_count=second, observed_output_reads=list(map(hex, reads)),
                context_status=hex(context_status[0]), register_at_return=hex(final_w0[0]),
                branches=trace['edges'])


def audit(path, kernel):
    thin, = [data for _, subtype, data in daemon_slices(path.read_bytes()) if subtype == 0x80000002]
    identity = selected_identity(thin)
    assert identity['sha256'] == SHA
    image = ThinView(thin)
    fixups = bindings(path, '-arch', 'arm64e')
    assert (1 << 1) * 0x3ee56fef == 0x7dcadfde
    assert (0x3ee56fef + 0xeffabebc) & U32 == 0x2ee02eab
    runs = [check_case(image, fixups, case) for case in CASES]
    return dict(daemon=identity, kernel=check_kernel(kernel), runs=runs,
                source_windows=[window(image, start, end) for start, end in (
                    (0x100584ccc, 0x100584d18), (0x1005647cc, 0x100564834),
                    (0x1005d9e74, 0x1005d9ec4), (0x1005d5f98, 0x1005d5ff0),
                    (0x100655190, 0x1006551e0), (PUBLISH, RETURN + 4),
                )], native_ipc_observed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path, help='unmodified fat lskdd executable')
    parser.add_argument('collection', type=Path, help='decompressed boot kernel collection')
    args = parser.parse_args()
    print(json.dumps(audit(args.image, args.collection), indent=2))
