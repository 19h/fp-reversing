#!/usr/bin/env python3
"""Pin kernel-to-fairplayd RPC 502 audit-token provenance on build 26C5035r."""

import argparse
from datetime import datetime
from hashlib import sha256
import json
from pathlib import Path
import re
import struct
import subprocess

from audit_live_fairplay_cf_receive import assert_instructions, prior_receipt
from audit_live_fairplay_reply_rights import compiler_ranges
from audit_live_fairplay_rpc_abi import Daemon, PINNED_DAEMON_SHA
from audit_live_kext_selector26 import Collection, IDENTITIES
from audit_live_kext_selector26_transfer import words
from audit_live_xpc_log_sites import direct_call
from bootpolicy_cache_reader import Cache, Dylib

KERNEL_RANGES = {
    'kernel_rpc': 0xFFFFFE000BD3D8D4,
    'copyin_from_kernel': 0xFFFFFE000BD0EACC,
    'initialize_trailer': 0xFFFFFE000BD0C150,
    'receive_results': 0xFFFFFE000BD24B70,
    'pack_for_user': 0xFFFFFE000BD0E28C,
}
KERNEL_CALLS = (
    (0xFFFFFE000BD3DA34, KERNEL_RANGES['copyin_from_kernel']),
    (0xFFFFFE000BD0ECE8, KERNEL_RANGES['initialize_trailer']),
    (0xFFFFFE000BD24E1C, 0xFFFFFE000BD0CE54),
    (0xFFFFFE000BD24E90, KERNEL_RANGES['pack_for_user']),
    (0xFFFFFE000BD0E678, 0xFFFFFE000BEC09CC),
    (0xFFFFFE000BD0E68C, 0xFFFFFE000BEC09CC),
    (0xFFFFFE000BD0E6C4, 0xFFFFFE000BEC09CC),
)
KERNEL_CHECKS = (
    (0xFFFFFE000BD0ECE4, 'mov', 'x1, #0'),
    (0xFFFFFE000BD0C168, 'mov', 'x21, x1'),
    (0xFFFFFE000BD0C178, 'cbz', 'x21, #0xfffffe000bd0c1e8'),
    (0xFFFFFE000BD0C1B8, 'stp', 'w10, w8, [x20, #0x14]'),
    (0xFFFFFE000BD0C1E0, 'str', 'w8, [x20, #0x30]'),
    (0xFFFFFE000BD0C1E8, 'str', 'wzr, [x20, #0x40]'),
    (0xFFFFFE000BD0C1EC, 'adrp', 'x8, #0xfffffe0007010000'),
    (0xFFFFFE000BD0C1F0, 'add', 'x8, x8, #0xaf8'),
    (0xFFFFFE000BD0C1F4, 'ldp', 'q0, q1, [x8]'),
    (0xFFFFFE000BD0C1F8, 'stp', 'q0, q1, [x20]'),
    (0xFFFFFE000BD0C1FC, 'ldp', 'q0, q1, [x8, #0x20]'),
    (0xFFFFFE000BD0C200, 'stp', 'q0, q1, [x20, #0x20]'),
    (0xFFFFFE000BD24DF4, 'ldr', 'x8, [x8, #0x78]'),
    (0xFFFFFE000BD24DF8, 'str', 'x8, [sp, #0x28]'),
    (0xFFFFFE000BD24E20, 'cbz', 'w0, #0xfffffe000bd24e68'),
    (0xFFFFFE000BD24E84, 'mov', 'x3, x21'),
    (0xFFFFFE000BD24E88, 'mov', 'x4, x20'),
    (0xFFFFFE000BD24E8C, 'mov', 'w5, #0'),
    (0xFFFFFE000BD0E348, 'ldr', 'x11, [x4, #0x18]'),
    (0xFFFFFE000BD0E424, 'str', 'w9, [x14, #4]'),
    (0xFFFFFE000BD0E428, 'ldr', 'w12, [x21, #0x10]'),
    (0xFFFFFE000BD0E42C, 'str', 'xzr, [x14, #0x34]!'),
    (0xFFFFFE000BD0E430, 'stur', 'w12, [x14, #-0x2c]'),
    (0xFFFFFE000BD0E434, 'str', 'xzr, [x14, #8]'),
    (0xFFFFFE000BD0E438, 'ldr', 'x12, [x21, #0x18]'),
    (0xFFFFFE000BD0E43C, 'mov', 'w15, #-0xfffffff'),
    (0xFFFFFE000BD0E458, 'str', 'x12, [x14]'),
    (0xFFFFFE000BD0E5F4, 'sub', 'w26, w10, #8'),
    (0xFFFFFE000BD0E5F8, 'xtn', 'v1.2s, v1.2d'),
    (0xFFFFFE000BD0E600, 'add', 'w24, w8, w9'),
    (0xFFFFFE000BD0E618, 'ldr', 'w9, [x1, #0x10]'),
    (0xFFFFFE000BD0E624, 'cmp', 'w24, w9'),
    (0xFFFFFE000BD0E628, 'b.ls', '#0xfffffe000bd0e634'),
    (0xFFFFFE000BD0E680, 'sub', 'w2, w24, w26'),
    (0xFFFFFE000BD0E6BC, 'mov', 'w2, w24'),
    (0xFFFFFE000BD0E7D4, 'ubfx', 'x9, x3, #0x18, #4'),
    (0xFFFFFE000BD0E804, 'cmp', 'x9, #7'),
    (0xFFFFFE000BD0E808, 'b.eq', '#0xfffffe000bd0e84c'),
    (0xFFFFFE000BD0E84C, 'mov', 'w9, #-0xfffffff'),
    (0xFFFFFE000BD0E850, 'cmp', 'x11, x9'),
    (0xFFFFFE000BD0E854, 'mov', 'w9, #0x44'),
    (0xFFFFFE000BD0E858, 'mov', 'w15, #0x40'),
    (0xFFFFFE000BD0E85C, 'csel', 'w9, w15, w9, lo'),
)
DAEMON_CHECKS = (
    (0x10000511C, 'ldr', 'w8, [x10, #0x50]!'),
    (0x1000051CC, 'ldur', 'q0, [x10, #0x14]'),
    (0x1000051D0, 'ldur', 'q1, [x10, #0x24]'),
    (0x1000051E0, 'add', 'x6, sp, #0x30'),
    (0x1000051F8, 'bl', '#0x100422d48'),
    (0x1007FC728, 'str', 'xzr, [sp]'),
    (0x1007FC730, 'add', 'x6, sp, #4, lsl #12'),
    (0x1007FC734, 'add', 'x6, x6, #0x620'),
    (0x1007FC754, 'blraa', 'x8, x17'),
    (0x1007FC75C, 'ldr', 'w8, [x8, #0x620]'),
    (0x1007FC788, 'ldr', 'x8, [x26, w8, sxtw #3]'),
)


def kernel_evidence(kc):
    kernel = Collection(kc, IDENTITIES[1])
    assert subprocess.check_output(['sysctl', '-n', 'kern.uuid'], text=True).strip().lower() == IDENTITIES[1][1]
    extents = compiler_ranges(kernel)
    retained = {}
    for role, start in KERNEL_RANGES.items():
        ordinal, end = extents[start]
        blob = kernel.read(start, end - start)
        retained[role] = dict(start=hex(start), end=hex(end), ordinal=ordinal,
                              sha256=sha256(blob).hexdigest(), bytes=blob.hex())
    checks = assert_instructions(kernel.read, KERNEL_CHECKS)
    calls = [direct_call(kernel, site, target) for site, target in KERNEL_CALLS]
    template = kernel.read(0xFFFFFE0007010AF8, 64)
    assert struct.unpack('<16I', template) == (0, 8, 0, 0, 1) + (0,) * 11
    return dict(identity=IDENTITIES[1], ranges=retained, instruction_pins=checks, calls=calls,
                template_address='0xfffffe0007010af8', template_prefix_bytes=template.hex(),
                trailing_zero_store_bytes=4)


def userspace_evidence(path):
    daemon = Daemon(path)
    assert sha256(daemon.data).hexdigest() == PINNED_DAEMON_SHA
    fixups = subprocess.check_output(['xcrun', 'dyld_info', '-fixups', path], text=True)
    row, = (line.split() for line in fixups.splitlines() if '0x1010A0500' in line)
    assert row[2:] == ['0x1010A0500', 'auth-bind', 'libbsm/_audit_token_to_au32',
                      '(div=0xDC55', 'ad=0', 'key=IA)']
    cache = Cache()
    bsm = Dylib(cache, '/usr/lib/libbsm.0.dylib')
    cf = prior_receipt('live_fairplay_cf_receive_audit')
    assert cache.uuid == cf['cache_uuid'] == '8b1e17c6-72d6-3017-91a4-916022e3612e'
    assert cf['daemon']['thin_sha256'] == PINNED_DAEMON_SHA
    assert bsm.uuid == 'ccdec355-884e-36f6-a571-7291f637b936'
    start = bsm.exports['_audit_token_to_au32']['address']
    assert start == 0x206C3F758
    bsm_pins = assert_instructions(cache.read, (
        (0x206C3F768, 'mov', 'x19, x0'),
        (0x206C3F7AC, 'cbz', 'x6, #0x206c3f7b8'),
        (0x206C3F7B0, 'ldr', 'w8, [x19, #0x14]'),
        (0x206C3F7B4, 'str', 'w8, [x6]'),
    ))
    for pc, register in zip(range(0x1007FC738, 0x1007FC750, 4), (1, 2, 3, 4, 5, 7), strict=True):
        daemon.instruction(pc, 'mov', f'x{register}, #0')
    contract = cf['sdk']
    option = int(contract['no_timeout_option'], 16)
    assert option >> 24 & 15 == 7
    assert (contract['capacity_bytes'], contract['inline_bytes'], contract['trailer_bytes']) == (3072, 80, 68)
    return dict(daemon_sha256=PINNED_DAEMON_SHA, cache_uuid=cache.uuid, libbsm_uuid=bsm.uuid,
                libbsm_function=bsm.function(start), libbsm_pins=bsm_pins,
                daemon_fixup=' '.join(row[2:]), daemon_fixup_bytes=daemon.read(int(row[2], 16), 8).hex(),
                daemon_pins=assert_instructions(daemon.read, DAEMON_CHECKS),
                daemon_pid_window=words(daemon, 0x1007FC728, 0x74),
                prior_cf_receive_contract=contract)


def inspect_diagnostics(start, end):
    def epoch(utc):
        parsed = datetime.fromisoformat(utc)
        assert parsed.utcoffset().total_seconds() == 0
        return int(parsed.timestamp())

    query = '(process == "fairplayd" OR senderImagePath ENDSWITH "FairPlayIOKit")'
    log = subprocess.check_output(['/usr/bin/log', 'show', '--start', f'@{epoch(start)}',
        '--end', f'@{epoch(end)}', '--style', 'ndjson', '--info', '--predicate', query], text=True)
    rows = [json.loads(line) for line in log.splitlines() if line.strip()]
    info = subprocess.run(['/usr/bin/ktrace', 'info'], capture_output=True, text=True)
    diagnostic = 'Too many levels of remote in path'
    names = ('MACH_IPC_msg_send', 'MACH_IPC_msg_recv', 'MACH_IPC_kmsg_info', 'MACH_IPC_kmsg_link')
    codes = ('0x0120000c', '0x01200010', '0x01200028', '0x0120002c')
    decoded = subprocess.check_output(['/usr/bin/ktrace', 'decode', *codes], text=True)
    assert re.findall(r'debugid: (\S+) \(([^)]+)\)', decoded) == list(zip(codes, names, strict=True))
    return dict(utc_start=start, utc_end=end, log_predicate=query, log_rows=len(rows),
                log_events=sum('eventMessage' in row for row in rows), ktrace_info_status=info.returncode,
                ktrace_info_diagnostic=diagnostic if diagnostic in info.stderr else None,
                trace_debug_ids=dict(zip(codes, names, strict=True)), trace_events_collected=0)


def audit(kc, daemon):
    if subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip() != '26C5035r':
        raise ValueError('expected build 26C5035r')
    kernel = kernel_evidence(kc)
    user = userspace_evidence(daemon)
    trailer = bytes.fromhex(kernel['template_prefix_bytes']) + bytes(kernel['trailing_zero_store_bytes'])
    audit_token = struct.unpack_from('<8I', trailer, 20)
    assert len(trailer) == 68 and audit_token == (0,) * 8
    return dict(build='26C5035r', kernel=kernel, userspace=user, native_transaction_observed=False,
                static_composition=dict(kernel_audit_words=audit_token, user_pid_word=5,
                    pid_offset_in_message_bytes=80 + 20 + 5 * 4,
                    expected_kernel_sender_pid_output=audit_token[5],
                    inline_message_bytes=80, trailer_bytes=68, footprint_bytes=80 + 68))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('daemon', type=Path)
    parser.add_argument('--diagnostics', nargs=2, metavar=('START_UTC', 'END_UTC'))
    args = parser.parse_args()
    report = audit(args.collection, args.daemon)
    if args.diagnostics:
        report['diagnostics'] = inspect_diagnostics(*args.diagnostics)
    print(json.dumps(report, indent=2))
