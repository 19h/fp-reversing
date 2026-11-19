#!/usr/bin/env python3
"""Verify installed Mach wrapper sites and repeat an audit-owned receive-right handoff."""

import hashlib
import json
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from audit_daemon_iokit_native_registry import command, sysctl
from audit_live_fairplay_cf_receive import assert_instructions
from audit_live_iokit_mach_transport import CACHE_UUID, LIBKERNEL, Cache, Dylib, dyld_uuid


def library_evidence():
    cache = Cache()
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    library = Dylib(cache, LIBKERNEL)
    assert library.uuid == '780a6c1f-be02-34cc-84dd-00e05f61c89b'
    exports = {
        '_mach_ports_register': 0x180550880,
        '_mach_ports_lookup': 0x180554a14,
    }
    for name, address in exports.items():
        assert library.exports[name]['address'] == address, name
    checks = assert_instructions(cache.read, (
        (0x1805508a0, 'cmp', 'w2, #3'),
        (0x1805508fc, 'bl', '#0x180574668'),
        (0x180550940, 'b', '#0x18055de58'),
        (0x1805746e0, 'mov', 'x4, #0xd4b00000000'),
        (0x1805746ec, 'bl', '#0x18055b918'),
        (0x180554a7c, 'bl', '#0x18055df44'),
        (0x180554a98, 'bl', '#0x180574794'),
        (0x180574804, 'mov', 'x4, #0xd4c00000000'),
        (0x180574810, 'bl', '#0x18055b918'),
    ))
    return dict(cache_uuid=cache.uuid, library_uuid=library.uuid,
                exports={name: hex(address) for name, address in exports.items()}, checks=checks)


def cross_task_control():
    source = Path(__file__).with_name('probe_mach_receive_handoff.c')
    repetitions = 2
    with TemporaryDirectory() as directory:
        executable = Path(directory) / 'probe'
        subprocess.run(['xcrun', 'clang', '-Wall', '-Wextra', '-Werror', '-O2',
                        str(source), '-o', str(executable)], check=True, timeout=30)
        runs = [json.loads(command(str(executable))) for _ in range(repetitions)]
    first = runs[0]
    assert all(run == first for run in runs)
    assert first['single_descriptor_message_bytes'] == 44
    assert first['marker_message_bytes'] == 28
    evidence = dict(one_retained_send_ref=True, child_received_marker_on_carried_name=True,
                    original_name_reused=True, second_marker_received_on_original_name=True,
                    clean_exit=True)
    assert first['cases'] == [
        dict(marked=False, flags_before_handoff=0, flags_in_child=0, flags_after_return=0,
             **evidence),
        dict(marked=True, flags_before_handoff=9, flags_in_child=8, flags_after_return=8,
             **evidence),
    ]
    return dict(source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                repetitions=repetitions, **first)


def main():
    build = command('sw_vers', '-buildVersion').decode().strip()
    kernel_uuid = sysctl('kern.uuid').lower()
    assert build == '26C5035r'
    assert kernel_uuid == '90195379-954d-3ca3-baac-327341f14211'
    print(json.dumps(dict(build=build, kernel_uuid=kernel_uuid, library=library_evidence(),
                          cross_task_control=cross_task_control(),
                          native_fairplay_handoff_observed=False,
                          live_slot17_continuity_established=False), indent=2))


if __name__ == '__main__':
    main()
