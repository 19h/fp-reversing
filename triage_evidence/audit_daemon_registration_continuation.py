#!/usr/bin/env python3
"""Replay the pinned post-registration daemon continuations with modeled imports."""

import json
from struct import unpack_from

import probe_daemon_registration as registration
from daemon_receive_tools import FIXUPS, IMAGE

GATE = 0x100083974
EXTENSION = [
    (0x10009697c, 0x100097030),
    (0x1000b73f0, 0x1000b74a8),
    (0x100027310, 0x100027360),
    (0x1000a7738, 0x1000a77a8),
]
BINDINGS = {
    0x101090830: (0x10009697c, 0x1858),
    0x101083118: (0x100027310, 0x1858),
    0x1010829c0: (0x1000b73f0, 0xb66f),
    0x101060500: (0x10004e594, 0xf2b9),
    0x101067290: (0x1000a7738, 0xbcef),
    0x1010a02e0: ('CoreFoundation/_CFRelease', 0x1883),
}
SUCCESS = [
    (GATE, 0x10009697c, 0x1858),
    (0x10009702c, 0x1000b73f0, 0xb66f),
    (0x1000b74a4, 0x10004e594, 0xf2b9),
]


class ContinuationProbe(registration.RegistrationProbe):
    def hook(self, u, address, size, user):
        if address == GATE:
            self.visited.add(address)
            return super(registration.RegistrationProbe, self).hook(u, address, size, user)
        return super().hook(u, address, size, user)


def inspect():
    original_ranges = registration.RANGES
    registration.RANGES = [*original_ranges, *EXTENSION]
    rows = []
    try:
        for failure in (None, 0, 1, 2, 3, 4):
            probe = ContinuationProbe(str(failure), entry=0x100083778,
                                      checkin_status=0 if failure is None else 1102,
                                      fail_service=failure)
            result = probe.run_registration()
            assert result['stop_reason'] == 'unreviewed_native_continuation'
            post_gate = [edge for edge in result['pac_bypasses']
                         if int(edge['site'], 16) == GATE or any(
                             lo <= int(edge['site'], 16) < hi for lo, hi in EXTENSION)]
            edges = [tuple(int(edge[key], 16) for key in ('site', 'target', 'modifier'))
                     for edge in post_gate]
            stop = int(result['records'][-1]['pc'], 16)
            if failure == 4:
                assert edges == [
                    (GATE, 0x100027310, 0x1858),
                    (0x10002735c, 0x1000a7738, 0xbcef),
                    (0x1000a7794, probe.import_addresses['CoreFoundation/_CFRelease'], 0x1883),
                    (0x1000a77a4, 0x1000856ac, 0xbcef),
                ]
                assert stop == 0x1000856ac
                release = result['calls'][-1]
                assert release['name'] == 'CoreFoundation/_CFRelease'
                assert int(release['return_pc'], 16) == 0x1000a7798
                header = bytes.fromhex(result['final_header_72_bytes'])
                assert int(release['args'][0], 16) == unpack_from('<Q', header, 40)[0] != 0
            else:
                assert edges == SUCCESS and stop == 0x10004e594
                release = None
            rows.append({'failed_checkin_ordinal': failure, 'frontier': hex(stop),
                         'edges': post_gate, 'post_gate_cf_release': release,
                         'source_sha256': result['source_sha256'],
                         'verified_instructions': result['original_instruction_bytes_verified']})
    finally:
        registration.RANGES = original_ranges

    bindings = {}
    for address, (target, modifier) in BINDINGS.items():
        row = FIXUPS[address]
        assert row['target'] == target
        assert row['annotation'] == f'(div=0x{modifier:04X} ad=0 key=IA)'
        bindings[hex(address)] = {'target': target, 'diversity': hex(modifier),
                                  'source_bytes': IMAGE.read(address, 8).hex()}
    return {'cases': rows, 'bindings': bindings, 'native_ipc_observed': False}


if __name__ == '__main__':
    print(json.dumps(inspect(), indent=2, sort_keys=True))
