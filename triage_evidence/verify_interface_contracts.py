#!/usr/bin/env python3
"""Verify byte provenance and representation views, without running the target.

Time O(B + S), space O(B + S): B is total input binary bytes, S evidence size.
The Clang step checks layouts, not native IPC behavior or semantic equivalence.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Image:
    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        assert self.data[:4] == bytes.fromhex('cffaedfe')
        self.segments = []
        offset = 32
        for _ in range(struct.unpack_from('<I', self.data, 16)[0]):
            cmd, size = struct.unpack_from('<II', self.data, offset)
            if cmd == 0x19:
                va, _, fileoff, filesize = struct.unpack_from('<QQQQ', self.data, offset+24)
                self.segments.append((va, fileoff, filesize))
            offset += size

    def read(self, address, size):
        for va, fileoff, filesize in self.segments:
            if va <= address and address+size <= va+filesize:
                offset = fileoff+address-va
                return self.data[offset:offset+size]
        raise ValueError(f'unbacked range {address:#x}+{size:#x}')


def read_json(name):
    return json.loads((ROOT/name).read_text())


def main():
    daemon = Image('/Users/___/Downloads/zut/fairplayd.arm64e')
    kext_info = read_json('selector26_core_rpc_native.json')
    kext = Image(kext_info['input'])
    assert sha(kext.data) == kext_info['sha256']
    assert sha(daemon.data) == '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    count = 0
    for evidence, image_override in [
        (read_json('selector26_native.json'), None),
        (kext_info['functions'], None),
        (read_json('daemon_abi_native.json')['ranges'], daemon),
        (read_json('daemon_mig_stub_native.json'), daemon),
        (read_json('selector26_lifecycle_contract.json')['lifecycle_shims'], None),
        (read_json('host_port_rpc_callers_native.json'), None),
        ([read_json('core2_dispatch_prefix_native.json')], None),
    ]:
        image = image_override or kext
        for item in evidence:
            raw = bytes.fromhex(item['bytes'])
            assert image.read(int(item['start'], 16), len(raw)) == raw
            count += 1
    prior = read_json('daemon_prior_proof_manifests.json')
    checked_ranges = checked_slots = checked_chains = 0
    for item in prior['manifests']:
        m = item['contents']
        for kind in ['ranges', 'banks']:
            for r in m.get(kind, []):
                assert sha(daemon.read(int(r['address'], 16), r['size'])) == r['sha256']
                checked_ranges += 1
        for s in m.get('slots', []):
            if 'chain' in s:
                raw = struct.unpack('<Q', daemon.read(int(s['address'], 16), 8))[0]
                assert raw == int(s['chain'], 16)
                checked_chains += 1
            checked_slots += 1
    live = read_json('daemon_prior_proof_readback.json')
    assert all(x['match'] for x in live['ranges']+live['slots'])
    assert len(live['ranges']) == checked_ranges
    tables = read_json('daemon_mig_tables.json')
    rows = [r for t in tables for r in t['routines'] if r['stub'] != '0x0']
    assert len(tables) == 5 and len(rows) == 11
    for t in tables:
        assert daemon.read(int(t['header'], 16), 32)[8:20] == bytes.fromhex(t['header_hex'])[8:20]
        # Stub pointers are chained on disk; compare nonpointer descriptor fields.
        for r in t['routines']:
            raw = daemon.read(int(r['descriptor'], 16), 40)
            observed = bytes.fromhex(r['descriptor_hex'])
            assert raw[16:] == observed[16:]
    selector = read_json('selector26_lifecycle_contract.json')['selector26']
    assert kext.read(int(selector['record'], 16), 48) == bytes.fromhex(selector['record_bytes'])
    assert (selector['index'], selector['input_bytes'], selector['output_bytes']) == (25, 16, 16)
    container_info = read_json('daemon_container_identity.json')
    container = Path(container_info['path']).read_bytes()
    assert sha(container) == container_info['sha256']
    arm = next(s for s in container_info['slices'] if s['subtype'] == '0x80000002')
    assert container[arm['file_offset']:arm['file_offset']+arm['size']] == daemon.data
    command = ['clang', '-target', 'arm64e-apple-macos13.0', '-std=c11',
               '-fsyntax-only', str(ROOT/'abi_layout_contracts.c')]
    subprocess.run(command, check=True, capture_output=True, text=True)
    result = {'kext_sha256': sha(kext.data), 'daemon_sha256': sha(daemon.data),
              'native_range_byte_comparisons': count,
              'prior_range_and_bank_hashes': checked_ranges,
              'prior_live_slot_comparisons': checked_slots,
              'original_chain_word_comparisons': checked_chains,
              'mig_tables': len(tables), 'non_null_mig_stubs': len(rows),
              'layout_compiler_command': command,
              'target_executed': False,
              'scope': 'saved live snapshots, original file bytes, layout arithmetic; no IPC or PAC execution'}
    (ROOT/'interface_contract_validation.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
