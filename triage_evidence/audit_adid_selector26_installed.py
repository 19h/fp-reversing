#!/usr/bin/env python3
"""Compare retained CoreADI selector 26 evidence with both installed ARM slices."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import uuid

from bootpolicy_cache_reader import CS
from resolve_kernel_collection_interfaces import commands, macho

ROOT = Path(__file__).resolve().parent
SUBTYPES = {
    0x80000002: ('arm64e', 0x10001f908, 0x10004967c, 0x1002d8400),
    0x8000000c: ('arm64e.x1', 0x10001f790, 0x100049180, 0x1002d0400),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def inspect_slice(path, thin, subtype):
    arch, primary, avp, slot = SUBTYPES[subtype]
    segments = macho(thin, 0, arch)['segments']

    def read(pc, size):
        segment = next(s for s in segments
                       if s['address'] <= pc and pc + size <= s['address'] + s['file_size'])
        offset = segment['file_offset'] + pc - segment['address']
        return thin[offset:offset + size]

    bind = subprocess.check_output(['dyld_info', '-arch', arch, '-fixups', str(path)], text=True)
    binding, = [line.split() for line in bind.splitlines()
                if 'IOKit/_IOConnectCallStructMethod ' in line]
    assert int(binding[2], 16) == slot
    assert binding[3:] == ['auth-bind', 'IOKit/_IOConnectCallStructMethod',
                           '(div=0xE258', 'ad=0', 'key=IA)']
    word, = struct.unpack('<Q', read(slot, 8))
    assert word >> 62 == 3 and (word >> 32) & 0x7ffff == 0xe258
    at, = [at for at, command, _ in commands(thin, 0) if command == 0x1b]
    result = {
        'uuid': str(uuid.UUID(bytes=thin[at + 8:at + 24])),
        'sha256': digest(thin),
        'bind_slot': hex(slot),
        'bind_word': hex(word),
        'binding': binding[3:],
        'windows': {},
    }
    windows = {
        'primary_call_and_count_gate': (primary - 0x20, 0x4c),
        'primary_extent_and_address': (primary + 0x30, 0x88),
        'avp_call_and_status': (avp - 0x20, 0x4c),
    }
    for name, (pc, size) in windows.items():
        raw = read(pc, size)
        words = list(CS.disasm(raw, pc))
        assert len(words) * 4 == size
        result['windows'][name] = {'start': hex(pc), 'bytes': raw.hex(), 'words': [
            [hex(word.address), word.mnemonic, word.op_str] for word in words
        ]}
    if arch == 'arm64e':
        retained = json.loads((ROOT / 'adid_iokit_contracts.json').read_text())
        assert result['uuid'] == retained['uuid'].lower()
        assert result['sha256'] != retained['thin_sha256']
        for window in retained['original_windows']:
            expected = bytes.fromhex(window['bytes'])
            assert read(int(window['start'], 16), len(expected)) == expected
        result['retained_byte_window_matches'] = len(retained['original_windows'])
    return result


def audit(path):
    raw = path.read_bytes()
    assert raw[:4] == bytes.fromhex('cafebabe')
    slices = {}
    count, = struct.unpack_from('>I', raw, 4)
    for index in range(count):
        cpu, subtype, start, size, _ = struct.unpack_from('>5I', raw, 8 + 20 * index)
        if cpu == 0x100000c and subtype in SUBTYPES:
            slices[SUBTYPES[subtype][0]] = inspect_slice(path, raw[start:start + size], subtype)
    assert set(slices) == {'arm64e', 'arm64e.x1'}
    regular, specialized = slices['arm64e']['windows'], slices['arm64e.x1']['windows']
    for name in regular:
        assert regular[name]['bytes'] == specialized[name]['bytes'], name
    return {'container_sha256': digest(raw), 'slices': slices, 'native_exchange_observed': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('provider', type=Path)
    print(json.dumps(audit(parser.parse_args().provider), indent=2))
