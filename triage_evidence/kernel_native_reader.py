#!/usr/bin/env python3
"""Original kernel collection reader with compiler bounds, no target execution."""
import bisect
import hashlib
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from resolve_kernel_collection_interfaces import CACHE, commands, macho, string


class Kernel:
    def __init__(self):
        self.data = CACHE.read_bytes()
        self.sha256 = hashlib.sha256(self.data).hexdigest()
        assert self.sha256 == 'd5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
        self.root = macho(self.data, 0, 'collection')
        self.entries = []
        for at, cmd, size in commands(self.data, 0):
            if cmd == 0x80000035:
                va, off, ident, reserved = struct.unpack_from('<QQII', self.data, at+8)
                self.entries.append(macho(self.data, off, string(self.data, at+ident)))
        self.kernel = next(e for e in self.entries if e['name'] == 'com.apple.kernel')
        base = next(s['address'] for s in self.kernel['segments'] if s['name'] == '__TEXT')
        self.starts = []
        for at, cmd, size in commands(self.data, self.kernel['header_offset']):
            if cmd != 0x26:
                continue
            off, size = struct.unpack_from('<II', self.data, at+8)
            pos, value = off, base
            while pos < off+size:
                delta = shift = 0
                while True:
                    byte = self.data[pos]
                    pos += 1
                    delta |= (byte & 127) << shift
                    shift += 7
                    if byte < 128:
                        break
                    assert shift < 70
                if not delta:
                    break
                value += delta
                self.starts.append(value)
        assert len(self.starts) == 23033
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    def read(self, address, size):
        s = next(s for s in self.root['segments'] if
                 s['address'] <= address and address+size <= s['address']+s['file_size'])
        off = s['file_offset']+address-s['address']
        return self.data[off:off+size]

    def function(self, address, exact=True):
        index = bisect.bisect_right(self.starts, address)-1
        start, end = self.starts[index:index+2]
        if exact:
            assert start == address, (hex(address), hex(start))
        raw = self.read(start, end-start)
        decoded = list(self.cs.disasm(raw, start))
        assert sum(i.size for i in decoded) == len(raw)
        return {'start': hex(start), 'end': hex(end), 'bytes': raw.hex(),
                'sha256': hashlib.sha256(raw).hexdigest(),
                'instructions': [{'ea': hex(i.address), 'mnemonic': i.mnemonic,
                                  'operands': i.op_str} for i in decoded]}

    def show(self, address, calls_only=False):
        rec = self.function(address)
        print('RANGE', rec['start'], rec['end'])
        for i in rec['instructions']:
            if not calls_only or i['mnemonic'] in ('bl', 'b', 'blr', 'blraa'):
                print(i['ea'], i['mnemonic'], i['operands'])

    def symbols(self, addresses):
        wanted = set(addresses)
        result = {hex(a): [] for a in wanted}
        for e in self.entries:
            if 'symtab' not in e:
                continue
            so, count, st, ss = e['symtab']
            for j in range(count):
                sx, ty, se, ds, value = struct.unpack_from('<IBBHQ', self.data, so+16*j)
                if value in wanted and sx and sx < ss:
                    result[hex(value)].append({'name': string(self.data, st+sx),
                                               'entry': e['name'], 'n_type': ty,
                                               'n_section': se})
        return result
