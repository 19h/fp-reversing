#!/usr/bin/env python3
"""Read-only native kernel RPC transport recovery from the matching collection.

Function bounds come from the original kernel LC_FUNCTION_STARTS, not inferred
source-function names. Source-correlated roles remain distinct from exact nlist
matches. No native target execution, runtime PAC test, or IDB mutation.
O(B+N+F+D) extraction time/space for image bytes B, symbol records N, function
starts F and decoded instructions D. SMT proof cost is solver-dependent.
"""
import bisect
import hashlib
import json
from pathlib import Path
import struct
import subprocess
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from resolve_kernel_collection_interfaces import CACHE, commands, macho, string

ROOT = Path(__file__).resolve().parent
EXPECTED = 'd5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
ROLES = {
    0xfffffe000bcf59e0: 'kernel RPC common transport',
    0xfffffe000bcf5e28: 'mach_msg_rpc_from_kernel_proper',
    0xfffffe000bcf5f18: 'mig_get_reply_port',
    0xfffffe000bcf5f24: 'mig_dealloc_reply_port',
    0xfffffe000bcf5f2c: 'mig_put_reply_port',
    0xfffffe000bcf8e14: 'thread kernel-special-reply-port creation/binding',
    0xfffffe000bcf837c: 'thread kernel-special-reply-port teardown',
    0xfffffe000bcc68c4: 'ipc_kmsg_get_from_kernel',
    0xfffffe000bcc6b10: 'ipc_kmsg_copyin_from_kernel',
    0xfffffe000bcc751c: 'ipc_kmsg_put_to_kernel',
    0xfffffe000bcc6154: 'ipc_kmsg_copyout_dest_to_kernel',
    0xfffffe000bcc9718: 'ipc_object_copyin_from_kernel',
    0xfffffe000bcc9240: 'object reference release',
    0xfffffe000bcc2390: 'ipc_kmsg_sign_descriptors',
    0xfffffe000bcd0628: 'make send-once right while locked',
}


def main():
    data = CACHE.read_bytes()
    assert hashlib.sha256(data).hexdigest() == EXPECTED
    collection = macho(data, 0, 'collection')
    entries = []
    for at, cmd, size in commands(data, 0):
        if cmd == 0x80000035:
            va, off, ident, reserved = struct.unpack_from('<QQII', data, at+8)
            entries.append(macho(data, off, string(data, at+ident)))
    kernel = next(e for e in entries if e['name'] == 'com.apple.kernel')
    text_base = next(s['address'] for s in kernel['segments'] if s['name'] == '__TEXT')
    starts = []
    for at, cmd, size in commands(data, kernel['header_offset']):
        if cmd != 0x26:
            continue
        off, size = struct.unpack_from('<II', data, at+8)
        original_starts = data[off:off+size]
        pos, value = off, text_base
        while pos < off+size:
            delta = shift = 0
            while True:
                byte = data[pos]
                pos += 1
                delta |= (byte & 127) << shift
                shift += 7
                if byte < 128:
                    break
                assert shift < 70
            if not delta:
                break
            value += delta
            starts.append(value)
    assert len(starts) == 23033 and starts == sorted(set(starts))

    def read(address, size):
        seg = next(s for s in collection['segments'] if
                   s['address'] <= address and address+size <= s['address']+s['file_size'])
        off = seg['file_offset']+address-seg['address']
        return data[off:off+size], off

    cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    native, edges = [], []
    for address, role in ROLES.items():
        index = bisect.bisect_left(starts, address)
        assert starts[index] == address
        end = starts[index+1]
        raw, offset = read(address, end-address)
        instructions = list(cs.disasm(raw, address))
        assert sum(i.size for i in instructions) == len(raw)
        for i in instructions:
            if i.mnemonic in ('bl', 'b'):
                target = int(i.op_str.removeprefix('#'), 16)
                if i.mnemonic == 'bl' or not address <= target < end:
                    edges.append({'site': hex(i.address), 'instruction': i.mnemonic,
                                  'target': hex(target),
                                  'source_correlated_role': ROLES.get(target)})
        native.append({'start': hex(address), 'end': hex(end),
                       'source_correlated_role': role, 'bound_basis': 'LC_FUNCTION_STARTS',
                       'file_offset': offset, 'bytes': raw.hex(),
                       'sha256': hashlib.sha256(raw).hexdigest(),
                       'instructions': [{'ea': hex(i.address), 'mnemonic': i.mnemonic,
                                         'operands': i.op_str} for i in instructions]})
    wanted = set(ROLES) | {int(e['target'], 16) for e in edges} | {0xfffffe0007e63348}
    exact = {v: [] for v in wanted}
    symbol_count = 0
    for entry in entries:
        if 'symtab' not in entry:
            continue
        so, count, st, ss = entry['symtab']
        symbol_count += count
        for index in range(count):
            sx, ty, se, ds, value = struct.unpack_from('<IBBHQ', data, so+16*index)
            if value in wanted and sx and sx < ss:
                exact[value].append({'name': string(data, st+sx), 'entry': entry['name'],
                                     'n_type': ty, 'n_section': se})
    for record in native:
        record['exact_symbols'] = exact[int(record['start'], 16)]
        record['role_is_exact_symbol'] = bool(record['exact_symbols'])
    for edge in edges:
        edge['exact_target_symbols'] = exact[int(edge['target'], 16)]

    # These checks bind manually recovered control/ABI statements to original
    # canonical instructions. They are not a general ARM emulator or path proof.
    by_ea = {int(i['ea'], 16): i for n in native for i in n['instructions']}
    checks = {
      0xfffffe000bcf5a08: ('mrs', 'x19, tpidr_el1'),
      0xfffffe000bcf5a6c: ('ldr', 'x21, [x19, #0x3f0]'),
      0xfffffe000bcf5aa8: ('bl', '#0xfffffe000bcf8e14'),
      0xfffffe000bcf5b2c: ('str', 'x21, [x23, #0x10]'),
      0xfffffe000bcf5b40: ('bl', '#0xfffffe000bcc6b10'),
      0xfffffe000bcf5b88: ('ldadd', 'w8, w8, [x0]'),
      0xfffffe000bcf5ba0: ('mov', 'w1, #0x10001'),
      0xfffffe000bcf5ba4: ('mov', 'w2, #0'),
      0xfffffe000bcf5c44: ('bl', '#0xfffffe000bcc83b4'),
      0xfffffe000bcf5c7c: ('tbz', 'w8, #5, #0xfffffe000bcf5bec'),
      0xfffffe000bcf5ce4: ('bl', '#0xfffffe000bcc9240'),
      0xfffffe000bcf5d48: ('adds', 'w20, w19, #0x44'),
      0xfffffe000bcf5d50: ('cmp', 'w8, w19'),
      0xfffffe000bcf5d7c: ('bl', '#0xfffffe000bcc6154'),
      0xfffffe000bcf5dc0: ('bl', '#0xfffffe000bcc751c'),
      0xfffffe000bcf8ec4: ('str', 'x20, [x19, #0x3f0]'),
      0xfffffe000bcf839c: ('str', 'xzr, [x19, #0x3f0]'),
      0xfffffe000bcc69fc: ('tbnz', 'x22, #0x25, #0xfffffe000bcc6adc'),
      0xfffffe000bcc6ae0: ('bl', '#0xfffffe000bcc2390'),
      0xfffffe000bcc7608: ('tbz', 'x20, #0x25, #0xfffffe000bcc7624'),
      0xfffffe000bcc7754: ('movk', 'x17, #0x5d4f, lsl #48'),
      0xfffffe000bcc7790: ('autda', 'x16, x17'),
      0xfffffe000bcc76ec: ('str', 'x8, [x10], #0x10'),
    }
    for address, (mnemonic, operands) in checks.items():
        assert by_ea[address]['mnemonic'] == mnemonic, (hex(address), by_ea[address])
        assert by_ea[address]['operands'] == operands, (hex(address), by_ea[address])
    disp_bytes, disp_off = read(0xfffffe0007010ab0, 24)
    dispositions = struct.unpack('<6I', disp_bytes)
    assert dispositions == (16, 17, 18, 17, 17, 18)

    queries = {
      'valid_port_bits': '''(declare-fun p () (_ BitVec 64))
(assert (not (= (bvuge (bvadd p #x0000000000000001) #x0000000000000002)
 (and (not (= p #x0000000000000000)) (not (= p #xffffffffffffffff))))))''',
      'trailer_extent': '''(declare-fun s () (_ BitVec 32))
(declare-fun c () (_ BitVec 32))
(assert (bvule s #xffffffbb))
(assert (bvuge c s))
(define-fun n () (_ BitVec 64) ((_ zero_extend 32) s))
(define-fun cap () (_ BitVec 64) ((_ zero_extend 32) c))
(define-fun out () (_ BitVec 64)
 (ite (bvult cap (bvadd n #x0000000000000008)) n
  (ite (bvuge c (bvadd s #x00000044))
   ((_ zero_extend 32) (bvadd s #x00000044)) (bvadd n #x0000000000000008))))
(assert (or (bvult out n) (bvugt out cap)))''',
    }
    proofs = []
    for name, body in queries.items():
        p = ROOT/f'kernel_rpc_{name}.smt2'
        p.write_text('(set-logic QF_BV)\n'+body+'\n(check-sat)\n')
        proc = subprocess.run(['z3', '-smt2', str(p)], check=True, capture_output=True, text=True)
        assert proc.stdout.strip() == 'unsat', (name, proc.stdout, proc.stderr)
        proofs.append({'name': name, 'path': p.name, 'result': 'unsat'})

    # The exact kext client capacities remain separate original-file evidence.
    from kext_port_tools import IMAGE, CS
    clients = []
    for start, call in [(0xfffffe000a5a2064, 0xfffffe000a5a20f8),
                        (0xfffffe000a5a22d4, 0xfffffe000a5a2368)]:
        raw = IMAGE.read(start, call+4-start)
        decoded = list(CS.disasm(raw, start))
        by = {i.address: i for i in decoded}
        assert (by[call-8].mnemonic, by[call-8].op_str) == ('mov', 'w1, #0x58')
        assert (by[call-4].mnemonic, by[call-4].op_str) == ('mov', 'w2, #0x190')
        clients.append({'start': hex(start), 'call_site': hex(call), 'send_bytes': 88,
                        'receive_capacity_bytes': 400, 'bytes': raw.hex(),
                        'normal_reply_inline_bytes': 392, 'normal_trailer_bytes': 8})

    output = {'collection_path': str(CACHE), 'sha256': EXPECTED,
      'kernel_uuid': kernel['uuid'], 'kernel_function_starts': len(starts),
      'function_starts_raw_sha256': hashlib.sha256(original_starts).hexdigest(),
      'scanned_symbol_records': symbol_count, 'native_ranges': native,
      'direct_edges': edges, 'instruction_checks': len(checks), 'smt_proofs': proofs,
      'disposition_table': {'address': hex(0xfffffe0007010ab0), 'file_offset': disp_off,
                            'inputs': list(range(16, 22)), 'outputs': list(dispositions)},
      'kext_client_capacity': clients, 'thread_reply_field': '0x3f0',
      'kernel_extension_policy': '0x2000000000', 'ool_memory_pac_discriminator': '0x5d4f',
      'unknowns': ['exact target-source revision for stripped helper names',
                   'actual runtime ports, PAC signatures and selected process slice',
                   'complete downstream ipc_mqueue_receive / user copyout behavior',
                   'complete destination lifecycle in protected FairPlay publication/close'],
      'target_executed': False, 'idb_mutated': False}
    (ROOT/'kernel_rpc_transport_contracts.json').write_text(json.dumps(output, indent=2)+'\n')
    print(json.dumps({'native_ranges': len(native), 'function_starts': len(starts),
                     'direct_edges': len(edges), 'instruction_checks': len(checks),
                     'smt_unsat': len(proofs), 'kext_client_capacities': len(clients)}))


if __name__ == '__main__':
    main()
