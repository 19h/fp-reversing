#!/usr/bin/env python3
"""Recover kernel-to-user Mach copyout contracts without target execution.

Original compiler bounds, native instructions and source-correlated roles are
separate. Fixtures are synthetic ABI witnesses, not native/runtime tests.
O(B+N+F+D) extraction time/space for image bytes, symbol records, compiler
starts and retained instructions; SMT proof cost is solver-dependent.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
from kernel_native_reader import Kernel

ROOT = Path(__file__).resolve().parent
ROLES = {
  0xfffffe000bcc4194: 'initialize/sign trailer, with kernel template for null task',
  0xfffffe000bcc4bb4: 'compute user copyout size',
  0xfffffe000bcc4e98: 'normal message header and body copyout',
  0xfffffe000bcc5564: 'copyout descriptor loop, including OOL memory mapping',
  0xfffffe000bcc5b2c: 'pseudo-receive copyout, separate from normal receive',
  0xfffffe000bcc62d0: 'deflate header/descriptors/trailer and copy to user',
  0xfffffe000bcc6b10: 'copyin from kernel, null-task trailer initialization',
  0xfffffe000bcdcc7c: 'user receive results',
  0xfffffe000bdd148c: 'validate VM-copy provenance, type and extent',
  0xfffffe000bdd1574: 'vm_map_copyout exported wrapper',
}


def memory_flags(flags):
    # W16 AND mask, followed by conditional increment from the native loop.
    masked = flags & 0xff00ff00
    return masked + ((flags & 0xff00) == 0x100)


def fixtures():
    ndr = bytes.fromhex('0000000001000000')
    profiles = []
    for pointer_bits in (64, 32):
        # Post-copyout remote=reply send-once type18, local=used destination
        # send type17; no voucher in this synthetic profile.
        received_bits = 0x80001112
        header = struct.pack('<IIQQII', received_bits, 88, 0x203, 0x107, 0, 502)
        desc = struct.pack('<QII', 0x10000, 0x01000100, 37)
        tail = ndr + struct.pack('<IQQQ', 37, 0x100000c, 0, 1)
        kernel = header+struct.pack('<I', 1)+desc+tail
        flags = memory_flags(0x01000100)
        user_desc = struct.pack('<QII', 0x10000, flags, 37) if pointer_bits == 64 else struct.pack('<III', 0x10000, 37, flags)
        size = 24+4+len(user_desc)+len(tail)
        user = struct.pack('<6I', received_bits, size, 0x203, 0x107, 0, 502)+struct.pack('<I', 1)+user_desc+tail
        assert len(kernel) == 88 and len(user) == (80 if pointer_bits == 64 else 76)
        if pointer_bits == 64:
            assert struct.unpack_from('<I', user, 0x28)[0] == struct.unpack_from('<I', user, 0x34)[0] == 37
            assert struct.unpack_from('<I', user, 0x24)[0] == 0x01000101
        profiles.append({'scope': 'synthetic post-namespace-conversion request packing',
          'user_pointer_bits': pointer_bits, 'kernel_bytes': len(kernel),
          'user_bytes': len(user), 'kernel_hex': kernel.hex(), 'user_hex': user.hex()})
    # This is a delivery-extent witness, not a native fault or allocation proof.
    message, requested_trailer, capacity = 80, 52, 112
    copied = min(message+requested_trailer, capacity)
    actual_trailer = copied-message
    stub_read_end = message+52
    witness = {'scope': 'synthetic scalar receive-capacity/advertised-trailer witness',
      'inline_message_bytes': message, 'requested_and_advertised_trailer_bytes': requested_trailer,
      'receive_capacity_bytes': capacity, 'copied_total_bytes': copied,
      'reported_actual_trailer_bytes': actual_trailer,
      'stub_guard_type': 0, 'stub_guard_size_at_least_32': requested_trailer >= 32,
      'stub_audit_read_exclusive_end': stub_read_end,
      'audit_bytes_outside_delivered_prefix': stub_read_end-copied,
      'actual_framework_allocation_extent': 'unknown', 'native_reachability': 'unknown',
      'reference_source_reported_trailer_bytes': (requested_trailer-(capacity-(message+requested_trailer))) & 0xffffffff}
    assert copied == 112 and actual_trailer == 32 and witness['audit_bytes_outside_delivered_prefix'] == 20
    assert witness['reference_source_reported_trailer_bytes'] == 72
    return profiles, witness


def main():
    k = Kernel()
    native = []
    for address, role in ROLES.items():
        r = k.function(address)
        r['source_correlated_role'] = role
        r['bounds_source'] = 'original kernel LC_FUNCTION_STARTS'
        native.append(r)
    by_ea = {int(i['ea'], 16): i for r in native for i in r['instructions']}
    checks = {
      0xfffffe000bcc6d28: ('mov', 'x1, #0'),
      0xfffffe000bcc6d2c: ('bl', '#0xfffffe000bcc4194'),
      0xfffffe000bcc41bc: ('cbz', 'x21, #0xfffffe000bcc422c'),
      0xfffffe000bcc4238: ('ldp', 'q0, q1, [x8]'),
      0xfffffe000bcc4244: ('stp', 'q0, q1, [x20, #0x20]'),
      0xfffffe000bcc52b4: ('add', 'x3, sp, #0x4c'),
      0xfffffe000bcc52c4: ('bl', '#0xfffffe000bcca164'),
      0xfffffe000bcc53c8: ('ldp', 'w9, w8, [sp, #0x48]'),
      0xfffffe000bcc53dc: ('stp', 'x9, x8, [x22, #8]'),
      0xfffffe000bcc541c: ('b', '#0xfffffe000bcc5564'),
      0xfffffe000bcc5674: ('autda', 'x16, x17'),
      0xfffffe000bcc5698: ('bl', '#0xfffffe000bdd148c'),
      0xfffffe000bcc56a4: ('cmp', 'w8, #2'),
      0xfffffe000bcc56b0: ('tst', 'x8, #0x3fff'),
      0xfffffe000bcc56e8: ('bl', '#0xfffffe000bdcb374'),
      0xfffffe000bcc5878: ('bl', '#0xfffffe000bdc1cd4'),
      0xfffffe000bcc58b0: ('bl', '#0xfffffe000bdd048c'),
      0xfffffe000bcc58c8: ('bl', '#0xfffffe000bdc1ec0'),
      0xfffffe000bcc58d0: ('cmp', 'w0, #6'),
      0xfffffe000bcc58f8: ('bl', '#0xfffffe000bdc6308'),
      0xfffffe000bcc55b4: ('str', 'x8, [x19]'),
      0xfffffe000bcc55b8: ('str', 'w26, [x19, #0xc]'),
      0xfffffe000bcc6468: ('str', 'w9, [x14, #4]'),
      0xfffffe000bcc6470: ('str', 'xzr, [x14, #0x34]!'),
      0xfffffe000bcc65c4: ('cmp', 'w6, #0x100'),
      0xfffffe000bcc65d0: ('str', 'x26, [x6, #-0x10]!'),
      0xfffffe000bcc65d8: ('cinc', 'w24, w16, eq'),
      0xfffffe000bcc6638: ('sub', 'w26, w10, #8'),
      0xfffffe000bcc663c: ('xtn', 'v1.2s, v1.2d'),
      0xfffffe000bcc6660: ('subs', 'w8, w9, w8'),
      0xfffffe000bcc6670: ('str', 'w8, [x21, #4]'),
      0xfffffe000bcc6708: ('bl', '#0xfffffe000be7798c'),
      0xfffffe000bcc6730: ('str', 'xzr, [x21]'),
      0xfffffe000bcdcf28: ('bl', '#0xfffffe000bcc4e98'),
      0xfffffe000bcdcf9c: ('bl', '#0xfffffe000bcc62d0'),
      0xfffffe000bdd14e8: ('cmp', 'w10, #2'),
      0xfffffe000bdd14f0: ('cmp', 'w10, #3'),
      0xfffffe000bdd1554: ('str', 'x8, [x2]'),
    }
    for a, pair in checks.items():
        got = by_ea[a]
        assert (got['mnemonic'], got['operands']) == pair, (hex(a), got, pair)
    edges = []
    for r in native:
        start, end = int(r['start'], 16), int(r['end'], 16)
        for i in r['instructions']:
            if i['mnemonic'] not in ('bl', 'b'):
                continue
            target = int(i['operands'].removeprefix('#'), 16)
            if i['mnemonic'] == 'bl' or not start <= target < end:
                edges.append({'site': i['ea'], 'mnemonic': i['mnemonic'], 'target': hex(target)})
    wanted = set(ROLES) | {int(e['target'], 16) for e in edges}
    exact = k.symbols(wanted)
    for r in native:
        r['exact_symbols'] = exact[r['start']]
    for edge in edges:
        edge['exact_target_symbols'] = exact[edge['target']]

    template = k.read(0xfffffe0007010a68, 68)
    assert struct.unpack('<17I', template) == (0, 8, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    audit = template[20:52]
    assert audit == bytes(32)
    # Independently refresh the daemon stub's exact size/type/count guards and
    # its trailer loads from the original thin binary, not an IDA label.
    from verify_interface_contracts import Image
    daemon = Path('/Users/___/Downloads/zut/fairplayd.arm64e')
    assert hashlib.sha256(daemon.read_bytes()).hexdigest() == '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    image = Image(daemon)
    raw = image.read(0x1000050c8, 0x134)
    di = list(k.cs.disasm(raw, 0x1000050c8))
    db = {i.address: i for i in di}
    assert db[0x1000050fc].op_str == 'w8, w9'
    assert db[0x100005128].op_str == 'w8, #0x1f'
    assert db[0x1000051cc].op_str == 'q0, [x10, #0x14]'
    assert db[0x1000051d0].op_str == 'q1, [x10, #0x24]'

    queries = {
      'memory_flags': '''(declare-fun f () (_ BitVec 32))
(define-fun masked () (_ BitVec 32) (bvand f #xff00ff00))
(define-fun native () (_ BitVec 32)
 (ite (= (bvand f #x0000ff00) #x00000100) (bvadd masked #x00000001) masked))
(define-fun specified () (_ BitVec 32)
 (bvor masked (ite (= ((_ extract 15 8) f) #x01) #x00000001 #x00000000)))
(assert (not (= native specified)))''',
      'scalar_capacity': '''(declare-fun u () (_ BitVec 32))
(declare-fun t () (_ BitVec 32))
(declare-fun c () (_ BitVec 32))
(assert (bvuge c u))
(assert (bvuge (bvadd u t) u))
(define-fun copied () (_ BitVec 32) (ite (bvugt (bvadd u t) c) c (bvadd u t)))
(define-fun actual () (_ BitVec 32) (bvsub copied u))
(assert (or (bvult copied u) (bvugt copied c) (bvugt actual t)))''',
    }
    proofs = []
    for name, body in queries.items():
        p = ROOT/f'kernel_user_{name}.smt2'
        p.write_text('(set-logic QF_BV)\n'+body+'\n(check-sat)\n')
        proc = subprocess.run(['z3', '-smt2', str(p)], capture_output=True, text=True, check=True)
        assert proc.stdout.strip() == 'unsat', (name, proc.stdout, proc.stderr)
        proofs.append({'name': name, 'path': p.name, 'result': 'unsat'})
    profiles, witness = fixtures()
    trailer_sizes = {'0': 8, '1': 12, '2': 20, '3': 52,
                     '4': {'32_bit_map': 56, '64_bit_map': 60},
                     '7': {'32_bit_map': 64, '64_bit_map': 68}, 'other': 68}
    output = {'collection_sha256': k.sha256, 'kernel_uuid': k.kernel['uuid'],
      'native_ranges': native, 'direct_edges': edges, 'instruction_checks': len(checks),
      'proofs': proofs, 'synthetic_abi_profiles': profiles, 'truncation_witness': witness,
      'kernel_trailer_template': {'address': '0xfffffe0007010a68', 'bytes': template.hex(),
        'audit_u32_words': list(struct.unpack('<8I', audit)), 'audit_offset': 20,
        'security_u32_words': list(struct.unpack_from('<2I', template, 12))},
      'native_trailer_element_sizes_bytes': trailer_sizes,
      'map64_predicate': 'map.max_offset >= 0x00000000f0000001',
      'daemon_stub_refresh': {'start': '0x1000050c8', 'bytes': raw.hex(),
        'sha256': hashlib.sha256(raw).hexdigest(), 'thin_image_sha256': hashlib.sha256(daemon.read_bytes()).hexdigest()},
      'unknowns': ['CFMachPort actual receive option/capacity/allocation/cleanup',
        'complete reachability of this user receive path from the actual installed framework',
        'actual runtime VM-copy type/extent, map and resulting addresses/names',
        'all native internals of namespace creation and VM overwrite/copyout',
        'application uses of the copied audit token and service receive name'],
      'target_executed': False, 'idb_mutated': False}
    (ROOT/'kernel_user_copyout_contracts.json').write_text(json.dumps(output, indent=2)+'\n')
    print(json.dumps({'native_ranges': len(native), 'direct_edges': len(edges),
      'instruction_checks': len(checks), 'smt_unsat': len(proofs),
      'synthetic_abi_profiles': len(profiles), 'audit_words': output['kernel_trailer_template']['audit_u32_words'],
      'truncation_witness_undelivered_audit_bytes': witness['audit_bytes_outside_delivered_prefix']}))


if __name__ == '__main__':
    main()
