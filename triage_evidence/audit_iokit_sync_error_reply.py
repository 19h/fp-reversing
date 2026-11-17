#!/usr/bin/env python3
"""Verify source slices for IOKit 2865/2965 simple error results."""
import hashlib
import json
import sys

import z3

from audit_userclient_fallback_metadata import solve
from bootpolicy_cache_reader import CS
from kernel_native_reader import Kernel
from lskd_values_symbolic import resize
from prove_kernel_receive_delivery import V
from verify_daemon_reader_record_payloads_publication import ROOT, read, sha

NAME = 'iokit_sync_error_reply'
STRUCTURE = 'iokit_structure_arguments_source.json'
RECEIVE = 'kernel_receive_delivery_source.json'
CLEANUP = 'userclient_populated_cleanup_audit.json'
DEPS = (
    STRUCTURE, RECEIVE, CLEANUP, 'iokit_connection_lifecycle_source.json',
    'prove_kernel_receive_delivery.py', 'kernel_native_reader.py',
    'bootpolicy_cache_reader.py', 'iokit_structure_arguments_checks.json', 'zut_trace_decoded.json',
)
SCOPE = ('Static forwarding from the nominal selector 26 handler through the synchronous '
         'IOKit server, simple MIG 2965 reply fields and the framework result, conditional '
         'on ordinary calls, valid storage, normal copyout and successful Mach transport.')
BASE = 0xfffffe0000000000
NDR = BASE + 0xca92798
MASK = (1 << 64) - 1
# Distinct abstract byte-array placements for reply header, frame and related cells.
H, SP, ARG, CLIENT, COUNTS = 0x400000, 0x500000, 0x600000, 0x700000, 0x800000
STATUS = z3.BitVec('method_status_u32', 32)


def k(offset):
    return BASE + offset


def load(name):
    return json.loads(read(ROOT / name))


class Sources:
    def __init__(self):
        self.kernel = Kernel()
        self.structure = load(STRUCTURE)
        assert self.kernel.sha256 == self.structure['kernel_sha256']
        self.kernel_functions = self.structure['kernel_functions'] + load(RECEIVE)['functions']
        self.cache_functions = self.structure['cache_functions']
        self.spans = {}

    def span(self, start, end):
        if (start, end) in self.spans:
            return self.spans[start, end]
        functions = self.kernel_functions if start >= BASE else self.cache_functions
        row = next(f for f in functions if int(f['start'], 16) <= start < end <= int(f['end'], 16))
        raw = bytes.fromhex(row.get('bytes', '') or row['bytes_hex'])
        assert hashlib.sha256(raw).hexdigest() == row['sha256']
        first = start - int(row['start'], 16)
        raw = raw[first:first + end - start]
        if start >= BASE:
            assert raw == self.kernel.read(start, end - start)
        out = {'label': 'slice', 'start': hex(start), 'end_exclusive': hex(end),
               'bytes_hex': raw.hex(), 'sha256': hashlib.sha256(raw).hexdigest()}
        self.spans[start, end] = out
        return out

    def insn(self, address):
        row = self.span(address, address + 4)
        return next(CS.disasm(bytes.fromhex(row['bytes_hex']), address))

    def edge(self, address, mnemonic, target):
        i = self.insn(address)
        assert i.mnemonic == mnemonic
        assert int(i.op_str.split('#')[-1], 16) & MASK == target


class Slice(V):
    def __init__(self, sources, regs=(), memory=()):
        super().__init__({'spans': []})
        self.sources = sources
        self.negative, self.equal, self.carry, self.overflow = [
            z3.BoolVal(False) for _ in range(4)
        ]
        for name, value in regs:
            self.seed(name, value)
        for address, size, value in memory:
            self.store(resize(address, 64), size, resize(value, size * 8), 0)

    def run_slice(self, start, end):
        self.c = {'spans': [self.sources.span(start, end)]}
        self.run('slice')
        return self

    def get(self, address, size):
        return self.load(resize(address, 64), size)


def selector_status(src):
    # The adapter's authenticated tail branch inherits externalMethod's link.
    src.edge(k(0xc562fec), 'bl', k(0xc565154))
    i = src.insn(k(0xc5653b4))
    assert i.mnemonic == 'braa' and i.op_str == 'x17, x7'
    legacy = Slice(src, [('x0', resize(STATUS, 64)), ('sp', SP), ('x22', ARG + 0x60),
                         ('w21', 0xe00002c2)], [(SP + 0x10, 8, 16)])
    legacy.run_slice(k(0xc562ff0), k(0xc563008))
    # The legacy return restores only callee-saved registers and SP.
    epilogue = src.span(k(0xc563008), k(0xc563020))
    insns = list(CS.disasm(bytes.fromhex(epilogue['bytes_hex']), k(0xc563008)))
    assert all(i.mnemonic in ('ldp', 'add', 'retab') and not i.op_str.startswith('x0')
               for i in insns)
    src.edge(k(0xc5708a0), 'b', k(0xc5708bc))
    dispatch = Slice(src, [('x0', legacy.read('x0'))])
    dispatch.run_slice(k(0xc5708bc), k(0xc5708c0))
    src.edge(k(0xc5708dc), 'bl', k(0xc566e4c))
    # Opaque unlock/accounting preserves X20.
    dispatch.run_slice(k(0xc5708e0), k(0xc5708e4))
    src.edge(k(0xc570ba0), 'bl', k(0xc5707ec))
    impl = Slice(src, [('x0', dispatch.read('x0')), ('sp', SP), ('x27', COUNTS),
                       ('x28', ARG + 0x34), ('x21', 0), ('x22', 0)],
                 [(SP + 0x80, 4, 0), (SP + 0x90, 4, 16), (SP + 0xa0, 4, 0),
                  (SP + 0x20, 8, H + 0x2c)])
    impl.run_slice(k(0xc570ba4), k(0xc570bc8))
    src.edge(k(0xc570bc8), 'cbz', k(0xc570bec))
    src.edge(k(0xc570bec), 'cbz', k(0xc5709a8))
    impl.run_slice(k(0xc5709a8), k(0xc5709ac))
    return impl.read('x0'), [
        legacy.get(ARG + 0x60, 4) != 16,
        impl.get(COUNTS, 4) != 0, impl.get(H + 0x2c, 4) != 16,
        impl.get(ARG + 0x34, 8) != 0, impl.read('x0') != resize(STATUS, 64),
    ]


def reply_fields(src, implementation_return, ndr):
    # Kernel dispatcher seeds the small simple reply before entering the stub.
    old_bits, right = z3.BitVec('request_bits_u32', 32), z3.BitVec('request_reply_object', 64)
    dispatcher = Slice(src, [('x16', H), ('x8', ARG), ('x23', NDR - 0x798)],
                       [(ARG, 4, old_bits), (ARG + 0x10, 8, right), (ARG + 0x1c, 4, 2865),
                        (NDR, 8, ndr)])
    dispatcher.run_slice(k(0xbcf4760), k(0xbcf4798))
    src.edge(k(0xbe3883c), 'bl', k(0xc5708f4))
    # X3 names the header and X4 names its body on the zero-descriptor route.
    # The stub retains X3 in X21 and advances X4 by 12 B into X24.
    dispatcher.seed('x3', H)
    dispatcher.run_slice(k(0xbe387a0), k(0xbe387a4))
    dispatcher.seed('x24', H + 0x20)
    dispatcher.run_slice(k(0xbe387d4), k(0xbe387e0))
    dispatcher.seed('x19', CLIENT)
    dispatcher.seed('x0', implementation_return)
    dispatcher.run_slice(k(0xbe38840), k(0xbe38844))
    src.edge(k(0xbe38844), 'cbz', k(0xbe3886c))
    release = src.insn(k(0xbe38864))
    assert release.mnemonic == 'blraa' and release.op_str == 'x9, x16'
    # The subsequent load recovers the stored status despite X0 clobbering.
    dispatcher.seed('x0', z3.BitVec('release_return_ignored', 64))
    dispatcher.run_slice(k(0xbe38868), k(0xbe3886c))
    src.edge(k(0xbe3886c), 'cbz', k(0xbe38884))
    dispatcher.run_slice(k(0xbe38870), k(0xbe38880))
    src.edge(k(0xbe38880), 'b', k(0xbe3876c))
    dispatcher.seed('x16', H)
    dispatcher.run_slice(k(0xbcf4898), k(0xbcf48a0))
    src.edge(k(0xbcf48a0), 'b.ne', k(0xbcf48b4))
    return dispatcher, [
        dispatcher.get(H, 4) != (z3.LShR(old_bits, 8) & 31),
        dispatcher.get(H + 4, 4) != 44,
        dispatcher.get(H + 8, 8) != right,
        dispatcher.get(H + 0x10, 8) != 0,
        dispatcher.get(H + 0x18, 4) != 0,
        dispatcher.get(H + 0x1c, 4) != 2965,
        dispatcher.get(H + 0x20, 8) != ndr,
        dispatcher.get(H + 0x28, 4) != STATUS,
        z3.Not(dispatcher.condition('ne')),
    ]


def copyout_and_client(src, reply):
    # Namespace copyout supplies converted names before simple header packing.
    name, bits = z3.BitVecs('converted_local_receive_name converted_simple_header_bits', 32)
    reply.store(resize(H + 8, 64), 8, resize(0, 64), 0)
    reply.store(resize(H + 0x10, 64), 8, resize(name, 64), 0)
    for r, v in [('x8', H), ('x0', H), ('w10', 44), ('w13', 0), ('w9', 0),
                 ('w12', bits), ('x21', ARG), ('w27', 0)]:
        reply.seed(r, v)
    reply.run_slice(k(0xbcc6630), k(0xbcc6658))
    # The packed 24 B header begins 8 B later in the same storage.
    fields = [(0, 4), (4, 4), (8, 4), (12, 4), (20, 4), (24, 8), (32, 4)]
    msg = {off: reply.get(H + 8 + off, size) for off, size in fields}
    kernel_to_user = [
        msg[0] != bits, msg[4] != 36, msg[8] != 0, msg[12] != name,
        msg[20] != 2965, msg[24] != reply.get(H + 0x20, 8), msg[32] != STATUS,
    ]
    src.edge(0x184e78090, 'bl', 0x188088a80)
    src.edge(0x184e78154, 'bl', 0x188076b70)

    def client(sizes):
        memory = [(SP + 0x10 + off, size, sizes if off == 4 else msg[off])
                  for off, size in fields]
        v = Slice(src, [('sp', SP), ('w19', 0)], memory)
        v.run_slice(0x184e780d0, 0x184e780d8)
        msg_id = v.read('w8')
        src.edge(0x184e780d8, 'b.eq', 0x184e78134)
        v.run_slice(0x184e780dc, 0x184e780e0)
        id_match = v.condition('eq')
        src.edge(0x184e780e0, 'b.ne', 0x184e7813c)
        v.run_slice(0x184e780e4, 0x184e780e8)
        simple = z3.Extract(31, 31, v.read('w8')) == 0
        src.edge(0x184e780e8, 'tbnz', 0x184e7814c)
        v.run_slice(0x184e780ec, 0x184e78100)
        small_arm = v.condition('ls')
        src.edge(0x184e78100, 'b.hi', 0x184e78144)
        v.run_slice(0x184e78104, 0x184e78124)
        src.edge(0x184e78124, 'b', 0x184e78150)
        src.edge(0x184e78158, 'b', 0x184e77f7c)
        # The destroy helper preserves X19. On equal canaries the epilogue returns it.
        v.run_slice(0x184e77f94, 0x184e77f98)
        return v.read('x0'), [msg_id != 2965, z3.Not(id_match), z3.Not(simple), z3.Not(small_arm)]

    good, edges = client(msg[4])
    wrong, wrong_edges = client(resize(44, 32))
    return kernel_to_user, good, edges, wrong, wrong_edges, z3.Extract(31, 31, bits) == 0


def public_wrapper(src, result):
    src.edge(0x184e78de4, 'bl', 0x184e77d74)
    src.edge(0x184e77e5c, 'bl', 0x184e77e8c)
    src.edge(0x184e77e68, 'b.hi', 0x184e77e74)
    src.edge(0x184e77e70, 'b', 0x184e77e78)
    v = Slice(src, [('x0', result), ('x19', COUNTS), ('x29', SP)],
              [(COUNTS, 8, 16), (SP - 0x14, 4, 16)])
    v.run_slice(0x184e77e60, 0x184e77e68)
    assert z3.is_false(z3.simplify(v.condition('hi')))
    v.run_slice(0x184e77e6c, 0x184e77e70)
    v.run_slice(0x184e77e78, 0x184e77e7c)
    for start, end in [(0x184e77e7c, 0x184e77e8c), (0x184e78de8, 0x184e78df4)]:
        row = src.span(start, end)
        insts = list(CS.disasm(bytes.fromhex(row['bytes_hex']), start))
        assert insts[-1].mnemonic == 'retab' and all(
            i.mnemonic in ('ldp', 'add') and not i.op_str.startswith('x0') for i in insts[:-1]
        )
    return v.read('x0'), v.get(COUNTS, 8)


def build():
    src = Sources()
    cleanup = load(CLEANUP)
    assert src.kernel.sha256 == cleanup['kernel_collection_sha256']
    statuses = {n: int(row['caller_forwarding']['handler_X0'], 16)
                for n, row in cleanup['profiles'].items()}
    assert statuses == {'miss': 0xffff5bbc, 'match': 0xffff5a87}
    assert [row['result'] for row in cleanup['source_proofs']] == ['unsat'] * 12
    ndr = int.from_bytes(src.kernel.read(NDR, 8), 'little')
    assert ndr == 0x0000000100000000
    mig = src.structure['MIG_routine2865']
    connection = load('iokit_connection_lifecycle_source.json')
    assert mig in connection['MIG_routines']
    addr = int(mig['address'], 16)
    assert src.kernel.read(addr, 32).hex() == mig['bytes_hex']
    assert mig['reply_descriptor_word18'] == 0 and mig['reply_size_word1c'] == 4284
    assert mig['stub']['target'] == hex(k(0xbe386b4))
    transport = next(r for r in connection['cache_stubs'] if r['address'] == '0x188088a80')
    assert connection['cache_UUID'] == src.structure['cache_UUID']
    assert transport['pointer']['exact_nlist'][0]['name'] == '_mach_msg2_internal'
    # Retain the code and fixup evidence without machine paths.
    transport['pointer'].pop('path', None)
    trace = load('zut_trace_decoded.json')
    assert {'2865', '2965'}.isdisjoint(trace['send_ids'])
    ret, boundaries = selector_status(src)
    fields, kernel_bad = reply_fields(src, ret, ndr)
    packed_bad, result, guards, wrong, wrong_guards, simple_bits = copyout_and_client(src, fields)
    public, length = public_wrapper(src, result)
    private = [STATUS != 0, STATUS != resize(-305, 32)]
    proofs = [
        solve('legacy_and_synchronous_implementation_preserve_status', private, z3.Or(*boundaries)),
        solve('kernel_simple_reply_fields', private, z3.Or(*kernel_bad)),
        solve('copyout_preserves_reply_body_and_contracts_header', private, z3.Or(*packed_bad)),
    ]
    for name, value in statuses.items():
        proofs.append(solve(name + '_ordinary_framework_error_return', [STATUS == value, simple_bits],
                            z3.Or(*guards, public != resize(value, 64), length != 16)))
    proofs.append(solve('using_kernel_size_in_framework_selects_MIG_type_error',
                        [STATUS == statuses['miss'], simple_bits],
                        z3.Or(*wrong_guards, wrong != resize(resize(-300, 32), 64))))
    return {'scope': SCOPE, 'generator_sha256': sha(__file__),
            'dependencies': {n: sha(ROOT / n) for n in DEPS}, 'kernel_sha256': src.kernel.sha256,
            'kernel_UUID': src.kernel.kernel['uuid'], 'retained_cache_UUID': src.structure['cache_UUID'],
            'kernel_request_id': 2865, 'reply_id': 2965, 'reply_routine_record': mig,
            'kernel_reply_size_bytes': 44, 'user_reply_size_bytes': 36,
            'kernel_reply_retcode_offset_bytes': 40, 'user_reply_retcode_offset_bytes': 32,
            'ndr_bytes_hex': ndr.to_bytes(8, 'little').hex(),
            'framework_transport_veneer': transport,
            'historical_trace': {'send_count': trace['send_count'], 'request_2865_observed': False},
            'statuses': {n: hex(v) for n, v in statuses.items()},
            'source_spans': list(src.spans.values()), 'proofs': proofs,
            'all_checks_pass': True, 'native_exchange_observed': False, 'full_goal_complete': False}


if __name__ == '__main__':
    from contextlib import redirect_stdout

    with redirect_stdout(sys.stderr):
        evidence = build()
    print(json.dumps(evidence, indent=2))
