#!/usr/bin/env python3
"""Independent scalar replay, byte-epoch search and universal splice codecs.
O(parent bytes + selected visits*32 + write bytes + read bytes*log(writes)
+ proof DAG) time; O(receipts + selected frames + proof DAG) space.
Solver search is additional, limited to 30 s/query. No native operation.
"""
import gc
import json
from bisect import bisect_left
from collections import Counter, defaultdict
import z3
from daemon_receive_tools import ROOT, SOURCE, IMAGE, FIXUPS
from verify_daemon_reader_record_payloads_publication import read, sha
from audit_daemon_append_fields import Trace, number
from audit_daemon_alternative_fill import Source
from recover_daemon_record_banks import instruction
import recover_daemon_record_input_origin as R

DEPS = ['audit_daemon_append_fields.py', 'audit_daemon_alternative_fill.py',
        'audit_daemon_state_table_mixing.py', 'recover_daemon_return_bank_origins.py',
        'lskd_values_symbolic.py']


def check_frame(v, f):
    assert number(v.read('sp')) == int(f['SP'], 16)
    for j, x in enumerate(f['registers31']): assert number(v.read('x'+str(j))) == int(x, 16), (f['pc'], j)
    flags = 0
    for bit, x in zip([31, 30, 29, 28], [v.n, v.z, v.carry, v.overflow]):
        b = z3.simplify(x); assert z3.is_true(b) or z3.is_false(b)
        flags |= int(z3.is_true(b)) << bit
    assert flags == int(f['NZCV'], 16), (f['pc'], 'NZCV')


def replay(chunk):
    v = Trace(chunk['reads'], chunk['writes']); f = chunk['frames'][0]
    for j, x in enumerate(f['registers31']): v.seed('x'+str(j), int(x, 16))
    v.seed('sp', int(f['SP'], 16)); nzcv = int(f['NZCV'], 16)
    v.n, v.z, v.carry, v.overflow = [z3.BoolVal(bool(nzcv & (1 << k))) for k in [31, 30, 29, 28]]
    edges = {x['source_visit_index']: x for x in chunk['edges']}; counts = Counter()
    for j, visit in enumerate(chunk['visits']):
        f, following = chunk['frames'][j:j+2]; check_frame(v, f)
        pc = int(visit['pc'], 16); assert f['pc'] == visit['pc'] and visit['bytes_hex'] == IMAGE.read(pc, 4).hex()
        i = instruction(pc); m = i.mnemonic; next_pc = pc+4
        assert not any(i.reg_name(r).startswith(('v', 'q', 'd', 's')) and i.reg_name(r) != 'sp' for r in sum(i.regs_access(), []))
        if m == 'pacibsp': counts['logical_PAC_prologues'] += 1
        elif m in ['braa', 'blraa', 'retab']:
            target = number(v.read('x30' if m == 'retab' else i.reg_name(i.operands[0].reg)))
            edge = edges[chunk['start_visit']+j]
            assert edge['pc'] == hex(pc) and edge['target'] == hex(target) and edge['kind'] == m
            if m != 'retab': assert edge['modifier'] == hex(number(v.read(i.reg_name(i.operands[1].reg))))
            if m == 'blraa': v.write('x30', z3.BitVecVal(pc+4, 64))
            next_pc = target; counts['logical_edges'] += 1
        elif m.startswith('b.'):
            choose = z3.simplify(v.condition(m[2:])); assert z3.is_true(choose) or z3.is_false(choose)
            if z3.is_true(choose): next_pc = i.operands[0].imm
            counts['conditional_branches'] += 1
        elif m == 'cneg':
            name = i.reg_name(i.operands[0].reg)
            value = v.read(i.reg_name(i.operands[1].reg))
            v.write(name, z3.If(v.condition(i.op_str.rsplit(',', 1)[1].strip()), -value, value))
        else: v.one(i)
        assert following['pc'] == hex(next_pc), (hex(pc), following['pc'], hex(next_pc))
        counts['source_visits'] += 1
    check_frame(v, chunk['frames'][-1])
    assert v.ri == len(chunk['reads']) and v.wi == len(chunk['writes'])
    counts.update(GP_SP_values=(len(chunk['visits'])+1)*32, NZCV_frames=len(chunk['visits'])+1,
                  reads=v.ri, writes=v.wi, chunks=1)
    return dict(counts)


def independent_origins(row, case):
    """Per-address histories plus predecessor search, independent of the fold."""
    wanted = {int(x['reader']['address'], 16)+k for x in case['selected_read_origins'] for k in range(x['reader']['size_bytes'])}
    history = defaultdict(list)
    for w in row['source_writes']:
        a = int(w['address'], 16)
        for k in range(w['size_bytes']):
            if a+k in wanted: history[a+k].append((w['source_visit_index'], w, k))
    checked = external = 0
    for x in case['selected_read_origins']:
        r = x['reader']; actual = []; incoming = []
        for k, byte in enumerate(bytes.fromhex(r['bytes_hex'])):
            h = history[int(r['address'], 16)+k]
            n = bisect_left(h, r['source_visit_index'], key=lambda p: p[0])
            if n:
                j, w, wb = h[n-1]; assert j < r['source_visit_index'] and bytes.fromhex(w['after_hex'])[wb] == byte
                actual.append({'reader_byte': k, 'writer': w, 'writer_byte': wb}); checked += 1
            else: incoming.append(k); external += 1
        assert actual == x['origins'] and incoming == x['incoming_or_image_byte_indices']
    return {'last_writer_bytes_checked': checked, 'incoming_or_image_bytes_separate': external}


def obligations():
    out = []
    def prove(label, bad):
        s = z3.Solver(); s.set(timeout=30000); assert s.check() == z3.sat
        s.add(z3.simplify(bad)); result = s.check(); assert result == z3.unsat, (label, str(result))
        out.append({'label': label, 'premises_nonvacuous': True, 'result': 'unsat', 'query': s.to_smt2()})
    word, counter = z3.BitVecs('origin_word32 origin_counter32', 32)
    source, dest = z3.BitVecs('origin_word_source64 origin_word_dest64', 64)
    v = Source({0x100be0454: (4, word)})
    for n, x in {'x13': source, 'x1': dest, 'w11': counter, 'w12': 0xd3286d1e}.items(): v.seed(n, x)
    v.run_block(0x100be0454, 0x100be04e4)
    assert len(v.loads) == 1 and len(v.stores) == 4
    offsets = [0, 2, 1, 3]; masks = [0x6c, 0x61, 0xb5, 0x6f]
    prove('serializer_all_u32_word_bits_and_modular_addresses', z3.Or(
        v.loads[0][1] != source+0x48,
        *[z3.Or(s['address'] != dest+z3.ZeroExt(32, counter+0xd3286d1e+k),
                    s['value'] != (z3.Extract(31-8*k, 24-8*k, word)^masks[k]), s['size_bytes'] != 1)
          for s, k in zip(v.stores, offsets)]))
    prove('serializer_encoding_equals_BE32_state_XOR98', z3.Or(*[
        (z3.Extract(31-8*k, 24-8*k, word)^masks[k]) !=
        (z3.Extract(31-8*k, 24-8*k, word^0xf4f92df7)^0x98) for k in range(4)]))
    frame, output, table, target = z3.BitVecs('origin_F64 origin_output64 origin_table64 origin_target64', 64)
    phase = z3.BitVec('origin_phase32', 32)
    values = {0x100aaa370: (8, output), 0x100aaa3d8: (8, target)}
    bytes_by_offset = {off: z3.BitVec('origin_byte_'+hex(off)[2:]+'_8', 8) for off in R.MAP}
    # Derive each original load's local offset from the decoded source operand.
    for pc in range(0x100aaa324, 0x100aaa3e0, 4):
        i = instruction(pc)
        if i.mnemonic == 'ldrb': values[pc] = (1, bytes_by_offset[i.operands[1].mem.disp])
    v = Source(values)
    for n, x in {'sp': frame, 'x20': table, 'w22': phase}.items(): v.seed(n, x)
    v.run_block(0x100aaa324, 0x100aaa3e0)
    assert len(v.stores) == 20 and len(v.loads) == 22
    by_address = list(zip(v.stores, [19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]))
    prove('formatter_all_twenty_independent_bytes_and_output_offsets', z3.Or(*[
        z3.Or(s['address'] != output+k, s['value'] != bytes_by_offset[R.MAP[k]], s['size_bytes'] != 1)
        for s, k in by_address]))
    expected = {pc: frame+instruction(pc).operands[1].mem.disp for pc in values if instruction(pc).mnemonic == 'ldrb'}
    expected.update({0x100aaa370: frame+0x90, 0x100aaa3d8: table+z3.SignExt(32, phase)*8})
    prove('formatter_all_read_addresses_encoded_zero_and_dispatch_values', z3.Or(
        *[a != expected[pc] for pc, a, n in v.loads], v.read('w8') != 0x8b3dc651,
        v.read('x9') != target, v.read('x17') != 0xc6fe, v.read('w21') != (phase^0x221b)))
    result = z3.BitVec('origin_result32', 32); record = z3.BitVec('origin_record64', 64)
    v = Source({0x100427da8: (4, result)}); v.seed('sp', frame); v.seed('x19', record)
    v.run_block(0x100427da8, 0x100427db0)
    prove('wrapper_transfers_four_byte_descriptor_result', z3.Or(v.loads[0][1] != frame+0x18,
        v.stores[0]['address'] != record+8, v.stores[0]['value'] != result, v.stores[0]['size_bytes'] != 4))
    v = Source(); v.seed('x28', record); v.run_block(0x1000d4910, 0x1000d491c)
    prove('helper_success_suffix_publishes_encoded_zero', z3.Or(v.stores[0]['address'] != record+8,
        v.stores[0]['size_bytes'] != 4, v.stores[0]['value'] != 0x8b3dc651))
    return out


def alias_controls():
    """Original formatter source with byte memory; excludes unsafe alias transfer."""
    class Bytes(Source):
        def __init__(self):
            super().__init__(); self.bytes = {}
        def load(self, address, n):
            a = number(address)
            return z3.BitVecVal(int.from_bytes(bytes(self.bytes[a+k] for k in range(n)), 'little'), 8*n)
        def store(self, address, n, value, pc):
            super().store(address, n, value, pc)
            a = number(address); raw = number(z3.Extract(8*n-1, 0, value)).to_bytes(n, 'little')
            self.bytes.update({a+k: b for k, b in enumerate(raw)})
    out = []; frame = 0x680005fb60
    for kind, output in [('disjoint', 0x680006c5b0), ('overlapping', frame+0x1bc)]:
        v = Bytes()
        for n, x in {'sp': frame, 'x20': 0x101039ef0, 'w22': 0x7aa5}.items(): v.seed(n, x)
        for k, off in enumerate(R.MAP): v.bytes[frame+off] = k
        for a, raw in [(frame+0x90, output.to_bytes(8, 'little')), (0x101077418, (0x100a653cc).to_bytes(8, 'little'))]:
            v.bytes.update({a+k: b for k, b in enumerate(raw)})
        v.run_block(0x100aaa324, 0x100aaa3e0)
        actual = bytes(v.bytes[output+k] for k in range(20))
        assert (actual == bytes(range(20))) == (kind == 'disjoint')
        out.append({'kind': kind, 'output_base': hex(output), 'source_formatter_output_hex': actual.hex(),
                    'snapshot_splice_matches': kind == 'disjoint', 'native_execution': False})
    return out


def audit():
    e = json.loads(read(ROOT/(R.P+'_checks.json'))); totals = Counter(); cases = []
    old = json.loads(read(ROOT/'daemon_record_extension_checks.json'))
    for c in e['cases']:
        for p in c['chunks']: totals.update(replay(p))
        row = R.Parent.unpack(old['classes'][c['class_index']]['intervals'][c['interval_index']]['interval_packed'])
        epoch = independent_origins(row, c); totals.update(epoch)
        # Independent byte snapshots use all parent stores and verify preservation.
        snapshots = {}
        queries = [(c['calls'][0]['source_visit_index'], int(c['serialized_base'], 16), 20, c['serialized20_hex']),
                   (c['chunks'][-1]['end_visit_exclusive'], int(c['output_base'], 16), 20, c['record_input20_hex']),
                   (len(row['source_visits']), int(c['output_base'], 16), 20, c['record_input20_hex'])]
        for stop, a, n, expected in queries:
            image = {}
            for w in row['source_writes']:
                if w['source_visit_index'] >= stop: break
                for k, b in enumerate(bytes.fromhex(w['after_hex'])):
                    at = int(w['address'], 16)+k
                    if a <= at < a+n: image[at] = b
            assert bytes(image[a+k] for k in range(n)).hex() == expected
            snapshots[hex(a)+'@'+str(stop)] = expected; totals['snapshot_bytes'] += n
        assert len(c['state_word_later_writes']) == 20
        assert {w['pc'] for w in c['state_word_later_writes']} == {'0x100a66654'}
        cases.append({'class_index': c['class_index'], 'epoch_checks': epoch, 'snapshots': snapshots, 'all_checks_pass': True})
        del row; gc.collect()
    proofs = obligations()
    # Identity and contiguous-copy counterexamples constrain classification.
    controls = []
    for c in e['cases']:
        s, t, o = [bytes.fromhex(c[k]) for k in ['serialized20_hex', 'transform_output16_hex', 'record_input20_hex']]
        assert s[2:18] != t and o != s and o == s[:2]+t+s[18:]
        controls.append({'class_index': c['class_index'], 'middle_identity_rejected': True,
                         'whole_serialized20_copy_rejected': True, 'two_16_two_splice_matches': True})
    return {'scope': __doc__, 'auditor_sha256': sha(__file__), 'extractor_sha256': sha(ROOT/('recover_'+R.P+'.py')),
            'checks_sha256': sha(ROOT/(R.P+'_checks.json')), 'source_sha256': sha(SOURCE),
            'dependencies': {p: sha(ROOT/p) for p in DEPS}, 'cases': cases, 'independent_totals': dict(totals),
            'source_proofs': proofs, 'source_queries_unsat': len(proofs), 'classification_controls': controls,
            'alias_controls': alias_controls(),
            'native_API_executed': False, 'native_daemon_kext_pairing_established': False,
            'digest_message_or_algorithm_established': False, 'transform_algorithm_established': False,
            'full_goal_complete': False, 'all_checks_pass': True}


if __name__ == '__main__':
    result = audit(); (ROOT/(R.P+'_audit.json')).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'independent_totals': result['independent_totals'], 'source_queries_unsat': result['source_queries_unsat']}), flush=True)
