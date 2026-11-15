#!/usr/bin/env python3
"""Replay retained core, prove address/exit cuts and compare independent DAG evaluation.
O(parent bytes + retained replay*32 + vector source visits + vector DAG nodes
+ immutable bytes + proof DAG) time/space; solver search additional, 30 s/query.
Concrete source lift and DAG evaluation share source interpretation provenance;
the DAG evaluator implements bit-vector operators independently. No native run.
"""
import json
from collections import Counter, defaultdict
from copy import deepcopy
from hashlib import sha256
import z3
from daemon_receive_tools import ROOT, SOURCE, IMAGE, verify_original_fixups
from verify_daemon_reader_record_payloads_publication import read, sha
from audit_daemon_record_input_origin import replay
from audit_daemon_alternative_fill import Source
from audit_daemon_append_fields import number
from lskd_values_symbolic import resize
from recover_daemon_record_banks import instruction
from daemon_core_lookup_kernel import transform
import recover_daemon_core_lookup as R

DEPS = ['daemon_core_lookup_kernel.py', 'audit_daemon_record_input_origin.py',
        'audit_daemon_alternative_fill.py', 'audit_daemon_append_fields.py',
        'audit_daemon_state_table_mixing.py', 'lskd_values_symbolic.py']


def obligations(model, ci):
    groups = defaultdict(list)
    for kind, pc, bad in model.conditions: groups[kind].append((pc, bad))
    out = []
    for kind, rows in groups.items():
        solver = z3.Solver(); solver.set(timeout=30000)
        assert solver.check() == z3.sat
        solver.add(z3.Or(*[bad for pc, bad in rows])); result = solver.check()
        assert result == z3.unsat, (ci, kind, str(result), solver.reason_unknown())
        out.append({'label': str(ci)+'_'+kind, 'class_index': ci, 'kind': kind,
                    'conditions': len(rows), 'coordinates': [pc for pc, bad in rows],
                    'premises_nonvacuous': True, 'result': 'unsat', 'query': solver.to_smt2()})
        print(json.dumps({'source_proof': out[-1]['label'], 'conditions': len(rows), 'result': 'unsat'}), flush=True)
    return out


class Concrete(Source):
    """Original instructions and byte memory; no expression graph is executed."""
    def __init__(self, case, data):
        super().__init__()
        self.case = case; self.bytes = {int(a, 16): b for a, b in case['initial_context_bytes'].items()}
        self.bytes.update({R.INPUT+j: b for j, b in enumerate(data)})
        self.ri = self.wi = 0; self.accesses = []
        self.lookup = {x['pc']: x for x in case['graph']['lookups']}
        f = case['source_chunk']['frames'][0]
        for j, x in enumerate(f['registers31']): self.seed('x'+str(j), int(x, 16))
        self.seed('sp', int(f['SP'], 16)); nz = int(f['NZCV'], 16)
        self.n, self.z, self.carry, self.overflow = [z3.BoolVal(bool(nz & (1 << b))) for b in [31, 30, 29, 28]]

    def one(self, ins):
        if ins.mnemonic == 'cneg':
            self.pc = ins.address
            reg = ins.reg_name(ins.operands[0].reg); value = self.read(ins.reg_name(ins.operands[1].reg))
            self.write(reg, z3.If(self.condition(ins.op_str.rsplit(',', 1)[1].strip()), -value, value))
            return
        return super().one(ins)

    def load(self, address, n):
        a = number(address); row = self.case['source_chunk']['reads'][self.ri]; self.ri += 1
        assert row['pc'] == hex(self.pc) and row['size_bytes'] == n
        if row['pc'] in self.lookup:
            r = self.lookup[row['pc']]; unit = r['unit_bytes']; delta = a-int(r['base'], 16)
            assert n == unit and 0 <= delta < 256*unit and delta % unit == 0
            raw = IMAGE.read(a, n)
            self.accesses.append({'pc': row['pc'], 'address': hex(a), 'bytes_hex': raw.hex()})
        else:
            assert a == int(row['address'], 16)
            raw = bytes(self.bytes[a+j] for j in range(n))
        return z3.BitVecVal(int.from_bytes(raw, 'little'), n*8)

    def store(self, address, n, value, pc):
        a = number(address); row = self.case['source_chunk']['writes'][self.wi]; self.wi += 1
        assert (row['pc'], row['address'], row['size_bytes']) == (hex(pc), hex(a), n)
        raw = number(resize(value, n*8)).to_bytes(n, 'little')
        self.bytes.update({a+j: b for j, b in enumerate(raw)})

    def run(self):
        for pc in range(R.START, R.STOP-4, 4): self.one(instruction(pc))
        assert self.ri == len(self.case['source_chunk']['reads']) and self.wi == len(self.case['source_chunk']['writes'])
        assert hex(number(self.read('x8'))) == self.case['exit']['target']
        assert hex(number(self.read('x17'))) == self.case['exit']['modifier']
        return bytes(self.bytes[R.OUTPUT+j] for j in range(16)), self.accesses


def vectors(retained):
    out = [('retained', bytes.fromhex(retained)), ('zero', bytes(16)), ('ones', bytes([255])*16), ('ramp', bytes(range(16)))]
    out.extend(('basis_'+str(j), (1 << j).to_bytes(16, 'little')) for j in range(128))
    out.extend(('sha256_'+str(j), sha256(b'core-lookup-vector-'+str(j).encode()).digest()[:16]) for j in range(16))
    assert len(out) == len({data for label, data in out}) == 148
    return out


def controls(case):
    z = bytes(16); a, b = bytes([1])+bytes(15), bytes([2])+bytes(15)
    ab = bytes([3])+bytes(15)
    outputs = [transform(case, x)[0] for x in [z, a, b, ab]]
    residual = bytes(outputs[0][j]^outputs[1][j]^outputs[2][j]^outputs[3][j] for j in range(16))
    assert any(residual)
    damaged = deepcopy(case); base = damaged['graph']['lookups'][16]['base']
    reference, accesses = transform(case, bytes.fromhex(case['entry_input16_hex']))
    used = accesses[16]; offset = int(used['address'], 16)-int(base, 16)
    raw = bytearray.fromhex(damaged['graph']['windows'][base]['bytes_hex']); raw[offset] ^= 1
    damaged['graph']['windows'][base]['bytes_hex'] = raw.hex()
    changed = transform(damaged, bytes.fromhex(case['entry_input16_hex']))[0]
    assert changed != reference
    return {'nonaffine_counterexample': {'inputs16_hex': [x.hex() for x in [z, a, b, ab]],
             'outputs16_hex': [x.hex() for x in outputs], 'four_output_XOR16_hex': residual.hex()},
            'corrupted_literal_table_control': {'base': base, 'changed_address': used['address'],
             'xor8': 1, 'reference_output16_hex': reference.hex(), 'changed_output16_hex': changed.hex()}}


def audit():
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    assert e == R.build(); totals = Counter(); proofs = []; checked = []; references = []; fixups = set()
    assert e['cases'][0]['graph'] == e['cases'][1]['graph']
    for case, parent in zip(e['cases'], R.parents()):
        chunk = R.core(parent); assert case['source_chunk'] == chunk
        totals.update(replay(chunk))
        model = R.Model(chunk).run(); assert R.graph(model) == case['graph']
        proofs.extend(obligations(model, case['class_index']))
        assert len({r['pc'] for r in case['graph']['lookups']}) == 192
        assert sorted(r['offset'] for r in case['fixed_reads'] if r['kind'] == 'input') == list(range(16))
        window_rows = []
        for base, r in case['graph']['windows'].items():
            raw = IMAGE.read(int(base, 16), 256*r['unit_bytes']); assert raw.hex() == r['bytes_hex']
            values = [int.from_bytes(raw[j:j+r['unit_bytes']], 'little') for j in range(0, len(raw), r['unit_bytes'])]
            window_rows.append({'base': base, 'unit_bytes': r['unit_bytes'], 'rows': 256, 'distinct_values': len(set(values))})
            totals['immutable_window_bytes_checked'] += len(raw)
        references.append({'class_index': case['class_index'], 'windows': window_rows})
        fixups.update(int(r['address'], 16) for r in case['fixed_reads'] if r['kind'] == 'original_fixup')
        source_reads = {r['pc']: r for r in chunk['reads']}
        out, accesses = transform(case, bytes.fromhex(case['entry_input16_hex']))
        assert out.hex() == case['expected_output16_hex']
        for r in accesses:
            original = source_reads[r['pc']]
            assert all(original[k] == value for k, value in r.items())
        totals['retained_graph_lookup_reads_checked'] += len(accesses)
        inputs = vectors(case['entry_input16_hex'])
        selected = inputs if not checked else inputs[:4]+inputs[-4:]
        rows = []
        for vi, (label, data) in enumerate(selected):
            actual, log = Concrete(case, data).run(); expected, reference_log = transform(case, data)
            assert actual == expected and log == reference_log
            rows.append({'label': label, 'input16_hex': data.hex(), 'output16_hex': actual.hex(),
                         'lookup_accesses_sha256': sha256(json.dumps(log, sort_keys=True).encode()).hexdigest()})
            totals.update(source_vector_runs=1, source_vector_visits=(R.STOP-R.START)//4-1,
                          graph_vector_runs=1, source_graph_lookup_values_checked=len(log),
                          source_vector_output_bytes_checked=16)
            if vi % 16 == 0: print(json.dumps({'class_index': case['class_index'], 'vector': vi, 'of': len(selected), 'source_DAG_match': True}), flush=True)
        checked.append({'class_index': case['class_index'], 'vectors': rows})
    assert len(proofs) == 14 and sum(p['conditions'] for p in proofs) == 676
    return {'scope': __doc__, 'auditor_sha256': sha(__file__), 'generator_sha256': sha(ROOT/(R.P.replace('daemon_', 'recover_daemon_', 1)+'.py')),
            'source_sha256': sha(SOURCE), 'checks_sha256': sha(ROOT/(R.P+'_checks.json')),
            'dependencies': {p: sha(ROOT/p) for p in DEPS}, 'independent_totals': dict(totals),
            'identical_retained_context_graphs': True, 'references': references,
            'source_queries_unsat': len(proofs), 'source_proofs': proofs,
            'original_fixups': verify_original_fixups(fixups), 'vectors': checked,
            'controls': controls(e['cases'][0]), 'native_API_executed': False,
            'native_daemon_kext_pairing_established': False, 'transform_algorithm_established': False,
            'full_goal_complete': False}


if __name__ == '__main__':
    a = audit(); (ROOT/(R.P+'_audit.json')).write_text(json.dumps(a, indent=2)+'\n')
    print(json.dumps(a['independent_totals']), flush=True)
