#!/usr/bin/env python3
"""Source-derived core lookup graph under two retained entry contexts.
O(parent bytes + source visits + expression DAG + reference bytes) time/space.
No native execution, root admission, hardware PAC or IDB modification.
"""
import json
from collections import Counter
import z3
from daemon_receive_tools import ROOT, SOURCE, IMAGE, FIXUPS
from verify_daemon_reader_record_payloads_publication import read, sha
from recover_daemon_record_banks import instruction
from recover_daemon_block_staging import BANKS, subchunk
from audit_daemon_alternative_fill import Source
from audit_daemon_append_fields import number
from lskd_values_symbolic import resize

P = 'daemon_core_lookup'
START, STOP = 0x10010eabc, 0x1001112c0
INPUT, OUTPUT = 0x680005fa80, 0x680005fa90
PINS = {'daemon_record_input_origin_checks.json': '450d52130015a8ae1e0f033db234be880051d9071b9f478cc93e9778bce7a12e',
        'daemon_block_staging_checks.json': 'f544501de6a7ceefa17c5bba23a8f1de5137bbf8cd53d812e66b8e5e5a0e00a6'}
DEPS = ['daemon_receive_tools.py', 'daemon_receive_fixups.txt', 'recover_daemon_record_banks.py',
        'recover_daemon_block_staging.py', 'audit_daemon_alternative_fill.py',
        'audit_daemon_append_fields.py', 'audit_daemon_state_table_mixing.py', 'lskd_values_symbolic.py']


def variables(x):
    """Visit shared AST nodes once; tree recursion expands repeated subterms."""
    seen, found, pending = set(), {}, [x]
    while pending:
        y = pending.pop(); key = y.get_id()
        if key in seen: continue
        seen.add(key)
        if z3.is_const(y) and y.decl().kind() == z3.Z3_OP_UNINTERPRETED: found[str(y)] = y
        else: pending.extend(y.children())
    return [found[k] for k in sorted(found)]


def parents():
    for p, digest in PINS.items(): assert sha(ROOT/p) == digest
    return json.loads(read(ROOT/'daemon_record_input_origin_checks.json'))['cases']


def core(parent):
    p = parent['chunks'][-1]
    lo = next(j for j, v in enumerate(p['visits']) if int(v['pc'], 16) == START)
    hi = next(j for j, v in enumerate(p['visits']) if int(v['pc'], 16) == STOP-4)+1
    assert [int(v['pc'], 16) for v in p['visits'][lo:hi]] == list(range(START, STOP, 4))
    return subchunk(p, lo, hi, 'core_lookup')


class Model(Source):
    def __init__(self, chunk):
        super().__init__()
        self.chunk, self.shadow, self.initial = chunk, {}, {}
        self.ri = self.wi = 0
        self.lookups, self.output, self.conditions, self.fixed = [], [], [], []
        self.windows = {}; self.inputs = [z3.BitVec('core_input_%02d_8' % j, 8) for j in range(16)]
        f = chunk['frames'][0]
        for j, x in enumerate(f['registers31']): self.seed('x'+str(j), int(x, 16))
        self.seed('sp', int(f['SP'], 16)); nz = int(f['NZCV'], 16)
        self.n, self.z, self.carry, self.overflow = [z3.BoolVal(bool(nz & (1 << b))) for b in [31, 30, 29, 28]]

    def condition_record(self, kind, pc, bad):
        self.conditions.append((kind, hex(pc), z3.simplify(bad)))

    def one(self, ins):
        if ins.mnemonic == 'cneg':
            self.pc = ins.address
            value = self.read(ins.reg_name(ins.operands[1].reg))
            self.write(ins.reg_name(ins.operands[0].reg), z3.If(self.condition(ins.op_str.rsplit(',', 1)[1].strip()), -value, value))
            return
        return super().one(ins)

    def load(self, address, n):
        r = self.chunk['reads'][self.ri]; self.ri += 1
        assert (r['pc'], r['size_bytes']) == (hex(self.pc), n)
        at = int(r['address'], 16); address = z3.simplify(address)
        if all(at+j in self.shadow for j in range(n)):
            self.condition_record('shadow_read_address', self.pc, address != at)
            return self.shadow[at] if n == 1 else z3.Concat(*[self.shadow[at+j] for j in reversed(range(n))])
        if INPUT <= at < INPUT+16:
            assert n == 1
            self.condition_record('input_read_address', self.pc, address != at)
            self.fixed.append({'kind': 'input', 'pc': hex(self.pc), 'offset': at-INPUT})
            return self.inputs[at-INPUT]
        word = n == 4 and any(b <= at < b+1024 for b in BANKS)
        if self.pc != STOP-12 and (word or variables(address)):
            if word:
                base = next(b for b in BANKS if b <= at < b+1024); unit = 4
                index = z3.simplify(z3.LShR(address-base, 2))
            else:
                assert n == 1 and address.decl().kind() == z3.Z3_OP_BADD
                base = sum(x.as_long() for x in address.children() if z3.is_bv_value(x)) % (1 << 64)
                assert base and 0 <= at-base < 256
                unit = 1; index = z3.simplify(address-base)
            self.condition_record('lookup_extent_and_stride', self.pc,
                                  z3.Or(z3.UGT(index, 255), address != base+unit*index))
            name = 'core_lookup_%03d_%d' % (len(self.lookups), n*8)
            value = z3.BitVec(name, n*8)
            self.lookups.append({'pc': hex(self.pc), 'base': hex(base), 'unit_bytes': unit,
                                 'name': name, 'index': index, 'value': value})
            key = hex(base)
            self.windows[key] = {'unit_bytes': unit, 'rows': 256,
                                 'bytes_hex': IMAGE.read(base, 256*unit).hex()}
            return value
        self.condition_record('fixed_read_address', self.pc, address != at)
        raw = bytes.fromhex(r['bytes_hex'])
        origin = 'retained_context'
        if at in FIXUPS and n == 8:
            assert FIXUPS[at]['target'] == int.from_bytes(raw, 'little'); origin = 'original_fixup'
        else:
            try:
                if IMAGE.read(at, n) == raw: origin = 'original_image'
            except (AssertionError, ValueError, KeyError): pass
        self.fixed.append({'kind': origin, 'pc': hex(self.pc), 'address': hex(at), 'bytes_hex': raw.hex()})
        for j, b in enumerate(raw):
            if at+j in self.initial: assert self.initial[at+j] == b
            self.initial[at+j] = b
        return z3.BitVecVal(int.from_bytes(raw, 'little'), n*8)

    def store(self, address, n, value, pc):
        w = self.chunk['writes'][self.wi]; self.wi += 1
        assert (w['pc'], w['size_bytes']) == (hex(pc), n)
        at = int(w['address'], 16); value = resize(value, n*8)
        self.condition_record('store_address', pc, address != at)
        for j in range(n): self.shadow[at+j] = z3.simplify(z3.Extract(j*8+7, j*8, value))
        if OUTPUT <= at < OUTPUT+16:
            assert n == 1
            self.output.append({'offset': at-OUTPUT, 'pc': hex(pc), 'value': z3.simplify(value)})

    def run(self):
        for pc in range(START, STOP-4, 4): self.one(instruction(pc))
        edge, = self.chunk['edges']; assert edge['pc'] == hex(STOP-4)
        self.condition_record('fixed_exit_target', STOP-4, self.read('x8') != int(edge['target'], 16))
        self.condition_record('fixed_exit_modifier', STOP-4, self.read('x17') != int(edge['modifier'], 16))
        assert self.ri == len(self.chunk['reads']) and self.wi == len(self.chunk['writes'])
        assert len(self.lookups) == 192 and len(self.output) == 16
        assert sorted(o['offset'] for o in self.output) == list(range(16))
        return self


def graph(model):
    """Topological, shared bit-vector DAG; variable lookup cuts are explicit."""
    nodes, ids = [], {}
    def add(root):
        pending = [(root, False)]
        while pending:
            x, ready = pending.pop(); key = x.get_id()
            if key in ids: continue
            if not ready:
                pending.append((x, True)); pending.extend((y, False) for y in reversed(x.children()))
                continue
            args = [ids[y.get_id()] for y in x.children()]
            width = x.size() if z3.is_bv(x) else 0
            if z3.is_bv_value(x): row = ['literal', width, x.as_long()]
            elif z3.is_true(x) or z3.is_false(x): row = ['bool', 0, z3.is_true(x)]
            elif x.decl().kind() == z3.Z3_OP_UNINTERPRETED: row = ['variable', width, str(x)]
            else: row = [str(x.decl().name()), width, list(x.decl().params()), args]
            ids[key] = len(nodes); nodes.append(row)
        return ids[root.get_id()]
    inputs = [add(x) for x in model.inputs]; lookups = []
    for r in model.lookups:
        lookups.append({k: v for k, v in r.items() if k not in ['index', 'value']} |
                       {'index_node': add(r['index']), 'value_node': add(r['value'])})
    outputs = [{k: v for k, v in r.items() if k != 'value'} | {'value_node': add(r['value'])} for r in model.output]
    return {'nodes': nodes, 'input_nodes': inputs, 'lookups': lookups, 'output': outputs,
            'windows': model.windows}


def build():
    cases = []; counts = Counter()
    staging = json.loads(read(ROOT/'daemon_block_staging_checks.json'))
    for parent in parents():
        chunk = core(parent); model = Model(chunk).run(); g = graph(model)
        counts.update(retained_contexts=1, source_visits=len(chunk['visits']), lookup_nodes=len(g['lookups']),
                      input_byte_reads=16, output_byte_stores=16, fixed_read_value_cells=len(model.fixed)-16,
                      address_and_exit_conditions=len(model.conditions), expression_nodes=len(g['nodes']))
        cases.append({'class_index': parent['class_index'], 'source_chunk': chunk,
                      'graph': g, 'fixed_reads': model.fixed,
                      'initial_context_bytes': {hex(a): b for a, b in sorted(model.initial.items())},
                      'condition_labels': [[kind, pc] for kind, pc, bad in model.conditions],
                      'entry_input16_hex': staging['cases'][len(cases)]['vectors']['staged_input16_hex'],
                      'expected_output16_hex': staging['cases'][len(cases)]['vectors']['core_output16_hex'],
                      'exit': chunk['edges'][0]})
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'source_sha256': sha(SOURCE),
            'parent_pins': PINS, 'dependencies': {p: sha(ROOT/p) for p in DEPS}, 'cases': cases,
            'verified_counts': dict(counts), 'native_API_executed': False,
            'native_daemon_kext_pairing_established': False, 'transform_algorithm_established': False,
            'full_goal_complete': False}


if __name__ == '__main__':
    e = build(); (ROOT/(P+'_checks.json')).write_text(json.dumps(e, indent=2)+'\n')
    print(json.dumps(e['verified_counts']), flush=True)
