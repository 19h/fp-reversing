#!/usr/bin/env python3
"""Private descriptor rekeying, sixteen-byte staging and table-read footprint.
Fixed 68 chunks: O(parent bytes + visits + effect bytes + selected frames)
time/space. No new CPU interval, root admission, native API, IPC or IDB edit.
"""
import json
from collections import Counter, defaultdict
from daemon_receive_tools import ROOT, SOURCE, IMAGE, TABLE, FIXUPS
from verify_daemon_reader_record_payloads_publication import read, sha
from recover_daemon_record_banks import span, instruction

P = 'daemon_block_staging'
PINS = {'daemon_record_input_origin_checks.json': '450d52130015a8ae1e0f033db234be880051d9071b9f478cc93e9778bce7a12e',
        'daemon_record_input_origin_audit.json': '3fc418ed9272a785fbea01bef58a11a625b4c748dbab9d2fd3b04f8d4fb84363'}
DEPS = ['daemon_receive_tools.py', 'daemon_receive_fixups.txt', 'recover_daemon_record_banks.py',
        'verify_daemon_reader_record_payloads_publication.py']
SPANS = {'wrapper_encoding': (0x100427c4c, 0x100427ce8),
         'descriptor_decoder': (0x100411584, 0x1004115f0),
         'staging_count': (0x100411610, 0x100411614),
         'dispatch_load': (0x10041160c, 0x100411610),
         'input_loop': (0x10004e8b8, 0x10004e9d0),
         'output_loop': (0x100085b08, 0x100085c1c)}
BANKS = [0x100e40e10, 0x100f33b10, 0x100fdec70, 0x100e94720,
         0x100f400e0, 0x100ed3a70, 0x100f2e680, 0x10101ab70]


def register(frame, name):
    key = {'fp': 29, 'lr': 30}.get(name)
    if key is None:
        assert name.startswith(('x', 'w'))
        key = int(name[1:])
    value = int(frame['registers31'][key], 16)
    return value & ((1 << (32 if name.startswith('w') else 64))-1)


def subchunk(parent, lo, hi, kind):
    start = parent['start_visit']+lo; stop = parent['start_visit']+hi
    return {'kind': kind, 'start_visit': start, 'end_visit_exclusive': stop,
            'visits': parent['visits'][lo:hi], 'frames': parent['frames'][lo:hi+1],
            'Q_registers32_preserved': parent['Q_registers32_preserved'],
            'reads': [r for r in parent['reads'] if start <= r['source_visit_index'] < stop],
            'writes': [w for w in parent['writes'] if start <= w['source_visit_index'] < stop],
            'edges': [e for e in parent['edges'] if start <= e['source_visit_index'] < stop]}


def stages(parent, kind):
    a, b = SPANS[kind+'_loop']; n = (b-a)//4
    out = []
    for lo, v in enumerate(parent['visits']):
        if int(v['pc'], 16) != a: continue
        assert [int(x['pc'], 16) for x in parent['visits'][lo:lo+n]] == list(range(a, b, 4))
        c = subchunk(parent, lo, lo+n, kind)
        def rr(pc):
            hits = [r for r in c['reads'] if r['pc'] == hex(pc)]; assert len(hits) == 1
            return hits[0]
        src = rr(0x10004e954 if kind == 'input' else 0x100085b10)
        store_pc = 0x10004e9a8 if kind == 'input' else 0x100085bfc
        stores = [w for w in c['writes'] if w['pc'] == hex(store_pc)]; assert len(stores) == 1
        dst = stores[0]; assert src['size_bytes'] == dst['size_bytes'] == 1
        h = int(c['frames'][0]['SP'], 16)
        position = int(dst['address'], 16)-(h+0xd0) if kind == 'input' else int(src['address'], 16)-(h+0xe0)
        assert 0 <= position < 16
        entry = c['frames'][0]
        if kind == 'input':
            assert register(entry, 'x3') == position+1 and register(entry, 'w10') == 0x81f7
            assert register(entry, 'w6') == 0x3f2 and register(entry, 'x11') == h+0xd0
        else:
            assert register(entry, 'x8') == (position-15) & ((1 << 64)-1)
            assert register(entry, 'w9') == 0x3808 and register(entry, 'w16') == 0x5f91
            assert register(entry, 'x10') == h+0xef
        pcs = [0x10004e988, 0x10004e990, 0x10004e994] if kind == 'input' else [0x100085bbc, 0x100085bd0, 0x100085be0]
        rows = [rr(pc) for pc in pcs]
        assert all(r['size_bytes'] == 1 and IMAGE.read(int(r['address'], 16), 1).hex() == r['bytes_hex'] for r in rows)
        coefficient, constant = (0x6f, 0x43) if kind == 'input' else (0x17, 0xd8)
        mask = ((position*coefficient) ^ constant)
        for r in rows: mask ^= bytes.fromhex(r['bytes_hex'])[0]
        mask &= 255
        assert bytes.fromhex(dst['after_hex'])[0] == bytes.fromhex(src['bytes_hex'])[0]^mask
        out.append({'position': position, 'inner_SP': hex(h), 'input': src, 'output': dst,
                    'bank_reads': rows, 'mask_byte': mask, 'source_chunk': c})
    assert [c['position'] for c in out] == list(range(15, -1, -1))
    return out


def extract(parent, ci):
    stage = {name: stages(parent, name) for name in ['input', 'output']}
    def contiguous(name):
        a, b = SPANS[name]; n = (b-a)//4
        hits = [j for j, v in enumerate(parent['visits']) if int(v['pc'], 16) == a]; assert len(hits) == 1
        lo = hits[0]; assert [int(v['pc'], 16) for v in parent['visits'][lo:lo+n]] == list(range(a, b, 4))
        return subchunk(parent, lo, lo+n, name)
    records = [contiguous('wrapper_encoding'), contiguous('descriptor_decoder')]
    desc = next(r for r in parent['reads'] if r['pc'] == '0x1004115b0')
    d = int(desc['address'], 16)-12; w = int.from_bytes(bytes.fromhex(desc['bytes_hex']), 'little')
    index = w ^ (((d & 0xffffffff)^0x966e5812)*0x592e2f77 & 0xffffffff)
    assert index == 0x81f7 and not d & 15
    load = next(r for r in parent['reads'] if r['pc'] == '0x10041160c')
    assert load['address'] == hex(TABLE+8*index)
    assert int.from_bytes(bytes.fromhex(load['bytes_hex']), 'little') == FIXUPS[TABLE+8*index]['target'] == 0x10004e8b8
    footprint = []
    for r in parent['reads']:
        a = int(r['address'], 16); pc = int(r['pc'], 16)
        if not (0x10010eabc <= pc <= 0x1001112bc and r['size_bytes'] == 4): continue
        hits = [b for b in BANKS if b <= a < b+1024]
        if not hits: continue
        assert len(hits) == 1; b = hits[0]; assert (a-b)%4 == 0
        ins = instruction(pc); assert ins.mnemonic == 'ldr'
        frame = parent['frames'][r['source_visit_index']-parent['start_visit']]
        assert register(frame, ins.reg_name(ins.operands[1].mem.base)) == b
        assert r['bytes_hex'] == IMAGE.read(a, 4).hex()
        footprint.append({'read': r, 'bank_base': hex(b), 'index': (a-b)//4})
    counts = Counter(int(x['bank_base'], 16) for x in footprint)
    assert counts == Counter({b: 36 if j < 4 else 4 for j, b in enumerate(BANKS)})
    masks = {k: bytes(x['mask_byte'] for x in reversed(v)).hex() for k, v in stage.items()}
    windows = {}
    for kind, rows in stage.items():
        bases = [int(r['address'], 16) for r in rows[-1]['bank_reads']]
        assert all([int(r['address'], 16) for r in x['bank_reads']] == [b+x['position'] for b in bases] for x in rows)
        windows[kind] = [{'base': hex(b), 'bytes_hex': IMAGE.read(b, 16).hex(), 'extent_bytes': 16} for b in bases]
    def vector(xs, key, value):
        return ''.join(x[key][value] for x in reversed(xs))
    vectors = {'external_input16_hex': vector(stage['input'], 'input', 'bytes_hex'),
               'staged_input16_hex': vector(stage['input'], 'output', 'after_hex'),
               'core_output16_hex': vector(stage['output'], 'input', 'bytes_hex'),
               'external_output16_hex': vector(stage['output'], 'output', 'after_hex')}
    assert len(set(x['inner_SP'] for k in stage.values() for x in k)) == 1
    return {'class_index': ci, 'descriptor_base': hex(d), 'descriptor_raw_control32': hex(w),
            'decoded_dispatch_index32': hex(index), 'dispatch_read': load,
            'descriptor_chunks': records, 'stages': stage, 'mask16_hex': masks, 'mask_windows': windows, 'vectors': vectors,
            'core_word_table_reads': footprint, 'word_table_counts': {hex(b): counts[b] for b in BANKS},
            'native_execution': False}


def build():
    for p, digest in PINS.items(): assert sha(ROOT/p) == digest
    old = json.loads(read(ROOT/'daemon_record_input_origin_checks.json')); cases = []; counts = Counter()
    for source in old['cases']:
        c = extract(source['chunks'][-1], source['class_index']); cases.append(c)
        chunks = c['descriptor_chunks']+[x['source_chunk'] for k in c['stages'].values() for x in k]
        counts.update(retained_classes=1, selected_chunks=len(chunks), source_visits=sum(len(x['visits']) for x in chunks),
                      staged_input_bytes=16, staged_output_bytes=16, core_word_table_reads=len(c['core_word_table_reads']),
                      mask_bank_bytes_checked=sum(len(x['bank_reads']) for k in c['stages'].values() for x in k))
    counts.update(immutable_word_banks=8, immutable_word_rows=2048, immutable_word_bytes=8192,
                  immutable_mask_windows=6, immutable_mask_bytes=96,
                  new_target_intervals=0, new_root_bytes=0)
    routes = [0x81f7, 0x8205, 0x3808, 0x6799]
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'source_sha256': sha(SOURCE),
            'dependencies': {p: sha(ROOT/p) for p in DEPS}, 'parent_pins': PINS, 'cases': cases,
            'source_spans': {k: span(*v) for k, v in SPANS.items()},
            'word_banks': {hex(b): {'bytes_hex': IMAGE.read(b, 1024).hex(), 'extent_bytes': 1024} for b in BANKS},
            'dispatch': [{'index': hex(i), 'slot': hex(TABLE+8*i),
                          'word_hex': IMAGE.read(TABLE+8*i, 8).hex(), 'fixup': FIXUPS[TABLE+8*i]} for i in routes],
            'verified_counts': dict(counts), 'native_API_executed': False,
            'native_daemon_kext_pairing_established': False, 'transform_algorithm_established': False,
            'full_goal_complete': False}


if __name__ == '__main__':
    e = build(); (ROOT/(P+'_checks.json')).write_text(json.dumps(e, indent=2)+'\n')
    print(json.dumps(e['verified_counts']), flush=True)
