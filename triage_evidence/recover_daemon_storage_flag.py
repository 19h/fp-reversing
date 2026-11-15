#!/usr/bin/env python3
"""Recover storage-mode selection and its retained conditional byte custody.
O(parent bytes + retained visits + exports + text words) time/space. No new
target interval, guest input, owner/root definition or API-return premise.
"""
import gc
import json
import struct
from collections import Counter
from hashlib import sha256
from daemon_receive_tools import ROOT, SOURCE, IMAGE, TABLE, FIXUPS, verify_original_fixups
from audit_daemon_environment_outputs import DEC
from audit_daemon_network_record import state_bytes, fixture_bytes
from recover_daemon_append_fields import custody
from recover_daemon_iokit_census import text_section
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_daemon_alternate_word as Parent
import recover_daemon_record_selection as Selection
import recover_daemon_state_emitter_completion as Emitter
import recover_daemon_state_table_mixing as Mixing
import recover_daemon_table_consumer as Consumer
import recover_daemon_constructor_gate as Gate

P = 'daemon_storage_flag'
SP, U, FLAG = 0x6800060100, 0x6600060000, 0x680006672f
unpack = Gate.unpack
PINS = {**Parent.PINS,
 'daemon_alternate_word_checks.json': '871cad82eef3e7836eefecb9f7d6394335485bbf58342a3ce88485fa5c135e23',
 'daemon_alternate_word_audit.json': '91a53e7e9be47bd361c75184c7ecc33482bd3e95bf1207bbd462a42e861b75bb',
 'daemon_state_container_construction_checks.json': '1d19f7bc139ef5a334eb536ffc6f47a6f176553211402458b2a82fb649260ade',
 'daemon_state_container_construction_audit.json': '1db414094dfe83752510cf330f25090c8f2b1fc63a75d1911c1a9481e47c4ea6',
 'daemon_state_allocation_cascade_checks.json': '661c3f804d79bbbf49c44f4c464a1c773f43cbbc3fb796212d40a4deea46f809',
 'daemon_state_allocation_cascade_audit.json': '81d62f637d5d932dce165be5686198ae50afcf727fd8aba6d4b90794f1f99641',
 'daemon_state_emitter_completion_checks.json': '7339ebf095b22c8c390b536023d1639fbd2d36295124208a1784f1737f0bd2f1',
 'daemon_state_emitter_completion_audit.json': 'f94527805283b8d0c99a5fd964e914e043ba57869bd551c4864c02ceb03931ba',
 'daemon_state_table_mixing_checks.json': '48880e37460e2a7bf8862ebb59b739357791656bcb426a4b2ecc4643a94edbe7',
 'daemon_state_table_mixing_audit.json': '15c8b51ba1a781a2ee03efa37e24e14737faed37851c614a037a30aebf0dac91',
 'daemon_table_consumer_checks.json': '5137ecaa23c9984c362309dced8482323b1aca63357dcac61d3de3090a695f14',
 'daemon_table_consumer_audit.json': '05e23d2ba79cb44cde6226bc8dcf93fc280110810a3fdae1bed49edab9f05f8a'}
DEPS = ['recover_daemon_alternate_word.py', 'recover_daemon_record_selection.py',
        'recover_daemon_state_allocation_cascade.py', 'recover_daemon_state_emitter_completion.py',
        'recover_daemon_state_table_mixing.py', 'recover_daemon_table_consumer.py',
        'recover_daemon_constructor_gate.py', 'recover_daemon_append_fields.py',
        'recover_daemon_iokit_census.py', 'daemon_receive_tools.py', 'daemon_receive_fixups.txt',
        'audit_daemon_environment_outputs.py', 'audit_daemon_network_record.py']
SPANS = {'save_inputs': (0x10083c8c4, 0x10083c8cc),
         'pointer_gate': (0x10098aab0, 0x10098ab04),
         'nonnull_gate': (0x1008a3be0, 0x1008a3c34),
         'tag_comparison': (0x10068f774, 0x10068f7e0),
         'null_gate': (0x100753c74, 0x100753cc8),
         'zero_flag': (0x100910200, 0x100910220),
         'flag_publication': (0x1008258b0, 0x1008258d4),
         'base_publication': (0x100825884, 0x100825894),
         'word_selector': (0x1005320f8, 0x100532150)}
REPLAY_END = {'save_inputs': 0x10083c8cc, 'pointer_gate': 0x10098aafc,
              'nonnull_gate': 0x1008a3c28, 'tag_comparison': 0x10068f7d8,
              'flag_publication': 0x1008258d4, 'base_publication': 0x100825894}


def overlapping(w, a=FLAG, n=1):
    return int(w['address'], 16) < a+n and a < int(w['address'], 16)+w['size_bytes']


def preserved(row):
    initial = fixture_bytes(row, 'private') | fixture_bytes(row, 'image')
    assert initial[FLAG] == state_bytes(row)[FLAG] == 1
    assert not any(overlapping(w) for w in row['source_writes'])
    return {'entry': row['entry_PC'], 'exit': row['boundary']['pc'],
            'source_visits': len(row['source_visits']), 'overlapping_writes': 0, 'flag_before': 1, 'flag_after': 1}


def extract():
    for name, digest in PINS.items():
        assert sha(ROOT/name) == digest, name
    slices, cases, snapshots, persistence = [], [], [], []
    counts = Counter()
    def select(row, kind, group, ci):
        a, b = SPANS[kind][0], REPLAY_END[kind]
        lo = next(i for i, v in enumerate(row['source_visits']) if v['pc'] == hex(a))
        hi = lo+(b-a)//4
        assert [v['pc'] for v in row['source_visits'][lo:hi]] == [hex(pc) for pc in range(a, b, 4)]
        slices.append({'group': group, 'class_index': ci, 'interval_index': 0, 'kind': kind,
                       'start_visit': lo, 'end_visit_exclusive': hi, 'entry': row['source_frames'][lo],
                       'exit': row['source_frames'][hi],
                       'reads': [r for r in row['source_reads'] if lo <= r['source_visit_index'] < hi],
                       'writes': [w for w in row['source_writes'] if lo <= w['source_visit_index'] < hi]})
        return slices[-1]
    cc = json.loads(read(ROOT/'daemon_state_container_construction_checks.json'))
    assert len(cc['contexts']) == 76
    for ci, c in enumerate(cc['contexts']):
        row = unpack(c['allocation_cases'][1]['interval_packed'])
        selected = {k: select(row, k, 'constructor', ci) for k in ['save_inputs', 'pointer_gate', 'nonnull_gate', 'tag_comparison']}
        rr = [r for k in ['pointer_gate', 'nonnull_gate'] for r in selected[k]['reads'] if r['pc'] in ['0x10098aad4', '0x1008a3bf0', '0x1008a3bf8']]
        assert [(r['address'], r['bytes_hex']) for r in rr] == [('0x6800069d20', '3c5b110065000000'),
            ('0x6500115b3c', '06000000'), ('0x6800069d2c', '76e1404e')]
        chains = [{'read': r, 'custody': custody(row, r)} for r in rr]
        assert all(x['last_writer_in_this_interval'] is not None for k in [0, 2] for x in chains[k]['custody'])
        assert all(x['last_writer_in_this_interval'] is None for x in chains[1]['custody'])
        ws = [w for w in row['source_writes'] if overlapping(w)]
        assert len(ws) == 1 and (ws[0]['pc'], ws[0]['after_hex']) == ('0x10068f7c0', '01')
        for kind, reg, value in [('pointer_gate', 9, '0x66c1'), ('nonnull_gate', 11, '0x245b'), ('tag_comparison', 9, '0x1e2')]:
            assert selected[kind]['entry']['registers31'][reg] == value
        assert state_bytes(row)[FLAG] == 1
        cases.append({'constructor_index': ci, 'read_custody': chains, 'flag_writer': ws[0],
                      'pointed_word32': 6, 'tag32': '0x4e40e176', 'selected_flag_byte': 1})
        snapshots.append({'phase': 'container', 'parent_index': ci, 'flag_byte': 1})
    del cc
    gc.collect()
    # Continue with the existing source/ABI admissions; only the selector byte
    # is freshly projected here, not a second complete machine-state replay.
    cascade = json.loads(read(ROOT/'daemon_state_allocation_cascade_checks.json'))
    for ci, c in enumerate(cascade['contexts']):
        assert c['parent_context_index'] == ci
        for item in [c['allocation21_cases'][1], c['allocation48_cases'][1]]:
            assert not any(overlapping(x) for x in item['API_return_premise']['invalidated_spans'])
            persistence.append({'phase': 'cascade', 'parent_index': ci, **preserved(unpack(item['interval_packed']))})
        row = unpack(c['refill_comparison']['interval_packed'])
        persistence.append({'phase': 'cascade', 'parent_index': ci, **preserved(row)})
        snapshots.append({'phase': 'cascade', 'parent_index': ci, 'flag_byte': state_bytes(row)[FLAG]})
    del cascade
    gc.collect()
    for module in [Emitter, Mixing, Consumer]:
        d = json.loads(read(ROOT/(module.P+'_checks.json')))
        for ri, row in enumerate(module.intervals(d)):
            persistence.append({'phase': module.P, 'row_index': ri, **preserved(row)})
        assert {c['parent_index'] for c in d['coverage']} == set(range(76))
        for c in d['coverage']:
            value = state_bytes(unpack(c['derived_terminal_state_packed']))[FLAG]
            assert value == 1
            snapshots.append({'phase': module.P, 'parent_index': c['parent_index'], 'flag_byte': value})
        del d
        gc.collect()
    gate, old, growth = Selection.parents()
    for ci, c in enumerate(gate['classes']):
        row = unpack(c['interval_packed'])
        persistence.append({'phase': 'initializer', 'class_index': ci, **preserved(row)})
        for kind in ['flag_publication', 'base_publication']:
            select(row, kind, 'initializer', ci)
        reads = [r for r in row['source_reads'] if r['pc'] == '0x1008258b4']
        assert len(reads) == 1 and reads[0]['address'] == hex(FLAG) and reads[0]['bytes_hex'] == '01'
        assert all(x['last_writer_in_this_interval'] is None for x in custody(row, reads[0]))
    assert {c['parent_index'] for c in gate['coverage']} == set(range(76))
    for c in gate['coverage']:
        assert all(not overlapping(f | {'size_bytes': len(bytes.fromhex(f['bytes_hex']))}) for f in c['entry_premises'])
        value = state_bytes(unpack(c['derived_terminal_state_packed']))[FLAG]
        assert value == 1
        snapshots.append({'phase': 'initializer', 'parent_index': c['parent_index'], 'flag_byte': value})
    object_views = []
    for phase, coverage in [('initializer', gate['coverage']), ('prefix', old['prefix_coverage']),
                            ('constructor', old['coverage']), ('growth', growth['coverage'])]:
        for c in coverage:
            if phase == 'constructor' and old['branches'][c['branch_index']]['pointer_return64'] == '0x0':
                continue
            if phase == 'growth' and c['pointer_return64'] == '0x0':
                continue
            row = unpack(c['derived_terminal_state_packed'])
            m = state_bytes(row)
            word = lambda a, n: int.from_bytes(bytes(m[a+j] for j in range(n)), 'little')
            assert word(U, 8) == 0 and word(U+0x28, 4) == 0xd299e642
            expected = 0x6600050000 if phase in ['initializer', 'prefix'] else 0x6600070000 if phase == 'constructor' else 0x6600080000
            assert word(U+8, 8) == expected
            object_views.append({'phase': phase, 'U0': '0x0', 'U8': hex(expected), 'U28': '0xd299e642'})
    assert len(snapshots) == 456 and len(object_views) == 608
    del gate, old, growth
    gc.collect()
    source = [{'kind': k, 'start': hex(a), 'end_exclusive': hex(b), 'bytes_hex': IMAGE.read(a, b-a).hex()}
              for k, (a, b) in SPANS.items()]
    routes = []
    for idx, target, modifier in [(0x66c1,0x1008a3be0,0x4f69),(0x66d6,0x100753c74,0x4f69),
        (0x245b,0x10068f774,0x724e),(0x246d,0x10068ae70,0x724e),(0xae32,0x100910200,0x6d79),
        (0x76bf,0x10068ae70,0x6d79),(0x9a64,0x1008c0750,0x2175),(0x9a68,0x100934280,0x2175)]:
        slot = TABLE+8*idx
        raw = IMAGE.read(slot,8)
        word = int.from_bytes(raw,'little')
        assert FIXUPS[slot]['target'] == target and (word>>32)&65535 == modifier and (word>>48)&7 == 0
        routes.append({'index32':hex(idx),'target':hex(target),'IA_modifier':hex(modifier),'slot':hex(slot),'word_hex':raw.hex()})
    a,n = text_section()
    text = IMAGE.read(a,n)
    census = {}
    for name,op in [('STRB',0x39000000),('LDRB',0x39400000)]:
        census[name] = [{'pc':hex(a+4*j),'word_hex':struct.pack('<I',w).hex(),'base_register':(w>>5)&31,'value_register':w&31,
                         'context_start':hex(a+4*j-32),'context_bytes_hex':IMAGE.read(a+4*j-32,36).hex()}
                        for j,(w,) in enumerate(struct.iter_unpack('<I',text)) if w&0xfffffc00 == op|(0x62f<<10)]
    assert len(census['STRB']) == 6 and len(census['LDRB']) == 3
    counts.update(constructor_cases=len(cases), byte_phase_snapshots=len(snapshots), object_views=len(object_views),
                  object_field_values_checked=3*len(object_views), object_bytes_checked=20*len(object_views),
                  persistence_rows=len(persistence), persistence_visits=sum(r['source_visits'] for r in persistence),
                  source_instructions=sum((b-a)//4 for a,b in SPANS.values()), replay_slices=len(slices),
                  dispatch_routes=len(routes), text_words_scanned=n//4, direct_STRB_candidates=6, direct_LDRB_candidates=3)
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE), 'parent_pins':PINS,
            'dependencies':{p:sha(ROOT/p) for p in DEPS},'source_spans':source,'cases':cases,'slices':slices,
            'phase_snapshots':snapshots,'byte_persistence':persistence,'object_views':object_views,
            'routes':routes,'original_fixups':verify_original_fixups(int(r['slot'],16) for r in routes),
            'direct_displacement_census':{'text_start':hex(a),'text_bytes':n,'text_sha256':sha256(text).hexdigest(),
                'candidates':census,'scope':'Aligned unsigned-immediate STRB/LDRB with displacement 0x62f, all base registers. Other widths/forms/aliases and frame epochs excluded.'},
            'verified_counts':dict(counts),'prior_admissions_rerun':False,'new_target_intervals':0,
            'new_guest_input_bytes':0,'new_API_return_premises':0,'native_target_executed':False,'full_goal_complete':False}


if __name__ == '__main__':
    e=extract()
    (ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n')
    print(json.dumps(e['verified_counts']),flush=True)
