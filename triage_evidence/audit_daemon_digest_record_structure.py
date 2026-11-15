#!/usr/bin/env python3
"""Independent retained field, count, tempering and future-write audit.
Conservative O(P+(Q+C)*E+(E+Q)*log(E+Q)+32V+proof DAG) time and
O(parent receipts+largest interval+selected frames+proof DAG) space; solver
search additional, 30 s/query. No native target or IDB operation.
"""
import contextlib
import gc
import io
import json
from collections import Counter
import z3
from daemon_receive_tools import ROOT, SOURCE
from verify_daemon_reader_record_payloads_publication import read, sha
from recover_daemon_record_extension import unpack
from audit_daemon_record_input_origin import replay, independent_origins
from audit_daemon_alternative_fill import Source
from audit_daemon_state_table_mixing import Scalar
from recover_daemon_record_banks import instruction
from verify_daemon_second_mix_publication import canonical_expression
import audit_daemon_packed_words as Packed
import recover_daemon_digest_record_structure as R

DEPS=['audit_daemon_packed_words.py','audit_daemon_record_input_origin.py','audit_daemon_append_fields.py',
      'audit_daemon_state_table_mixing.py','audit_daemon_alternative_fill.py','lskd_values_symbolic.py']


def obligations():
    out=[]
    def prove(label,bad,premises=()):
        s=z3.Solver();s.set(timeout=30000);s.add(*premises);assert s.check()==z3.sat
        s.add(z3.simplify(bad));assert s.check()==z3.unsat,label
        out.append({'label':label,'premises_nonvacuous':True,'result':'unsat','query':s.to_smt2()})
    raw,phase=z3.BitVecs('structure_raw32 structure_phase32',32)
    v=Scalar();v.seed('w19',raw);v.seed('w10',phase)
    v.run_block(0x100a7ccc0,0x100a7ccf0)
    y=raw^z3.LShR(raw,11);y^=(y<<7)&0x9d2c5680;y^=(y<<15)&0xefc60000;y^=z3.LShR(y,18)
    prove('original_tempering_all_u32_words',v.read('w9')!=y,[(phase&31)==6])
    holder,owner=z3.BitVecs('structure_holder64 structure_owner64',64)
    v=Source({0x1009dad04:(8,owner)});v.seed('w11',raw);v.seed('x5',holder)
    v.run_block(0x1009dabb0,0x1009dad18)
    prove('original_indexed_word_additive_mixer',z3.Or(v.read('w11')!=((raw+0xb69f7313)^0xe4b5bf34),
          v.loads[0][1]!=holder+8,v.read('x9')!=owner))
    return out


def compare_prior_proofs():
    old=json.loads(read(ROOT/'daemon_packed_words_audit.json'))
    with contextlib.redirect_stdout(io.StringIO()):proofs,norms=Packed.obligations()
    assert len(proofs)==50 and len(norms)==1 and norms==old['ring_normalizations']
    for a,b in zip(old['source_proofs'],proofs):
        x,y=dict(a),dict(b);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
        assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
        assert len(p)==len(q) and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
    return proofs,norms


def field_check(field,row,bodycase,totals):
    ii=field['interval_index'];off=field['owner_offset_bytes'];values=field['values']
    wg,=[w for w in bodycase['word_groups'] if w['interval_index']==ii and w['owner_offset_bytes']==off]
    assert field['end_visit_exclusive']==wg['writer_visits'][-1]+1
    assert values['writer_W11']==wg['source_W11'] and values['normalized4_hex']==wg['decoded4_hex']
    if field['kind']=='packed':
        lo=field['start_visit'];assert row['source_visits'][lo]['pc']=='0x100c29254'
        n=values['count32'];d=values['decoded_scalar32'];encoded=int(values['packed32'],16)
        a=int(row['source_frames'][lo]['registers31'][8],16)&0xffffffff
        assert values['source_A32']==hex(a) and int(values['auxiliary32'],16)==a^0x6703cce9
        # Decode independently from the produced word, rather than reconstructing it.
        assert encoded==int.from_bytes(bytes.fromhex(wg['decoded4_hex']),'big')
        assert encoded>>27==n and encoded&((1<<n)-1)==d and 1<=n<=27 and n==max(1,d.bit_length())
        assert (encoded&0x07ffffff)>>n==int(values['retained_auxiliary_value'],16)
        assert values['retained_auxiliary_bits']==27-n
        kr,nr=values['scalar_and_count_reads'];fp=int(row['source_frames'][lo]['registers31'][29],16)
        assert kr['address']==hex(fp-0xd0) and nr['address']==hex(fp-0xcc)
        assert int.from_bytes(bytes.fromhex(kr['bytes_hex']),'little')==d^0x8b3dc651
        assert int.from_bytes(bytes.fromhex(nr['bytes_hex']),'little')==n
        totals.update({'scalar_count_'+k:v for k,v in independent_origins(row,{'selected_read_origins':values['scalar_and_count_origins']}).items()})
        for j,s in enumerate(values['count_steps']):
            visit=s['source_visit'];regs=[int(x,16) for x in row['source_frames'][visit]['registers31']]
            assert row['source_visits'][visit]['pc']=='0x100cc81e0' and all(regs[k]==v for k,v in R.PHASE.items())
            assert s['counter32']==regs[10]==j and s['current_scalar32']==(regs[11]^0x8b3dc651)==d>>j
            edge,=[e for e in row['logical_edges'] if e['source_visit_index']==visit+19]
            assert edge['target']==('0x100add458' if j==n-1 else '0x100cc81e0')
            totals['count_iterations_checked']+=1
        totals['packed_fields_checked']+=1
    elif field['kind']=='array':
        p,r=values['array_pointer_read'],values['array_element_read'];lo=field['start_visit']
        assert row['source_visits'][lo]['pc']=='0x1009dab6c' and r['source_visit_index']==lo+1
        base=int.from_bytes(bytes.fromhex(p['bytes_hex']),'little');index=int(row['source_frames'][lo+1]['registers31'][11],16)
        raw=int.from_bytes(bytes.fromhex(r['bytes_hex']),'little')
        assert values['array_base']==hex(base) and values['index32']==index and values['raw_element32']==hex(raw)
        assert int(r['address'],16)==base+4*index and int.from_bytes(bytes.fromhex(wg['decoded4_hex']),'big')==(raw+0xb69f7313)&0xffffffff
        totals.update({'array_'+k:v for k,v in independent_origins(row,{'selected_read_origins':values['element_origins']}).items()})
        totals['array_fields_checked']+=1
    else:
        assert field['kind'] in ['opaque_a','opaque_b'] and values['application_semantics']=='unknown'
        assert row['source_frames'][field['start_visit']]['registers31'][8]==values['source_A32']
        totals['opaque_producer_paths_checked']+=1


def audit():
    e=json.loads(read(ROOT/(R.P+'_checks.json')))
    for p,d in R.PINS.items():assert sha(ROOT/p)==d
    old=json.loads(read(ROOT/'daemon_record_extension_checks.json'))
    body=json.loads(read(ROOT/'daemon_digest_body_origins_checks.json'))
    totals=Counter();cases=[]
    for case,bc in zip(e['cases'],body['cases']):
        ci=case['class_index'];assert ci==bc['class_index'];future=[]
        for ir in case['intervals']:
            ii=ir['interval_index'];item=old['classes'][ci]['intervals'][ii]
            assert ir['parent_interval_sha256']==item['interval_packed']['decoded_sha256'];row=unpack(item['interval_packed'])
            for p in ir['chunks']:
                lo,hi=p['start_visit'],p['end_visit_exclusive']
                assert p['visits']==row['source_visits'][lo:hi]
                assert p['frames']==[{k:v for k,v in f.items() if k!='Q_registers32'} for f in row['source_frames'][lo:hi+1]]
                assert all(f['Q_registers32']==p['Q_registers32_preserved'] for f in row['source_frames'][lo:hi+1])
                for key,field in [('reads','source_reads'),('writes','source_writes'),('edges','logical_edges')]:
                    assert p[key]==[x for x in row[field] if lo<=x['source_visit_index']<hi]
                totals.update(replay(p))
            totals.update({'selected_read_'+k:v for k,v in independent_origins(row,ir).items()})
            for field in case['fields']:
                if field['interval_index']==ii:field_check(field,row,bc,totals)
            for t in [t for t in case['tempered_words'] if t['interval_index']==ii]:
                lo=t['start_visit'];assert row['source_visits'][lo]['pc']=='0x100a7ccc0'
                raw=int(row['source_frames'][lo]['registers31'][19],16)&0xffffffff
                assert t['raw_W19']==hex(raw)
                y=raw^(raw>>11);y^=(y<<7)&0x9d2c5680;y^=(y<<15)&0xefc60000;y^=y>>18
                assert int(t['tempered_W9'],16)==y and (int(row['source_frames'][lo]['registers31'][10],16)&31)==6
                matches=[b for b in bc['byte_fields'] if b['interval_index']==ii and b['source_W9']==t['tempered_W9']]
                assert [b['start_visit'] for b in matches]==t['consumer_start_visits'] and [b['destination'] for b in matches]==t['destinations']
                for cut in t['consumer_start_visits']:
                    assert all((int(f['registers31'][9],16)&0xffffffff)==y for f in row['source_frames'][lo+12:cut+1])
                    for v in row['source_visits'][lo+12:cut]:
                        ins=instruction(int(v['pc'],16))
                        assert not any(ins.reg_name(r) in ['x9','w9'] for r in ins.regs_access()[1])
                    totals['W9_preserved_frame_checks']+=cut-(lo+12)+1
                    totals['byte_consumers_joined']+=1
                totals['tempered_words_checked']+=1
            queries=0
            for chain in bc['chains']:
                for s in chain['steps']:
                    if s['interval_index']!=ii:continue
                    queries+=1;totals['all_lineage_queries_checked']+=1;cut=s['before_visit_exclusive']
                    if cut is None:continue
                    a=int(s['address'],16)
                    later=[w for w in row['source_writes'] if w['source_visit_index']>=cut and int(w['address'],16)<=a<int(w['address'],16)+w['size_bytes']]
                    if not later:continue
                    w=later[0];k=a-int(w['address'],16);b=bytes.fromhex(w['after_hex'])[k]
                    future.append({'interval_index':ii,'body_byte':chain['body_byte'],'query_kind':s['kind'],
                                   'address':s['address'],'reader_cut':cut,'consumed_byte':chain['stored_byte'],
                                   'first_later_writer':w,'writer_byte':k,'later_byte':b,'value_changed':b!=chain['stored_byte']})
                    assert s['kind']=='incoming' and b!=chain['stored_byte']
                    totals['incoming_read_later_overwrites_checked']+=1
                    totals['changed_post_read_bytes_checked']+=int(b!=chain['stored_byte'])
            assert queries==ir['lineage_queries']
            print(json.dumps({'audit_class':ci,'interval':ii,'chunks':len(ir['chunks'])}),flush=True)
            del row;gc.collect()
        assert future==case['post_read_overwrites'] and len(future)==158
        fields={f['owner_offset_bytes']:f for f in case['fields']}
        d={off:f['values']['decoded_scalar32'] for off,f in fields.items() if f['kind']=='packed'}
        assert d=={77:48,85:1,97:28,105:1}
        assert 77+d[77]==97+d[97]==125 and 77+20==97 and 97+20+8==125
        assert [fields[o]['values']['index32'] for o in [81,101]]==[3,4]
        assert case['layout']=={'parent_start':77,'parent_span':48,'prefix_bytes':20,'child_start':97,
                               'child_span':28,'payload_start':117,'payload_size_bytes':8,'end_exclusive':125}
        totals['nested_layouts_checked']+=1
        cases.append({'class_index':ci,'layout':case['layout'],'packed_scalars':{str(k):v for k,v in d.items()},'indexed_fields':[3,4],
                      'later_overwrites':len(future)})
    proofs=obligations();prior,norms=compare_prior_proofs()
    totals['new_source_queries_unsat']=len(proofs);totals['prior_source_queries_freshly_rechecked']=len(prior)
    totals['prior_ring_normalizations_freshly_rechecked']=len(norms)
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),
            'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'parent_pins':R.PINS,
            'dependencies':{p:sha(ROOT/p) for p in DEPS},'independent_totals':dict(totals),'cases':cases,
            'source_proofs':proofs,'rechecked_prior_source_proofs':prior,'rechecked_ring_normalizations':norms,
            'retained_nested_span_layout_established':True,'native_schema_established':False,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False}


if __name__=='__main__':
    x=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(x,indent=2)+'\n')
    print(json.dumps(x['independent_totals']),flush=True)
