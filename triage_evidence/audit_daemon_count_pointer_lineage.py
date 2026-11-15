#!/usr/bin/env python3
"""Independent interval ordering, pointer-byte epochs and source-copy audit.
O(image bytes+parent bytes+write-event bytes+cell byte queries*log(writes)+32C+proof DAG)
time, O(parent receipts+largest interval+compact lineage+proof DAG) space;
solver search capped at 30 s/query. No native target/API/IPC or IDB action.
"""
import gc
import json
import re
from bisect import bisect_left
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_daemon_state_container_construction import unpack
from audit_daemon_record_input_origin import replay
from audit_daemon_alternative_fill import Source
import recover_daemon_count_pointer_lineage as R


def original_selectors(m):
    pi=m['constructor_parent'];out=[]
    def add(n,p):out.append((n,p))
    def exported(n,field,value,condition=lambda x:True):
        j,= [j for j,c in enumerate(R.parent(n)['coverage']) if c[field]==value and condition(c)]
        add(n,['coverage',j])
    add('state_container_construction',['contexts',pi,'buffer_frees',0])
    add('state_container_construction',['contexts',pi,'allocation_cases',1])
    add('state_allocation_cascade',['contexts',pi,'allocation21_cases',1])
    add('state_allocation_cascade',['contexts',pi,'allocation48_cases',1])
    add('state_allocation_cascade',['contexts',pi,'refill_comparison'])
    for j in range(len(R.parent('state_emitter_completion')['classes'][m['emitter_class']]['intervals'])):
        add('state_emitter_completion',['classes',m['emitter_class'],'intervals',j])
    exported('state_emitter_completion','parent_index',pi)
    for j in range(len(R.parent('state_table_mixing')['shared_intervals'])):add('state_table_mixing',['shared_intervals',j])
    add('state_table_mixing',['handoff_classes',m['mix_handoff_class']]);exported('state_table_mixing','parent_index',pi)
    for j in range(2):add('table_consumer',['classes',m['consumer_class'],'intervals',j])
    exported('table_consumer','parent_index',pi)
    add('constructor_gate',['classes',m['gate_class']]);exported('constructor_gate','parent_index',pi)
    add('constructor_buffer',['prefixes',m['buffer_prefix']])
    j,=[j for j,c in enumerate(R.parent('constructor_buffer')['prefix_coverage']) if c['parent_index']==pi]
    add('constructor_buffer',['prefix_coverage',j])
    for j in range(2):add('constructor_buffer',['branches',m['buffer_branch'],'intervals',j])
    exported('constructor_buffer','parent_index',pi,lambda c:c['branch_index']==m['buffer_branch'])
    add('descriptor_walk',['classes',m['walk_class']]);exported('descriptor_walk','cohort_index',m['cohort'])
    add('descriptor_polynomial',['classes',m['polynomial_class']]);exported('descriptor_polynomial','cohort_index',m['cohort'])
    for j in range(2):add('descriptor_growth',['classes',m['growth_class'],'intervals',j])
    add('descriptor_growth',['coverage',m['growth_coverage']])
    for j in range(2):add('record_extension',['classes',m['record_class'],'intervals',j])
    return out


def mapping_check(m):
    ec=m['record_class'];pi=m['constructor_parent']
    assert (ec,pi,m['record_parent'],m['cohort'],m['buffer_branch']) in [(2,0,0,0,1),(3,17,272,68,5)]
    ext=R.parent('record_extension')['classes'][ec]
    assert ext['normal_branch'] and ext['representative_parent_index']==m['record_parent']
    filtered=[(j,c) for j,c in enumerate(R.parent('descriptor_growth')['coverage']) if c['pointer_return64']=='0x6600080000']
    gi,g=filtered[m['record_parent']];assert gi==m['growth_coverage'] and g['cohort_index']==m['cohort'] and g['class_index']==m['growth_class']
    for name,field in [('descriptor_polynomial','polynomial_class'),('descriptor_walk','walk_class')]:
        c,=[c for c in R.parent(name)['coverage'] if c['cohort_index']==m['cohort']]
        assert c['class_index']==m[field]
        if name=='descriptor_walk':assert c['parent_index']==pi and c['parent_branch_index']==m['buffer_branch']
    b=R.parent('constructor_buffer')['branches'][m['buffer_branch']]
    assert pi in b['member_parent_indices'] and b['pointer_return64']=='0x6600070000' and b['prefix_class_index']==m['buffer_prefix']
    for name,field,kind in [('constructor_gate','gate_class','class_index'),('table_consumer','consumer_class','class_index'),
                            ('state_table_mixing','mix_handoff_class','handoff_class_index'),('state_emitter_completion','emitter_class','class_index')]:
        c,=[c for c in R.parent(name)['coverage'] if c['parent_index']==pi];assert c[kind]==m[field]


def initial(row,a):
    values=[]
    for name in ['initial_private_fixtures','initial_image_fixtures']:
        for f in row[name]:
            start=int(f['address'],16);data=bytes.fromhex(f['bytes_hex'])
            if start<=a<start+len(data):values.append(data[a-start])
    assert values and len(set(values))==1
    return values[0]


def disjoint_premises(payload):
    pending=[payload];spans=[]
    while pending:
        x=pending.pop()
        if isinstance(x,list):pending.extend(x)
        elif isinstance(x,dict):
            pending.extend(x.values())
            if 'address' in x and ('size_bytes' in x or 'bytes_hex' in x):
                a=int(x['address'],16);n=x['size_bytes'] if 'size_bytes' in x else len(bytes.fromhex(x['bytes_hex']))
                assert a+n<=R.CELL or R.CELL+8<=a
                spans.append((a,n))
    return sorted(spans)


def obligations():
    ctx,sp=z3.BitVecs('cpl_context64 cpl_SP64',64);out=[]
    def prove(label,bad):
        s=z3.Solver();s.set(timeout=30000);assert s.check()==z3.sat
        s.add(z3.simplify(bad));assert s.check()==z3.unsat,label
        out.append({'label':label,'premises_nonvacuous':True,'result':'unsat','query':s.to_smt2()})
    v=Source({0x1005d0f74:(8,ctx)});v.seed('sp',sp);v.run_block(0x1005d0f74,0x1005d0f7c);w,=v.stores
    prove('original_saved_context_base_cell_copy',z3.Or(v.loads[0][1]!=sp+0x9b8,w['address']!=sp+0x7f38,w['value']!=ctx))
    v=Source({0x1008337c4:(8,ctx)});v.seed('sp',sp);v.run_block(0x1008337c4,0x1008337c8)
    # Composition requires the separately checked intervening X21/SP preservation.
    v.run_block(0x10071062c,0x100710634);w,=v.stores
    prove('composed_saved_context_load_and_count_pointer_publication',z3.Or(v.loads[0][1]!=sp+0x7f38,w['address']!=sp+0x71c0,w['value']!=ctx+28))
    return out


def audit():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));totals=Counter()
    for p,h in R.PINS.items():assert sha(ROOT/p)==h
    candidates=[]
    for va,offset,n in IMAGE.segments:
        raw=IMAGE.data[offset:offset+n]
        for match in re.finditer(rb'[\xe0-\xff]\x9f\x3f\xf9',raw):
            k=match.start()
            if k%4==0:candidates.append({'PC':hex(va+k),'word_hex':raw[k:k+4].hex()})
    assert candidates==e['direct_SP_7f38_store_pattern_candidates']
    assert len(candidates)==3 and e['direct_store_scan_mask32']==0xffffffe0 and e['direct_store_scan_pattern32']==0xf93f9fe0
    totals['direct_store_pattern_candidates_checked']=len(candidates)
    assert len(e['conditional_lineages'])==2 and len(e['upstream_base_publications'])==16
    for x in e['upstream_base_publications']:
        c=R.parent('state_path_family')['cases'][x['family_case_index']];packed=c['intervals_packed'][27]
        row=unpack(packed);assert x['interval_sha256']==packed['decoded_sha256']
        assert x['read'] in row['source_reads'] and x['write'] in row['source_writes']
        assert x['parent_case_index']==c['parent_case_index'] and x['ABI_clobber_pattern']==c['ABI_clobber_pattern']
        r,w=x['read'],x['write'];assert r['address']=='0x6800060ab8' and w['address']=='0x6800068038'
        assert not any(int(old['address'],16)<0x6800060ac0 and 0x6800060ab8<int(old['address'],16)+old['size_bytes'] and old['source_visit_index']<177 for old in row['source_writes'])
        assert bytes(initial(row,0x6800060ab8+k) for k in range(8)).hex()==r['bytes_hex']==w['after_hex']==R.J.to_bytes(8,'little').hex()
        totals.update(upstream_base_publications_checked=1,upstream_fixture_bytes_checked=8)
    for chain in e['conditional_lineages']:
        m=chain['mapping'];mapping_check(m);stages=chain['stages']
        assert [(s['parent_name'],s['selector']) for s in stages]==original_selectors(m)
        prior=None;prior_pc=None;roots=0
        for ordinal,s in enumerate(stages):
            obj=R.at(R.parent(s['parent_name']),s['selector']);key='interval_packed' if s['kind']=='interval' else 'derived_terminal_state_packed'
            packed=obj[key];row=unpack(packed);assert packed['decoded_sha256']==s['interval_sha256']
            assert s['API_return_premise']==obj.get('API_return_premise')
            authoritative_roots=[]
            for key in (['entry_premises','node_premises','entry_premise','root_premise'] if s['kind']=='interval' else []):
                if key in obj:authoritative_roots.extend(obj[key] if isinstance(obj[key],list) else [obj[key]])
            assert s['entry_roots']==authoritative_roots
            roots+=sum(len(f['bytes_hex'])//2 for f in authoritative_roots)
            actual_spans=disjoint_premises([s['API_return_premise'],authoritative_roots])
            assert actual_spans==sorted((int(x['address'],16),x['size_bytes']) for x in s['disjoint_premise_spans'])
            totals['disjoint_premise_spans_checked']+=len(actual_spans)
            cut=s['cut_visit_exclusive'] if s['cut_visit_exclusive'] is not None else len(row['source_visits'])
            assert cut==s['examined_source_visits']
            assert sum(w['source_visit_index']<cut for w in row['source_writes'])==s['examined_write_events']
            output=[];overlapping=[]
            for k in range(8):
                a=R.CELL+k;history=[]
                for w in row['source_writes']:
                    start=int(w['address'],16)
                    if start<=a<start+w['size_bytes']:history.append((w['source_visit_index'],w,start))
                j=bisect_left(history,cut,key=lambda x:x[0])
                if ordinal==0:
                    assert j==1;_,w,start=history[j-1];assert w['pc']=='0x100710630'
                    output.append(bytes.fromhex(w['after_hex'])[a-start]);overlapping.append(w)
                else:
                    assert j==0
                    value=initial(row,a);assert value==bytes.fromhex(prior)[k]
                    output.append(value);totals['boundary_cell_bytes_checked']+=1
            assert bytes(output).hex()==s['outgoing_cell_hex']==R.EXPECTED
            if ordinal:
                assert s['incoming_cell_hex']==prior
                assert s['overlapping_writes']==[]
            else:assert all(w==s['overlapping_writes'][0] for w in overlapping) and len(s['overlapping_writes'])==1
            entry=row['entry_PC'] if s['kind']=='interval' else row['boundary']['pc']
            end=row['source_frames'][cut]['pc'] if cut<len(row['source_visits']) else row['boundary']['pc']
            assert (entry,end)==(s['entry_PC'],s['end_PC'])
            if prior_pc is not None:
                want=int(prior_pc,16)
                if s['API_return_premise']:
                    assert s['API_return_premise']['call_site']==prior_pc;want+=4;totals['API_boundary_links_checked']+=1
                assert int(entry,16)==want;totals['PC_boundary_links_checked']+=1
            if 'consumer_read' in s:
                r=s['consumer_read'];assert r in row['source_reads'] and r['source_visit_index']==cut-1==86098
                assert r['pc']=='0x10083e780' and int(r['address'],16)==R.CELL and r['bytes_hex']==R.EXPECTED
                totals['consumer_pointer_reads_checked']+=1
            prior=s['outgoing_cell_hex'];prior_pc=end;totals['lineage_stages_checked']+=1
            totals['recorded_visits_examined']+=cut;totals['recorded_write_events_examined']+=s['examined_write_events']
            if s['kind']=='export':totals['derived_exports_checked']+=1
            del row;gc.collect()
        assert roots==116;totals['inherited_root_bytes_checked']+=roots
    for chunk in e['chunks']:totals.update(replay(chunk))
    proofs=obligations();totals['new_source_queries_unsat']=len(proofs)
    return {'scope':__doc__,'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'source_sha256':sha(SOURCE),'parent_pins':R.PINS,
            'dependencies':{p:sha(ROOT/p) for p in ['audit_daemon_record_input_origin.py','audit_daemon_alternative_fill.py','audit_daemon_append_fields.py']},
            'source_proofs':proofs,'independent_totals':dict(totals),
            'conditional_count_pointer_byte_lineage_established':True,'full_constructor_to_consumer_epoch_join_established':False,
            'native_constructor_epoch_join_established':False,'native_API_executed':False,
            'native_daemon_kext_pairing_established':False,'full_goal_complete':False,'all_checks_pass':True}

if __name__=='__main__':
    x=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(x,indent=2)+'\n');print(json.dumps(x['independent_totals']),flush=True)
