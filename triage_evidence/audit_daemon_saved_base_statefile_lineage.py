#!/usr/bin/env python3
"""Independent 76-route ordering, saved-base byte epochs and source composition.
O(parent bytes+unique recorded visits+effects+32C+chain links+proof DAG) time;
O(parent receipts+largest interval+compact stages/chains+proof DAG) space.
Fixed eight-byte fixture queries; solver search capped at 30 s/query.
No native target/API/IPC, hardware authentication or IDB action.
"""
import gc,json
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_daemon_state_container_construction import unpack
from recover_daemon_count_pointer_lineage import parent,at
from audit_daemon_append_fields import Lift
from audit_daemon_record_input_origin import replay
from recover_daemon_record_banks import instruction
from lskd_values_symbolic import resize
import recover_daemon_saved_base_statefile_lineage as R


def original_order(pi):
    """Independent finite-parent derivation, not the extractor's ancestry map."""
    ri,qi=divmod(pi,19);wi=[0,2,21,23][ri];ii=int(ri>=2)
    c=parent('state_container_construction')['contexts'][pi]
    assert (c['parent_context_index'],c['parent_SIDN_query_index'])==(ri,qi)
    r=parent('state_path_removal')['contexts'][ri];assert r['parent_case_index']==wi
    w=parent('state_word_routing')['cases'][wi]
    assert (w['parent_context_index'],w['parent_timestamp_case_index'])==(ii,0)
    assert w['raw_big_endian_word32']==('0x0' if ri%2==0 else '0x7000c') and not w['inside_source_interval']
    inp=parent('state_file_input')['contexts'][ii];assert inp['parent_context_index']==ii
    meta=parent('state_file_metadata')['contexts'][ii]
    assert (meta['parent_context_index'],meta['parent_open_case_index'])==(0,0)
    adm=parent('state_file_admission')['contexts'][0];assert adm['parent_case_index']==0
    assert not adm['open_cases'][0]['invoke_callback']
    out=[('state_path_family',['cases',0,'intervals_packed',j]) for j in [27,28]]
    def add(n,p):out.append((n,p))
    for key,j in [('stat_cases',0),('mode_cases',1)]:add('state_file_admission',['contexts',0,key,j])
    for j in range(5):add('state_file_admission',['contexts',0,'open_cases',0,'intervals_packed',j])
    for key,j in [('open_cases',3),('fstat_cases',0),('size_cases',2)]:add('state_file_metadata',['contexts',ii,key,j])
    for key,j in [('nonnull_allocations',2),('read_cases',4),('success_lock_cases',0),('success_lock_cases',1)]:add('state_file_input',['contexts',ii,key,j])
    tp=['contexts',ii,'timestamp_cases',0]
    for key in ['seconds','nanoseconds']:add('state_file_input',tp+[key])
    for j in range(3):add('state_file_input',tp+['completion',j])
    for key in ['prefix','errno_accessor']:add('state_word_routing',['cases',wi,key])
    rp=['contexts',ri]
    if qi in [0,1]:
        add('state_path_removal',rp+['stat_cases',0]);add('state_path_removal',rp+['mode_cases',qi+3])
        origin=('mode',qi+3)
    elif qi<14:
        ei,bi=divmod(qi-2,4);add('state_path_removal',rp+['stat_cases',ei+1]);add('state_path_removal',rp+['error_accessors',ei])
        add('state_path_removal',rp+['error_accessors',ei,'word_cases',bi]);origin=('errno',qi-2)
    else:
        add('state_path_removal',rp+['stat_cases',0]);add('state_path_removal',rp+['mode_cases',1])
        add('state_path_removal',rp+['unlink_cases',qi-13 if qi<17 else 0])
        if qi>=17:
            for j in range(4):add('state_path_removal',rp+['synchronization_cases',qi-17,'returns',j])
        origin=('unlink',qi-13) if qi<17 else ('sync',qi-17)
    q=r['SIDN_queries'][qi];assert (q['origin_kind'],q['origin_index'])==origin
    assert (c['parent_origin_kind'],c['parent_origin_index'])==origin
    add('state_path_removal',rp+['SIDN_queries',qi])
    for key,j in [('stat_cases',0),('mode_cases',0),('buffer_frees',0)]:add('state_container_construction',['contexts',pi,key,j])
    return out


def incoming(row,address):
    result=None
    for key in ['initial_private_fixtures','initial_image_fixtures']:
        for f in row[key]:
            a=int(f['address'],16);i=address-a;h=f['bytes_hex']
            if 0<=i<len(h)//2:result=int(h[2*i:2*i+2],16)
    assert result is not None
    return result


def disjoint(payload):
    stack=[payload];spans=[]
    while stack:
        item=stack.pop()
        if isinstance(item,list):stack.extend(item)
        elif isinstance(item,dict):
            stack.extend(item.values())
            if 'address' in item and ('size_bytes' in item or 'bytes_hex' in item):
                a=int(item['address'],16);n=item.get('size_bytes',len(item.get('bytes_hex',''))//2)
                assert a+n<=R.CELL or R.CELL+8<=a
                spans.append((a,n))
    return sorted(spans)


def obligations():
    class Memory(Lift):
        def __init__(self):
            super().__init__();self.byte_memory=z3.Array('base_lineage_memory',z3.BitVecSort(64),z3.BitVecSort(8));self.loads=[]
        def load(self,a,n):
            self.loads.append((self.pc,a,n));return z3.Concat(*[z3.Select(self.byte_memory,a+k) for k in reversed(range(n))])
        def store(self,a,n,v,pc):
            super().store(a,n,v,pc);v=resize(v,n*8)
            for k in range(n):self.byte_memory=z3.Store(self.byte_memory,a+k,z3.Extract(8*k+7,8*k,v))
    ctx,sp=z3.BitVecs('base_lineage_context64 base_lineage_SP64',64);out=[]
    for mutated in [False,True]:
        v=Memory();v.seed('sp',sp);v.seed('x22',ctx)
        v.run_block(0x1004cf268,0x1004cf26c);v.run_block(0x1005d0f74,0x1005d0f7c)
        if mutated:
            a=sp+0x7f38;v.byte_memory=z3.Store(v.byte_memory,a,z3.Select(v.byte_memory,a)^z3.BitVecVal(1,8))
        v.run_block(0x1008337c4,0x1008337c8);v.run_block(0x10071062c,0x100710634)
        assert len(v.stores)==3 and len(v.loads)==2
        bad=v.stores[-1]['value']==ctx+28 if mutated else z3.Or(
            *[x['address']!=sp+k for x,k in zip(v.stores,[0x9b8,0x7f38,0x71c0])],
            *[a!=sp+k for (_,a,n),k in zip(v.loads,[0x9b8,0x7f38])],v.stores[-1]['value']!=ctx+28)
        s=z3.Solver();s.set(timeout=30000);assert s.check()==z3.sat;s.add(z3.simplify(bad));assert s.check()==z3.unsat
        out.append({'label':'overlapping_low_byte_write_breaks_composed_lineage' if mutated else 'original_six_instruction_saved_base_count_pointer_composition',
                    'premises_nonvacuous':True,'result':'unsat','query':s.to_smt2()})
    return out


def audit():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));totals=Counter()
    for p,h in R.PINS.items():assert sha(ROOT/p)==h
    stages=e['stages'];assert len(e['chains'])==76
    seen=set()
    for pi,chain in enumerate(e['chains']):
        expected=original_order(pi);actual=[(stages[k]['parent_name'],stages[k]['selector']) for k in chain['stage_indices']]
        assert actual==expected
        assert chain['ancestry']=={'constructor_parent':pi,'removal_context':pi//19,'SIDN_query':pi%19,
            'word_case':[0,2,21,23][pi//19],'input_context':int(pi>=38),'timestamp_case':0,
            'metadata_context':int(pi>=38),'admission_context':0,'open_case':0,'family_case':0}
        previous=None
        for si in chain['stage_indices']:
            s=stages[si]
            if previous is not None:
                assert s['incoming_cell_hex']==previous['outgoing_cell_hex']==R.VALUE
                assert int(s['entry_PC'],16)==int(previous['end_PC'],16)+(4 if s['API_return_premise'] else 0)
                if s['API_return_premise']:assert s['API_return_premise']['call_site']==previous['end_PC'];totals['API_chain_links_checked']+=1
                elif s['output_premise']:totals['scalar_output_chain_links_checked']+=1
                else:totals['direct_PC_chain_links_checked']+=1
                totals.update(chain_boundary_links_checked=1,chain_boundary_bytes_checked=8)
            previous=s;seen.add(si)
        totals['chain_stages_checked']+=len(chain['stage_indices'])
    assert seen==set(range(len(stages)))
    ns=parent('context_network_storage');cp=parent('count_pointer_origin')
    for s in stages:
        n,p=s['parent_name'],s['selector'];obj=at(parent(n),p)
        if p[-2]=='intervals_packed':
            packed=obj;ev=at(parent(n),p[:-2]+['API_return_premises',p[-1]]);output=None
        else:packed=obj['interval_packed'];ev=obj.get('API_return_premise');output=obj.get('output_premise')
        row=unpack(packed);first=n=='state_path_family' and p[-1]==27;last=n=='state_container_construction' and p[-2]=='buffer_frees'
        lo=177 if first else 0;hi=113 if last else len(row['source_visits'])
        if first:ev=None;output=None
        assert (s['start_visit'],s['cut_visit_exclusive'],s['interval_sha256'])==(lo,hi,packed['decoded_sha256'])
        assert s['entry_PC']==(row['source_frames'][lo]['pc'] if lo else row['entry_PC'])
        assert s['end_PC']==(row['source_frames'][hi]['pc'] if hi<len(row['source_visits']) else row['boundary']['pc'])
        assert s['API_return_premise']==ev and s['output_premise']==output
        spans=disjoint([ev,output]);assert spans==sorted((int(x['address'],16),x['size_bytes']) for x in s['disjoint_premise_spans'])
        totals['disjoint_premise_spans_checked']+=len(spans)
        writes=[w for w in row['source_writes'] if lo<=w['source_visit_index']<hi and int(w['address'],16)<R.CELL+8 and R.CELL<int(w['address'],16)+w['size_bytes']]
        assert writes==s['overlapping_writes']
        if first:
            w,=writes;assert w['pc']=='0x1005d0f78' and w['source_visit_index']==178 and w['after_hex']==R.VALUE
            prior=ns['saved_base_lineages'][0]['stages'][-1]
            assert prior['interval_sha256']==s['interval_sha256'] and prior['alias_store']==w
            assert s['incoming_cell_hex'] is None
            totals['earlier_alias_source_joins_checked']+=1
        else:
            assert not writes and s['incoming_cell_hex']==bytes(incoming(row,R.CELL+k) for k in range(8)).hex()==R.VALUE
            totals['unique_incoming_fixture_bytes_checked']+=8
        if last:
            pi=p[1];r=s['base_reload'];w=s['count_pointer_store'];old=cp['cases'][pi]['pointer_paths'][0]
            assert r in row['source_reads'] and w in row['source_writes']
            assert (r['pc'],r['source_visit_index'],r['address'],r['bytes_hex'])==('0x1008337c4',29,hex(R.CELL),R.VALUE)
            assert old['interval_sha256']==packed['decoded_sha256'] and old['saved_context_pointer_read']==r and old['count_pointer_write']==w
            assert (w['pc'],w['source_visit_index'],w['address'],w['after_hex'])==('0x100710630',112,'0x68000672c0',(R.J+28).to_bytes(8,'little').hex())
            assert all(f['registers31'][21]==hex(R.J) for f in row['source_frames'][30:113])
            for v in row['source_visits'][30:111]:
                ins=instruction(int(v['pc'],16));assert v['bytes_hex']==IMAGE.read(ins.address,4).hex()
                assert not {'x21','w21'}&{ins.reg_name(x) for x in ins.regs_access()[1]}
                assert ins.mnemonic not in ['bl','blr','blraa','blrab']
            assert row['source_frames'][29]['SP']==row['source_frames'][111]['SP']=='0x6800060100'
            totals.update(constructor_base_reads_checked=1,count_pointer_publications_checked=1,X21_frames_checked=83,X21_definition_call_exclusions_checked=81,prior_constructor_source_joins_checked=1)
        assert s['outgoing_cell_hex']==R.VALUE
        nw=sum(lo<=w['source_visit_index']<hi for w in row['source_writes'])
        assert (s['recorded_visits_examined'],s['recorded_write_events_examined'])==(hi-lo,nw)
        totals.update(unique_stages_checked=1,unique_recorded_visits_examined=hi-lo,unique_recorded_write_events_examined=nw,
            unique_API_transition_stages_checked=int(bool(ev)),unique_scalar_output_stages_checked=int(bool(output)),zero_visit_stages_checked=int(hi==lo))
        del row;gc.collect()
    for chunk in e['chunks']:totals.update(replay(chunk))
    proofs=obligations();totals['new_source_queries_unsat']=len(proofs)
    return {'scope':__doc__,'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'source_sha256':sha(SOURCE),'parent_pins':R.PINS,
            'dependencies':{p:sha(ROOT/p) for p in ['audit_daemon_append_fields.py','audit_daemon_record_input_origin.py','recover_daemon_record_banks.py','lskd_values_symbolic.py']},
            'source_proofs':proofs,'independent_totals':dict(totals),
            'conditional_saved_base_to_count_producer_lineage_established':True,
            'whole_machine_context_lifetime_established':False,'native_constructor_epoch_join_established':False,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False,'all_checks_pass':True}


if __name__=='__main__':
    x=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(x,indent=2)+'\n');print(json.dumps(x['independent_totals']),flush=True)
