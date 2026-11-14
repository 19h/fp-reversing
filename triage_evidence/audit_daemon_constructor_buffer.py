#!/usr/bin/env python3
"""Fresh conditional admissions, ABI/owner transitions and buffer contracts.
Ordered source byte effects and conservative register projections admit all
parent-specific exports. Full numeric replay is a separately pinned receipt.
Time O(visits+parents*demands+joins*M*log(M)+query DAG); storage O(receipts+
largest interval+parent byte maps), M defined bytes. Solver timeout 30 s/query.
No native target API, allocation/free, IPC, PAC or IDB operation executes.
"""
import json
from collections import Counter
from hashlib import sha256
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_network_record import state_bytes
from audit_daemon_state_table_mixing import Scalar,admission,expected,requirement_receipt
from audit_daemon_state_emitter_completion import requirements
from lskd_values_symbolic import mem,cell
import recover_daemon_constructor_buffer as R
import replay_daemon_constructor_buffer as Replay
AD=['audit_daemon_state_table_mixing.py','audit_daemon_state_emitter_completion.py',
    'audit_daemon_network_record.py','recover_daemon_return_bank_origins.py','lskd_values_symbolic.py']
FINAL='06b96706b135bd9145be84e9f3294b56ee8a446d91be78bca6f224f6ead548dc1edc4606892f2c7089bf1be39ed56dc2be8568ed1d86b43775'
def raw(m,a,n):return bytes(m[a+j] for j in range(n))
def selected(r,pc,kind='source_writes'):return [w for w in r[kind] if w['pc']==hex(pc)]
def overlaps(w,a,n):return int(w['address'],16)<a+n and a<int(w['address'],16)+w['size_bytes']

def abi(before,event,pattern):
    b=before['boundary'];r=event['return_registers31'];q=event['return_Q_registers32'];old=b['registers31']
    assert event['call_site']==b['pc'] and event['symbol']==b['detail']['symbol']
    assert event['continuation_PC']==hex(int(b['pc'],16)+4) and r[30]==event['continuation_PC']
    assert event['ABI_return_and_output_premise'] and not event['native_API_executed']
    assert r[18:30]==old[18:30] and event['return_NZCV']==hex(0x50000000 if pattern else 0xa0000000)
    for j in range(32):
        bits=((j+1)*0x123456789abcdef0123456789abcdef+pattern*0xfedcba9876543210fedcba9876543210)&((1<<128)-1)
        if 8<=j<16:bits=(bits&~((1<<64)-1))|(int(b['Q_registers32'][j],16)&((1<<64)-1))
        assert int(q[j],16)==bits
    owners=list(before['foreign_owners']);invalid=[{'address':hex(R.APIParent.E),'size_bytes':4}]
    if event['symbol']=='libSystem/_malloc':
        assert b['pc']==hex(R.MALLOC) and old[0]==hex(R.N) and event['pointer_return64']==r[0]
        p=int(r[0],16);assert p in [0,R.F]
        if p:
            o={'address':hex(R.F),'size_bytes':R.N}
            assert event['allocated_owner_premise']==dict(o,initial_bytes_defined=False)
            assert all(not(int(x['address'],16)<R.F+R.N and R.F<int(x['address'],16)+x['size_bytes']) for x in owners)
            assert not any(R.F<=a<R.F+R.N for a in state_bytes(before));owners.append(o)
        else:assert event['allocated_owner_premise'] is None
    else:
        assert event['symbol']=='libSystem/_free' and event['void_return_premise']
        assert int(r[0],16)==(0xa5b6c7d8e9f01234^pattern)
        o=event['retired_owner_premise'];assert o['address']==old[0] and (int(o['address'],16),o['size_bytes']) in [(R.T,21),(R.U,48)]
        owners.remove(o);invalid.append(o)
    assert event['invalidated_spans']==invalid
    entry=R.fixture_state(before,event);m=state_bytes(before)
    for x in invalid:
        a=int(x['address'],16);m={k:v for k,v in m.items() if not a<=k<a+x['size_bytes']}
    assert state_bytes(entry)==m and entry['foreign_owners']==owners and entry['boundary']['SP']==b['SP']
    return entry

def controls(rep,need,projection,effects,totals,root=None):
    m=state_bytes(rep);a=root if root is not None else next(a for a,(b,o) in need.items() if o=='incoming')
    assert a in need
    for remove in [False,True]:
        bad=dict(m)
        if remove:del bad[a]
        else:bad[a]^=1
        try:admission(rep,rep,need,projection,memory=bad)
        except AssertionError:totals['missing_demanded_byte_rejected' if remove else 'changed_demanded_byte_rejected']+=1
        else:raise AssertionError('bad demanded byte admitted')
    for n in ['SP',next(n for n in projection['required'] if n.startswith('X'))]:
        bad=R.machine(rep);bad[n]=hex(int(bad[n],16)^16)
        try:admission(rep,rep,need,projection,values=bad)
        except AssertionError:totals['changed_required_register_rejected']+=1
        else:raise AssertionError('bad demanded register admitted')
    try:admission({**rep,'foreign_owners':rep['foreign_owners'][:-1]},rep,need,projection)
    except AssertionError:totals['changed_owner_rejected']+=1
    else:raise AssertionError('bad owner admitted')
    assert 'Q0' not in projection['required'] and 'Q0' not in projection['written']
    bad=R.machine(rep);bad['Q0']=hex(int(bad['Q0'],16)^1);_,v=admission(rep,rep,need,projection,values=bad)
    assert v['Q0']==bad['Q0'];totals['unused_Q_preservation_controls']+=1
    a=next(a for a in sorted(m) if a not in need and a not in effects and 0x6800000000<=a<0x6800100000)
    bad=dict(m);bad[a]^=1;v,_=admission(rep,rep,need,projection,memory=bad);assert (v|effects)[a]==bad[a]
    totals['unused_byte_preservation_controls']+=1

def coverage(e,parents):
    totals=Counter();out=[];prefix={};views={x['parent_index']:x for x in e['prefix_coverage']};seen=set()
    def interval_group(states,row,projection,terminals,label,root=None):
        rep=states[next(iter(states))];need,effects,ct=requirements(rep,[row]);totals.update(ct)
        assert R.registers([row])==projection
        controls(rep,need,projection,effects,totals,root)
        for i,p in states.items():
            m,v=admission(p,rep,need,projection);s=R.export(p,row,projection)
            expected(p,s,effects,projection,row,m,v)
            if terminals is not None:assert s==R.unpack(terminals[i]['derived_terminal_state_packed'])
            totals.update(parent_interval_admissions=1,incoming_byte_demands_checked=len(need),incoming_register_demands_checked=len(projection['required']),terminal_bytes_checked=len(m|effects))
            states[i]=s
        out.append({'label':label,'members':list(states),'required_bytes':requirement_receipt(need),'effect_bytes':len(effects),'all_checks_pass':True})
    for ci,c in enumerate(e['prefixes']):
        states={i:R.premised(parents[i])[0] for i in c['member_parent_indices']};r=R.unpack(c['interval_packed'])
        rep=states[c['representative_parent_index']];assert R.key(rep)==c['class_key'] and R.premised(parents[c['representative_parent_index']])[1]==c['entry_premise']
        assert not seen.intersection(states);seen.update(states)
        interval_group(states,r,c['register_projection'],views,'prefix_'+str(ci),int(c['entry_premise']['address'],16));prefix.update(states)
    assert seen==set(range(76)) and len(views)==76
    for bi,c in enumerate(e['branches']):
        states={i:prefix[i] for i in c['member_parent_indices']};terminals={x['parent_index']:x for x in e['coverage'] if x['branch_index']==bi}
        assert set(terminals)==set(states)
        for j,x in enumerate(c['intervals']):
            states={i:abi(p,x['API_return_premise'],c['ABI_clobber_pattern']) for i,p in states.items()}
            interval_group(states,R.unpack(x['interval_packed']),x['register_projection'],terminals if j==len(c['intervals'])-1 else None,'branch_'+str(bi)+'_'+str(j))
        totals['terminal_exports_checked']+=len(states)
    assert len(e['coverage'])==totals['terminal_exports_checked']==304
    return {'intervals':out,'verified_counts':dict(totals),'all_checks_pass':True}

def contracts(e,parents):
    totals=Counter();out=[];prefix={x['parent_index']:R.unpack(x['derived_terminal_state_packed']) for x in e['prefix_coverage']}
    for ci,c in enumerate(e['prefixes']):
        r=R.unpack(c['interval_packed']);sp=int(r['caller_SP'],16);m=state_bytes(r);a=sp+0x10cb8
        initial=state_bytes(R.premised(parents[c['representative_parent_index']])[0])
        for base,n in [(R.S,64),(R.T,21),(R.U,48),(R.J,552)]:
            assert {k:v for k,v in m.items() if base<=k<base+n}=={k:v for k,v in initial.items() if base<=k<base+n}
            assert not any(overlaps(w,base,n) for w in r['source_writes'])
        assert len(r['source_calls'])==1 and r['source_calls'][0]['pc']=='0x10057f5ec' and r['source_calls'][0]['target']=='0x10045f984'
        assert raw(m,a,4).hex()=='81ead876' and raw(m,a+4,4).hex()=='b6736f1c' and int.from_bytes(raw(m,a+8,8),'little')==R.U
        assert raw(m,a+16,4).hex()=='cef44793' and raw(m,sp+0x6fc4,4).hex()=='73726576'
        w=selected(r,0x1004aa840);assert len(w)==1 and w[0]['address']==hex(a) and w[0]['after_hex']=='81ead876'
        assert r['boundary']['pc']==hex(R.MALLOC) and r['boundary']['registers31'][0]==hex(57)
        totals.update(validation_records_checked=1,pending_malloc57_calls_checked=1)
    for bi,c in enumerate(e['branches']):
        rows=[R.unpack(x['interval_packed']) for x in c['intervals']];initial=state_bytes(prefix[c['representative_parent_index']]);last=rows[-1];m=state_bytes(last)
        warm=int(c['pointer_return64'],16)!=0;sp=int(last['boundary']['SP'],16)
        assert all(not overlaps(w,R.J,552) for r in rows for w in r['source_writes']) and raw(m,R.J,552)==raw(initial,R.J,552)
        assert all(not r['native_target_executed'] for r in rows)
        assert not any(R.T<=a<R.T+21 for a in m) and not any(x['address']==hex(R.T) for x in last['foreign_owners'])
        if warm:
            assert len(rows)==2 and rows[0]['boundary']['pc']=='0x100514c64' and rows[0]['boundary']['registers31'][0]==hex(R.T)
            first=state_bytes(rows[0]);assert sum(R.F+j in first for j in range(57))==21
            uw=[w for w in rows[0]['source_writes'] if overlaps(w,R.U,48)]
            assert [(w['pc'],int(w['address'],16)-R.U,w['after_hex']) for w in uw]==[
                ('0x1006b1960',20,'4ac4ec10'),('0x10070f4a8',0,'00'*8),
                ('0x10070f4b4',8,R.F.to_bytes(8,'little').hex()),('0x10070f4bc',16,'4ac4ec10')]
            rr=selected(rows[0],0x100758b8c,'source_reads');ww=selected(rows[0],0x100758b90)
            assert len(rr)==len(ww)==21
            for j,(r,w) in enumerate(zip(rr,ww)):
                k=20-j;assert (r['address'],w['address'],r['bytes_hex'],w['after_hex'])==(hex(R.T+k),hex(R.F+k),raw(initial,R.T+k,1).hex(),raw(initial,R.T+k,1).hex())
            assert int.from_bytes(raw(first,R.U+8,8),'little')==R.F and raw(first,R.U+16,4)==raw(first,R.U+20,4)==bytes.fromhex('4ac4ec10')
            assert raw(m,R.F,57).hex()==FINAL and raw(m,R.U+8,8)==R.F.to_bytes(8,'little') and raw(m,R.S,8)==R.U.to_bytes(8,'little')
            assert [j for j in range(48) if R.U+j not in m]==list(range(28,32))+list(range(44,48))
            writes=[w for w in rows[1]['source_writes'] if overlaps(w,R.F,57)];assert len(writes)==38 and all(w['size_bytes']==1 for w in writes)
            assert sorted(int(w['address'],16)-R.F for w in writes)==[15,16,*range(21,57)]
            assert last['boundary']['pc']==hex(R.WARM) and last['boundary']['detail']['address']==hex(sp+0x2b0) and all(sp+0x2b0+j not in m for j in range(8))
            totals.update(warm_paths_checked=1,descending_copy_byte_pairs_checked=21,final_buffer_bytes_checked=57,post_free_buffer_stores_checked=38,U_undefined_bytes_preserved=8)
        else:
            assert len(rows)==3 and [r['boundary']['pc'] for r in rows]==['0x1003174d0','0x100336dec',hex(R.FAIL)]
            assert [r['boundary']['registers31'][0] for r in rows[:2]]==[hex(R.T),hex(R.U)]
            fill=[w for w in rows[1]['source_writes'] if overlaps(w,R.U,48)];assert len(fill)==48 and all(w['pc']=='0x1002a9a04' and w['size_bytes']==1 for w in fill)
            assert [int(w['address'],16) for w in fill]==list(range(R.U+47,R.U-1,-1))
            assert len({w['after_hex'] for w in fill})>1 and any(w['after_hex']!='00' for w in fill)
            gate=[w for w in rows[1]['source_writes'] if overlaps(w,0x1010b5de0,4)]
            assert [(w['pc'],w['after_hex']) for w in gate]==[('0x1003adb90','ef940a00'),('0x1002a7dcc','965d0000')]
            assert raw(m,0x1010b5de0,4)==bytes.fromhex('965d0000')
            for pc,lo,n,want in [(0x1001fb314,0x65001151be,158,'e74f48f2c451c0e39151897099a9a526beed50fef6c01c0240478ec7ddcc8db3'),
                                 (0x1002e7418,0x650010011c,174,'d31ced9b8d94071336b9c77dbdde6fa0a15cc4ebec81e13589f3fda2e338aec8')]:
                ws=selected(rows[1],pc);assert len(ws)==n and all(w['size_bytes']==1 for w in ws)
                assert [int(w['address'],16) for w in ws]==list(range(lo+n-1,lo-1,-1))
                assert all(gate[0]['source_visit_index']<w['source_visit_index']<gate[1]['source_visit_index'] for w in ws)
                assert sha256(bytes.fromhex(''.join(w['after_hex'] for w in ws))).hexdigest()==want
            for pc,address,value in [(0x1002c61b4,0x1010b5f18,'778301081f07a41a'),
                                     (0x100223e14,0x6500100008,'4676823b618c875e'),(0x1001eab24,0x650011525c,'4676823b618c875e')]:
                ws=selected(rows[1],pc);assert len(ws)==1 and (ws[0]['address'],ws[0]['size_bytes'],ws[0]['after_hex'])==(hex(address),8,value)
                assert gate[0]['source_visit_index']<ws[0]['source_visit_index']<gate[1]['source_visit_index']
            assert not any(R.U<=a<R.U+48 for a in m) and not any(x['address']==hex(R.U) for x in last['foreign_owners'])
            zero=selected(rows[2],0x1006d1354);assert len(zero)==1 and zero[0]['address']==hex(R.S) and zero[0]['after_hex']=='00'*8
            assert raw(m,R.S,8)==bytes(8) and last['boundary']['detail']=={'address':hex(R.S+48),'size_bytes':8} and all(R.S+48+j not in m for j in range(8))
            totals.update(NULL_paths_checked=1,U_destructive_fill_bytes_checked=48,S_zero_stores_checked=1,cleanup_gate_acquire_release_pairs_checked=1,
                          cleanup_arena_fill_bytes_checked=332,cleanup_arena_descriptor_stores_checked=3)
        assert [j for j in range(64) if R.S+j not in m]==list(range(48,56))+list(range(61,64))
        totals.update(context_bytes_preserved=552,T_retired_bytes_checked=21)
        out.append({'branch_index':bi,'allocation_non_NULL':warm,'boundary':last['boundary']['pc'],'final_buffer_hex':FINAL if warm else None,'all_checks_pass':True})
    return {'cases':out,'verified_counts':dict(totals),'all_checks_pass':True,'native_ownership_established':False,'new_Mach_or_IOKit_emission_established':False}

def foundation():
    p=json.loads(read(ROOT/'daemon_return_bank_origins_checks.json'));out=[]
    for j,c in enumerate(p['upstream_cases']):
        sp=int(c['frame_base'],16);ww=[w for w in c['source_writes'] if overlaps(w,sp+0x260,8)]
        assert len(ww)==1 and ww[0]['pc']=='0x10061a5e8' and ww[0]['size_bytes']==8 and ww[0]['after_hex']==((sp+R.BIAS)&((1<<64)-1)).to_bytes(8,'little').hex()
        out.append({'profile_index':j,'frame_base':hex(sp),'writer':ww[0]})
    assert len(out)==12
    return {'initializer_profiles':out,'additional_root_bytes_per_parent':8,'source_fragments':[{'start':hex(a),'bytes_hex':IMAGE.read(a,n).hex()} for a,n in [(0x10061a5c8,16),(0x10061a5dc,16)]],
            'root_formula':'u64(SP+0x44b9fd860c43a9f6)','continuous_epoch_join_established':False}

class ByteInput(Scalar):
    def __init__(self,b):super().__init__();self.byte=b;self.loads=[]
    def load(self,a,n):assert n==1;self.loads.append(a);return self.byte

def obligations():
    out=[]
    def prove(label,bad,premises=()):
        s=z3.Solver();s.set(timeout=30000);s.add(*premises);assert s.check()==z3.sat;s.add(z3.simplify(bad));assert s.check()==z3.unsat,label
        out.append({'label':label,'query':s.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    sp=z3.BitVec('buffer_frame64',64);v=Scalar();v.seed('sp',sp);v.run_block(0x10061a5c8,0x10061a5d8);v.run_block(0x10061a5dc,0x10061a5ec)
    w=v.stores[-1];prove('all_u64_original_address_dependent_SP260_root',z3.Or(w['address']!=sp+0x260,w['value']!=sp+R.BIAS))
    cap,append=z3.BitVecs('buffer_raw_capacity32 buffer_append_operand32',32);v=Scalar();v.seed('sp',0x6800060100);v.seed('w8',cap);v.seed('w20',0x8b3dc645);v.seed('w14',0x6cf4);mem(v,0x680006322c,4,append)
    v.run_block(0x100709a64,0x100709ad4);prove('all_u32_original_growth_raw_capacity_plus_encoded_append_minus20',cell(v,0x6800063c80,4)!=cap+append-20)
    v=Scalar()
    for n,x in {'w25':0x5f29,'w26':0x9717,'w9':0x37ee,'w12':0xef1233cf,'w8':cap}.items():v.seed(n,x)
    v.run_block(0x10083dd08,0x10083dd10);v.run_block(0x10083dd18,0x10083dd20)
    prove('all_u32_original_malloc_count_decode_zeroextends',v.read('x0')!=z3.ZeroExt(32,cap+0xef133bef))
    src,dst,count=z3.BitVecs('buffer_copy_source64 buffer_copy_dest64 buffer_copy_count64',64);byte=z3.BitVec('buffer_copy_byte8',8);v=ByteInput(byte)
    for n,x in {'x22':src,'x10':dst,'x9':count}.items():v.seed(n,x)
    v.run_block(0x100758b88,0x100758b94);w=v.stores[-1]
    prove('all_u64_original_descending_copy_single_byte',z3.Or(v.read('x9')!=count-1,v.loads[0]!=src+count-1,w['address']!=dst+count-1,w['value']!=byte))
    v=Scalar();v.seed('sp',0x6800060100);v.seed('w10',cap)
    for off,value in [(0x2388,0),(0x58c0,R.U),(0xf88,R.F),(0x4cc8,R.U+8),(0x66b0,R.U+16)]:mem(v,0x6800060100+off,8,z3.BitVecVal(value,64))
    v.run_block(0x10070f4a0,0x10070f4c0)
    prove('all_u32_original_U_pointer_and_capacity_publication',z3.Or(cell(v,R.U,8)!=0,cell(v,R.U+8,8)!=R.F,cell(v,R.U+16,4)!=cap))
    pointer=z3.BitVec('buffer_S_pointer64',64);v=Scalar();v.seed('x22',pointer);v.run_block(0x1006d1354,0x1006d1358);w=v.stores[-1]
    prove('all_u64_original_NULL_cleanup_zeroes_S_head',z3.Or(w['address']!=pointer,w['value']!=0))
    return out

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));replay=json.loads(read(ROOT/(R.P+'_replay.json')));p=json.loads(read(ROOT/(R.Parent.P+'_checks.json')))
    assert replay['all_checks_pass'] and replay['checks_sha256']==sha(ROOT/(R.P+'_checks.json'))
    parents={x['parent_index']:R.unpack(x['derived_terminal_state_packed']) for x in p['coverage']}
    return {'scope':__doc__,'auditor_sha256':sha(__file__),'replayer_sha256':sha(Replay.__file__),'generator_sha256':sha(R.__file__),
            'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'replay_sha256':sha(ROOT/(R.P+'_replay.json')),'source_sha256':sha(SOURCE),
            'dependencies':e['dependencies'],'auditor_dependencies':{n:sha(ROOT/n) for n in AD},'verified_counts':e['verified_counts'],
            'independent_totals':replay['independent_totals'],'coverage':coverage(e,parents),'model':contracts(e,parents),'foundation':foundation(),
            'source_proofs':obligations(),'source_queries_unsat':6,'all_checks_pass':True,'native_API_executed':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'coverage':e['coverage']['verified_counts'],'model':e['model']['verified_counts'],'source_queries_unsat':e['source_queries_unsat']}),flush=True)
