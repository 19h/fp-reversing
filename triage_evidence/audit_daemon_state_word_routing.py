#!/usr/bin/env python3
"""Independent SIDB word/range/errno/path source replay and equations.

O(receipts+visits*(register/effect state)+owner joins+query DAG) time/storage;
30 s/query. Synthetic prefixes and ordinary ABI returns are explicit
premises. No native target API/IPC/filesystem/allocation/free/PAC executes.
"""
import json,struct
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_readiness_arena import Lift as ParentLift
from audit_daemon_environment_outputs import DEC
from audit_daemon_network_record import state_bytes
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import mem,cell
import recover_daemon_state_word_routing as R
import audit_daemon_state_file_admission as Common
from audit_daemon_state_file_input import HEADER_SEEDS

AD=['audit_daemon_readiness_arena.py','audit_daemon_network_record.py','audit_daemon_state_file_admission.py','audit_daemon_environment_outputs.py',
    'audit_daemon_state_file_input.py','recover_daemon_return_bank_origins.py','lskd_values_symbolic.py']

class Lift(ParentLift):
    def __init__(self,c):
        super().__init__(c)
        if c['entry_PC']==hex(R.BYTE):
            slot=0x10103f8c0;target=0x10059ab00
            assert c['entry_registers31'][9]==hex(target) and FIXUPS[slot]['target']==target
            self.last_authenticated_load=(slot,target);self.counts['inherited_X9_fixup_origins_checked']+=1

    def integer(self,x):
        value=super().integer(x)
        if self.pc==0x1006655bc and value==0x1007c5fc8:
            # Metadata witness for the inherited private value, not a claim
            # that this interval loaded the original fixup slot or produced
            # the private copy. The parent's defined bytes are premises.
            sp=super().integer(self.read('sp'));a=sp+0x8658;slot=0x101040f50
            assert self.projected(z3.Concat(*[self.bytes[a+j] for j in range(7,-1,-1)]))==value
            assert FIXUPS[slot]['target']==value
            reads=[r for r in self.c['source_reads'] if r['pc']=='0x1006655b4']
            assert len(reads)==1 and reads[0]['address']==hex(a) and reads[0]['size_bytes']==8
            assert reads[0]['bytes_hex']==value.to_bytes(8,'little').hex()
            self.last_authenticated_load=(slot,value);self.counts['private_dispatch_values_matched_to_original_fixups']+=1
        return value

def contract(c,parent):
    counts=Counter();ci=c['parent_context_index'];ti=c['parent_timestamp_case_index'];word=int(c['raw_big_endian_word32'],16)
    before=R.unpack(parent['timestamp_cases'][ti]['completion'][-1]['interval_packed']);initial=state_bytes(before)
    assert before['boundary']['pc']==hex(R.BYTE) and before['boundary']['detail']=={'address':hex(R.A),'size_bytes':1}
    origins=[x for x in before['source_reads'] if x['pc']=='0x1005b94f4']
    assert len(origins)==1 and origins[0]['address']=='0x10103f8c0' and origins[0]['size_bytes']==8 and origins[0]['bytes_hex']=='00ab590001000000'
    tail=before['source_visits'][origins[0]['source_visit_index']+1:];assert [x['pc'] for x in tail]==['0x1005b94f8']
    for x in tail:
        i=next(DEC.disasm(IMAGE.read(int(x['pc'],16),4),int(x['pc'],16)))
        assert not any(i.reg_name(r) in ['x9','w9'] for r in i.regs_access()[1])
    assert before['boundary']['registers31'][9]=='0x10059ab00';counts['parent_to_entry_X9_origins_checked']+=1
    assert all(R.A+j not in initial for j in range(R.N))
    supplied=c['prefix'];row=R.unpack(supplied['interval_packed']);effect=supplied['output_premise']
    assert effect=={'address':hex(R.A),'bytes_hex':word.to_bytes(4,'big').hex(),'size_bytes':4,'kind':'synthetic_file_prefix4'}
    counts.update(Common.join(before,row,effect=effect));assert c['ABI_clobber_pattern']==1-parent['ABI_clobber_pattern']
    gp=[int(x,16) for x in row['entry_registers31']]
    assert gp[28]==R.A and gp[0]==0xec3e0ab8 and all(gp[k]==v for k,v in HEADER_SEEDS.items())
    assert row['caller_SP']=='0x6800060100'
    file_reads=[x for x in row['source_reads'] if Common.overlap(x,R.A,R.N)]
    assert [(r['pc'],r['address'],r['size_bytes'],r['bytes_hex']) for r in file_reads]==[
        (hex(pc),hex(R.A+j),1,word.to_bytes(4,'big')[j:j+1].hex()) for j,pc in enumerate([R.BYTE,0x1005b9508,0x1005b9514,0x1005b952c])]
    counts['synthetic_prefix_source_reads_checked']+=4
    for pc,address in [(0x1005b95bc,0x6800069094),(0x10059ab14,0x6800067144)]:
        ws=Common.select(row,pc);assert len(ws)==1 and ws[0]['address']==hex(address) and ws[0]['size_bytes']==4
        assert ws[0]['after_hex']==struct.pack('<I',word^0x8b3dc651).hex();counts['raw_word_private_stores_checked']+=1
    frames={f['pc']:f for f in row['source_frames']}
    f=frames[hex(R.GATE1)];assert int(f['registers31'][19],16)==word^0x6703cce9 and f['registers31'][9]=='0x3c5d'
    edge=next(e for e in row['logical_edges'] if e['pc']=='0x1005faa8c')
    assert edge['target']==hex(R.GATE2 if word>=R.LOW else 0x1006655b0) and edge['modifier']=='0x8aec'
    counts['lower_gate_source_partitions_checked']+=1
    if word>=R.LOW:
        f=frames[hex(R.GATE2)];assert int(f['registers31'][19],16)==word^0x6703cce9 and f['registers31'][8]=='0x9039'
        edge=next(e for e in row['logical_edges'] if e['pc']=='0x10054e9f8')
        assert edge['target']==hex(0x100531de0 if word<R.HIGH else 0x1006655b0) and edge['modifier']=='0xd28d'
        counts['upper_gate_source_partitions_checked']+=1
    inside=R.LOW<=word<R.HIGH;assert c['inside_source_interval']==inside
    assert row['boundary']['pc']==hex(R.MALLOC if inside else R.ERROR) and row['boundary']['kind']=='before_unmodeled_import_call'
    if inside:
        assert row['boundary']['detail']['symbol']=='libSystem/_malloc' and row['boundary']['detail']['modifier']=='0x6aa4'
        assert row['boundary']['registers31'][0]=='0x40' and c['errno_accessor'] is None
        assert [(x['pc'],x['target'],x['modifier']) for x in row['source_calls']]==[('0x100531ea0','0x100436378','0x58a3')]
        ws=Common.select(row,0x100436380);assert len(ws)==1 and ws[0]['address']=='0x6800070db8' and ws[0]['after_hex']=='50c63d8b'
        counts['inside_pending_64_byte_allocations_checked']+=1
    else:
        assert row['boundary']['detail']['symbol']=='libSystem/___error' and row['boundary']['detail']['modifier']=='0x6e96'
        assert [(x['pc'],x['target'],x['modifier']) for x in row['source_calls']]==[
            ('0x10089fb34','0x10041a980','0xb69a'),('0x10041ac34','0x1004946d8','0xf248'),('0x100494920','0x100493f38','0x4e06')]
        for call,arg in zip(row['source_calls'],[0x6800070db8,0x68000600c8,0x68000600c8]):assert call['arguments8'][0]==hex(arg)
        item=c['errno_accessor'];after=R.unpack(item['interval_packed']);event=item['API_return_premise']
        counts.update(Common.join(row,after,event=event));assert event['invalidated_spans']==[]
        assert after['boundary']['pc']==hex(R.LSTAT) and after['boundary']['detail']['symbol']=='libSystem/_lstat' and after['boundary']['detail']['modifier']=='0xf401'
        assert after['boundary']['registers31'][:2]==[hex(R.B+32),'0x680005ff38']
        assert after['source_writes']==[
            {'pc':'0x1004cd120','source_visit_index':0,'address':hex(R.E),'size_bytes':4,'after_hex':'00000000'},
            {'pc':'0x1004cd124','source_visit_index':1,'address':'0x680005ff20','size_bytes':8,'after_hex':struct.pack('<Q',R.B).hex()}]
        assert not after['source_calls'] and after['foreign_owners']==row['foreign_owners']
        counts['errno_clear_and_pending_lstat_requests_checked']+=1
    for interval in R.case_intervals(c):
        state=state_bytes(interval);assert interval['foreign_owners']==before['foreign_owners']
        assert {k:v for k,v in state.items() if R.A<=k<R.A+R.N}=={R.A+j:v for j,v in enumerate(word.to_bytes(4,'big'))}
        assert not any(Common.overlap(w,R.A,R.N) for w in interval['source_writes'])
        for o in before['foreign_owners']:
            a=int(o['address'],16);n=o['size_bytes']
            if a in [R.A,R.E]:continue
            assert {k:v for k,v in state.items() if a<=k<a+n}=={k:v for k,v in initial.items() if a<=k<a+n}
        assert Common.raw(state,R.J+0x34,32)==Common.raw(initial,R.J+0x34,32)
        counts['owner_and_generated_stream_preservation_intervals_checked']+=1;counts['unsupplied_payload_bytes_preserved_checked']+=R.N-4
    return {'model_checks':dict(counts),'all_checks_pass':True}

def obligations():
    out=[]
    def prove(label,bad):
        s=z3.Solver();s.set(timeout=30000);assert s.check()==z3.sat;s.add(z3.simplify(bad));assert s.check()==z3.unsat,label
        out.append({'label':label,'query':s.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    w=z3.BitVec('sidb_raw_BE_word32',32);base=0x70000000
    bs=z3.BitVecs('sidb_byte0 sidb_byte1 sidb_byte2 sidb_byte3',8);v=Algebra()
    for k,value in HEADER_SEEDS.items():v.seed('w'+str(k),value)
    v.seed('x28',base)
    for j,b in enumerate(bs):mem(v,base+j,1,b)
    v.run_block(R.BYTE,0x1005b9550)
    prove('all_four_bytes_original_first_word_codec',v.read('w19')!=(z3.Concat(*bs)^0x6703cce9))
    v=Algebra();v.seed('w19',w^0x6703cce9);v.seed('w0',0xec3e0ab8);v.seed('x22',base)
    v.run_block(0x1005b95b8,0x1005b95c0)
    prove('all_u32_original_first_private_store',cell(v,base+0x5b4,4)!=(w^0x8b3dc651))
    v.seed('x10',base);v.run_block(0x10059ab14,0x10059ab18)
    prove('all_u32_original_second_private_store',cell(v,base+0x1044,4)!=(w^0x8b3dc651))
    v=Algebra();v.seed('sp',base);v.seed('w9',0x3c5d);v.seed('w19',w^0x6703cce9)
    v.run_block(R.GATE1,0x1005faa5c);lo=z3.UGE(w,R.LOW)
    prove('all_u32_original_lower_gate_modular_sum',z3.Or(v.read('w10')!=w-R.LOW,v.read('w12')!=z3.BitVecVal((-R.LOW)&0xffffffff,32)))
    v.run_block(0x1005faa5c,0x1005faa78)
    prove('all_u32_original_lower_gate_index',v.read('w9')!=z3.If(lo,z3.BitVecVal(0x450b,32),z3.BitVecVal(0x3c5d,32)))
    v=Algebra();v.seed('sp',base);v.seed('w8',0x9039);v.seed('w19',w^0x6703cce9)
    v.run_block(R.GATE2,0x10054e9d8);hi=z3.UGE(w,R.HIGH)
    prove('all_u32_original_upper_gate_modular_sum',z3.Or(v.read('w9')!=w-R.HIGH,v.read('w11')!=z3.BitVecVal((-R.HIGH)&0xffffffff,32)))
    v.run_block(0x10054e9d8,0x10054e9ec)
    prove('all_u32_original_upper_gate_index',v.read('w8')!=z3.If(hi,z3.BitVecVal(0x9045,32),z3.BitVecVal(0x9039,32)))
    prove('all_u32_combined_range_exactly_half_open_interval',z3.And(lo,z3.Not(hi))!=z3.And(z3.UGE(w,R.LOW),z3.ULT(w,R.HIGH)))
    ptr,obj=z3.BitVecs('sidb_errno_pointer64 sidb_object_pointer64',64)
    v=Algebra();v.seed('sp',base);v.seed('x0',R.E);v.seed('x19',obj);v.run_block(R.ERROR+4,0x1004cd12c)
    prove('all_object_pointer_bits_original_borrowed_errno_clear_and_path_offset',z3.Or(cell(v,R.E,4)!=0,cell(v,base+0x10,8)!=obj,v.read('x19')!=obj+32))
    v.run_block(0x1004cd188,R.LSTAT)
    prove('all_pointers_original_lstat_arguments',z3.Or(v.read('x0')!=obj+32,v.read('x1')!=base+0x28,v.read('x17')!=0xf401))
    v=Algebra();v.run_block(0x10058bf44,R.MALLOC)
    prove('original_inside_route_pending_allocator_count_and_IA',z3.Or(v.read('x0')!=64,v.read('x17')!=0x6aa4))
    v=Algebra();v.seed('x0',ptr);v.run_block(0x100436378,0x100436384)
    prove('all_pointers_original_inside_record_leaf_word',cell(v,ptr,4)!=0x8b3dc650)
    return out

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));parent=json.loads(read(ROOT/(R.Parent.P+'_checks.json')))
    assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    cases=[];total=Counter();model=Counter()
    for j,c in enumerate(e['cases']):
        lifts=[]
        for row in R.case_intervals(c):
            lift=Lift(row).run();assert lift['all_checks_pass'];lifts.append(lift);total.update(lift['verified_counts'])
        ct=contract(c,parent['contexts'][c['parent_context_index']]);model.update(ct['model_checks'])
        cases.append({'independent_lifts':lifts,'contract':ct,'all_checks_pass':True})
        if j%128==0:print(json.dumps({'case':j,'source_visits':total['source_visits']}),flush=True)
    qs=obligations()
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'source_sha256':sha(SOURCE),'dependencies':e['dependencies'],'auditor_dependencies':{n:sha(ROOT/n) for n in AD},
            'verified_counts':e['verified_counts'],'cases':cases,'independent_totals':dict(total),'model_checks':dict(model),
            'source_proofs':qs,'source_queries_unsat':len(qs),'all_checks_pass':True,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'independent':e['independent_totals'],'model':e['model_checks'],'queries':e['source_queries_unsat']}),flush=True)
