#!/usr/bin/env python3
"""Independent gate/readiness/arena replay, byte joins and source equations.

O(receipts+visits*(state+byte effects)+query DAG) time/space; 30 s/query.
Native API/IPC, allocation/free, concurrency and hardware PAC do not execute.
"""
import json,struct
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_context_state_publish import Lift as ParentLift
from audit_daemon_environment_outputs import DEC
from audit_daemon_network_record import join,state_bytes,fixture_bytes
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import mem,cell
import recover_daemon_readiness_arena as R

class Lift(ParentLift):
    def integer(self,x):
        value=super().integer(x)
        if self.pc==0x100a860c4 and value==0x100c190f4:
            slot=0x10103a438;assert FIXUPS[slot]['target']==value
            self.last_authenticated_load=(slot,value);self.counts['retained_X8_fixup_origins_checked']+=1
        return value

    def one(self,i):
        if i.mnemonic=='casal':
            assert i.address==R.CAS and i.op_str=='w8, w13, [x9]'
            a=self.address(i,i.operands[2]);old=self.load(a,4)
            match=self.projected(old)==self.projected(self.read('w8'))
            # The CPU journal records an identity write on failed CAS. Match
            # its byte event without inferring a native hardware write cycle.
            self.store(a,4,self.read('w13') if match else old,i.address)
            self.write('w8',old);self.counts['CAS_value_transitions_checked']+=1;return
        return super().one(i)

def joined(before,after,effects=()):
    join(before,after,effects)
    assert before['boundary']['Q_registers32']==after['entry_Q_registers32']
    assert before['boundary']['pc']==after['entry_PC']

def interfaces(e):
    p=json.loads(read(ROOT/(R.Parent.P+'_checks.json')));counts=Counter()
    for c in e['prefixes']:
        old=p['cases'][c['parent_main_case_index']]['intervals'][-1];r=c['intervals'][0]
        n=next(j for j,v in enumerate(old['source_visits']) if int(v['pc'],16)==R.CAS)
        assert n==849 and old['entry_registers31']==r['entry_registers31'] and old['entry_Q_registers32']==r['entry_Q_registers32']
        assert old['entry_NZCV']==r['entry_NZCV'] and old['caller_SP']==r['caller_SP'] and old['foreign_owners']==r['foreign_owners']
        expected=fixture_bytes(old,'private')|fixture_bytes(old,'image')
        assert sum(len(bytes.fromhex(f['bytes_hex'])) for f in c['effects'])==24
        for f in c['effects']:expected.update({int(f['address'],16)+j:b for j,b in enumerate(bytes.fromhex(f['bytes_hex']))})
        assert expected==fixture_bytes(r,'private')|fixture_bytes(r,'image')
        for key in ['source_visits','source_frames']:assert r[key]==old[key][:n]
        for key in ['source_reads','source_writes','logical_edges','source_calls']:assert r[key]==[x for x in old[key] if x['source_visit_index']<n]
        assert r['boundary']['registers31']==old['source_frames'][n]['registers31'] and r['boundary']['Q_registers32']==old['source_frames'][n]['Q_registers32']
        assert r['boundary_NZCV']==old['source_frames'][n]['NZCV']
        counts['exact_parent_prefixes_checked']+=1
    for c in e['gate_cases']:
        before=e['prefixes'][c['parent_prefix_index']]['intervals'][-1];r=c['intervals'][0];joined(before,r,[c['effect']])
        word=int(c['gate_word32'],16);new=0xa94ef if word==0x5d96 else word
        assert r['source_reads'][0]['address']==hex(R.GATE) and r['source_reads'][0]['bytes_hex']==struct.pack('<I',word).hex()
        assert r['source_writes']==[{'pc':hex(R.CAS),'source_visit_index':0,'address':hex(R.GATE),'size_bytes':4,'after_hex':struct.pack('<I',new).hex()}]
        assert r['boundary']['pc']==hex(R.ACQUIRED if word==0x5d96 else R.RETRY)
        assert len(r['source_visits'])==8;counts['gate_word_controls_checked']+=1
    for c in e['acquired_cases']:
        before=e['gate_cases'][c['parent_gate_case_index']]['intervals'][-1];r=c['intervals'][0];joined(before,r)
        assert len(r['source_visits'])==43 and r['boundary']['registers31'][16]=='0x0'
        assert any(v['pc']=='0x100b73fa0' for v in r['source_visits']);counts['acquired_zero_pointer_producers_checked']+=1
    for c in e['flag_cases']:
        before=e['acquired_cases'][c['parent_acquired_index']]['intervals'][-1];r=c['intervals'][0];joined(before,r,[c['effect']])
        warm=c['flag8']==1;assert len(r['source_visits'])==(129 if warm else 69)
        assert r['source_reads'][0]['address']==hex(R.FLAG) and r['source_reads'][0]['size_bytes']==1
        if warm:
            assert r['boundary']['pc']==hex(R.DESC_READ) and r['boundary']['registers31'][28]==hex(R.D)
            assert r['boundary']['registers31'][30]==hex(R.SENTINEL)
            assert not any(int(x['address'],16)<=R.CELL<int(x['address'],16)+x['size_bytes'] for x in r['source_reads'])
            origin=[x for x in r['source_reads'] if x['pc']=='0x100b9eefc'];assert len(origin)==1 and origin[0]['address']=='0x10103a438'
            assert int.from_bytes(bytes.fromhex(origin[0]['bytes_hex']),'little')==FIXUPS[0x10103a438]['target']==0x100c190f4
            for v in r['source_visits'][origin[0]['source_visit_index']+1:]:
                i=next(DEC.disasm(IMAGE.read(int(v['pc'],16),4),int(v['pc'],16)))
                assert not any(i.reg_name(t) in ['x8','w8'] for t in i.regs_access()[1])
            assert r['boundary']['registers31'][8]=='0x100c190f4'
        else:
            assert r['boundary']['pc']==hex(R.Parent.ARC) and r['boundary']['detail']['symbol']=='libSystem/_arc4random'
            sp=int(r['caller_SP'],16);assert bytes(state_bytes(r)[sp+0x190+j] for j in range(8))==bytes(8)
            releases=[w for w in r['source_writes'] if w['address']==hex(R.GATE)]
            assert len(releases)==1 and releases[0]['pc']=='0x100a8c078' and releases[0]['size_bytes']==4 and releases[0]['after_hex']=='965d0000'
            counts['cold_gate_releases_checked']+=1
        counts['readiness_byte_controls_checked']+=1
    for c in e['descriptor_cases']:
        before=e['flag_cases'][c['parent_flag_case_index']]['intervals'][-1];r=c['intervals'][0];joined(before,r,[c['effect']])
        word=int(c['descriptor_word64'],16);assert r['source_reads'][0]['address']==hex(R.CELL) and r['source_reads'][0]['size_bytes']==8
        if word==R.SENTINEL:
            assert r['boundary']['pc']=='0x100a7b8d8' and r['boundary']['registers31'][0]=='0x1388'
            assert r['boundary']['detail']['symbol']=='libSystem/_malloc' and len(r['source_visits'])==52
            counts['pending_expansion_malloc_controls']+=1
            at=next(j for j,v in enumerate(r['source_visits']) if v['pc']=='0x100a860c4')
            for v in r['source_visits'][:at]:
                i=next(DEC.disasm(IMAGE.read(int(v['pc'],16),4),int(v['pc'],16)))
                assert not any(i.reg_name(t) in ['x8','w8'] for t in i.regs_access()[1])
            assert r['entry_registers31'][8]=='0x100c190f4';counts['retained_X8_origin_chains_checked']+=1
        else:
            assert r['boundary']['pc']==hex(R.NODE_READ) and r['boundary']['registers31'][9]==hex(word)
            assert not any(int(x['address'],16)==word+8 for x in r['source_reads'])
            counts['unexecuted_node_header_cuts']+=1
        counts['descriptor_word_controls_checked']+=1
    for c in e['header_cases']:
        before=e['descriptor_cases'][c['parent_descriptor_case_index']]['intervals'][-1];r=c['intervals'][0];joined(before,r,[c['effect']])
        assert r['foreign_owners']==before['foreign_owners']+[{'address':hex(R.H),'size_bytes':R.N}]
        raw=bytes.fromhex(c['effect']['bytes_hex']);header=int.from_bytes(raw,'little');delta=c['decoded_marker_offset_bytes']
        assert header-R.M==delta and delta==(R.N-24 if c['header_epoch']=='fresh_startup' else 86620)
        assert r['boundary']['pc']=='0x100b6a918' and r['boundary']['kind']=='before_undefined_foreign_owner_read'
        assert r['boundary']['detail']=={'address':hex(R.H+delta),'size_bytes':8}
        gp=r['boundary']['registers31'];assert gp[12]=='0xb399' and gp[13]==hex(header) and gp[15]==hex(R.H+delta) and gp[16]==hex(delta)
        assert len(r['source_visits'])==2732
        start=fixture_bytes(r,'private')|fixture_bytes(r,'image')
        assert not any(R.H+delta+j in start for j in range(8))
        assert not any(int(x['address'],16)<R.H+delta+8 and R.H+delta<int(x['address'],16)+x['size_bytes'] for x in r['source_reads']+r['source_writes'])
        counts['separate_arena_header_controls_checked']+=1
    assert e['producer_evidence']==R.producer() and e['snapshot_evidence']==R.snapshot_evidence()
    for row in R.intervals(e):
        assert all(not(int(w['address'],16)<=R.GATE<int(w['address'],16)+w['size_bytes']) or w['pc'] in [hex(R.CAS),'0x100a8c078'] for w in row['source_writes'])
    return {'verified_counts':dict(counts),'cold_gate_release_observed':True,'warm_gate_release_observed':False,'epoch_join_established':False,
            'scope':'Sequential source gates and explicit runtime-state sensitivity. Native synchronization, ownership, admission and daemon-kext linkage remain unknown.'}

class GateEquation(Algebra):
    def one(self,i):
        if i.mnemonic=='casal':
            a=self.address(i,i.operands[2]);old=self.load(a,4);desired=self.read('w13')
            self.store(a,4,z3.If(old==self.read('w8'),desired,old),i.address);self.write('w8',old);return
        return super().one(i)

def obligations():
    qs=[]
    def prove(label,bad):
        s=z3.Solver();s.set(timeout=30000);assert s.check()==z3.sat;s.add(z3.simplify(bad));assert s.check()==z3.unsat,label
        qs.append({'label':label,'query':s.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    old=z3.BitVec('ra_gate_word32',32);v=GateEquation();v.seed('x9',R.GATE);v.seed('w8',0x5d96);v.seed('w13',0xa94ef)
    mem(v,R.GATE,4,old);v.run_block(R.CAS,R.CAS+4)
    prove('all_u32_CAS_returns_old_and_conditionally_replaces_word',z3.Or(v.read('w8')!=old,cell(v,R.GATE,4)!=z3.If(old==0x5d96,z3.BitVecVal(0xa94ef,32),old)))
    v.seed('w14',0x5d96);v.seed('w11',0x758f);v.seed('w10',0x177c);v.run_block(R.CAS+4,0x100a6e5cc)
    prove('all_u32_CAS_admission_indices',v.read('w8')!=z3.If(old==0x5d96,z3.BitVecVal(0x62f3,32),z3.BitVecVal(0x177c,32)))
    b=z3.BitVec('ra_readiness8',8);v=Algebra();v.seed('x11',R.FLAG);v.seed('w19',0xb399);v.seed('w14',0x82);mem(v,R.FLAG,1,b)
    v.run_block(R.FLAG_READ,0x100b74060)
    prove('all_u8_readiness_exact_one_partition',v.read('w11')!=z3.If(b==1,z3.BitVecVal(0x4b3a,32),z3.BitVecVal(0x82,32)))
    word=z3.BitVec('ra_link64',64);v=Algebra();v.seed('x28',R.D);v.seed('x30',R.SENTINEL);v.seed('w13',0xa057);mem(v,R.CELL,8,word)
    v.run_block(R.DESC_READ,0x100ba7740)
    prove('all_u64_descriptor_sentinel_partition',v.read('w13')!=z3.If(word==R.SENTINEL,z3.BitVecVal(0xa059,32),z3.BitVecVal(0xa057,32)))
    v=Algebra();v.seed('x0',word);v.seed('x9',R.SENTINEL);v.run_block(0x10032a56c,0x10032a570);v.seed('x28',R.D)
    v.run_block(R.DESC_READ,R.DESC_READ+4)
    prove('all_u64_same_epoch_descriptor_writer_reader_identity',v.read('x9')!=word)
    v=Algebra();v.seed('x0',word);v.run_block(0x100a7b8d0,0x100a7b8d8)
    prove('all_prior_X0_expansion_malloc_count_5000',z3.Or(v.read('x0')!=5000,v.read('x17')!=0x6aa4))
    node,header=z3.BitVecs('ra_node64 ra_header64',64);v=Algebra();v.seed('w12',0xb399);v.seed('x9',node);v.seed('x13',header)
    v.run_block(0x100b6a8e0,0x100b6a918)
    prove('all_u64_arena_header_decodes_marker_address',z3.Or(v.read('x16')!=header-R.M,v.read('x15')!=node+header-R.M))
    v=Algebra();v.seed('sp',0x680005fce0);v.seed('w8',old);mem(v,0x680005fda0,8,z3.BitVecVal(R.GATE,64))
    v.run_block(0x100a8c070,0x100a8c07c)
    prove('all_prior_W8_cold_path_restores_gate_available_word',cell(v,R.GATE,4)!=0x5d96)
    return qs

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    lifts=[];total=Counter()
    for j,row in enumerate(R.intervals(e)):
        a=Lift(row).run();a['interval_index']=j;lifts.append(a);total.update(a['verified_counts'])
        if j%8==0:print(json.dumps({'interval':j,'source_visits':total['source_visits']}),flush=True)
    qs=obligations()
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'source_sha256':sha(SOURCE),'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],
            'independent_lifts':lifts,'independent_totals':dict(total),'interfaces':interfaces(e),'source_proofs':qs,'source_queries_unsat':len(qs),
            'all_checks_pass':True,'native_API_executed':False,'native_daemon_kext_pairing_established':False,
            'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'replay':e['independent_totals'],'interfaces':e['interfaces']}),flush=True)
