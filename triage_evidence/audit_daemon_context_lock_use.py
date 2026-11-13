#!/usr/bin/env python3
"""Independent scalar/AdvSIMD replay and restored-context lock/path interfaces.

O(receipts+visits*(register state+byte effects)+query DAG) time/space;
solver work separate, 30 s/query. No native operations or hardware PAC.
"""
import json,struct
from collections import Counter
import z3
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_context_unseal import Lift,Equation
from audit_daemon_network_record import fixture_bytes,state_bytes,join
from audit_daemon_return_bank_origins import UpstreamReplay
from lskd_values_symbolic import mem,cell
from recover_daemon_return_bank_origins import Algebra
import recover_daemon_context_lock_use as R

class Initializer(UpstreamReplay):
    def code(self,u,a,n,d):
        if self.seq==len(self.steps):
            s=int(self.p['frame_base'],16)
            for off,(value,pc) in R.ROOTS.items():
                assert int.from_bytes(u.mem_read(s+off,8),'little')==value
                self.counts['new_live_root_cells_checked']+=1
            assert bytes(u.mem_read(s+R.PATH_OFFSET,len(R.PATH)))==R.PATH
            self.counts['new_live_path_bytes_checked']+=len(R.PATH)
        return super().code(u,a,n,d)

def return_join(before,event,after):
    assert event['call_site']==before['boundary']['pc'] and event['symbol']==before['boundary']['detail']['symbol']
    assert after['entry_PC']==event['continuation_PC']==hex(int(event['call_site'],16)+4)
    assert after['entry_registers31']==event['return_registers31'] and after['entry_NZCV']==event['return_NZCV']
    assert after['entry_Q_registers32']==event['return_Q_registers32']
    assert after['entry_registers31'][18:30]==before['boundary']['registers31'][18:30]
    assert int(after['entry_registers31'][30],16)==int(event['call_site'],16)+4
    for j in range(8,16):
        assert (int(after['entry_Q_registers32'][j],16)&((1<<64)-1))==(int(before['boundary']['Q_registers32'][j],16)&((1<<64)-1))
    assert event['ABI_return_and_output_premise'] and event['separate_SIMD_clobber_premise'] and not event['native_API_executed']
    join(before,after,same_registers=False)

def interfaces(e):
    parent=json.loads(read(ROOT/'daemon_context_unseal_checks.json'));counts=Counter();tokens=Counter()
    for c in e['cases']:
        pc=parent['cases'][c['parent_case_index']];before=pc['intervals'][-1];s=int(before['caller_SP'],16)
        assert c['producer_name']==pc['producer_name'] and c['raw_lock_word64']==pc['final_raw_lock64']
        assert c['raw_lock_word64'] in ['0x6600001000','0xf64ac418c20e70bc'];tokens[c['raw_lock_word64']]+=1
        for row,t in zip(c['intervals'],c['transitions']):
            if t['import_return']:
                assert not t['effects'];ev=t['import_return'];return_join(before,ev,row)
                assert int(row['entry_registers31'][0],16)&0xffffffff==c['import_status32']
                counts['import_return_joins']+=1
            else:
                join(before,row,t['effects']);assert before['boundary']['Q_registers32']==row['entry_Q_registers32']
                if t['effects']:
                    d=before['boundary']['detail'];assert before['boundary']['kind']=='before_unknown_private_read'
                    assert d['address']==t['effects'][0]['address'] and d['snapshot']['known_mask_hex']=='00'*d['size_bytes']
                    counts['separate_root_or_string_joins']+=1
                else:assert before['boundary']['pc']==row['entry_PC'];counts['retained_entry_joins']+=1
            before=row
        rows=c['intervals'];assert len(rows)==len(c['transitions'])==8
        reads=[x for r in rows for x in r['source_reads'] if R.Parent.D<=int(x['address'],16)<R.Parent.D+552]
        expected=[('0x1006150f4',0x18,4,0),('0x100615100',0x10,8,0),('0x1005fadd4',8,8,int(c['raw_lock_word64'],16)),
                  ('0x1005faea0',0x18,4,0),('0x1006053bc',0x10,8,0)]
        assert [(x['pc'],int(x['address'],16)-R.Parent.D,x['size_bytes'],int.from_bytes(bytes.fromhex(x['bytes_hex']),'little')) for x in reads]==expected
        capture=[w for r in rows for w in r['source_writes'] if w['pc']=='0x1005fae24'];assert len(capture)==1
        assert capture[0]['address']==hex(s+0x10cc0) and capture[0]['size_bytes']==8
        assert int.from_bytes(bytes.fromhex(capture[0]['after_hex']),'little')==int(c['raw_lock_word64'],16)
        assert rows[4]['boundary']['registers31'][19]==rows[5]['boundary']['registers31'][0]==c['raw_lock_word64']
        assert rows[1]['boundary']['registers31'][0]=='0x1010b7478'
        inc=[w for r in rows for w in r['source_writes'] if w['pc']=='0x10050feb4'];assert len(inc)==1
        assert inc[0]['address']=='0x1010c5760' and inc[0]['after_hex']=='01000000'
        calls=[x for r in rows for x in r['source_calls']]
        assert [(x['pc'],x['target']) for x in calls]==[('0x10050ff50','0x1004423f8'),('0x10050ff98','0x1000056c8'),
                ('0x1005fae90','0x10043e280'),('0x1004877e8','0x1000056c8')]
        scan=[x for x in rows[-1]['source_reads'] if x['pc']=='0x10052da40']
        assert len(scan)==len(R.PATH) and [x['address'] for x in scan]==[hex(s+R.PATH_OFFSET+j) for j in range(len(R.PATH))]
        assert bytes.fromhex(''.join(x['bytes_hex'] for x in scan))==R.PATH
        # Encoding reads the distinct literal constructed in this suffix.
        ew=[w for r in rows for w in r['source_writes'] if s+0x103a6<=int(w['address'],16)<s+0x103a6+len(R.PATH)]
        assert len(ew)==21 and all(w['size_bytes']==1 for w in ew)
        assert [w['address'] for w in ew]==[hex(s+0x103a6+j) for j in range(21)]
        assert [w['pc'] for w in ew]==[hex(0x10050fff8+12*j) for j in range(20)]+['0x1005100ec']
        assert bytes.fromhex(''.join(w['after_hex'] for w in ew))==R.PATH
        initial=fixture_bytes(rows[0],'private');assert not any(s+0x103a6+j in initial for j in range(21))
        frozen=fixture_bytes(rows[-1],'private')
        assert bytes(frozen[s+0x103a6+j] for j in range(len(R.PATH)))==R.PATH
        assert rows[-1]['boundary']['pc']=='0x1006b6fb0' and rows[-1]['boundary']['registers31'][0]=='0x15'
        assert not any(R.Parent.D<=int(w['address'],16)<R.Parent.D+552 for r in rows for w in r['source_writes'])
        counts.update(context_field_reads=len(reads),raw_lock_captures=1,exact_wrlock_arguments=1,source_counter_increments=1,
                      state_path_bytes_scanned=len(scan),original_encoding_input_bytes=len(R.PATH),pending_path_allocations=1)
    for c in e['allocation_cases']:
        before=e['cases'][c['parent_case_index']]['intervals'][-1];row=c['intervals'][0];ev=c['import_return'];return_join(before,ev,row)
        pointer=int(c['pointer_return64'],16);assert row['entry_registers31'][0]==ev['pointer_return64']==hex(pointer)
        assert 'return32' not in ev and not ev['native_API_executed']
        if pointer:
            owner=ev['allocated_owner_premise'];assert owner=={'address':hex(pointer),'size_bytes':len(R.PATH),'initial_bytes_defined':False}
            assert row['foreign_owners']==before['foreign_owners']+[{'address':hex(pointer),'size_bytes':len(R.PATH)}]
            initial=fixture_bytes(row,'image');assert not any(pointer+j in initial for j in range(len(R.PATH)))
            writes=[w for w in row['source_writes'] if pointer<=int(w['address'],16)<pointer+len(R.PATH)]
            assert len(writes)==22 and all(w['size_bytes']==1 for w in writes)
            assert [int(w['address'],16)-pointer for w in writes]==list(range(21))+[20]
            assert [w['pc'] for w in writes]==['0x10052e608']*20+['0x1004afba8','0x1004b4514']
            current=state_bytes(row);raw=bytes(current[pointer+j] for j in range(len(R.PATH)))
            assert raw.hex()==c['encoded_path_hex'] and raw==bytes(x^0x98 for x in R.PATH)
            assert not any(pointer<=int(x['address'],16)<pointer+len(R.PATH) for x in row['source_reads'])
            inputs=[x for x in row['source_reads'] if x['pc']=='0x10052e5e8'];s=int(row['caller_SP'],16)
            assert [x['address'] for x in inputs]==[hex(s+0x103a6+j) for j in range(20)]
            assert bytes.fromhex(''.join(x['bytes_hex'] for x in inputs))==R.PATH[:-1]
            assert all(f['registers31'][12]=='0xb374' for f in row['source_frames'] if f['pc']=='0x10052e5e8')
            assert row['boundary']['pc']=='0x1004b457c' and row['boundary']['registers31'][0]=='0x15'
            counts.update(successful_pointer_controls=1,encoded_path_bytes=21,encoded_path_write_events=22)
        else:
            assert ev['allocated_owner_premise'] is None and row['foreign_owners']==before['foreign_owners']
            assert row['boundary']['pc']=='0x100442650'
            assert [(x['pc'],x['target']) for x in row['source_calls']]==[('0x1006b26c0','0x1004423f8')]
            counts['NULL_pointer_cleanup_controls']+=1
        counts['malloc_return_joins']+=1
    assert tokens==Counter({'0x6600001000':30,'0xf64ac418c20e70bc':10})
    return {'verified_counts':dict(counts),'wrlock_argument_counts':dict(tokens),
            'scope':'Original source token/path flow under retained inputs and separate roots/import returns; native validity, epoch and pairing unknown.'}

def obligations():
    qs=[]
    def prove(label,bad):
        s=z3.Solver();s.set(timeout=30000);assert s.check()==z3.sat;s.add(bad);assert s.check()==z3.unsat,label
        qs.append({'label':label,'query':s.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    token=z3.BitVec('clu_token64',64);flag=z3.BitVec('clu_flag32',32);ptr=z3.BitVec('clu_pointer64',64)
    base=R.Parent.D;stack=0x6800060000
    v=Algebra();v.seed('x22',base);v.seed('sp',stack);v.seed('w27',0x92e1);mem(v,base+8,8,token)
    v.run_block(0x1005fadd0,0x1005fae28)
    prove('arbitrary_u64_raw_lock_word_captured_without_validation',cell(v,stack+0x10cc0,8)!=token)
    v=Algebra();v.seed('x8',base);mem(v,base+0x18,4,flag);mem(v,base+0x10,8,ptr)
    v.run_block(0x1006150f4,0x10061510c)
    prove('context_field18_zero_selects_context_and_field10_test_is_nonzero',z3.Or(v.read('x10')!=z3.If(flag==0,z3.BitVecVal(base,64),z3.BitVecVal(0,64)),v.read('w15')!=z3.If(ptr!=0,z3.BitVecVal(1,32),z3.BitVecVal(0,32))))
    byte=z3.BitVec('clu_plain_byte8',8);v=Algebra();v.seed('w12',0xb374);v.seed('sp',stack);v.seed('x9',0);v.seed('x20',R.ALLOC)
    mem(v,stack+0x103a6,1,byte);v.run_block(0x10052e5c4,0x10052e60c)
    prove('original_path_byte_encoder_is_XOR_98_for_all_256_values',cell(v,R.ALLOC,1)!=(byte^0x98))
    v=Algebra();v.seed('x0',ptr);v.seed('sp',stack);v.seed('w25',0x324b);v.run_block(0x1006b6fb4,0x1006b6fcc)
    prove('malloc_full_u64_pointer_saved_and_branch_uses_nonzero',z3.Or(cell(v,stack+0x7a70,8)!=ptr,v.read('w8')!=z3.If(ptr!=0,z3.BitVecVal(0x324b|0x25,32),z3.BitVecVal(0x324b,32))))
    prove('XOR_98_maps_only_input_zero_to_encoded_98',((byte^0x98)==0x98)!=(byte==0))
    return qs

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e['generator_sha256']==sha(R.__file__)
    assert e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    counts=Counter();lifts=[]
    for j,row in enumerate(R.intervals(e)):
        r=Lift(row).run();r['interval_index']=j;lifts.append(r);counts.update(r['verified_counts'])
        if j%8==0:print(json.dumps({'interval':j,'source_visits':counts['source_visits']}),flush=True)
    init=json.loads(read(ROOT/'daemon_return_bank_origins_checks.json'));runs=[];totals=Counter()
    for j,c in enumerate(init['upstream_cases']):
        r=Initializer(c,3).run();r['profile_index']=j;runs.append(r);totals.update(r['verified_counts'])
    qs=obligations()
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'source_sha256':sha(SOURCE),'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],
            'independent_lifts':lifts,'independent_totals':dict(counts),'interfaces':interfaces(e),'source_proofs':qs,
            'source_queries_unsat':len(qs),'initializer_lifts':runs,'initializer_totals':dict(totals),'all_checks_pass':True,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'replay':e['independent_totals'],'interfaces':e['interfaces']}),flush=True)
