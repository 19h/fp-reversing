#!/usr/bin/env python3
"""Independent saved-pointer, register-definition and byte-transfer audit.
O(P+V+E+32C+proof DAG) time and O(parent receipts+largest interval+
selected chunks+proof DAG) space; solver search limited to 30 s/query.
No native execution, Mach operation, hardware PAC or IDB action.
"""
import json
from collections import Counter
import z3
from capstone.arm64 import ARM64_OP_IMM
from daemon_receive_tools import ROOT, SOURCE, IMAGE
from verify_daemon_reader_record_payloads_publication import read, sha
from recover_daemon_state_container_construction import unpack
from recover_daemon_record_banks import instruction
from audit_daemon_append_fields import Lift
from audit_daemon_alternative_fill import Source
from audit_daemon_record_input_origin import replay
from audit_daemon_payload_count_flow import PostTrace, check_frame, number
from recover_daemon_digest_body_origins import invalidated
import recover_daemon_count_pointer_origin as R


class BytePost:
    def one(self,i):
        if not (i.writeback and i.mnemonic in ['ldrb','strb']):return super().one(i)
        self.pc=i.address;o=i.operands
        assert len(o)==3 and o[2].type==ARM64_OP_IMM and o[2].imm==1 and o[1].mem.disp==0
        base=i.reg_name(o[1].mem.base);reg=i.reg_name(o[0].reg)
        assert base in ['x0','x1'] and reg=='w9'
        address=self.address(i,o[1])
        if i.mnemonic=='ldrb':self.write(reg,self.load(address,1))
        else:self.store(address,1,z3.Extract(7,0,self.read(reg)),i.address)
        self.write(base,address+1)


class ByteSource(BytePost,Source):pass
class ByteTrace(BytePost,PostTrace):pass


def byte_replay(chunk):
    v=ByteTrace(chunk['reads'],chunk['writes']);f=chunk['frames'][0]
    for j,x in enumerate(f['registers31']):v.seed('x'+str(j),int(x,16))
    v.seed('sp',int(f['SP'],16));flags=int(f['NZCV'],16)
    v.n,v.z,v.carry,v.overflow=[z3.BoolVal(bool(flags&(1<<k))) for k in [31,30,29,28]]
    assert len(chunk['visits'])==2
    for j,visit in enumerate(chunk['visits']):
        check_frame(v,chunk['frames'][j]);pc=int(visit['pc'],16)
        assert visit['bytes_hex']==IMAGE.read(pc,4).hex()
        i=instruction(pc);assert i.mnemonic==['ldrb','strb'][j] and i.writeback
        v.one(i);assert chunk['frames'][j+1]['pc']==hex(pc+4)
    check_frame(v,chunk['frames'][-1]);assert v.ri==v.wi==1
    return {'source_visits':2,'GP_SP_values':96,'NZCV_frames':3,'reads':1,'writes':1,'chunks':1,'byte_writeback_instructions':2}


def obligations():
    out=[]
    def prove(label,bad):
        s=z3.Solver();s.set(timeout=30000);assert s.check()==z3.sat
        s.add(z3.simplify(bad));assert s.check()==z3.unsat,label
        out.append({'label':label,'premises_nonvacuous':True,'result':'unsat','query':s.to_smt2()})
    ctx,sp,ptr,src,dst=z3.BitVecs('cpo_context64 cpo_SP64 cpo_pointer64 cpo_source64 cpo_destination64',64)
    byte=z3.BitVec('cpo_byte8',8)
    v=Source({0x1008337c4:(8,ctx)});v.seed('sp',sp);v.run_block(0x1008337c4,0x1008337c8)
    prove('original_saved_context_pointer_load',z3.Or(v.loads[0][1]!=sp+0x7f38,v.read('x21')!=ctx))
    v=Lift();v.seed('x21',ctx);v.seed('sp',sp);v.run_block(0x10071062c,0x100710634);w,=v.stores
    prove('original_count_pointer_initialization',z3.Or(w['address']!=sp+0x71c0,w['value']!=ctx+28,v.read('x21')!=ctx))
    v=Source({0x100595f5c:(8,ptr)});v.seed('sp',sp);v.run_block(0x100595f5c,0x100595f60)
    prove('original_snapshot_pointer_reload',z3.Or(v.loads[0][1]!=sp+0x71c0,v.read('x20')!=ptr))
    for pc in range(0x10046f9e4,0x10046fa24,8):
        v=ByteSource({pc:(1,byte)});v.seed('x0',src);v.seed('x1',dst);v.run_block(pc,pc+8);w,=v.stores
        prove('original_snapshot_byte_pair_'+hex(pc),z3.Or(v.loads[0][1]!=src,w['address']!=dst,w['value']!=byte,
              v.read('x0')!=src+1,v.read('x1')!=dst+1,v.read('w9')!=z3.ZeroExt(24,byte)))
    return out


def incoming_bytes(row,address,n):
    result={}
    for f in row['initial_private_fixtures']+row['initial_image_fixtures']:
        a=int(f['address'],16)
        for k,b in enumerate(bytes.fromhex(f['bytes_hex'])):
            if address<=a+k<address+n:
                assert a+k not in result;result[a+k]=b
    assert len(result)==n
    return bytes(result[address+k] for k in range(n))


def audit():
    evidence=json.loads(read(ROOT/(R.P+'_checks.json')))
    for p,h in R.PINS.items():assert sha(ROOT/p)==h
    parent=json.loads(read(ROOT/'daemon_state_container_construction_checks.json'));totals=Counter()
    assert len(evidence['cases'])==len(parent['contexts'])==76
    for case,c in zip(evidence['cases'],parent['contexts']):
        assert len(case['pointer_paths'])==len(c['buffer_frees'])==12
        for path,item in zip(case['pointer_paths'],c['buffer_frees']):
            row=unpack(item['interval_packed']);assert path['interval_sha256']==item['interval_packed']['decoded_sha256']
            load=path['saved_context_pointer_read'];store=path['count_pointer_write']
            assert load in row['source_reads'] and store in row['source_writes']
            assert load['size_bytes']==store['size_bytes']==8
            for j in [29,111,112]:
                visit=row['source_visits'][j];assert visit['bytes_hex']==IMAGE.read(int(visit['pc'],16),4).hex()
            assert row['source_visits'][29]['pc']=='0x1008337c4'
            assert row['source_visits'][111]['pc']=='0x10071062c' and row['source_visits'][112]['pc']=='0x100710630'
            assert int(row['source_frames'][29]['SP'],16)+0x7f38==int(load['address'],16)
            assert incoming_bytes(row,int(load['address'],16),8)==bytes.fromhex(load['bytes_hex'])==R.J.to_bytes(8,'little')
            assert not any(R.overlap(w,int(load['address'],16),8) and w['source_visit_index']<29 for w in row['source_writes'])
            for j in range(30,113):assert row['source_frames'][j]['registers31'][21]==hex(R.J)
            for visit in row['source_visits'][30:111]:
                i=instruction(int(visit['pc'],16))
                assert not any(i.reg_name(r) in ['x21','w21'] for r in i.regs_access()[1])
                assert i.mnemonic not in ['bl','blr','blraa','blrab']
            assert row['source_frames'][112]['registers31'][9]==hex(R.J+28)
            assert int(row['source_frames'][112]['SP'],16)+0x71c0==int(store['address'],16)==R.CELL
            assert bytes.fromhex(store['after_hex'])==(R.J+28).to_bytes(8,'little')
            assert [w for w in row['source_writes'] if R.overlap(w,R.CELL,8)]==[store]
            totals.update(pointer_paths_checked=1,pointer_store_bytes_checked=8,X21_preserved_frames_checked=83,
                          X21_nondefinition_visits_checked=81)
        row=unpack(c['allocation_cases'][1]['interval_packed']);snap=case['snapshot']
        assert snap['interval_sha256']==c['allocation_cases'][1]['interval_packed']['decoded_sha256']
        assert incoming_bytes(row,R.CELL,8)==bytes.fromhex(case['pointer_paths'][0]['count_pointer_write']['after_hex'])
        for k in range(8):assert not invalidated(c['allocation_cases'][1]['API_return_premise'],R.CELL+k)
        assert not any(R.overlap(w,R.CELL,8) for w in row['source_writes'])
        assert snap['saved_pointer_reload'] in row['source_reads'] and snap['call'] in row['source_calls']
        assert snap['call']['arguments8'][:3]==[hex(R.J+28),hex(R.S+24),'0x18']
        for k,(r,w) in enumerate(zip(snap['reads'],snap['writes'])):
            assert r in row['source_reads'] and w in row['source_writes']
            assert int(r['address'],16)==R.J+28+k and int(w['address'],16)==R.S+24+k
            assert r['bytes_hex']==w['after_hex']==incoming_bytes(row,R.J+28+k,1).hex()
            assert not any(R.overlap(old,R.J+28+k,1) and old['source_visit_index']<r['source_visit_index'] for old in row['source_writes'])
            assert w['source_visit_index']==r['source_visit_index']+1 and r['size_bytes']==w['size_bytes']==1
            for e,m,base in [(r,'ldrb',0),(w,'strb',1)]:
                j=e['source_visit_index'];visit=row['source_visits'][j];pc=int(e['pc'],16)
                assert visit['pc']==e['pc'] and visit['bytes_hex']==IMAGE.read(pc,4).hex()
                i=instruction(pc);assert i.mnemonic==m and i.writeback
                assert i.reg_name(i.operands[0].reg)=='w9' and i.reg_name(i.operands[1].mem.base)=='x'+str(base)
                assert i.operands[2].type==ARM64_OP_IMM and i.operands[2].imm==1 and i.operands[1].mem.disp==0
                f,n=row['source_frames'][j:j+2];a=int(e['address'],16)
                assert int(f['registers31'][base],16)==a and int(n['registers31'][base],16)==a+1
                value=int(e['bytes_hex'] if m=='ldrb' else e['after_hex'],16)
                assert int((n if m=='ldrb' else f)['registers31'][9],16)==value
                totals['byte_transfer_instruction_checks']+=1
        assert len(snap['reads'])==len(snap['writes'])==24
        totals.update(snapshot_copies_checked=1,snapshot_bytes_checked=24,saved_pointer_boundary_bytes_checked=8)
    for c in evidence['representatives']:
        for p in c['chunks']:totals.update(byte_replay(p) if p['kind']=='snapshot_byte_transfer' else replay(p))
    proofs=obligations();totals['new_source_queries_unsat']=len(proofs)
    assert len(proofs)==11
    return {'scope':__doc__,'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'source_sha256':sha(SOURCE),'parent_pins':R.PINS,
            'dependencies':{p:sha(ROOT/p) for p in ['audit_daemon_append_fields.py','audit_daemon_alternative_fill.py',
              'audit_daemon_record_input_origin.py','audit_daemon_payload_count_flow.py','recover_daemon_digest_body_origins.py']},
            'source_proofs':proofs,'independent_totals':dict(totals),'retained_pointer_initialization_established':True,
            'full_constructor_to_consumer_epoch_join_established':False,'native_constructor_epoch_join_established':False,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False,'all_checks_pass':True}


if __name__=='__main__':
    x=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(x,indent=2)+'\n')
    print(json.dumps(x['independent_totals']),flush=True)
