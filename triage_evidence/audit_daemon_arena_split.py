#!/usr/bin/env python3
"""Independent split/fill/payload replay, provenance joins and source equations.

O(receipts+visits*(state+byte effects)+query DAG) time/space; 30 s/query.
No native API/IPC, allocation/free, concurrency, hardware PAC or IDB mutation.
"""
import json,struct
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_readiness_arena import Lift
from audit_daemon_context_state_publish import return_join
from audit_daemon_network_record import state_bytes,fixture_bytes,join
from audit_daemon_environment_outputs import DEC
from audit_daemon_clock_record import comparison_records
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import mem,cell
import recover_daemon_arena_split as R

def frame(row,pc):return row['source_frames'][next(j for j,v in enumerate(row['source_visits']) if v['pc']==hex(pc))]
def joined(before,after,effects=()):
    join(before,after,effects);assert before['boundary']['Q_registers32']==after['entry_Q_registers32']
    assert before['boundary']['pc']==after['entry_PC'] and before['foreign_owners']==after['foreign_owners']

def interfaces(e):
    p=json.loads(read(ROOT/(R.Parent.P+'_checks.json')));counts=Counter();fills=R.fill_evidence(p)
    assert e['snapshot_fields']==R.snapshot_fields() and e['fill_evidence']==fills
    for c in fills:
        row=p['header_cases'][c['parent_header_case_index']]['intervals'][-1]
        writes=[w for w in row['source_writes'] if w['pc']=='0x100be73cc'];assert len(writes)==156
        for k,w in enumerate(writes):
            f=row['source_frames'][w['source_visit_index']-7];assert f['pc']=='0x100be73b0'
            g=[int(x,16) for x in f['registers31']];value=((((g[14]+g[3])&0xffffffff)^0x88888888)+(g[15]&0xffffffff))*((g[15]^g[2])&0xffffffff)&255
            assert bytes.fromhex(w['after_hex'])==bytes([value])
            assert int(w['address'],16)==R.MARKER-1-k;counts['parent_fill_byte_equations_checked']+=1
        final=state_bytes(row);assert bytes(final[R.PAYLOAD+j] for j in range(64)).hex()==c['payload64_hex']
        counts['parent_payload_provenance_bytes_checked']+=64
        # X8 is a retained original fixup across this full parent interval.
        assert row['entry_registers31'][8]==row['boundary']['registers31'][8]=='0x100c190f4'
        for v in row['source_visits']:
            i=next(DEC.disasm(IMAGE.read(int(v['pc'],16),4),int(v['pc'],16)))
            assert not any(i.reg_name(t) in ['x8','w8'] for t in i.regs_access()[1])
        counts['parent_retained_X8_origin_chains_checked']+=1
    for c in e['marker_cases']:
        before=p['header_cases'][c['parent_header_case_index']]['intervals'][-1];row=c['intervals'][0];joined(before,row,c['effects'])
        assert row['foreign_owners']==before['foreign_owners'] and c['payload_bytes_supplied']==0
        initial=fixture_bytes(row,'private')|fixture_bytes(row,'image');assert all(R.PAYLOAD+j in initial for j in range(64))
        assert all(R.MARKER+8+j not in initial for j in range(8))
        if not c['marker_defined']:
            assert not row['source_visits'] and not row['source_reads'] and not row['source_writes'];counts['undefined_marker_stops']+=1;continue
        assert len(row['source_visits'])==134 and row['boundary']['pc']==hex(R.Parent.Parent.ARC)
        writes=row['source_writes'];assert len(writes)==8
        ledger=int.from_bytes(bytes.fromhex(e['snapshot_fields'][2]['bytes_hex']),'little');sp=int(row['caller_SP'],16)
        cookie=int.from_bytes(bytes(initial[sp+0x20+j] for j in range(8)),'little')
        expected=[(0x100a77d9c,R.H+8,R.M+86620-88,8),(0x100a77da4,R.BLOCK,R.M+86620-88,8),
                  (0x100a77df4,R.BLOCK+8,R.M-88,8),(0x100a77dfc,R.BLOCK+16,cookie,8),
                  (0x100a77e10,R.MARKER,R.M,8),(0x100a77e70,R.LEDGER,(ledger+88)&((1<<64)-1),8),
                  (0x100a8c054,sp+0x190,R.PAYLOAD,8),(0x100a8c078,R.Parent.GATE,0x5d96,4)]
        assert [(int(w['pc'],16),int(w['address'],16),int.from_bytes(bytes.fromhex(w['after_hex']),'little'),w['size_bytes']) for w in writes]==expected
        assert not any(int(w['address'],16)<R.PAYLOAD+64 and R.PAYLOAD<int(w['address'],16)+w['size_bytes'] for w in writes)
        # Marker+8 is not imported or accessed; only the first word matters here.
        assert not any(int(x['address'],16)<R.MARKER+16 and R.MARKER+8<int(x['address'],16)+x['size_bytes'] for x in row['source_reads']+writes)
        counts.update(original_split_controls_checked=1,original_split_metadata_writes_checked=8,preserved_payload_bytes_checked=64)
    comparisons=[]
    for c in e['seed_cases']:
        before=e['marker_cases'][c['parent_marker_case_index']]['intervals'][-1];rows=c['intervals']
        assert len(rows)==5 and len(c['transitions'])==4
        for row,t in zip(rows,c['transitions']):
            return_join(before,t['import_return'],row,t['effects']);assert before['foreign_owners']==row['foreign_owners'];before=row;counts['API_return_joins_checked']+=1
        joined(rows[-2],rows[-1]);counts['defined_payload_consumer_joins_checked']+=1
        assert [len(row['source_visits']) for row in rows]==[8140,22,19,273,53]
        payload_reads=[x for row in rows for x in row['source_reads'] if int(x['address'],16)<R.PAYLOAD+64 and R.PAYLOAD<int(x['address'],16)+x['size_bytes']]
        assert len(payload_reads)==1 and payload_reads[0]['address']==hex(R.PAYLOAD+4) and payload_reads[0]['size_bytes']==4
        demand=rows[-2]['boundary'];assert demand['pc']==hex(R.STOP) and demand['registers31'][10]==hex(R.PAYLOAD+4)
        assert c['consumed_address']==hex(R.PAYLOAD+4) and c['payload_bytes_supplied']==0 and c['payload_bytes_read']==4
        comparisons.append(comparison_records(rows[-2]));counts['comparison_contracts_checked']+=2
        row=rows[-1];assert row['boundary']['pc']==hex(R.NEXT) and row['boundary']['registers31'][19]=='0x2'
        reads=row['source_reads'];assert reads[0]['pc']==hex(R.STOP) and reads[0]['address']==hex(R.PAYLOAD+4) and reads[0]['bytes_hex']=='5c902e62'
        # Six overlapping source-text bytes are a local decoding dependency.
        code=[x for x in reads if x['pc'] in ['0x100a076f0','0x100a076f8']]
        assert [(x['address'],x['size_bytes']) for x in code]==[('0x100822c84',4),('0x100822c86',4)]
        for x in code:assert IMAGE.read(int(x['address'],16),4).hex()==x['bytes_hex']
        writes=row['source_writes'];rec=int(row['caller_SP'],16)+0x220
        assert len(writes)==1 and writes[0]['pc']=='0x100a0770c' and writes[0]['address']==hex(rec+4) and writes[0]['after_hex']=='c4f70bb5'
        assert all(not(R.PAYLOAD<=int(w['address'],16)<R.PAYLOAD+64) for w in writes)
        counts.update(defined_payload_word_consumers_checked=1,source_text_dependency_bytes_checked=6,private_record_word_updates_checked=1)
    return {'verified_counts':dict(counts),'comparison_contracts':comparisons,'native_epoch_join_established':False,
            'scope':'Original arena split, inherited source fill and first defined payload-to-record update; complete generator state and native transport pairing remain unknown.'}

class Equation(Algebra):
    def one(self,i):
        if i.writeback:
            assert i.mnemonic=='str' and i.op_str=='x13, [x22], #0x18'
            base=self.read('x22');self.store(base,8,self.read('x13'),i.address);self.write('x22',base+24);return
        return super().one(i)

class ConsumerEquation(Equation):
    def load(self,a,n):
        if self.pc==R.STOP:assert n==4;self.requested_address=a;return self.payload_word
        return super().load(a,n)

def obligations():
    qs=[]
    def prove(label,bad,premise=z3.BoolVal(True)):
        s=z3.Solver();s.set(timeout=30000);s.add(premise);assert s.check()==z3.sat;s.add(z3.simplify(bad));assert s.check()==z3.unsat,label
        qs.append({'label':label,'query':s.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    marker,header=z3.BitVecs('as_marker64 as_header64',64);v=Algebra();v.seed('x15',R.MARKER);v.seed('x13',header);v.seed('w12',0xb399);mem(v,R.MARKER,8,marker)
    v.run_block(R.ENTRY,0x100b6a938)
    prove('all_u64_marker_header_equality_partition',v.read('w12')!=z3.If(marker==header,z3.BitVecVal(0xa7c4,32),z3.BitVecVal(0xa059,32)))
    node,offset,total=z3.BitVecs('as_node64 as_offset64 as_total64',64);v=Algebra();v.seed('x9',node);v.seed('x16',offset);v.seed('x10',total);v.seed('x13',header)
    v.run_block(0x100a77d3c,0x100a77d48)
    prove('all_u64_split_block_and_reduced_header_equations',z3.Or(v.read('x12')!=node+offset-total,v.read('x13')!=header-total))
    v=Equation();v.seed('x9',R.H);v.seed('x16',86620);v.seed('x10',88);v.seed('x13',header)
    v.run_block(0x100a77d3c,0x100a77da8)
    prove('all_u64_headers_original_split_header_stores_and_payload_plus24',z3.Or(cell(v,R.H+8,8)!=header-88,cell(v,R.BLOCK,8)!=header-88,v.read('x22')!=R.PAYLOAD))
    v=Algebra();v.seed('w14',0x2de9);v.seed('x11',-total);v.seed('x12',R.BLOCK);v.run_block(0x100a77da8,0x100a77df8)
    prove('all_8_byte_aligned_u64_extents_original_encoded_negative_extent',cell(v,R.BLOCK+8,8)!=R.M-total,(total&7)==0)
    cookie=z3.BitVec('as_cookie64',64);v=Algebra();v.seed('sp',0x680005fce0);v.seed('x12',R.BLOCK);v.seed('x15',R.MARKER);mem(v,0x680005fd00,8,cookie)
    v.run_block(0x100a77df8,0x100a77e14)
    prove('all_u64_cookies_original_copy_and_old_marker_reset',z3.Or(cell(v,R.BLOCK+16,8)!=cookie,cell(v,R.MARKER,8)!=R.M))
    ledger=z3.BitVec('as_ledger64',64);v=Algebra();v.seed('x28',R.Parent.D);v.seed('x10',total);mem(v,R.LEDGER,8,ledger);v.run_block(0x100a77e14,0x100a77e74)
    prove('all_u64_ledger_and_extents_original_accounting_addition',cell(v,R.LEDGER,8)!=ledger+total)
    a,b,d=z3.BitVecs('as_fill_A32 as_fill_B32 as_fill_D32',32);counter=z3.BitVec('as_fill_counter64',64);k=z3.Extract(31,0,counter)
    v=Algebra();buf=0x70000000;sp=0x71000000
    v.seed('w14',a);v.seed('w3',b);v.seed('x15',counter);v.seed('w2',d);v.seed('x0',156);v.seed('x16',buf);v.seed('sp',sp)
    v.run_block(0x100be73b0,0x100be73d8);formula=z3.Extract(7,0,(((a+b)^0x88888888)+k)*(k^d))
    prove('all_word_fill_inputs_and_u64_counter_original_byte_and_transition',z3.Or(cell(v,buf+155,1)!=formula,v.read('x0')!=155,v.read('x15')!=counter+1))
    word,old,phase,flag=z3.BitVecs('as_payload32 as_old_record32 as_phase32 as_flag32',32);addr=z3.BitVec('as_payload_address64',64);text=z3.BitVec('as_source_text48',48)
    v=ConsumerEquation();v.payload_word=word;v.seed('x10',addr);v.seed('w12',phase);v.seed('w13',flag);v.seed('sp',sp);v.seed('x8',4);v.seed('x14',0x100822c84);v.seed('x11',0x100822c86)
    rec=0x72000000;mem(v,sp+0x1c0,8,rec);mem(v,rec+4,4,old)
    mem(v,0x100822c84,4,z3.Extract(31,0,text));mem(v,0x100822c86,4,z3.Extract(47,16,text))
    v.run_block(R.STOP,0x100a07710)
    result=(z3.Extract(31,0,addr)*0xc40ba787)^word^(phase&0xc68e91c5)^(flag&1)^(old-((old<<1)&0x377b9daa)+0x1bbdced5)^z3.Extract(31,0,text)^z3.Extract(47,16,text)^0xe2715a91
    prove('all_payload_record_phase_address_and_overlapping_text_inputs_original_update',z3.Or(v.requested_address!=addr,cell(v,rec+4,4)!=result))
    return qs

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    lifts=[];totals=Counter()
    for j,row in enumerate(R.intervals(e)):
        a=Lift(row).run();a['interval_index']=j;lifts.append(a);totals.update(a['verified_counts'])
        if j%8==0:print(json.dumps({'interval':j,'source_visits':totals['source_visits']}),flush=True)
    qs=obligations()
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'source_sha256':sha(SOURCE),'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],
            'independent_lifts':lifts,'independent_totals':dict(totals),'interfaces':interfaces(e),'source_proofs':qs,'source_queries_unsat':len(qs),
            'all_checks_pass':True,'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'replay':e['independent_totals'],'interfaces':e['interfaces']['verified_counts']}),flush=True)
