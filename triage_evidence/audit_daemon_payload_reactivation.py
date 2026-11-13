#!/usr/bin/env python3
"""Independent payload lifecycle replay, producer checkpoints and source proofs.

O(producer+consumer visits*(state+effects)+query DAG) time;
O(receipts+largest replay+2184-byte models) storage; 30 s/query.
No native API/IPC, allocation/free, hardware PAC or IDB mutation executes.
"""
import json,struct,zlib,base64
from collections import Counter
from hashlib import sha256
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_readiness_arena import Lift as ParentLift
from audit_daemon_environment_outputs import DEC
from audit_daemon_context_unseal import Equation
from audit_daemon_network_record import fixture_bytes,state_bytes,join
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import mem,cell
from validate_daemon_callback_payload import encode,decode,byte_mask,shuffle_index
from replay_daemon_callback_revisit import Replay
import recover_daemon_payload_reactivation as R

class Lift(ParentLift):
    def __init__(self,row,previous=None):
        super().__init__(row)
        if row['entry_PC']==hex(R.REQUEST):
            assert previous and previous['boundary']['pc']==row['entry_PC']
            origins=[x for x in previous['source_reads'] if x['pc']=='0x10086723c']
            assert len(origins)==1;origin=origins[0];slot=int(origin['address'],16)
            target=int.from_bytes(bytes.fromhex(origin['bytes_hex']),'little')
            assert slot==0x10109fe90 and FIXUPS[slot]['target']==target==0x100add594
            assert int(row['entry_registers31'][8],16)==target
            for visit in previous['source_visits'][origin['source_visit_index']+1:]:
                pc=int(visit['pc'],16);ins=next(DEC.disasm(IMAGE.read(pc,4),pc))
                assert not any(ins.reg_name(reg) in ['x8','w8'] for reg in ins.regs_access()[1])
            self.last_authenticated_load=(slot,target)
            self.counts['cross_interval_X8_fixup_origins_checked']+=1

def raw(s,a,n):return bytes(s[a+j] for j in range(n))
def word(s,a,n=8):return int.from_bytes(raw(s,a,n),'little')
def selected(row,pc,kind='source_reads'):return [x for x in row[kind] if x['pc']==hex(pc)]
def joined(before,after,effects=()):
    join(before,after,effects);assert before['boundary']['Q_registers32']==after['entry_Q_registers32']
    assert before['boundary']['pc']==after['entry_PC'] and before['foreign_owners']==after['foreign_owners']

def contract(c,parent):
    before=R.unpack(parent['intervals_packed'][-1]);rows=[R.unpack(p['packed']) for p in c['intervals']]
    effect=c['producer_state_effect'];assert effect=={'address':hex(R.D),'bytes_hex':R.producer()['payload']['after_hex'],'provenance':'separate_original_constructor_encoded_payload2184'}
    assert all(R.D+j not in state_bytes(before) for j in range(R.N))
    model=Counter();start=state_bytes(before);baseline=bytes.fromhex(R.producer()['payload']['before_hex']);encoded=bytes.fromhex(effect['bytes_hex'])
    for j,row in enumerate(rows):
        joined(before,row,[effect] if j==0 else []);model['complete_interval_joins_checked']+=1
        assert not row['native_target_executed'];before=row
    states=[state_bytes(r) for r in rows];s0=fixture_bytes(rows[0],'private')|fixture_bytes(rows[0],'image')
    words=list(struct.unpack('<273Q',encoded));writes=rows[0]['source_writes'];assert len(writes)==816
    for i in range(1,273):
        j=shuffle_index(R.SEED,i);a,b=words[i],words[j]
        triple=writes[3*(i-1):3*i]
        assert [(w['pc'],w['address'],w['after_hex']) for w in triple]==[
            ('0x1008660fc',hex(R.D+8*i),struct.pack('<Q',a^b).hex()),
            ('0x100866108',hex(R.D+8*j),struct.pack('<Q',a).hex()),
            ('0x100866114',hex(R.D+8*i),struct.pack('<Q',b).hex())]
        words[i],words[j]=b,a
    unshuffled=struct.pack('<273Q',*words);assert raw(states[0],R.D,R.N)==unshuffled
    assert unshuffled==bytes(((v^byte_mask(R.SEED,j))*0x93)&255 for j,v in enumerate(baseline))
    assert raw(states[1],R.D,R.N)==baseline and decode(encoded,R.SEED)==baseline
    model.update(inverse_word_swaps_checked=272,inverse_payload_bytes_checked=2184)
    assert selected(rows[2],0x100866240,'source_writes')==[{'pc':'0x100866240','source_visit_index':1,'address':hex(R.J+0x100),'size_bytes':8,'after_hex':struct.pack('<Q',R.D).hex()}]
    request=rows[2]['boundary'];assert request['pc']==hex(R.REQUEST)
    record=int(request['registers31'][0],16);output=int(request['SP'],16)+0x4dbc;s=states[2]
    k=(((record&0xffffffff)^0xeaae0ac9)*0x7398180b)&0xffffffff
    assert word(s,record+8)==output and ((word(s,record+16,2)-(k&65535)-0x153b)&65535)==4 and ((word(s,record+20,4)+k)&0xffffffff)==0xb399
    model.update(raw_pointer_publications_checked=1,four_byte_request_records_checked=1)
    generated_reads=[selected(rows[3],pc)[0] for pc in [0x1005b94fc,0x1005b9508,0x1005b9514,0x1005b952c]]
    generated=bytes(int(x['bytes_hex'],16) for x in generated_reads)
    assert [x['address'] for x in generated_reads]==[hex(output+j) for j in range(4)]
    stores=selected(rows[3],0x100a0ca74,'source_writes');assert len(stores)==4
    assert [w['address'] for w in stores]==[hex(output+j) for j in range(3,-1,-1)] and [w['after_hex'] for w in stores]==[generated[j:j+1].hex() for j in range(3,-1,-1)]
    be=int.from_bytes(generated,'big');header=(be>>1)+1
    assert int(rows[3]['boundary']['registers31'][28],16)==be^0x8b3dc651
    header_writes=selected(rows[4],0x1004decb8,'source_writes');assert len(header_writes)==1
    assert header_writes[0]['address']==hex(R.D+16) and int.from_bytes(bytes.fromhex(header_writes[0]['after_hex']),'little')==header
    clears=selected(rows[4],0x100570e28,'source_writes');assert len(clears)==30
    assert [w['address'] for w in clears]==[hex(R.D+24+72*j) for j in range(30)] and all(w['size_bytes']==4 and w['after_hex']=='00'*4 for w in clears)
    modified=bytearray(baseline);modified[16:20]=struct.pack('<I',header)
    for j in range(30):modified[24+72*j:28+72*j]=bytes(4)
    assert raw(states[4],R.D,R.N)==bytes(modified)
    assert raw(states[5],R.D,R.N)==encode(modified,R.SEED)
    assert decode(raw(states[5],R.D,R.N),R.SEED)==bytes(modified)
    assert len([w for w in rows[5]['source_writes'] if w['pc']=='0x1004a0c34'])==272
    model.update(generated_bytes_copied_checked=4,header_word_updates_checked=1,slot_clear_fields_checked=30,resealed_payload_bytes_checked=2184)
    assert selected(rows[6],0x1004a0d00,'source_writes')[0]['address']==hex(R.J+0x100)
    assert raw(states[6],R.J+0x100,8)==bytes.fromhex('2e4c2bee000003c5')
    model['encoded_pointer_publications_checked']+=1
    # The temporary adjustment word has two original writers. It is not the
    # request's separate completion-status word.
    generator=rows[3];initial=selected(generator,0x100add74c,'source_writes');restore=selected(generator,0x100acdb1c,'source_writes')
    load=selected(generator,0x100add7d8);status=selected(generator,0x100a6d390,'source_writes');delta=selected(generator,0x100add7e4,'source_writes')
    assert len(initial)==len(restore)==len(load)==len(status)==len(delta)==1
    initial,restore,load,status,delta=initial[0],restore[0],load[0],status[0],delta[0]
    assert initial['address']==restore['address']==load['address'] and status['address']==hex(record) and status['address']!=load['address']
    seed64=int.from_bytes(bytes.fromhex(restore['after_hex']),'little')
    assert (int.from_bytes(bytes.fromhex(initial['after_hex']),'little')+0xb0)&((1<<64)-1)==seed64
    assert int.from_bytes(bytes.fromhex(load['bytes_hex']),'little')==seed64&0xffffffff
    assert status['after_hex']=='51c63d8b' and delta['after_hex']=='00'*8
    assert initial['source_visit_index']<restore['source_visit_index']<load['source_visit_index']
    assert not any(int(w['address'],16)<int(load['address'],16)+8 and int(load['address'],16)<int(w['address'],16)+w['size_bytes'] for w in generator['source_writes'] if restore['source_visit_index']<w['source_visit_index']<load['source_visit_index'])
    model['distinct_status_and_adjustment_channels_checked']+=1
    # Full state recurrence is checked again for the newly requested word.
    g=0x1010c784c;prior=fixture_bytes(generator,'private')|fixture_bytes(generator,'image');mt=list(struct.unpack('<624I',raw(prior,g,2496)))
    updates=[]
    for pc in [0x100a5e93c,0x100b312a4,0x100a2f634]:updates.extend(selected(generator,pc,'source_writes'))
    assert len(updates)==624
    for i,w in enumerate(updates):
        nxt=mt[(i+1)%624];y=(mt[i]&0x80000000)|(nxt&0x7fffffff)
        mt[i]=(mt[(i+397)%624]^(y>>1)^(0x9908b0df if nxt&1 else 0))&0xffffffff
        assert w['address']==hex(g+4*i) and w['after_hex']==struct.pack('<I',mt[i]).hex()
    assert raw(states[3],g,2496)==struct.pack('<624I',*mt) and word(states[3],0x1010c67dc,4)==word(states[3],0x1010c8258,4)==9
    model['generator_twist_words_checked']+=624
    for row,s in zip(rows,states):
        assert raw(s,R.J+0x34,32)==raw(start,R.J+0x34,32)
        assert not any(int(x['address'],16)<R.J+0x54 and R.J+0x34<int(x['address'],16)+x['size_bytes'] for x in row['source_reads']+row['source_writes'])
        if int(c['auxiliary_pointer64'],16):
            a=int(c['auxiliary_pointer64'],16);assert not any(a<=int(x['address'],16)<a+104 for x in row['source_reads']+row['source_writes'])
    model['original_stream_bytes_preserved_checked']+=32
    boundary=rows[-1]['boundary'];assert boundary==c['final_boundary'] and rows[-1]['boundary_NZCV']==c['final_NZCV']
    assert boundary['pc']==hex(R.NEXT) and boundary['kind']=='before_unmodeled_import_call' and boundary['detail']['symbol']=='libSystem/_malloc' and boundary['registers31'][0]=='0x4a'
    calls=[call for row in rows for call in row['source_calls']];assert len(calls)==5 and calls[-1]['pc']=='0x1004cef30' and calls[-1]['target']=='0x100410c4c'
    return {'parent_case_index':c['parent_case_index'],'generated4_hex':generated.hex(),'BE32':hex(be),'header_u32':hex(header),
            'status_record_pointer':hex(record),'adjustment_temporary_pointer':load['address'],'adjustment_seed64':hex(seed64),
            'adjustment_output_pointer':delta['address'],'adjustment64':0,
            'payload_raw_after_sha256':sha256(modified).hexdigest(),'payload_encoded_after_sha256':sha256(raw(states[6],R.D,R.N)).hexdigest(),
            'raw_pointer_publication':selected(rows[2],0x100866240,'source_writes')[0],
            'encoded_pointer_publication':selected(rows[6],0x1004a0d00,'source_writes')[0],
            'next_internal_call':calls[-1],'model_checks':dict(model),'all_checks_pass':True}

def audit_case(c,parent):
    lifts=[];totals=Counter();previous=None
    for k,p in enumerate(c['intervals']):
        row=R.unpack(p['packed']);result=Lift(row,previous).run();assert result['all_checks_pass'];lifts.append(result);totals.update(result['verified_counts']);previous=row
        print(json.dumps({'parent_case':c['parent_case_index'],'interval':k,'source_visits':totals['source_visits']}),flush=True)
    return {'parent_case_index':c['parent_case_index'],'independent_lifts':lifts,'independent_totals':dict(totals),'contract':contract(c,parent),'all_checks_pass':True}

def producer_replay():
    p=R.producer();snap=json.loads(read(ROOT/'daemon_callback_revisit_snapshot.json'))
    profile=json.loads(read(ROOT/'daemon_callback_revisit_profiles.json'));trace=json.loads(zlib.decompress(base64.b64decode(profile['payload_zlib_base64'])))
    class Check(Replay):
        def code(self,u,a,n,d):
            if a in [0x100462818,0x100462974]:
                expected=p['payload']['before_hex' if a==0x100462818 else 'after_hex']
                assert bytes(u.mem_read(R.D,R.N)).hex()==expected;self.counts['producer_payload_checkpoint_bytes_checked']+=R.N
            if a==0x1002fb268:
                assert bytes(u.mem_read(R.J+0x100,8)).hex()=='2e4c2bee000003c5';self.counts['producer_pointer_publication_bytes_checked']+=8
            return super().code(u,a,n,d)
    result=Check(snap,trace,3).run();assert result['all_checks_pass'] and result['verified_counts']['source_visits']==160048
    return result

def obligations(e):
    out=[]
    def prove(label,bad,premise=z3.BoolVal(True)):
        s=z3.Solver();s.set(timeout=30000);s.add(premise);assert s.check()==z3.sat;s.add(z3.simplify(bad));assert s.check()==z3.unsat,label
        out.append({'label':label,'query':s.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    byte,mask=z3.BitVecs('react_byte8 react_mask8',8)
    prove('all_byte_bits_affine_byte_inverse',((((byte^mask)*0x93)*0x9b)^mask)!=byte)
    seed,index=z3.BitVecs('react_seed32 react_index32',32);data=z3.BitVec('react_data128',128);base=0x70000000
    v=Equation();v.seed('x11',base);v.seed('q16',z3.Concat(seed,seed,seed,seed));v.seed('q5',0x009b009b009b009b);v.seed('q6',int.from_bytes(bytes.fromhex('9b00'*8),'little'));v.seed('q4',int.from_bytes(IMAGE.read(0x100e2c6c0,16),'little'))
    for q,off in [(0,12),(1,8),(2,4),(3,0)]:v.seed('q'+str(q),z3.Concat(*[index+off+j for j in range(3,-1,-1)]))
    mem(v,base,16,data);v.block(0x100866164,0x1008661c8)
    expected=z3.Concat(*reversed([(z3.Extract(j*8+7,j*8,data)*0x9b)^z3.Extract(7,0,seed^((index+j+seed)*(index+j-seed))) for j in range(16)]))
    prove('all_seed_index_data_bits_original_inverse_vector',cell(v,base,16)!=expected)
    tail=z3.BitVec('react_tail32',32);v=Equation();v.seed('x11',base);v.seed('q0',z3.Concat(seed,seed,seed,seed));v.seed('q1',z3.Concat(*[index+j for j in range(3,-1,-1)]));v.seed('q2',0x009b009b009b009b);mem(v,base,4,tail)
    v.block(0x100866204,0x10086622c)
    expected=z3.Concat(*reversed([(z3.Extract(j*8+7,j*8,tail)*0x9b)^z3.Extract(7,0,seed^((index+j+seed)*(index+j-seed))) for j in range(4)]))
    prove('all_seed_index_data_bits_original_inverse_tail',cell(v,base,4)!=expected)
    v=Equation();v.seed('x17',base);v.seed('x11',0);v.seed('q1',z3.Concat(seed,seed,seed,seed))
    for q,off in [(2,12),(3,8),(4,4),(5,0)]:v.seed('q'+str(q),z3.Concat(*[index+off+j for j in range(3,-1,-1)]))
    for q,a in [(6,0x100fc43a0),(7,0x100fc43b0),(16,0x100fc43c0),(17,0x100fc43d0),(18,0x100e2c6c0)]:v.seed('q'+str(q),int.from_bytes(IMAGE.read(a,16),'little'))
    v.seed('q19',int.from_bytes(bytes.fromhex('93'*16),'little'));mem(v,base,16,data);v.block(R.RESEAL,0x1004a0b8c)
    expected=z3.Concat(*reversed([((z3.Extract(j*8+7,j*8,data)^z3.Extract(7,0,seed^((index+j+seed)*(index+j-seed))))*0x93) for j in range(16)]))
    prove('all_seed_index_data_bits_original_reseal_vector',cell(v,base,16)!=expected)
    v=Equation();v.seed('x1',base);v.seed('q0',z3.BitVec('react_unused_tail_lanes128',128));v.seed('q1',z3.Concat(seed,seed,seed,seed));v.seed('q2',z3.Concat(*[index+j for j in range(3,-1,-1)]));v.seed('q3',0x0093009300930093);mem(v,base,4,tail);v.block(0x1004a0bc8,0x1004a0bf4)
    expected=z3.Concat(*reversed([((z3.Extract(j*8+7,j*8,tail)^z3.Extract(7,0,seed^((index+j+seed)*(index+j-seed))))*0x93) for j in range(4)]))
    prove('all_seed_index_data_bits_original_reseal_tail',cell(v,base,4)!=expected)
    row=R.unpack(e['cases'][0]['intervals'][3]['packed']);frame=next(f for f in row['source_frames'] if f['pc']=='0x1005b94f0');v=Algebra()
    for j,x in enumerate(frame['registers31']):v.seed('x'+str(j),int(x,16))
    be=z3.BitVec('react_generated_BE32',32);outbase=int(frame['registers31'][28],16)
    for j in range(4):mem(v,outbase+j,1,z3.Extract(31-8*j,24-8*j,be))
    v.run_block(0x1005b94f8,0x1005b9550);v.run_block(0x1005b95b8,0x1005b95bc)
    prove('all_generated_words_original_scalar_pack',v.read('w28')!=(be^0x8b3dc651))
    v.seed('x15',0x6cf4);v.run_block(0x1004dec48,0x1004decac)
    prove('all_generated_words_original_header_positive31',v.read('w11')!=z3.LShR(be,1)+1)
    prove('all_generated_words_header_range',z3.Or(z3.ULT(z3.LShR(be,1)+1,1),z3.UGT(z3.LShR(be,1)+1,0x80000000)))
    ptr,offset=z3.BitVecs('react_payload_base64 react_slot_offset64',64);v=Algebra();v.seed('x8',base);v.seed('x10',offset);mem(v,base,8,ptr);v.run_block(0x100570e20,0x100570e2c);v.run_block(0x100570e40,0x100570e44)
    prove('all_bases_offsets_original_slot_clear_and_stride',z3.Or(v.stores[-1]['address']!=ptr+offset,v.stores[-1]['value']!=0,v.read('x10')!=offset+72))
    v=Algebra();v.seed('x8',base);v.seed('x17',base+0x100);mem(v,base+0x158,8,ptr);v.run_block(R.RAW,R.RAW+8)
    prove('all_pointer_words_original_raw_publication',cell(v,base,8)!=ptr)
    return out

def assemble(e,cases,producer):
    assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS} and e['producer_evidence']==R.producer()
    counts=Counter();model=Counter()
    for c in cases:assert c['all_checks_pass'];counts.update(c['independent_totals']);model.update(c['contract']['model_checks'])
    proofs=obligations(e)
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'source_sha256':sha(SOURCE),'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],
            'cases':cases,'independent_totals':dict(counts),'model_checks':dict(model),'producer_replay':producer,
            'source_proofs':proofs,'source_queries_unsat':len(proofs),'all_checks_pass':True,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));parent=json.loads(read(ROOT/(R.Parent.P+'_checks.json')))
    cases=[audit_case(c,parent['cases'][c['parent_case_index']]) for c in e['cases']]
    return assemble(e,cases,producer_replay())

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'replay':e['independent_totals'],'model':e['model_checks'],'source_queries_unsat':e['source_queries_unsat']}),flush=True)
