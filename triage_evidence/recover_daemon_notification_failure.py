#!/usr/bin/env python3
"""Notification failure suffix, encoded record cleanup and actual caller return.

The clock-success caller/root prefix and post-provider registration cut remain
unjoined. Nonempty cleanup records are explicit separate entry premises.
Imports stop before execution; void free returns are declared continuations.
O(cases*(visits+effects)+source+queries) time/space excluding solver cost,
30 s/query. No native API/IPC, allocation/free or hardware PAC executes.
"""
import itertools,json,struct
from collections import Counter
import z3
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,selected,qword
from verify_daemon_reader_record_payloads_publication import read,sha
from lskd_values_symbolic import mem,cell
from recover_daemon_return_bank_origins import Algebra
import recover_daemon_notification_registration as Reg

Parent=Reg.Parent;P='daemon_notification_failure';COMMON=0x100e24d08
SENTINELS=[0x0e5d2a6f87a8427c,0x7dd5cf10709e5799]
FIELDS=[0x160,0x1c0];RECORDS=[Parent.Base.P+0x4000,Parent.Base.P+0x5000]
PAYLOADS=[Parent.Base.P+0x6000,Parent.Base.P+0x7000]
FREES=[0x100e24e28,0x100e24eec,0x100e24fdc,0x100e2507c]
TARGETS={0x1006cdaf8,0x100709868}

class Run(Reg.Run):
    def __init__(self,c):
        pcfg={'placement':c['placement'],'pattern':c['pattern'],'cache_mode':'miss','flag8':c['flag8'],
              'controllers':c['controllers'],'argument64':0xfffffffffffffffe,'null_mask':0,'kind':'caller'}
        Parent.Run.__init__(self,pcfg);self.cfg=c;self.caller_configuration=pcfg;self.cut_stops=set();self.allow_consumer=False
        for j,at in enumerate(Reg.TOKENS):self.image_fixture(at,(0x7001+j).to_bytes(4,'little'),'declared_initial_token')

    def code(self,u,a,n,d):
        if self.allow_consumer and a==Parent.RETURN:
            frame={'pc':hex(a),'registers31':[hex(self.reg(j)) for j in range(31)],
                   'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'NZCV':hex(u.reg_read(ar.UC_ARM64_REG_NZCV))}
            before=self.seq;out=Parent.Base.Run.code(self,u,a,n,d)
            if self.seq>before:self.frames.append(frame)
            return out
        return super().code(u,a,n,d)

    def interval(self,start,role):
        row=super().interval(start,role)
        row['source_calls']=[{k:v for k,v in r.items() if k!='record'} for r in self.calls]
        return row

def probe(c):
    v=Run(c);v.cut_stops={Reg.ROOT_STOP};prefix=v.interval(Parent.CLOCK_SUCCESS,'actual_caller_to_helper_root_prefix')
    assert prefix['boundary']['pc']==hex(Reg.ROOT_STOP)
    v.cut_stops={COMMON};rows=[];events=[];start=Reg.START
    while True:
        row=v.interval(start,'separate_post_provider_failure_cut');rows.append(row);pc=int(row['boundary']['pc'],16)
        if pc==COMMON:break
        assert pc in Reg.REG+Reg.CHECK and row['boundary']['kind']=='before_unmodeled_import_call'
        j=(Reg.REG if pc in Reg.REG else Reg.CHECK).index(pc);output=None;status=0
        fail=c['outcome']==('register_fail' if pc in Reg.REG else 'check_fail')+str(j)
        if fail:status=c['failure_status32']
        elif pc in Reg.REG:output=(Reg.TOKENS[j],struct.pack('<I',0x7101+j))
        else:output=(int(row['boundary']['registers31'][1],16),struct.pack('<I',c['changed32']))
        events.append(v.imported_return(row,status,output));start=pc+4
    f=v.C-0x4a0;premises=[]
    if c['kind']=='cleanup_control':
        for j,state in enumerate(c['record_states']):
            raw=RECORDS[j] if state else 0;encoded=(raw+SENTINELS[j])&((1<<64)-1)
            v.fixture(f+FIELDS[j],struct.pack('<Q',encoded))
            entry={'frame_offset':hex(FIELDS[j]),'encoded64':hex(encoded),'raw_record':hex(raw),'state':state,'separate_entry_premise':True}
            if state:
                payload=PAYLOADS[j] if state==2 else 0;data=struct.pack('<QII',payload,0x12345678,0x9abcdef0)
                v.fixture(raw,data);entry.update(payload=hex(payload),accessed_record_bytes=16,bytes_hex=data.hex())
            premises.append(entry)
    else:
        assert c['record_states']==[0,0]
        assert [int.from_bytes(v.u.mem_read(f+off,8),'little') for off in FIELDS]==SENTINELS
    v.cut_stops=TARGETS;start=COMMON;tail=[];free_events=[]
    while True:
        row=v.interval(start,'original_failure_cleanup_and_return');tail.append(row);pc=int(row['boundary']['pc'],16)
        if pc==Parent.RETURN:break
        assert pc in FREES and row['boundary']['detail']['symbol']=='libSystem/_free'
        event=v.imported_return(row,0);event.pop('return32');event['void_return_premise']=True
        unspecified=0xabcdef0123456789^c['pattern'];v.set(0,unspecified)
        event['unspecified_X0_fixture']=hex(unspecified);event['return_registers31'][0]=hex(unspecified)
        free_events.append(event);start=pc+4
    v.allow_consumer=True;consumer=v.interval(Parent.RETURN,'actual_original_caller_return_consumer')
    assert int(consumer['boundary']['pc'],16) in TARGETS
    return {'configuration':c,'root_prefix':prefix,'registration_intervals':rows,'registration_return_premises':events,
            'cleanup_entry_premises':premises,'cleanup_intervals':tail,'free_return_premises':free_events,
            'caller_consumer':consumer,'final_ready8':v.u.mem_read(Parent.FLAG,1)[0],
            'final_tokens32':[int.from_bytes(v.u.mem_read(at,4),'little') for at in Reg.TOKENS],
            'native_target_executed':False,'uninterrupted_provider_join_established':False}

def configurations():
    outcomes=['register_fail'+str(j) for j in range(3)]+['check_fail'+str(j) for j in range(3)]
    for place,controllers,flag,outcome in itertools.product([0,0x100],[(0,0),(0xffffffff,0x87654321)],[0,2],outcomes):
        yield {'kind':'retained_failure','placement':place,'pattern':0x35 if place==0 else 0xca,'controllers':list(controllers),
               'flag8':flag,'outcome':outcome,'record_states':[0,0],'failure_status32':0xdeadbeef if place else 1,
               'changed32':0xffffffff if place else 0}
    for place,controllers,a,b in itertools.product([0,0x100],[(0,0),(0xffffffff,0x87654321)],range(3),range(3)):
        yield {'kind':'cleanup_control','placement':place,'pattern':0x35 if place==0 else 0xca,'controllers':list(controllers),
               'flag8':0,'outcome':'register_fail0','record_states':[a,b],'failure_status32':0xffffffff,'changed32':0}

def intervals(c):return [c['root_prefix']]+c['registration_intervals']+c['cleanup_intervals']+[c['caller_consumer']]

def banks():
    rows=[]
    for name,l,r,key,add in [('payload_A',0x101033700,0x101033a30,0x6a,0xad3),
                           ('record_A',0x101033700,0x101033a30,0x7b,0xa5a),
                           ('payload_B',0x101033930,0x101032e80,0x4a,0xac4),
                           ('record_B',0x1010332e0,0x101033800,0x44,0xae2)]:
        row=selected(l,r,key,add,base=Parent.DISPATCH);left=IMAGE.read(l,256);right=IMAGE.read(r,256)
        row.update(name=name,left256_hex=left.hex(),right256_hex=right.hex(),XOR_outputs_256=[j^right[left[j]^key] for j in range(256)])
        assert len(set(row['XOR_outputs_256']))==1 and row['target']=='libSystem/_free';rows.append(row)
    return rows

def source():
    return [{'name':name,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
                             for i in CS.disasm(IMAGE.read(a,b-a),a)]}
            for name,a,b in [('caller',Parent.CLOCK_SUCCESS,0x100701ac4),('sentinel_initializers',0x100e1e718,0x100e1e738),
                             ('cleanup_and_epilogue',COMMON,0x100e250bc)]]

def obligations():
    f,encoded,payload,raw,lr=z3.BitVecs('nf_frame64 nf_encoded64 nf_payload64 nf_raw64 nf_return64',64);qs=[]
    def prove(label,bad,extra=None):
        s=z3.Solver();s.set(timeout=30000);assert s.check()==z3.sat;s.add(z3.simplify(bad));assert s.check()==z3.unsat,label
        qs.append({'label':label,'query':s.to_smt2(),'premises_nonvacuous':True,'result':'unsat',**(extra or {})})
    def gate(label,v,name,value):
        ix=v.read(name);zero=z3.simplify(z3.substitute(ix,(value,z3.BitVecVal(0,64))));other=z3.simplify(z3.substitute(ix,(value,z3.BitVecVal(1,64))))
        assert z3.is_bv_value(zero) and z3.is_bv_value(other) and zero.as_long()!=other.as_long()
        prove(label,ix!=z3.If(value==0,zero,other),
              {'zero_index':hex(zero.as_long()),'nonzero_index':hex(other.as_long()),
               'zero_slot':hex(Parent.DISPATCH+8*zero.as_long()),'nonzero_slot':hex(Parent.DISPATCH+8*other.as_long()),
               'zero_target':hex(qword(Parent.DISPATCH+8*zero.as_long())),
               'nonzero_target':hex(qword(Parent.DISPATCH+8*other.as_long()))})
    v=Algebra();v.seed('sp',f);v.run_block(0x100e1e68c,0x100e1e69c)
    constant=v.read('x15');v.run_block(0x100e1e718,0x100e1e730)
    prove('constant_and_stores_initialize_two_encoded_null_sentinels',z3.Or(constant!=SENTINELS[0],cell(v,f+0x160,8)!=SENTINELS[0],cell(v,f+0x1c0,8)!=SENTINELS[1]))
    v=Algebra();v.seed('sp',f);v.seed('w25',0x1f8);mem(v,f+0x160,8,raw+SENTINELS[0]);v.run_block(COMMON,0x100e24d48)
    gate('first_record_present_iff_decoded_pointer_nonzero',v,'w9',raw)
    class Payload(Algebra):
        def load(self,a,n):
            if self.pc in [0x100e24d9c,0x100e24f78]:assert n==8;self.payload_address=a;return payload
            return super().load(a,n)
    v=Payload();v.seed('w8',0x841);v.seed('w11',0xde109bd7);v.seed('x20',encoded);v.run_block(0x100e24d60,0x100e24dc0)
    prove('first_record_decode_is_subtract_bias',z3.Or(v.payload_address!=encoded-SENTINELS[0],v.read('x19')!=encoded-SENTINELS[0]))
    gate('first_payload_present_iff_u64_field_nonzero',v,'w8',payload)
    v=Algebra();v.seed('x19',raw);v.seed('x20',raw+SENTINELS[0]);v.run_block(0x100e24e5c,0x100e24ea4)
    prove('first_accessed_header_rewrite_is_exact_16_bytes',z3.Or(cell(v,raw,8)!=0,cell(v,raw+8,4)!=0x374e946a,cell(v,raw+12,4)!=0))
    v=Algebra();v.seed('sp',f);v.seed('w22',0x296);mem(v,f+0x1c0,8,raw+SENTINELS[1]);v.run_block(0x100e24ef4,0x100e24f38)
    gate('second_record_present_iff_decoded_pointer_nonzero',v,'w9',raw)
    v=Payload();v.seed('x19',encoded);v.seed('w8',0xb26);v.run_block(0x100e24f5c,0x100e24f88)
    prove('second_record_decode_is_subtract_bias',z3.Or(v.payload_address!=encoded-SENTINELS[1],v.read('x24')!=encoded-SENTINELS[1]))
    gate('second_payload_present_iff_u64_field_nonzero',v,'w8',payload)
    v=Algebra();v.seed('x24',raw);v.seed('x19',raw+SENTINELS[1]);v.seed('w21',0x655b53a7);v.run_block(0x100e24ff4,0x100e25030)
    prove('second_accessed_header_rewrite_is_exact_16_bytes',z3.Or(cell(v,raw,8)!=0,cell(v,raw+8,4)!=0x1d6d1efe,cell(v,raw+12,4)!=0x655b53a7))
    v=Algebra();v.seed('x28',lr);v.run_block(0x100e25098,0x100e2509c)
    prove('epilogue_forwards_full_saved_result64',v.read('x0')!=lr)
    status=z3.BitVec('nf_import_status32',32);arbitrary=z3.BitVec('nf_prior_result64',64)
    parent=json.loads(read(ROOT/(Reg.P+'_checks.json')))
    success=next(c for c in parent['cases'] if c['configuration'].get('outcome')=='success');bad=[]
    ends=dict(zip(Reg.REG+Reg.CHECK,[0x100e1feb4,0x100e1ff80,0x100e20078,0x100e20294,0x100e201e8,0x100e2011c]))
    for site,end in ends.items():
        row=next(r for r in success['intervals'] if r['boundary']['pc']==hex(site));v=Algebra()
        for j,value in enumerate(row['boundary']['registers31']):v.seed('x'+str(j),int(value,16))
        for j in range(1,18):v.seed('x'+str(j),z3.BitVec('nf_volatile_'+str(j),64))
        v.seed('sp',f);mem(v,f+0x148,8,Parent.DISPATCH);v.seed('x0',z3.ZeroExt(32,status));v.seed('x28',arbitrary)
        v.run_block(site+4,end);bad.extend([v.read('x28')!=0,v.read('w25')!=0x1f8])
    prove('all_six_import_return_gates_clear_result_and_share_cleanup_phase',z3.Or(*bad))
    v=Algebra();v.seed('w19',0x79ea);v.seed('w21',0x1cb7);v.seed('w0',status);v.run_block(Parent.RETURN,0x100701ab8)
    transformed=status-((status<<1)&0x167b8ca2)
    prove('actual_caller_zero_only_selector_and_encoded_status',z3.Or(v.read('w8')!=z3.If(status==0,z3.BitVecVal(0x79ea,32),z3.BitVecVal(0x7a10,32)),
          v.read('w28')!=transformed+0x8b3dc651,(transformed==0)!=(status==0)))
    return qs

def build():
    cases=[probe(c) for c in configurations()];counts=Counter();pool={};used=set()
    for c in cases:
        counts['registration_return_premises']+=len(c['registration_return_premises']);counts['free_return_premises']+=len(c['free_return_premises'])
        for row in intervals(c):
            counts.update({'intervals':1,'source_visits':len(row['source_visits']),'read_events':len(row['source_reads']),
                           'write_events':len(row['source_writes']),'logical_edges':len(row['logical_edges'])})
            for v in row['source_visits']:
                a=int(v['pc'],16);i=next(CS.disasm(IMAGE.read(a,4),a));pool[hex(a)]={'pc':hex(a),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
            for x in row['source_reads']:
                a=int(x['address'],16)
                if x['size_bytes']==8 and a in FIXUPS:used.add(a)
    rules=banks();used.update(int(r['slot'],16) for r in rules);proofs=obligations()
    used.update(int(q[k],16) for q in proofs for k in ['zero_slot','nonzero_slot'] if k in q)
    deps=['recover_daemon_notification_registration.py','audit_daemon_notification_registration.py','daemon_notification_registration_checks.json',
          'daemon_notification_registration_audit.json','recover_daemon_environment_outputs.py','daemon_receive_tools.py','daemon_receive_fixups.txt']
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n) for n in deps},
            'source_regions':source(),'source_pool':pool,'source_fixups':Parent.fixups(used),'bank_rules':rules,
            'cases':cases,'source_proofs':proofs,'verified_counts':{'cases':len(cases),**counts},
            'entry_premises':'Original clock-success caller reaches helper root prefix continuously. Registration begins at a separate cut carrying source-compatible roots and source-initialized null sentinels; no provider-output/control/lifetime join is added. Nonempty cleanup records are additional separate entry premises.',
            'free_premises':'Free imports stop before execution. Declared void returns preserve private backing for analysis, change caller-saved registers/NZCV and leave native ownership unknown. No subsequent source access to retired record spans is permitted.',
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
