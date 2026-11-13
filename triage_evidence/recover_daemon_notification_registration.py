#!/usr/bin/env python3
"""Original daemon notification registration, readiness and exit-token consumers.

Root-prefix, post-provider cut and exit callback are separate source entries.
Imports stop before execution; explicit ABI return/output fixtures join local
intervals only. O(cases*(visits+effects)+source+queries) time/space excluding
solver cost, 30 s/query. No native API/IPC, allocation/free or PAC executes.
"""
import itertools,json,struct
from collections import Counter
import z3
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,selected,qword
from verify_daemon_reader_record_payloads_publication import read,sha
from lskd_values_symbolic import mem,cell,resize
from recover_daemon_return_bank_origins import Algebra
import recover_daemon_environment_outputs as Parent

P='daemon_notification_registration';START=0x100e1fd98;ROOT_STOP=0x100e1e97c
EXIT=0x100df2f60;TAIL=0x100df3218
NAMES=['com.apple.adid.midchangedV1','com.apple.adid.midchangedV1.5','com.apple.adid.midchangedV3']
TOKENS=[0x1010ca2c0,0x1010ca31c,0x1010ca324]
REG=[0x100e1fe88,0x100e1ff5c,0x100e20054]
CHECK=[0x100e20270,0x100e201c0,0x100e200f4]
ATEXIT=0x100e20318;CLOCK=0x100e203a8

class Run(Parent.Run):
    def __init__(self,c):
        pcfg={'placement':c['placement'],'pattern':c['pattern'],'cache_mode':'miss','flag8':c['flag8'],
              'controllers':c['controllers'],'argument64':0xfffffffffffffffe,'null_mask':0,'kind':'direct'}
        super().__init__(pcfg);self.cfg=c;self.caller_configuration=pcfg;self.cut_stops=set();self.mode='root'
        for j,at in enumerate(TOKENS):self.image_fixture(at,(0x7001+j).to_bytes(4,'little'),'declared_initial_token')
        self.image_fixture(0x1010c5498,c['controllers'][0].to_bytes(8,'little'),'declared_exit_controller')

    def image_fixture(self,a,raw,role):
        self.ensure(a,len(raw));self.u.mem_write(a,raw);self.image_fixtures.append({'address':hex(a),'bytes_hex':raw.hex(),'provenance':role})

    def code(self,u,a,n,d):
        if a in self.cut_stops:
            self.flush();return self.stop('before_explicit_source_cut')
        return super().code(u,a,n,d)

    def interval(self,start,role):
        self.visits=[];self.reads=[];self.writes=[];self.pending=[];self.edges=[];self.calls=[];self.frames=[];self.checkpoints=[]
        self.reason=None;self.boundary=None;self.seq=0
        entry=[hex(self.reg(j)) for j in range(31)];sp=hex(self.u.reg_read(ar.UC_ARM64_REG_SP));nz=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
        initial=list(self.initial);image=list(self.image_fixtures)
        self.ensure(start);self.u.emu_start(start,0,count=10000);self.flush();assert self.reason
        out={'role':role,'configuration':self.cfg,'entry_PC':hex(start),'caller_SP':sp,'entry_registers31':entry,'entry_NZCV':nz,
             'initial_private_fixtures':initial,'initial_image_fixtures':image,'source_visits':self.visits,
             'source_frames':self.frames,'source_reads':self.reads,'source_writes':self.writes,'logical_edges':self.edges,
             'boundary':self.boundary,'boundary_NZCV':hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV)),
             'native_target_executed':False}
        for w in self.writes:
            f={'address':w['address'],'bytes_hex':w['after_hex'],'provenance':'preceding_source_interval_effect'}
            (self.initial if Parent.Base.P<=int(w['address'],16)<Parent.Base.P+Parent.Base.SIZE else self.image_fixtures).append(f)
        return out

    def imported_return(self,row,status,output=None):
        pc=int(row['boundary']['pc'],16);assert row['boundary']['kind']=='before_unmodeled_import_call'
        event={'call_site':hex(pc),'symbol':row['boundary']['detail']['symbol'],'return32':hex(status),
               'ABI_return_and_output_premise':True,'native_API_executed':False}
        if output is not None:
            address,raw=output;event['output']={'address':hex(address),'bytes_hex':raw.hex()}
            if Parent.Base.P<=address<Parent.Base.P+Parent.Base.SIZE:self.fixture(address,raw)
            else:self.image_fixture(address,raw,'declared_API_output_premise')
        for j in range(1,18):self.set(j,((0xabcdef0102030405*(j+1))^self.cfg['pattern'])&((1<<64)-1))
        self.set(0,status);self.set(30,pc+4)
        self.u.reg_write(ar.UC_ARM64_REG_NZCV,0xa0000000 if self.cfg['pattern']==0x35 else 0x50000000)
        event['continuation_PC']=hex(pc+4)
        event['return_registers31']=[hex(self.reg(j)) for j in range(31)]
        event['return_NZCV']=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
        return event

def probe(c):
    v=Run(c);rows=[];events=[]
    if c['kind']=='registration':
        v.cut_stops={ROOT_STOP};prefix=v.interval(Parent.ENTRY,'separate_original_root_prefix')
        assert prefix['boundary']['pc']==hex(ROOT_STOP)
        f=v.C-0x4a0;v.fixture(f+0x78,struct.pack('<Q',Parent.Base.P+0x3000))
        v.cut_stops={0x100e24d08};start=START
        while True:
            row=v.interval(start,'post_provider_registration_cut');rows.append(row);pc=int(row['boundary']['pc'],16)
            if pc==0x100e24d08:break
            assert row['boundary']['kind']=='before_unmodeled_import_call',row['boundary']
            if pc==CLOCK:break
            symbol=row['boundary']['detail']['symbol'];output=None;status=0
            if pc in REG:
                j=REG.index(pc);assert symbol=='libSystem/_notify_register_check'
                if c['outcome']=='register_fail'+str(j):status=c['failure_status32']
                else:output=(TOKENS[j],struct.pack('<I',0x7101+j))
            elif pc in CHECK:
                j=CHECK.index(pc);assert symbol=='libSystem/_notify_check'
                if c['outcome']=='check_fail'+str(j):status=c['failure_status32']
                else:output=(int(row['boundary']['registers31'][1],16),struct.pack('<I',c['changed32']))
            else:
                assert pc==ATEXIT and symbol=='libSystem/_atexit';status=c['atexit_status32']
            event=v.imported_return(row,status,output);events.append(event);start=pc+4
        return {'configuration':c,'root_prefix':prefix,'intervals':rows,'API_return_premises':events,
                'final_ready8':v.u.mem_read(Parent.FLAG,1)[0],
                'final_tokens32':[int.from_bytes(v.u.mem_read(at,4),'little') for at in TOKENS],
                'native_target_executed':False,'uninterrupted_provider_join_established':False}
    assert c['kind']=='exit';v.cut_stops={TAIL};v.u.reg_write(ar.UC_ARM64_REG_SP,v.C)
    for j in range(31):v.set(j,((j+1)*0x0102030405060708)&((1<<64)-1))
    v.set(30,Parent.RETURN);start=EXIT
    while True:
        row=v.interval(start,'separate_exit_callback');rows.append(row);pc=int(row['boundary']['pc'],16)
        if pc==TAIL:break
        assert pc in [0x100df3114,0x100df318c] and row['boundary']['detail']['symbol']=='libSystem/_notify_cancel'
        event=v.imported_return(row,c['failure_status32']);events.append(event);start=pc+4
    return {'configuration':c,'intervals':rows,'API_return_premises':events,'native_target_executed':False,
            'native_exit_or_registration_lifetime_join_established':False}

def configurations():
    outcomes=['success','atexit_nonzero']+['register_fail'+str(j) for j in range(3)]+['check_fail'+str(j) for j in range(3)]
    for place,controllers,flag in itertools.product([0,0x100],[(0,0),(0xffffffff,0x87654321)],[0,1,2,3]):
        for outcome in (['already_ready'] if flag&1 else outcomes):
            yield {'kind':'registration','placement':place,'pattern':0x35 if place==0 else 0xca,'controllers':list(controllers),
                   'flag8':flag,'outcome':outcome,'failure_status32':0xdeadbeef if place else 1,
                   'changed32':0xffffffff if place else 0,'atexit_status32':0xffffffff if outcome=='atexit_nonzero' else 0}
    for place,controllers,status in itertools.product([0,0x100],[(0,0),(0xffffffff,0x87654321)],[0,0xffffffff]):
        yield {'kind':'exit','placement':place,'pattern':0x35 if place==0 else 0xca,'controllers':list(controllers),
               'flag8':1,'failure_status32':status}

def banks():
    rows=[]
    specs=[('registration_V1',0x1010331e0,0x101033600,0xba,0xaa2,Parent.DISPATCH,0),
           ('name_V1',0x101033700,0x101033a30,0x1d,-0x10,Parent.POOL,-12),
           ('registration_V1_5',0x101032d80,0x101032fe0,0x8b,0xb1a,Parent.DISPATCH,0),
           ('name_V1_5',0x101033930,0x101032e80,0x4a,-0x4f,Parent.POOL,0),
           ('registration_V3',0x1010330e0,0x101033500,0xa0,0xa93,Parent.DISPATCH,0),
           ('name_V3',0x101033700,0x101033a30,0x2f,-0x2b,Parent.POOL,-4),
           ('baseline_V1',0x101033930,0x101032e80,0x4a,0xaea,Parent.DISPATCH,0),
           ('baseline_V1_5',0x101033700,0x101033a30,0x7b,0xa80,Parent.DISPATCH,0),
           ('baseline_V3',0x1010332e0,0x101033800,0x3e,0xaad,Parent.DISPATCH,0),
           ('atexit',0x1010332e0,0x101033800,0x44,0xb09,Parent.DISPATCH,0),
           ('following_clock',0x101032d80,0x101032fe0,0x8b,0xb44,Parent.DISPATCH,0),
           ('exit_controller0',0x1010331e0,0x101033600,0xba,-0x7c,Parent.POOL,0),
           ('exit_controller1',qword(Parent.POOL+0x40)-8,qword(Parent.POOL+0x38)-12,0x8d,0,Parent.POOL,0),
           ('exit_dispatch',0x101032d80,0x101032fe0,0x8b,-7,Parent.POOL,-8),
           ('exit_token_V1',qword(Parent.POOL+0x18)-8,qword(Parent.POOL+0x170)-4,0x8b,-0xa,Parent.POOL,0),
           ('exit_cancel_V1',qword(Parent.POOL+0x18)-8,qword(Parent.POOL+0x170)-4,0x8b,0xb43,Parent.DISPATCH,0),
           ('exit_token_V1_5',qword(Parent.POOL+0x188),qword(Parent.POOL+0x150),0xfb,6,Parent.POOL,0),
           ('exit_cancel_V1_5',qword(Parent.POOL+0x100)-12,qword(Parent.POOL+0x148)-8,8,0xa61,Parent.DISPATCH,0),
           ('exit_token_V3',qword(Parent.POOL+0x18)-8,qword(Parent.POOL+0x170)-4,8,-0x86,Parent.POOL,0),
           ('exit_cancel_V3',qword(Parent.POOL+0x40)-8,qword(Parent.POOL+0x38)-12,0x8d,0xb34,Parent.DISPATCH,0)]
    for name,l,r,key,add,base,bias in specs:
        row=selected(l,r,key,add,base=base,bias=bias);left=IMAGE.read(l,256);right=IMAGE.read(r,256)
        row.update(name=name,left256_hex=left.hex(),right256_hex=right.hex(),XOR_outputs_256=[j^right[left[j]^key] for j in range(256)])
        assert len(set(row['XOR_outputs_256']))==1;rows.append(row)
    return rows

def source():
    return [{'name':name,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
                             for i in CS.disasm(IMAGE.read(a,b-a),a)]}
            for name,a,b in [('root_prefix',Parent.ENTRY,ROOT_STOP),('registration_and_ready',START,CLOCK+4),
                             ('exit_callback',EXIT,0x100df322c)]]

def obligations(cases):
    result=z3.BitVec('notification_status32',32);flag=z3.BitVec('notification_ready8',8);f=z3.BitVec('notification_frame64',64)
    qs=[]
    def prove(label,bad,extra=None):
        q=z3.Solver();q.set(timeout=30000);assert q.check()==z3.sat;q.add(z3.simplify(bad));assert q.check()==z3.unsat,label
        qs.append({'label':label,'query':q.to_smt2(),'premises_nonvacuous':True,'result':'unsat',**(extra or {})})
    class Flag(Algebra):
        def load(self,a,n):
            if self.pc==0x100e1fda4:assert n==1;return flag
            return super().load(a,n)
    v=Flag();v.seed('sp',f);mem(v,f+0x80,8,Parent.FLAG);v.run_block(START,0x100e1fdbc)
    prove('ready_selection_uses_only_bit0',v.read('w8')!=z3.If(flag&1!=0,z3.BitVecVal(0xd3,32),z3.BitVecVal(0xdf,32)),
          {'ready_target':hex(qword(Parent.DISPATCH+8*0xd3)),'not_ready_target':hex(qword(Parent.DISPATCH+8*0xdf))})
    success=next(c for c in cases if c['configuration']['kind']=='registration' and c['configuration']['outcome']=='success')
    loads={REG[0]:0x100e1feb4,REG[1]:0x100e1ff80,REG[2]:0x100e20078,
           CHECK[0]:0x100e20294,CHECK[1]:0x100e201e8,CHECK[2]:0x100e2011c}
    for site,end in loads.items():
        row=next(r for r in success['intervals'] if r['boundary']['pc']==hex(site));regs=row['boundary']['registers31'];v=Algebra()
        for j,value in enumerate(regs):v.seed('x'+str(j),int(value,16))
        for j in range(1,18):v.seed('x'+str(j),z3.BitVec('notification_volatile_'+str(j),64))
        v.seed('x0',z3.ZeroExt(32,result));v.seed('sp',f);mem(v,f+0x148,8,Parent.DISPATCH)
        v.run_block(site+4,end);ix=v.read('w8');zero=z3.simplify(z3.substitute(ix,(result,z3.BitVecVal(0,32))));other=z3.simplify(z3.substitute(ix,(result,z3.BitVecVal(1,32))))
        assert z3.is_bv_value(zero) and z3.is_bv_value(other) and zero.as_long()!=other.as_long()
        zero_slot=Parent.DISPATCH+8*zero.as_long();other_slot=Parent.DISPATCH+8*other.as_long()
        assert qword(other_slot)==0x100e24d08
        prove('zero_only_status_gate_'+hex(site),ix!=z3.If(result==0,zero,other),
              {'call_site':hex(site),'zero_index':hex(zero.as_long()),'nonzero_index':hex(other.as_long()),
               'zero_slot':hex(zero_slot),'nonzero_slot':hex(other_slot),'zero_target':hex(qword(zero_slot)),
               'nonzero_target':hex(qword(other_slot))})
    v=Algebra();v.seed('sp',f);v.seed('x0',z3.ZeroExt(32,result));mem(v,f+0x80,8,Parent.FLAG);mem(v,f+0x148,8,Parent.DISPATCH)
    v.run_block(0x100e2031c,0x100e2032c)
    prove('ready_byte_is_one_independently_of_atexit_result',cell(v,z3.BitVecVal(Parent.FLAG,64),1)!=1)
    lr=z3.BitVec('notification_return64',64);v=Algebra();v.seed('x30',lr);v.run_block(TAIL,TAIL+4)
    prove('exit_tail_guard_is_return_bits62_XOR61',z3.Extract(62,62,v.read('x16'))!=(z3.Extract(62,62,lr)^z3.Extract(61,61,lr)))
    return qs

def build():
    cases=[probe(c) for c in configurations()];counts=Counter();pool={};used=set()
    for c in cases:
        for row in ([c['root_prefix']] if 'root_prefix'in c else [])+c['intervals']:
            counts.update({'intervals':1,'source_visits':len(row['source_visits']),'read_events':len(row['source_reads']),
                           'write_events':len(row['source_writes']),'logical_edges':len(row['logical_edges'])})
            for v in row['source_visits']:
                a=int(v['pc'],16);i=next(CS.disasm(IMAGE.read(a,4),a));pool[hex(a)]={'pc':hex(a),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
            for x in row['source_reads']:
                a=int(x['address'],16)
                if x['size_bytes']==8 and a in FIXUPS:used.add(a)
        counts['API_return_premises']+=len(c['API_return_premises'])
    rules=banks();used.update(int(r['slot'],16) for r in rules);proofs=obligations(cases)
    used.update(int(q[k],16) for q in proofs for k in ['zero_slot','nonzero_slot'] if k in q)
    names=[{'name':name,'address':r['target'],'bytes_hex':IMAGE.read(int(r['target'],16),len(name)+1).hex()}
           for name,r in zip(NAMES,[r for r in rules if r['name'].startswith('name_')])]
    assert all(bytes.fromhex(r['bytes_hex'])==r['name'].encode()+b'\0' for r in names)
    deps=['recover_daemon_environment_outputs.py','audit_daemon_environment_outputs.py','daemon_environment_outputs_checks.json',
          'daemon_environment_outputs_audit.json','daemon_receive_tools.py','daemon_receive_fixups.txt','probe_daemon_descriptor_producers.py']
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n) for n in deps},
            'source_regions':source(),'source_pool':pool,'source_fixups':Parent.fixups(used),'bank_rules':rules,'notification_names':names,
            'cases':cases,'source_proofs':proofs,'verified_counts':{'cases':len(cases),**counts},
            'entry_premises':'Root prefix and post-provider registration cut are separate entries. Only source-compatible roots are carried; provider success, initialized MID/OTP outputs and uninterrupted lifetime are not established. Clock pointer is a declared private fixture. Exit callback is a separate entry, not observed native exit.',
            'return_premises':'Each import stops before its instruction. Listed status/output and caller-saved register/NZCV fixtures begin a separate local continuation; no imported implementation executes. Failure output is preserved by explicit fixture choice only.',
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
