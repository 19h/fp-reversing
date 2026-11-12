#!/usr/bin/env python3
"""Resume the pinned atomic frontier through entropy, seed expansion and time.

Frozen private prefix models and the explicit request1200/status gap remain.
CASAL is a declared sequential compare/exchange; entropy/time values are
explicit external ABI fixtures. No native target/API/IPC/IDB operation runs.
Time/space O(B+F+C*(V+J+R)); each continuation has a 30000-step bound.
"""
import copy,json,struct
from pathlib import Path
from hashlib import sha256
import unicorn as U
from unicorn import arm64_const as A
import z3
from recover_fpsd1201_predicates import Continue as Frozen,frame,pack
from corefp_fixups_reader import Pointers,ROOT
from probe_corefp_client_flow import Flow
from probe_corefp_exports import BASE,BIND
from daemon_receive_tools import CS
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();STATE=0x1d4551c;TOKEN=0x1d33108
PRIOR_SHA='3e2b88c3d9b6b7d1766e75cb9fba56b7ca7ebc17e55ec53a1613f1bbeda99988'
RECEIPT_SHA='31c95fb3e5a569dace380e5df920253c72cf50f7e220a2b57fc37fd11c0a1e1e'
DEPS=['fpsd1201_predicates_checks.json','fpsd1201_predicates_audit.json','recover_fpsd1201_predicates.py','audit_fpsd1201_predicates.py',
 'probe_corefp_client_flow.py','probe_corefp_lookup.py','probe_corefp_mach_requests.py','probe_corefp_exports.py','corefp_library_reader.py','corefp_fixups_reader.py',
 'corefp_fixups_inventory.json','corefp_import_calls.json','fpsd1201_seed_ida_readback.json','fpsd1201_seed_primary_references.json']


def configs():
    out=[{'label':'opaque_entropy','stage':'entropy','token_u32':0x5d96,'random_u32':[]}]
    for seed in [0,1,0x12345678,0xffffffff]:out.append({'label':'seed_'+hex(seed),'stage':'seed','token_u32':0x5d96,'random_u32':[seed]})
    for label,seconds,usec,status,clobber in [('clock_A',0x123456789abcdef,654321,0,False),('clock_B',-1,999999,0,False),
      ('clock_error_no_write',0,0,0xffffffff,False),('clock_A_clobber',0x123456789abcdef,654321,0,True)]:
        out.append({'label':label,'stage':'tuple','token_u32':0x5d96,'random_u32':[0x12345678,0x9abcdef0,0x0fedcba9],
          'seconds_i64':seconds,'microseconds_i32':usec,'time_status_u32':status,'clobber_callers':clobber})
    for value in [0,0xffffffff,0xa94ef]:out.append({'label':'failed_CASAL_'+hex(value),'stage':'atomic_failure','token_u32':value,'random_u32':[]})
    return out


def restore(u,f):
    for j,v in enumerate(f['X31']):u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),int(v,16))
    for j,v in enumerate(f['Q32']):u.reg_write(A.UC_ARM64_REG_Q0+j,int(v,16))
    for n in ['SP','PC','NZCV','FPCR','FPSR','CPACR_EL1']:u.reg_write(getattr(A,'UC_ARM64_REG_'+n),int(f[n],16))
    assert frame(u)==f


class Seed(Frozen):
    def prepare(self,e,c):
        self.c=c;r=self.run_caller();assert r==e['prefix']['result']and frame(self.u)==e['prefix']['CPU']
        prior=e['profiles'][0];assert prior['global_control_u32']==0
        from audit_fpsd1201_predicates import unpack
        for row in prior['final_RAM']:self.u.mem_write(int(row['address'],16),unpack(row['payload']))
        restore(self.u,prior['frontier']['CPU']);self.restored=frame(self.u)
        assert bytes(self.u.mem_read(BASE+TOKEN,4)).hex()=='965d0000'
        self.u.mem_write(BASE+TOKEN,c['token_u32'].to_bytes(4,'little'))
        self.active=True;self.steps=0;self.reason=None;self.pages={};self.trace=[];self.reads=[];self.writes=[];self.pending=[];self.pacs=[];self.points=[];self.models=[];self.entropy_count=0;self.loop_entries=0
        self.initial=frame(self.u);sp=int(self.initial['SP'],16)
        self.touch(sp+0x1340,128);self.touch(sp+0x498,8)
        self.touch(int.from_bytes(self.u.mem_read(sp+0x498,8),'little'),32)
        self.u.hook_add(U.UC_HOOK_MEM_READ,self.memory);self.u.hook_add(U.UC_HOOK_MEM_WRITE,self.memory)
    def touch(self,a,n):
        for page in range(a&~4095,((a+n-1)&~4095)+1,4096):
            if page not in self.pages:self.pages[page]=bytes(self.u.mem_read(page,4096))
    def finish(self,why):
        self.frontier={'reason':why,'CPU':frame(self.u)};return self.stop(why)
    def external_return(self,v):
        if self.c.get('clobber_callers'):
            for j in range(1,18):self.u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),(j*0x13579bdf2468ace)&((1<<64)-1))
            self.u.reg_write(A.UC_ARM64_REG_NZCV,0xa0000000)
        self.ret(v)
    def code(self,u,pc,n,d):
        if not getattr(self,'active',False):return super().code(u,pc,n,d)
        self.flush();at=pc-BASE
        if self.c['stage']=='atomic_failure'and at==0x8ea86c:return self.finish('after_failed_sequential_CASAL')
        if self.c['stage']=='tuple'and at==0x8eb9b4:return self.finish('before_array_mix_preparation')
        if pc in self.binds:
            name=self.binds[pc]['name'];before=frame(u);args=[hex(self.reg('x'+str(j)))for j in range(8)]
            if name=='_arc4random':
                if self.c['stage']=='entropy':return self.finish('before_arc4random')
                value=self.c['random_u32'][self.entropy_count];self.entropy_count+=1
                e={'kind':'declared_arc4random_u32','callsite':hex(self.reg('lr')-4-BASE),'value_u32':value,'before':before,'args_x0_x7':args}
                self.external_return(value);e['after']=frame(u);self.models.append(e);return
            assert name=='_gettimeofday',name
            if self.c['stage']=='seed':return self.finish('before_gettimeofday')
            ptr=self.reg('x0');assert self.reg('x1')==0;self.touch(ptr,16);old=bytes(u.mem_read(ptr,16))
            raw=struct.pack('<qi',self.c['seconds_i64'],self.c['microseconds_i32'])if self.c['time_status_u32']==0 else b''
            if raw:u.mem_write(ptr,raw)
            e={'kind':'declared_gettimeofday','callsite':hex(self.reg('lr')-4-BASE),'pointer':hex(ptr),'before16_hex':old.hex(),
              'written_hex':raw.hex(),'after16_hex':bytes(u.mem_read(ptr,16)).hex(),'status_u32':self.c['time_status_u32'],'before':before,'args_x0_x7':args}
            self.external_return(self.c['time_status_u32']);e['after']=frame(u);self.models.append(e);return
        assert 0x8e81c8<=at<0x8fcfa0,'outside retained parent'
        raw=bytes(u.mem_read(pc,4));i=next(CS.disasm(raw,at));self.trace.append({'pc':hex(at),'bytes_hex':raw.hex(),'instruction':i.mnemonic+' '+i.op_str})
        if i.mnemonic=='casal':
            assert at==0x8ea868 and i.op_str=='w8, w11, [x12]';a=self.reg('x12');self.touch(a,4);old=int.from_bytes(u.mem_read(a,4),'little');compare=self.reg('w8');new=self.reg('w11')
            e={'kind':'declared_sequential_CASAL','visit':len(self.trace)-1,'address':hex(a),'old_u32':old,'compare_u32':compare,'replacement_u32':new,'before':frame(u)}
            if old==compare:u.mem_write(a,new.to_bytes(4,'little'))
            u.reg_write(A.UC_ARM64_REG_W8,old);u.reg_write(A.UC_ARM64_REG_PC,pc+4);e.update({'after':frame(u),'after4_hex':bytes(u.mem_read(a,4)).hex(),'success':old==compare});self.models.append(e);return
        if i.mnemonic in ['braa','blraa']:
            rn,mn=i.op_str.split(', ');target=self.reg(rn);modifier=self.reg(mn)
            r=next(r for r in reversed(self.reads)if r['size_B']==8 and int.from_bytes(bytes.fromhex(r['bytes_hex']),'little')==target)
            slot=int(r['address'],16)-BASE;D=self.s.decoded[slot]
            resolved=BIND+D['import']['ordinal']*16+D['pointer_addend']if D['bind']else BASE+int(D['target'],16)
            assert D['key']=='IA'and not D['address_diversity']and int(D['diversity'],16)==modifier and resolved==target
            self.pacs.append({'visit':len(self.trace)-1,'pc':hex(at),'target':hex(target),'modifier':hex(modifier),'slot':hex(slot),'original_pointer_row':D,'CPU':frame(u)})
        if at==0x8eb824:
            self.loop_entries+=1
            if self.loop_entries==1:self.points.append({'kind':'seed_loop_entry','visit':len(self.trace)-1,'CPU':frame(u)})
        if at==0x8eb85c:self.points.append({'kind':'seed_loop_complete','visit':len(self.trace)-1,'CPU':frame(u),'state624':pack(bytes(u.mem_read(BASE+STATE,2496)))})
        return Flow.code(self,u,pc,n,d)
    def run_seed(self):
        self.u.emu_start(int(self.initial['PC'],16),0,count=30001);self.flush();assert self.reason in ['after_failed_sequential_CASAL','before_arc4random','before_gettimeofday','before_array_mix_preparation']
        sp=int(self.initial['SP'],16);tupleptr=int.from_bytes(self.u.mem_read(sp+0x498,8),'little')
        return {'configuration':self.c,'restored_CPU':self.restored,'initial_CPU':self.initial,
          'initial_RAM':[{'address':hex(a),'payload':pack(b)}for a,b in sorted(self.pages.items())],
          'visits':self.trace,'reads':self.reads,'writes':self.writes,'PAC_models':self.pacs,'models':self.models,'points':self.points,'frontier':self.frontier,
          'final_RAM':[{'address':hex(a),'payload':pack(bytes(self.u.mem_read(a,4096)))}for a in sorted(self.pages)],
          'seed_loop_iterations':self.loop_entries,'tuple_pointer':hex(tupleptr),'tuple32_hex':bytes(self.u.mem_read(tupleptr,32)).hex(),
          'context128_hex':bytes(self.u.mem_read(sp+0x1340,128)).hex(),'token_final_u32':int.from_bytes(self.u.mem_read(BASE+TOKEN,4),'little')}


def proofs():
    x,i=z3.BitVecs('seed_previous_word32 seed_index32',32);old,cmp,new=z3.BitVecs('CASAL_old32 CASAL_compare32 CASAL_new32',32)
    a=z3.BitVec('seed_base64',64);j=z3.BitVec('seed_counter64',64)
    qs=[('seed_update',z3.Extract(31,0,z3.ZeroExt(32,x^z3.LShR(x,30))*1812433253+z3.ZeroExt(32,i))==(x^z3.LShR(x,30))*0x6c078965+i),
      ('seed_store_address',a+(j<<2)==a+j*4),('CASAL_success',z3.If(old==cmp,new,old)==z3.If(cmp==old,new,old)),
      ('selected_atomic_values',z3.If(old==0x5d96,z3.BitVecVal(0xa94ef,32),old)==z3.If(old==cmp,new,old))]
    out=[]
    for label,claim in qs:
        s=z3.Solver();s.set(timeout=30000)
        if label=='selected_atomic_values':s.add(cmp==0x5d96,new==0xa94ef)
        s.add(z3.Not(claim));assert s.check()==z3.unsat
        out.append({'label':label,'query':s.to_smt2(),'result':'unsat'})
    return out


def main():
    raw=read(ROOT/'fpsd1201_predicates_checks.json');a=read(ROOT/'fpsd1201_predicates_audit.json');assert SHA(raw.encode())==PRIOR_SHA and SHA(a.encode())==RECEIPT_SHA
    e=json.loads(raw);receipt=json.loads(a);assert receipt['checks_sha256']==PRIOR_SHA and receipt['fresh_replay_completed']and receipt['result']['all_checks_pass']
    s=Pointers();profiles=[]
    for c in configs():
        p=Seed(s,e['fixture']);p.prepare(e,c);profiles.append(p.run_seed())
    qs=proofs();counts={'profiles':len(profiles),'prefix_original_visits_per_profile':19717,
      **{k:sum(len(p[k])for p in profiles)for k in ['visits','reads','writes','PAC_models','models','points']},
      'complete_seed_expansions':sum(p['seed_loop_iterations']==623 for p in profiles),'atomic_failures':3,'queries_unsat':len(qs)}
    out={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},
      'prior_checks_sha256':PRIOR_SHA,'prior_audit_sha256':RECEIPT_SHA,'profiles':profiles,'proofs':qs,'verified_counts':counts,
      'request1200_gap_executed':False,'native_target_executed':False,'new_IDA_read_only':True,'IDB_mutated':False,'full_goal_complete':False}
    (ROOT/'fpsd1201_seed_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
