#!/usr/bin/env python3
"""Source-initialized parent fragments and two pure record predicates.

The frozen private caller prefix stops before request1200. A declared PC-only
gap enters its later join without supplying reply bytes, statuses or results.
Fresh zero/nonzero global controls stop before atomic/uninitialized-pointer
frontiers. No target/API/IPC/IDB operation executes. O(B+F+C*(V+J+R)) time
and space, bounded 30000 instructions per fragment; SMT costs are separate.
"""
import base64,copy,json,struct,zlib
from pathlib import Path
from hashlib import sha256
from collections import Counter
import unicorn as U
from unicorn import arm64_const as A
import z3
import corefp_library_reader as L
L.SOURCE=Path(__file__).resolve().parent.parent/'CoreFP'
from corefp_fixups_reader import Pointers,ROOT,THIN_SHA
from probe_corefp_client_flow import Flow
from probe_corefp_exports import BASE
from daemon_receive_tools import CS
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest()
DEPS=['probe_corefp_client_flow.py','probe_corefp_lookup.py','probe_corefp_mach_requests.py','probe_corefp_exports.py',
 'corefp_library_reader.py','corefp_fixups_reader.py','corefp_fixups_inventory.json','corefp_import_calls.json',
 'corefp_client_flow_profiles.json','fpsd1201_caller_ida_readback.json']
RANGES=[(0x8e81c8,0x8fcfa0),(0x274ed0,0x274f74),(0x1abbe0,0x1abc70)]


def pack(b):return {'size_bytes':len(b),'sha256':SHA(b),'zlib_base64':base64.b64encode(zlib.compress(b,9)).decode()}


def frame(u):
    return {'X31':[hex(u.reg_read(getattr(A,'UC_ARM64_REG_X'+str(j))))for j in range(31)],
      **{n:hex(u.reg_read(getattr(A,'UC_ARM64_REG_'+n)))for n in ['SP','PC','NZCV','FPCR','FPSR','CPACR_EL1']},
      'Q32':[hex(u.reg_read(A.UC_ARM64_REG_Q0+j))for j in range(32)]}


class Prefix(Flow):
    def code(self,u,pc,n,d):
        if pc==BASE+0x8ea14c:return self.stop('before_original_request1200_call')
        return super().code(u,pc,n,d)


class Continue(Prefix):
    def code(self,u,pc,n,d):
        if not getattr(self,'active',False):return super().code(u,pc,n,d)
        self.flush()
        at=pc-BASE
        if at in [0x8ea868,0x8ea3b4]:
            self.frontier={'pc':hex(at),'instruction':next(CS.disasm(bytes(u.mem_read(pc,4)),at)).mnemonic,
              'CPU':frame(u),'reason':'before_atomic'if at==0x8ea868 else'before_uninitialized_global_pointer_read'}
            return self.stop(self.frontier['reason'])
        assert any(lo<=at<hi for lo,hi in RANGES),'unretained edge'
        raw=bytes(u.mem_read(pc,4));i=next(CS.disasm(raw,at))
        self.trace.append({'pc':hex(at),'bytes_hex':raw.hex(),'instruction':i.mnemonic+' '+i.op_str})
        if i.mnemonic in ['braa','blraa']:
            rn,mn=i.op_str.split(', ');target=self.reg(rn);modifier=self.reg(mn)
            r=next(r for r in reversed(self.reads)if r['size_B']==8 and int.from_bytes(bytes.fromhex(r['bytes_hex']),'little')==target)
            slot=int(r['address'],16)-BASE;D=self.s.decoded[slot]
            assert D['key']=='IA'and not D['address_diversity']and int(D['diversity'],16)==modifier and BASE+int(D['target'],16)==target
            self.pacs.append({'visit':len(self.trace)-1,'pc':hex(at),'target':hex(target-BASE),'modifier':hex(modifier),
              'slot':hex(slot),'original_pointer_row':D,'CPU':frame(u)})
        if at in [0x274ed0,0x1abbe0,0x8ea7a8,0x8ed05c]:
            p=self.reg('x0');self.points.append({'visit':len(self.trace)-1,'pc':hex(at),'CPU':frame(u),
              'record_pointer':hex(p),'record44_hex':bytes(u.mem_read(p,44)).hex()})
        return Flow.code(self,u,pc,n,d)
    def memory(self,u,access,a,n,v,d):
        if not getattr(self,'active',False):return
        for page in range(a&~4095,((a+n-1)&~4095)+1,4096):
            if page not in self.pages:self.pages[page]=bytes(u.mem_read(page,4096))
        if access==U.UC_MEM_READ:
            self.reads.append({'visit':len(self.trace)-1,'address':hex(a),'size_B':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
        else:
            e={'visit':len(self.trace)-1,'address':hex(a),'size_B':n,'before_hex':bytes(u.mem_read(a,n)).hex()}
            self.writes.append(e);self.pending.append(e)
    def flush(self):
        for e in self.pending:e['after_hex']=bytes(self.u.mem_read(int(e['address'],16),e['size_B'])).hex()
        self.pending=[]
    def run_fragment(self,flag):
        self.active=True;self.steps=0;self.reason=None;self.pages={};self.trace=[];self.reads=[];self.writes=[];self.pending=[];self.pacs=[];self.points=[]
        a=BASE+0x1d45f6c;before=bytes(self.u.mem_read(a,4)).hex();self.u.mem_write(a,flag.to_bytes(4,'little'))
        self.u.reg_write(A.UC_ARM64_REG_PC,BASE+0x8ea164);initial=frame(self.u)
        self.u.hook_add(U.UC_HOOK_MEM_READ,self.memory);self.u.hook_add(U.UC_HOOK_MEM_WRITE,self.memory)
        self.u.emu_start(BASE+0x8ea164,0,count=30001);self.flush();assert self.reason in ['before_atomic','before_uninitialized_global_pointer_read']
        sp=int(initial['SP'],16);fp=int(initial['X31'][29],16);P=int(initial['X31'][20],16);C=sp+0x1340
        return {'global_control_u32':flag,'control':{'address':hex(a),'before_hex':before,'after_hex':flag.to_bytes(4,'little').hex()},
          'initial_CPU':initial,'initial_RAM':[{'address':hex(a),'payload':pack(b)}for a,b in sorted(self.pages.items())],
          'visits':self.trace,'reads':self.reads,'writes':self.writes,'PAC_models':self.pacs,'record_points':self.points,'frontier':self.frontier,
          'final_RAM':[{'address':hex(a),'payload':pack(bytes(self.u.mem_read(a,4096)))}for a in sorted(self.pages)],
          'owner':hex(P),'context':hex(C),'context128_hex':bytes(self.u.mem_read(C,128)).hex(),
          'SP_1f0_hex':bytes(self.u.mem_read(sp+0x1f0,8)).hex(),'record44_hex':bytes(self.u.mem_read(fp-0xb8,44)).hex(),
          'request1200_gap_executed':False,'native_effects':False}


def proofs():
    p=z3.BitVec('predicate_record_address64',64);A0=z3.BitVecVal(0x83d2a2b8ac4eec68,64);B=~A0
    w=z3.BitVec('predicate_word32',32);f=z3.BitVec('predicate_flag32',32);x,y,h=z3.BitVecs('predicate_x64 predicate_y64 predicate_h64',64)
    mixed=(p|A0)-(p|B)+B
    claims=[('leaf274_pointer_mixer',mixed==(p^A0)),
      ('leaf1ab_pointer_mixer',((~p&~z3.BitVecVal(0x43e21bde5aac752d,64))|(p&0x43e21bde5aac752d))==~(p^0x43e21bde5aac752d)),
      ('leaf274_even_equality',(((x+h)-h)==((y-h)+h))==(x==y)),
      ('leaf1ab_even_equality',(x+h==y+h)==(x==y)),
      ('zero_control_dispatch',z3.If(f==0,(w^(w^0x21c5)),((w-8)^(w^0x21c5)))==z3.If(f==0,z3.BitVecVal(0x21c5,32),((w-8)^w^0x21c5))),
      ('selected_dispatch_constants',z3.If(f==0,z3.BitVecVal(0xa3efbea0,32),z3.BitVecVal(0xa3efbea0-8,32))^(z3.BitVecVal(0xa3efbea0,32)^0x21c5)==z3.If(f==0,z3.BitVecVal(0x21c5,32),z3.BitVecVal(0x21fd,32)))]
    out=[]
    for label,claim in claims:
        s=z3.Solver();s.set(timeout=30000);s.add(z3.Not(claim));assert s.check()==z3.unsat,label
        out.append({'label':label,'query':s.to_smt2(),'result':'unsat'})
    s=z3.Solver();s.add(z3.UGT(x,y),z3.Not(z3.UGT(x+h,y+h)));assert s.check()==z3.sat
    return out,{'query':s.to_smt2(),'result':'sat','counterexample':{str(v):hex(s.model().eval(v).as_long())for v in [x,y,h]},'scope':'unsigned ordering is not invariant under modular address-key addition'}


def main():
    s=Pointers();f=next(p['fixture']for p in json.loads(read(ROOT/'corefp_client_flow_profiles.json'))['profiles']if p['fixture']['label']=='cached_owned_cleanup')
    profiles=[];prefix=None
    for flag in [0,1,2,0xffffffff]:
        p=Continue(s,f);r=p.run_caller();assert r['stop_reason']=='before_original_request1200_call'
        current=copy.deepcopy({'CPU':frame(p.u),'result':r})
        if prefix is None:prefix=current
        else:assert current==prefix
        profiles.append(p.run_fragment(flag))
    spans=[s.function(a)for a in [0x8e81c8,0x274ed0,0x1abbe0]]
    qs,negative=proofs()
    counts={'prefix_engine_steps':prefix['result']['steps'],'prefix_original_visits':len(prefix['result']['visited_original_instructions']),'profiles':len(profiles),
      **{k:sum(len(p[k])for p in profiles)for k in ['visits','reads','writes','PAC_models','record_points']},
      'queries_unsat':len(qs),'ordering_countermodels_sat':1,'atomic_stops':1,'uninitialized_pointer_stops':3}
    e={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},
      'thin_sha256':THIN_SHA,'source_spans':spans,'fixture':f,'prefix':prefix,'profiles':profiles,'proofs':qs,'ordering_countermodel':negative,
      'verified_counts':counts,'request1200_gap_executed':False,'native_target_executed':False,'new_IDA_access':False,'IDB_mutated':False,'full_goal_complete':False}
    (ROOT/'fpsd1201_predicates_checks.json').write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
