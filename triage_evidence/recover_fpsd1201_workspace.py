#!/usr/bin/env python3
"""Original SP-relative context producer, pre-helper gate and shared prefix.

Independent declared fragments; the intervening parent gap is not executed.
Only source-produced pointer/prefix bytes pass from constructor to gate cases.
No API, arithmetic result, full helper, native message or IDB edit executes.
O(I+B+F+C*(V+J+R)) time/space; SMT separate; I is sealed predecessor data.
"""
import base64,json,struct,zlib
from pathlib import Path
from hashlib import sha256
from unicorn import arm64_const as A
import unicorn as uc
import z3
from recover_fpsd1201_record import Execution as Frozen,ROOT,RAM,SP,FP,OWNER
from recover_fpsd1201_consumer import unpack
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();T=0x1c81940;G=0x1d43500
DEPS=['fpsd1201_caller_ida_readback.json','corefp_fixups_inventory.json','recover_fpsd1201_record.py',
 'recover_fpsd1201_consumer.py','fpsd1200_certificate_checks.json','fpsd1200_certificate_audit.json',
 'recover_fpsd1200_certificate.py','audit_fpsd1200_certificate.py','corefp_client_flow_profiles.json']


def sources():
    a=json.loads(read(ROOT/'fpsd1201_caller_ida_readback.json'));p=next(r for r in a['spans']if r['role']=='parent')
    D={int(r['address'],16):r for r in json.loads(read(ROOT/'corefp_fixups_inventory.json'))['fixups']}
    return p,D


class Execute(Frozen):
    def __init__(self,c,parent,D,prior=None):
        self.c=c;self.D=D;self.phase=c['kind'];self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM)
        self.visits=[];self.reads=[];self.writes=[];self.pending=[];self.pac=[];self.points=[];self.used=set();self.controls=[]
        for a,n in [(0x8e8000,0x15000),(0x1c80000,0xa0000)]+RAM:self.u.mem_map(a,n)
        raw=bytes.fromhex(parent['bytes_hex']);self.u.mem_write(int(parent['start'],16),raw);self.ranges=[(0x8e81c8,0x8fcfa0)]
        for a,r in D.items():
            if 0x1c80000<=a<a+8<=0x1d20000 and not r['bind']:self.u.mem_write(a,int(r['target'],16).to_bytes(8,'little'))
        for a,n in RAM:self.u.mem_write(a,b'\xa5'*n)
        for j in range(31):self.setreg(j,((j+1)*0x13579bdf02468ace)&((1<<64)-1))
        for j,v in [(19,T),(20,OWNER),(12,(c['phase_u32']-0x8094)&0xffffffff),(16,c['cursor_u64']),(29,FP)]:self.setreg(j,v)
        self.u.reg_write(A.UC_ARM64_REG_SP,SP);self.u.reg_write(A.UC_ARM64_REG_NZCV,0);self.u.reg_write(A.UC_ARM64_REG_CPACR_EL1,3<<20)
        for j in range(32):self.u.reg_write(A.UC_ARM64_REG_Q0+j,int.from_bytes(bytes([j])*16,'little'))
        self.restore=None
        if prior is not None:
            for row in prior['final_RAM']:self.u.mem_write(int(row['address'],16),unpack(row['payload']))
            f=prior['terminal']
            for j,v in enumerate(f['registers31']):self.setreg(j,int(v,16))
            for name,key in [('SP','sp'),('PC','pc'),('NZCV','NZCV')]:self.u.reg_write(getattr(A,'UC_ARM64_REG_'+name),int(f[key],16))
            for j,v in enumerate(f['Q32']):self.u.reg_write(A.UC_ARM64_REG_Q0+j,int(v,16))
            assert self.frame()==f;self.restore={'CPU':self.frame(),'RAM':self.dump()}
            self.controls.append({'register':'X23','before':hex(self.reg(23)),'after':'0xc1f7','reason':'declared_control_after_unexecuted_gap'});self.setreg(23,0xc1f7)
            self.patch(SP+0x864,c['status_u32'].to_bytes(4,'little'),'declared_pre_helper_status')
            self.patch(SP+0x398,G.to_bytes(8,'little'),'declared_cursor_seed_pointer')
            self.patch(G,(0x123456789abcdef0).to_bytes(8,'little'),'declared_cursor_seed')
        self.entry=0x8ea19c if c['kind']=='constructor'else 0x8f33dc
        self.u.reg_write(A.UC_ARM64_REG_PC,self.entry);self.initial=self.frame();self.initial_RAM=self.dump()
        self.u.hook_add(uc.UC_HOOK_CODE,self.hook);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.readhook);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.writehook)
    def patch(self,a,b,why):
        self.controls.append({'address':hex(a),'before_hex':self.ram(a,len(b)).hex(),'after_hex':b.hex(),'reason':why});self.u.mem_write(a,b)
    def hook(self,u,pc,n,d):
        self.flush()
        stops=[0x8ea48c,0x8ed4c0]if self.c['kind']=='constructor'else[0x8f34f8,0x8f3664]
        if pc in stops:self.stop='selected_fragment_frontier';self.terminal=self.frame();u.emu_stop();return
        return super().hook(u,pc,n,d)
    def run(self):
        self.u.emu_start(self.entry,0,count=1000);self.flush();assert hasattr(self,'stop')
        C=(SP+0x9a0+self.c['cursor_u64'])&((1<<64)-1)
        return {'configuration':self.c,'restored_constructor':self.restore,'gap_controls':self.controls,'initial':self.initial,'initial_RAM':self.initial_RAM,
          'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'PAC_models':self.pac,'terminal':self.terminal,'final_RAM':self.dump(),
          'context_pointer':hex(C),'context128_hex':self.ram(C,128).hex(),'record80_hex':self.ram(FP-0xb8,80).hex(),
          'cursor_after_u64':hex(int.from_bytes(self.ram(SP+0x5c8,8),'little')),'used_original_pointer_rows':[self.D[a]for a in sorted(self.used)],
          'intervening_parent_gap_executed':False,'native_effects':False}


def server_witnesses():
    e=json.loads(read(ROOT/'fpsd1200_certificate_checks.json'));out=[]
    for j in [1,2]:
        packed=e['profiles'][j];raw=zlib.decompress(base64.b64decode(packed['payload_zlib_base64']))
        key=b'"montgomery_calls":';assert raw.count(key)==1;s=raw[raw.index(key)+len(key):].decode().lstrip()
        calls,_=json.JSONDecoder().raw_decode(s);assert len(calls)==94;c=calls[73];v=c['entry']['right']
        cap,stored,ptr=struct.unpack('<IIQ',bytes.fromhex(v['header16_hex']));n=(stored-0x693be708)&0xffffffff;assert n==32 and n<=cap
        limbs=struct.unpack('<32I',bytes.fromhex(v['active_limbs_hex']));x=sum((w^0xada56e3c)<<(32*k)for k,w in enumerate(limbs));b=x.to_bytes(128,'big')
        assert v['header_known_mask_hex']=='01'*16 and v['active_known_mask_hex']=='01'*128 and b[:9].hex()=='006664706300000001'
        out.append({'prior_profile_index':j,'label':packed['label'],'decoded_payload_size_B':len(raw),'decoded_payload_sha256':SHA(raw),
          'call_index':73,'call':c,'representative128_hex':b.hex(),'prefix9_hex':b[:9].hex()})
    return out


def proofs():
    sp,s=z3.BitVecs('workspace_sp64 workspace_cursor64',64);marker=z3.BitVec('workspace_status32',32)
    owner,j,k=z3.BitVecs('workspace_owner64 workspace_offset_j64 workspace_offset_k64',64)
    w12=z3.BitVecVal((0xc1f7-0x8094)&0xffffffff,32);w14=w12+0x83b3
    idx=z3.If(marker==(z3.BitVecVal(0xc1f7,32)^0xba27)-0x2030^0xba1da27b,z3.BitVecVal(1,32),z3.BitVecVal(0,32))*0xfe33^(z3.BitVecVal(0xc1f7,32)-0x4627)
    claims=[('selected_cursor_delta',s-0xbdc6+z3.ZeroExt(32,w14)==s+1872),
      ('saved_pointer_geometry',(sp+0x9a0+s+128)-(sp+0x9a0+s)==128),
      ('context_limit_geometry',(sp+0x9a0+s+0x6f0)-(sp+0x9a0+s)==1776),
      ('selected_pre_helper_status',idx==z3.If(marker==0xba1df9db,z3.BitVecVal(0x85e3,32),z3.BitVecVal(0x7bd0,32))),
      ('candidate_and_XOR_ranges_disjoint',z3.Implies(z3.And(z3.ULT(j,128),z3.ULT(k,128)),owner+0x880+j!=owner+0x900+k)),
      ('later_slot_store_is_byte_index',z3.ULE(s&255,255))]
    out=[]
    for label,claim in claims:
        q=z3.Solver();q.set(timeout=30000);q.add(z3.Not(claim));assert q.check()==z3.unsat
        out.append({'label':label,'query':q.to_smt2(),'result':'unsat'})
    q=z3.Solver();q.add(z3.ULT(s+1872,s));assert q.check()==z3.sat
    return out,{'label':'cursor_addition_can_wrap_without_bound','query':q.to_smt2(),'result':'sat','example_cursor_u64':hex(q.model()[s].as_long())}


def main():
    parent,D=sources();profiles=[]
    for phase in [0xc1f7,0xfd60]:
        for cursor in [0,16,32,256,4096]:
            c={'kind':'constructor','phase_u32':phase,'cursor_u64':cursor};profiles.append(Execute(c,parent,D).run())
    for j in range(5):
        for status in [0,0xba1df9db,0x45e2a205,0xba1df9da,0xffffffff]:
            c={'kind':'pre_helper_gate','phase_u32':0xc1f7,'cursor_u64':profiles[j]['configuration']['cursor_u64'],'constructor_profile_index':j,'status_u32':status}
            profiles.append(Execute(c,parent,D,profiles[j]).run())
    qs,negative=proofs();witnesses=server_witnesses()
    counts={'profiles':len(profiles),'constructor_profiles':10,'pre_helper_gate_profiles':25,'record_staging_stops':5,
      **{k:sum(len(p[k])for p in profiles)for k in ['source_visits','source_reads','source_writes','PAC_models']},'local_queries_unsat':len(qs),'local_wrap_control_sat':1,'server_witnesses':len(witnesses)}
    e={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},
      'parent_source':parent,'profiles':profiles,'proofs':qs,'wrap_countermodel':negative,'server_witnesses':witnesses,'verified_counts':counts,
      'whole_parent_replayed':False,'new_IDA_access':False,'native_target_executed':False,'IDB_edit_operations_requested':False,'full_goal_complete':False}
    (ROOT/'fpsd1201_workspace_checks.json').write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
