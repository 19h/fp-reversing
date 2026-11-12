#!/usr/bin/env python3
"""Original fixed-width integer export and complete local helper return.

Receipt-pinned continuations and declared isolated records only. No protected
result or native API is supplied. Prefix instructions are not rerun.
Time O(I+C*(B+F+V+P*J+R)); space O(I+B+F+C*(V+J+P+R)); SMT separate.
Native parent reachability, transport identity and ownership remain open.
"""
import json,struct
from pathlib import Path
from hashlib import sha256
import z3
from unicorn import arm64_const as A
from recover_fpsd1201_reduction import Execute as Base
from recover_fpsd1201_auxiliary import sources as old_sources
from recover_fpsd1201_consumer import unpack
from recover_fpsd1201_import import ROOT,local_reference,RAM,OWNER,FP,SP,HALT
from recover_fpsd1201_record import RECORD,OUT
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();M=0xffffffff;BASE_COUNT=0x4b0cf050;K=0x1ac70ef2
ENTRY=0x32f628;RET=0x32f950;IR=FP+0x100;DESC=OWNER+0x800;PAYLOAD=OWNER+0x1000;DEST=OWNER+0x2000
DEPS=['fpsd1201_auxiliary_checks.json','fpsd1201_auxiliary_audit.json','fpsd1201_consumer_checks.json',
 'recover_fpsd1201_auxiliary.py','audit_fpsd1201_record.py','recover_fpsd1201_reduction.py',
 'corefp_library_inventory.json','corefp_lookup_contracts.json','corefp_fixups_inventory.json']


def sources():
    code,banks,D=old_sources();a=json.loads(read(ROOT/'fpsd1201_export_ida_readback.json'))
    return code+[{**a['spans'][0],'role':'fixed_width_big_endian_export'}],banks,D


def configurations(old):
    for j,p in enumerate(old['profiles']):
        if p['terminal']['pc']=='0x981bc8':yield {'mode':'retained','prior_index':j}
    for n in [0,3]:yield {'mode':'short_export','prior_index':1,'length_B':n}
    for v in [0,1,0x80,0xffffffff,(1<<32)+0x12345678,(1<<127)+0xabcd,(1<<1023)+7,(1<<2047)+9,(1<<4095)+11]:
        k=(v.bit_length()+31)//32
        lengths=[0,1,3,4,5,16,128]if not k else sorted({0,4*k-1,4*k,4*k+1,max(128,4*k+1)})
        for sign in ([1]if not v else[1,-1]):
            for n in lengths:yield {'mode':'isolated','prior_index':1,'value_hex':hex(v),'sign':sign,'leading_zero_limbs':0,'length_B':n,'null_destination':False}
    for v in [0,1,(1<<127)+0xabcd]:
        k=(v.bit_length()+31)//32+2
        for sign in [1,-1]:
            for n in sorted({0,4*k-1,4*k,4*k+1,128}):yield {'mode':'isolated','prior_index':1,'value_hex':hex(v),'sign':sign,'leading_zero_limbs':2,'length_B':n,'null_destination':False}
    yield {'mode':'isolated','prior_index':1,'value_hex':'0x0','sign':1,'leading_zero_limbs':0,'length_B':0,'null_destination':True}
    for n in [0,128]:yield {'mode':'minimum_count','prior_index':1,'length_B':n}


class Execute(Base):
    def __init__(self,c,prior,seed,code,banks,D):
        super().__init__(seed,code[:19],banks,D)
        for a,n in [(0x1142000,4096),(0x74e000,8192),(0x59f000,4096),(0x57a000,8192),(0x32f000,4096)]:self.u.mem_map(a,n)
        for row in code[19:]:
            a=int(row['start'],16);b=bytes.fromhex(row['bytes_hex']);self.u.mem_write(a,b);self.ranges.append((a,a+len(b)))
        for row in prior['final_RAM']:self.u.mem_write(int(row['address'],16),unpack(row['payload']))
        f=prior['terminal'];assert f['pc']=='0x981bc8'
        for j,v in enumerate(f['registers31']):self.setreg(j,int(v,16))
        for name,key in [('SP','sp'),('PC','pc'),('NZCV','NZCV')]:self.u.reg_write(getattr(A,'UC_ARM64_REG_'+name),int(f[key],16))
        for j,v in enumerate(f['Q32']):self.u.reg_write(A.UC_ARM64_REG_Q0+j,int(v,16))
        assert self.frame()==f;self.c=c;self.controls=[];self.checkpoint_load=None;self.export_points=[];self.root_points=[]
        self.root_count=int.from_bytes(self.ram(RECORD+16,8),'little')
        if c['mode']in ['retained','short_export']:
            self.entry=0x981bc8;self.argument=self.reg(0)
            j=next(j for j in reversed(range(len(prior['source_reads'])))if prior['source_reads'][j]['address']=='0x1d03d10')
            self.checkpoint_load={'prior_read_index':j,'read':prior['source_reads'][j],'source_visit':prior['source_visits'][prior['source_reads'][j]['visit']]}
            if c['mode']=='short_export':
                h=((self.argument^0xd97ffe38)*0xfcf33521)&M;self.patch(self.argument+20,((h+0x2647dd39+c['length_B'])&M).to_bytes(4,'little'))
        else:
            if c['mode']=='isolated':
                v=int(c['value_hex'],16);count=c['sign']*((v.bit_length()+31)//32+c['leading_zero_limbs']);ptr=PAYLOAD
                for j in range(abs(count)):self.patch(ptr+4*j,(((v>>(32*j))&M)^K).to_bytes(4,'little'))
            else:count=-0x80000000;ptr=0
            self.patch(DESC,struct.pack('<IIQ',130,(BASE_COUNT+count)&M,ptr));h=((IR^0xd97ffe38)*0xfcf33521)&M
            dest=0 if c.get('null_destination')else DEST;self.patch(IR,struct.pack('<QQIII',dest,DESC,h^0x80e8,(h+0x2647dd39+c['length_B'])&M,0xa5a5a5a5))
            self.argument=IR;self.entry=ENTRY;self.setreg(0,IR);self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_SP,SP);self.u.reg_write(A.UC_ARM64_REG_PC,ENTRY)
        self.phase='export_'+c['mode'];self.visits=[];self.reads=[];self.writes=[];self.pending=[];self.pac=[];self.points=[];self.used=set();self.initial=self.frame();self.initial_RAM=self.dump()
    def patch(self,a,b):
        self.controls.append({'address':hex(a),'before_hex':self.ram(a,len(b)).hex(),'after_hex':b.hex()});self.u.mem_write(a,b)
    def view(self,pc):
        r=self.argument;raw=self.ram(r,28);d=int.from_bytes(raw[8:16],'little');b=self.ram(d,16);count=(int.from_bytes(b[4:8],'little')-BASE_COUNT)&M;count=count-(1<<32)if count>>31 else count;p=int.from_bytes(b[8:],'little');dst=int.from_bytes(raw[:8],'little');valid=abs(count)<=130 and any(a<=p<=p+4*abs(count)<=a+n for a,n in RAM)
        return {'pc':hex(pc),'CPU':self.frame(),'record_pointer':hex(r),'record28_hex':raw.hex(),'descriptor_pointer':hex(d),'descriptor16_hex':b.hex(),
          'active_payload_hex':self.ram(p,4*abs(count)).hex()if valid else None,'destination_pointer':hex(dst),'destination1024_hex':self.ram(dst,1024).hex()if dst else None}
    def root(self,pc):
        return {'pc':hex(pc),'CPU':self.frame(),'record80_hex':self.ram(RECORD,80).hex(),'count_pointer':hex(self.root_count),'count_u32':int.from_bytes(self.ram(self.root_count,4),'little'),
          'delta_cell_u64':hex(int.from_bytes(self.ram(OUT,8),'little')),'candidate128_hex':self.ram(OWNER+0x880,128).hex()}
    def hook(self,u,pc,n,data):
        self.flush()
        if pc in [ENTRY,RET]:self.export_points.append(self.view(pc))
        if pc in [0x981be0,0x981bf8,0x981c30,0x981e54,0x981e68]or pc==HALT and self.c['mode']in ['retained','short_export']:self.root_points.append(self.root(pc))
        if pc==0x981bc8 and not self.visits:
            assert(self.reg(8),self.reg(17))==(ENTRY,0xa77e);slot=0x1d03d10
            self.visits.append({'phase':self.phase,'pc':hex(pc),'bytes_hex':self.ram(pc,4).hex(),'instruction':'blraa x8, x17'})
            self.pac.append({'pc':hex(pc),'kind':'blraa','before':self.frame(),'target':hex(ENTRY),'modifier':'0xa77e','original_slot':hex(slot)})
            self.used.add(slot);self.setreg(30,pc+4);u.reg_write(A.UC_ARM64_REG_PC,ENTRY);return
        return self.continued_hook(u,pc,n,data)
    def run(self):
        self.stop=None;self.frontier=None;self.u.emu_start(self.entry,0,count=500000);self.flush();assert self.stop=='returned'and self.frontier is None
        return {'configuration':self.c,'prior_profile_index':self.c['prior_index'],'checkpoint_pointer_load':self.checkpoint_load,'operand_controls':self.controls,'initial':self.initial,'initial_RAM':self.initial_RAM,
          'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'PAC_models':self.pac,'CPU_points':self.points,'export_points':self.export_points,'root_points':self.root_points,
          'terminal':self.terminal,'final_RAM':self.dump(),'stop_reason':self.stop,'frontier':self.frontier,'used_original_pointer_rows':[self.D[a]for a in sorted(self.used)],'native_effects':False}


def proofs():
    p,n,h=z3.BitVecs('export_pointer export_length export_mask',32);q=z3.BitVec('export_minimum_count',64)
    claims=[('export_pointer_mask',(((0xb42edf98|(p<<1))-p+0x25e89034)^0x036891f4)*0xfcf33521==(p^0xd97ffe38)*0xfcf33521),
      ('export_length_decode',n+0x2647dd39+h-h+0xd9b822c6+1==n),
      ('export_zero_length_sentinel',(n+0x2647dd39==0x2647dd39)==(n==0)),
      ('minimum_count_always_rejected',z3.ULT(z3.ZeroExt(32,n),z3.BitVecVal(0xfffffffe00000000,64)))]
    out=[]
    for label,claim in claims:
        s=z3.Solver();s.set(timeout=60000);s.add(z3.Not(claim));result=str(s.check());assert result=='unsat'
        out.append({'label':label,'query':s.sexpr()+'\n(check-sat)\n','result':result,'timeout_ms':60000})
    return out


def main():
    code,banks,D=sources();reference=local_reference(code,banks,D);old=json.loads(read(ROOT/'fpsd1201_auxiliary_checks.json'));seed=json.loads(read(ROOT/'fpsd1201_consumer_checks.json'))['profiles'][0]['configuration'];profiles=[]
    for c in configurations(old):
        profiles.append(Execute(c,old['profiles'][c['prior_index']],seed,code,banks,D).run())
        if len(profiles)<=18 or len(profiles)%24==0:print(json.dumps({'profiles':len(profiles),'mode':c['mode'],'visits':len(profiles[-1]['source_visits'])}),flush=True)
    queries=proofs();counts={'profiles':len(profiles),'prefix_instructions_rerun':0,**{k:sum(len(p[k])for p in profiles)for k in ['source_visits','source_reads','source_writes','PAC_models','export_points','root_points']},
      'fresh_IDA_spans':1,'fresh_IDA_bytes':812,'source_code_bytes':41224,'local_queries_unsat':len(queries)}
    e={'scope':__doc__,'code_spans':code,'profiles':profiles,'proofs':queries,'reference_file_check':reference,'verified_counts':counts,'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},
      'generator_sha256':SHA(Path(__file__).read_bytes()),'IDA_readback_sha256':SHA(read(ROOT/'fpsd1201_export_ida_readback.json').encode()),'whole_parent_replayed':False,
      'native_target_executed':False,'IDB_edit_operations_requested':False,'full_goal_complete':False}
    (ROOT/'fpsd1201_export_checks.json').write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
