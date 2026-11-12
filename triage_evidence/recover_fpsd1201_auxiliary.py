#!/usr/bin/env python3
"""Original auxiliary magnitude-length, bit-selection and consumer continuation.

Resume receipt-pinned private checkpoints and execute declared helper inputs.
No native target operation or supplied arithmetic result. Prefix execution is
not rerun. Time O(I+C*(B+F+V+P*J+R)); space O(I+B+F+C*(V+J+P+R));
SMT separate. The full cross-layer interface goal remains active.
"""
import json,struct
from pathlib import Path
from hashlib import sha256
import z3
from unicorn import arm64_const as A
from recover_fpsd1201_reduction import Execute as Base
from recover_fpsd1201_product import sources as old_sources
from recover_fpsd1201_consumer import unpack
from recover_fpsd1201_import import ROOT,local_reference,RAM,OWNER,FP,SP,HALT,CS
from recover_fpsd1201_record import RECORD,OUT
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();M=(1<<32)-1;BASE=0x4b0cf050;K=0x1ac70ef2
LENGTH=0x59f4e8;BIT=0x57af24;IR=FP+0x100;DESC=OWNER+0x800;PAYLOAD=OWNER+0x1000
ENTRIES={LENGTH:0x59f704,BIT:0x57b090};EXITS={v:k for k,v in ENTRIES.items()}
DEPS=['fpsd1201_product_checks.json','fpsd1201_product_audit.json','fpsd1201_consumer_checks.json',
 'recover_fpsd1201_product.py','audit_fpsd1201_record.py','recover_fpsd1201_reduction.py',
 'corefp_library_inventory.json','corefp_lookup_contracts.json','corefp_fixups_inventory.json']


def sources():
    code,banks,D=old_sources();att=json.loads(read(ROOT/'fpsd1201_auxiliary_ida_readback.json'))
    return code+[{**r,'role':role}for r,role in zip(att['spans'],['magnitude_bit_length','magnitude_bit_selection'])],banks,D


def configurations():
    for j in range(12):yield {'mode':'retained','prior_index':12+j}
    for e in [0,1,2,3,17,65537,0x80000001,0xffffffff]:yield {'mode':'exponent','prior_index':20,'exponent_hex':hex(e)}
    for e in [0,2,17,65537]:yield {'mode':'exponent','prior_index':21,'exponent_hex':hex(e)}
    values=[0,1,2,3,65537,0xffffffff,1<<32,(1<<33)+3,(1<<127)+1,(1<<2047)+1]
    for v in values:
        for sign in ([1]if v==0 else[1,-1]):
            for leading in [0,2]:yield {'mode':'length','prior_index':12,'value_hex':hex(v),'sign':sign,'leading_zero_limbs':leading}
    for v in [0,1,65537,(1<<31)+3,(1<<32)+5,(1<<127)+1]:
        for sign in [1,-1]:
            for index in [0,1,16,31,32,63,127,128,-1,-32,-128,-0x80000000]:
                yield {'mode':'bit','prior_index':12,'value_hex':hex(v),'sign':sign,'index_i32':index,'leading_zero_limbs':0}
    for mode in ['length','bit']:
        for count in [0,-0x80000000]:yield {'mode':mode,'prior_index':12,'value_hex':'0x0','sign':1,'leading_zero_limbs':0,'special_count':count,'index_i32':0}


class Execute(Base):
    def __init__(self,c,prior,outer,code,banks,D):
        super().__init__(prior['configuration'],code[:19],banks,D)
        for a,n in [(0x1142000,4096),(0x74e000,8192),(0x59f000,4096),(0x57a000,8192)]:self.u.mem_map(a,n)
        for row in code[19:]:
            a=int(row['start'],16);b=bytes.fromhex(row['bytes_hex']);self.u.mem_write(a,b);self.ranges.append((a,a+len(b)))
        for row in prior['final_RAM']:self.u.mem_write(int(row['address'],16),unpack(row['payload']))
        f=prior['terminal']
        for j,v in enumerate(f['registers31']):self.setreg(j,int(v,16))
        for name,key in [('SP','sp'),('PC','pc'),('NZCV','NZCV')]:self.u.reg_write(getattr(A,'UC_ARM64_REG_'+name),int(f[key],16))
        for j,v in enumerate(f['Q32']):self.u.reg_write(A.UC_ARM64_REG_Q0+j,int(v,16))
        assert self.frame()==f and f['pc']=='0x11425bc'
        self.c=c;self.controls=[];self.checkpoint_load=None;self.outer=outer['consumer_points'][0];self.outer_record=int(self.outer['record_pointer'],16)
        self.outer_cursor=int(self.outer['caller_cursor_pointer'],16);self.outer_child_cursor=int(outer['consumer_points'][3]['child_cursor_pointer'],16)
        if c['mode']in ['retained','exponent']:
            self.entry=0x11425bc
            j=next(j for j in reversed(range(len(prior['source_reads'])))if prior['source_reads'][j]['address']=='0x1d037a8')
            self.checkpoint_load={'prior_read_index':j,'read':prior['source_reads'][j],'source_visit':prior['source_visits'][prior['source_reads'][j]['visit']]}
            if c['mode']=='exponent':
                d=int.from_bytes(self.ram(self.reg(0)+8,8),'little');self.descriptor(d,OWNER+0x3400,int(c['exponent_hex'],16),1,0)
        else:
            v=int(c['value_hex'],16);self.descriptor(DESC,PAYLOAD,v,c['sign'],c['leading_zero_limbs'],c.get('special_count'))
            if c['mode']=='length':
                h=((IR^0x1766cddd)*0xb7a7bfff)&M;self.patch(IR,struct.pack('<IIQ',(0x951a-h)&M,0xa5a5a5a5,DESC));self.entry=LENGTH
            else:
                h=((IR^0x542fbf9b)*0x4386951d)&M;index=c['index_i32']&M
                self.patch(IR,struct.pack('<IIIIQ',0xa5a5a5a5,(((index-0x02a682df)*0x43ea4365)&M)^h,(0x6873-h)&M,0xa5a5a5a5,DESC));self.entry=BIT
            self.setreg(0,IR);self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_SP,SP);self.u.reg_write(A.UC_ARM64_REG_PC,self.entry)
        self.phase='auxiliary_'+c['mode'];self.visits=[];self.reads=[];self.writes=[];self.pending=[];self.pac=[];self.points=[];self.used=set();self.helper_points=[];self.consumer_points=[];self.helper_stack=[]
        self.initial=self.frame();self.initial_RAM=self.dump()
    def patch(self,a,b):
        self.controls.append({'address':hex(a),'before_hex':self.ram(a,len(b)).hex(),'after_hex':b.hex()});self.u.mem_write(a,b)
    def descriptor(self,d,p,v,sign,leading,special=None):
        count=sign*((v.bit_length()+31)//32+leading)if special is None else special
        self.patch(d,struct.pack('<IIQ',130,(BASE+count)&M,0 if special is not None else p))
        if special is None:
            for j in range(abs(count)):self.patch(p+4*j,(((v>>(32*j))&M)^K).to_bytes(4,'little'))
    def desc(self,d):
        raw=self.ram(d,16);n=(int.from_bytes(raw[4:8],'little')-BASE)&M;n=n-(1<<32)if n>>31 else n;p=int.from_bytes(raw[8:],'little');valid=abs(n)<=130 and any(a<=p<=p+abs(n)*4<=a+s for a,s in RAM)
        return {'address':hex(d),'descriptor16_hex':raw.hex(),'active_payload_hex':self.ram(p,4*abs(n)).hex()if valid and n else ''if n==0 else None}
    def helper_view(self,pc,entry,r):
        return {'pc':hex(pc),'entry':hex(entry),'record_pointer':hex(r),'record24_hex':self.ram(r,24).hex(),
          'descriptor':self.desc(int.from_bytes(self.ram(r+(8 if entry==LENGTH else 16),8),'little')),'CPU':self.frame()}
    def consumer_view(self,pc):
        r=self.outer_record;raw=self.ram(r,48);ptr=lambda j:int.from_bytes(raw[j:j+8],'little')
        return {'pc':hex(pc),'CPU':self.frame(),'record48_hex':raw.hex(),'output':self.desc(ptr(8)),
          'input':self.desc(ptr(32)),'modulus':self.desc(ptr(40)),
          'wrapper_cursor_u64':hex(int.from_bytes(self.ram(self.outer_cursor,8),'little')),
          'child_cursor_u64':hex(int.from_bytes(self.ram(self.outer_child_cursor,8),'little'))}
    def hook(self,u,pc,n,data):
        self.flush()
        if pc==0x11425bc and not self.visits:
            slot=0x1d037a8;assert(self.reg(8),self.reg(17))==(LENGTH,0x7c9f)
            self.visits.append({'phase':self.phase,'pc':hex(pc),'bytes_hex':self.ram(pc,4).hex(),'instruction':'blraa x8, x17'})
            self.pac.append({'pc':hex(pc),'kind':'blraa','before':self.frame(),'target':hex(LENGTH),'modifier':'0x7c9f','original_slot':hex(slot)})
            self.used.add(slot);self.setreg(30,pc+4);u.reg_write(A.UC_ARM64_REG_PC,LENGTH);return
        if pc in ENTRIES:
            item=(pc,self.reg(0));self.helper_stack.append(item);self.helper_points.append(self.helper_view(pc,*item))
        elif pc in EXITS:
            item=self.helper_stack.pop();assert item[0]==EXITS[pc];self.helper_points.append(self.helper_view(pc,*item))
        if pc in [0x1142874,0x1142e2c,0x9819c8]:self.consumer_points.append(self.consumer_view(pc))
        if pc==0x59f650 and self.c['mode']=='retained'and self.helper_points[-1]['descriptor']['active_payload_hex']is None:
            self.stop='unbacked_auxiliary_payload';self.terminal=self.frame();self.frontier={'pc':hex(pc),'read_address':hex((self.reg(4)+4*self.reg(9))&((1<<64)-1)),'size_B':4,'instruction_executed':False};u.emu_stop();return
        return self.continued_hook(u,pc,n,data)
    def run(self):
        self.stop=None;self.frontier=None;self.u.emu_start(self.entry,0,count=500000);self.flush();assert self.stop in ['returned','unretained_callee','unbacked_auxiliary_payload']
        return {'configuration':self.c,'prior_profile_index':self.c['prior_index'],'checkpoint_pointer_load':self.checkpoint_load,'operand_controls':self.controls,
          'initial':self.initial,'initial_RAM':self.initial_RAM,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'PAC_models':self.pac,'CPU_points':self.points,
          'helper_points':self.helper_points,'consumer_points':self.consumer_points,'terminal':self.terminal,'final_RAM':self.dump(),'stop_reason':self.stop,'frontier':self.frontier,
          'used_original_pointer_rows':[self.D[a]for a in sorted(self.used)],'final_delta_cell_u64':hex(int.from_bytes(self.ram(OUT,8),'little')),
          'final_status_u32':hex(int.from_bytes(self.ram(RECORD+0x30,4),'little')),'native_effects':False}


def proofs():
    p,x=z3.BitVecs('auxiliary_pointer auxiliary_index',32)
    claims=[('length_pointer_mask',((2*(p&0x11f97c13)-p+0x6e0683ec)^0x79604e31)*0xb7a7bfff==(p^0x1766cddd)*0xb7a7bfff),
      ('bit_index_affine_inverse',((x-0x02a682df)*0x43ea4365)*0xef42366d+0x02a682df==x),
      ('negative_index_reflection',0xfd597d21-x==-(x+0x02a682df))]
    out=[]
    for label,claim in claims:
        q=z3.Solver();q.set(timeout=60000);q.add(z3.Not(claim));result=str(q.check());assert result=='unsat'
        out.append({'label':label,'query':q.sexpr()+'\n(check-sat)\n','result':result,'timeout_ms':60000})
    return out


def main():
    code,banks,D=sources();reference=local_reference(code,banks,D);old=json.loads(read(ROOT/'fpsd1201_product_checks.json'));outer=json.loads(read(ROOT/'fpsd1201_consumer_checks.json'));profiles=[]
    for c in configurations():
        j=c['prior_index'];profiles.append(Execute(c,old['profiles'][j],outer['profiles'][j-12],code,banks,D).run())
        if len(profiles)<=24 or len(profiles)%24==0:print(json.dumps({'profiles':len(profiles),'mode':c['mode'],'visits':len(profiles[-1]['source_visits']),'stop':profiles[-1]['stop_reason']}),flush=True)
    queries=proofs();counts={'profiles':len(profiles),'prefix_instructions_rerun':0,**{k:sum(len(p[k])for p in profiles)for k in ['source_visits','source_reads','source_writes','PAC_models','helper_points','consumer_points']},
      'fresh_IDA_spans':2,'fresh_IDA_bytes':912,'source_code_bytes':40412,'local_queries_unsat':len(queries)}
    e={'scope':__doc__,'code_spans':code,'profiles':profiles,'proofs':queries,'reference_file_check':reference,'verified_counts':counts,
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},'generator_sha256':SHA(Path(__file__).read_bytes()),
      'IDA_readback_sha256':SHA(read(ROOT/'fpsd1201_auxiliary_ida_readback.json').encode()),'whole_parent_replayed':False,
      'native_target_executed':False,'IDB_edit_operations_requested':False,'full_goal_complete':False}
    (ROOT/'fpsd1201_auxiliary_checks.json').write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
