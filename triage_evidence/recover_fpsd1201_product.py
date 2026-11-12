#!/usr/bin/env python3
"""CoreFP1201 complete Montgomery-product calls and next auxiliary consumer.

Resume audited checkpoints with retained or explicitly canonicalized inputs;
also execute declared isolated records. No protected result is supplied.
O(I+C*(B+F+V+P*J+R)) time, O(I+B+F+C*(V+J+P+R)) space; SMT separate.
Native lineage and the complete outer consumer remain open.
"""
import json,struct
from pathlib import Path
from hashlib import sha256
import z3
from unicorn import arm64_const as A
from recover_fpsd1201_reduction import Execute as Previous
from recover_fpsd1201_consumer import sources as previous_sources,unpack
from recover_fpsd1201_import import ROOT,local_reference,RAM,FP,SP,OWNER,HALT,CS
from recover_fpsd1201_record import RECORD,OUT
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();WRAP=0x74fd0c;CHILD=0x74eb08;MASK=(1<<32)-1;BASE=0x4b0cf050;K=0x1ac70ef2
IR=FP+0x100;AD=OWNER+0x800;BD=OWNER+0xa00;ND=OWNER+0xc00;Q=OWNER+0xd00;OD=OWNER+0xe00;CELL=OWNER+0xf00
PRINCIPALS=[WRAP,CHILD,0x649430,0x33abec,0x5a600c,0x5e8158]
DEPS=['fpsd1201_consumer_checks.json','fpsd1201_consumer_audit.json','fpsd1201_consumer_ida_readback.json',
 'recover_fpsd1201_consumer.py','audit_fpsd1201_consumer.py','fpsd1201_record_checks.json',
 'corefp_library_inventory.json','corefp_lookup_contracts.json','corefp_fixups_inventory.json']


def sources():
    code,banks,D=previous_sources();a=json.loads(read(ROOT/'fpsd1201_product_ida_readback.json'))
    return code+[{**r,'role':role}for r,role in zip(a['spans'],['product_cursor_wrapper','montgomery_product'])],banks,D


def direct_configurations():
    for n in [3,7,0xffffffff,0x80000001]:
        for j,(a,b)in enumerate([(0,n-1),(n-1,n-1),(n//2,n//3)]):
            for alias in ['distinct','first','second']:yield {'mode':'direct','label':f'word_{n}_{j}_{alias}','n_hex':hex(n),'a_hex':hex(a),'b_hex':hex(b),'alias':alias}
    for width in [2,4,8,16,32,64]:
        n=(1<<(32*width))-159
        for j,(a,b)in enumerate([(n-1,n-2),(1,n-1)]):
            for alias in ['distinct','first','second']:yield {'mode':'direct','label':f'wide_{width}_{j}_{alias}','n_hex':hex(n),'a_hex':hex(a),'b_hex':hex(b),'alias':alias}


class Execute(Previous):
    def __init__(self,prior,index,mode,code,banks,D,direct=None):
        c={**prior['configuration'],'product_mode':mode};super().__init__(c,code[:19],banks,D)
        self.u.mem_map(0x1142000,4096);self.u.mem_map(0x74e000,8192)
        for r in code[19:]:
            a=int(r['start'],16);b=bytes.fromhex(r['bytes_hex']);self.u.mem_write(a,b);self.ranges.append((a,a+len(b)))
        self.prior_index=index;self.controls=[];self.direct=direct;self.checkpoint_load=None
        if mode!='direct':
            for r in prior['final_RAM']:self.u.mem_write(int(r['address'],16),unpack(r['payload']))
            f=prior['terminal']
            for j,v in enumerate(f['registers31']):self.setreg(j,int(v,16))
            for name,key in [('SP','sp'),('PC','pc'),('NZCV','NZCV')]:self.u.reg_write(getattr(A,'UC_ARM64_REG_'+name),int(f[key],16))
            for j,v in enumerate(f['Q32']):self.u.reg_write(A.UC_ARM64_REG_Q0+j,int(v,16))
            assert self.frame()==f and f['pc']=='0x114245c'
            self.entry=0x114245c
            j=next(j for j in reversed(range(len(prior['source_reads'])))if prior['source_reads'][j]['address']=='0x1d03d18')
            self.checkpoint_load={'prior_read_index':j,'read':prior['source_reads'][j],'source_visit':prior['source_visits'][prior['source_reads'][j]['visit']]}
            if mode=='nested_canonical':
                r=self.reg(0);d=int.from_bytes(self.ram(r+40,8),'little');p=int.from_bytes(self.ram(d+8,8),'little');b=min(0x12345678,c['operand_u32']-1)
                self.patch(d+4,(BASE+(b!=0)).to_bytes(4,'little'));self.patch(p,(b^K).to_bytes(4,'little'))
        else:
            n,a,b=(int(direct[k],16)for k in ['n_hex','a_hex','b_hex'])
            for d,p,v in [(AD,OWNER+0x1000,a),(BD,OWNER+0x1800,b),(ND,OWNER+0x2000,n),(OD,OWNER+0x2800,0)]:
                count=(v.bit_length()+31)//32;self.patch(d,struct.pack('<IIQ',130,BASE+count,p))
                for j in range(count):self.patch(p+4*j,(((v>>(32*j))&MASK)^K).to_bytes(4,'little'))
            out={'distinct':OD,'first':AD,'second':BD}[direct['alias']]
            self.patch(Q,struct.pack('<QQII',AD,BD,(-pow(n,-1,1<<32))&MASK,0xa5a5a5a5));m=(((IR^0x7043a3fa)*0x4ecee2ad)&MASK)
            self.patch(IR,struct.pack('<QIIQQQQ',AD,m^0xd7f4,0xa5a5a5a5,ND,Q,out,BD));self.patch(CELL,b'\0'*8)
            self.setreg(0,IR);self.setreg(1,CELL);self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_SP,SP);self.u.reg_write(A.UC_ARM64_REG_PC,WRAP);self.entry=WRAP
        self.phase='product_'+mode;self.visits=[];self.reads=[];self.writes=[];self.pending=[];self.pac=[];self.points=[];self.used=set();self.product_points=[];self.call_stack=[];self.caller_points=[]
        self.initial=self.frame();self.initial_RAM=self.dump()
        self.exits={i.address:int(r['start'],16)for r in code if int(r['start'],16)in PRINCIPALS for i in CS.disasm(bytes.fromhex(r['bytes_hex']),int(r['start'],16))if i.mnemonic in ['ret','retab']}
        assert len(self.exits)==len(PRINCIPALS)
    def patch(self,a,b):
        self.controls.append({'address':hex(a),'before_hex':self.ram(a,len(b)).hex(),'after_hex':b.hex()});self.u.mem_write(a,b)
    def desc(self,a):
        d=self.ram(a,16);p=int.from_bytes(d[8:],'little');assert any(lo<=p<p+1024<=lo+n for lo,n in RAM)
        return {'address':hex(a),'descriptor16_hex':d.hex(),'payload1024_hex':self.ram(p,1024).hex()}
    def state(self,pc,entry,r,cursor):
        raw=self.ram(r,48);ptr=lambda j:int.from_bytes(raw[j:j+8],'little');extra={}
        if entry in [WRAP,CHILD]:
            q=ptr(24);views={name:self.desc(ptr(off))for name,off in [('first',0),('modulus',16),('output',32),('second',40)]}
            extra={'pair_pointer':hex(q),'pair24_hex':self.ram(q,24).hex(),'cursor_pointer':hex(cursor),'cursor_u64':hex(int.from_bytes(self.ram(cursor,8),'little'))}
        elif entry in [0x649430,0x33abec]:views={'first':self.desc(ptr(0)),'second':self.desc(ptr(16))}
        elif entry==0x5e8158:views={'first':self.desc(ptr(8)),'second':self.desc(ptr(16))}
        else:views={'operand':self.desc(ptr(8))}
        return {'pc':hex(pc),'entry':hex(entry),'record_pointer':hex(r),'record48_hex':raw.hex(),'views':views,**extra,'CPU':self.frame()}
    def hook(self,u,pc,n,data):
        self.flush()
        if pc in PRINCIPALS:
            item=(pc,self.reg(0),self.reg(1));self.call_stack.append(item)
            if pc==WRAP:self.product_signature=item
            self.product_points.append(self.state(pc,*item))
        elif pc in self.exits:
            item=self.call_stack.pop();assert item[0]==self.exits[pc];self.product_points.append(self.state(pc,*item))
        if pc in [0x74ec38,0x74ff14,0x1142460]:
            item=self.call_stack[0]if self.call_stack else self.product_signature
            self.caller_points.append(self.state(pc,*item))
        if pc==0x114245c and not self.visits:
            slot=0x1d03d18;assert(self.reg(8),self.reg(17))==(WRAP,0xca9b)
            self.visits.append({'phase':self.phase,'pc':hex(pc),'bytes_hex':self.ram(pc,4).hex(),'instruction':'blraa x8, x17'})
            self.pac.append({'pc':hex(pc),'kind':'blraa','before':self.frame(),'target':hex(WRAP),'modifier':'0xca9b','original_slot':hex(slot)})
            self.used.add(slot);self.setreg(30,pc+4);u.reg_write(A.UC_ARM64_REG_PC,WRAP);return
        return self.continued_hook(u,pc,n,data)
    def run(self):
        self.stop=None;self.frontier=None;self.u.emu_start(self.entry,0,count=500000);self.flush()
        assert self.stop==('returned'if self.direct else'unretained_callee')and not self.call_stack
        return {'configuration':self.c,'direct_configuration':self.direct,'prior_profile_index':self.prior_index,'checkpoint_pointer_load':self.checkpoint_load,
          'operand_controls':self.controls,'initial':self.initial,'initial_RAM':self.initial_RAM,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,
          'PAC_models':self.pac,'CPU_points':self.points,'product_points':self.product_points,'caller_points':self.caller_points,'terminal':self.terminal,'final_RAM':self.dump(),
          'stop_reason':self.stop,'frontier':self.frontier,'used_original_pointer_rows':[self.D[a]for a in sorted(self.used)],'native_effects':False}


def proofs():
    p=z3.BitVec('product_record',32);c=z3.BitVecVal(0x77e48841,32);raw=(((p&c)|~(p|c))^0xf858d444)*0x4ecee2ad
    seed=z3.BitVec('product_seed',64);top=z3.LShR(seed*0x2ea5+1,60);pad=((top<<4)+31)&0x1f0
    a,b=z3.BitVecs('product_first_raw_count product_second_raw_count',32)
    polynomial=b*0x57f4924c+(a+0x5cfe7d64)*(b+0xb4f30fb0)
    claims=[('product_record_mask',raw==(p^0x7043a3fa)*0x4ecee2ad),('product_zero_count_polynomial',polynomial==(a-BASE)*(b-BASE)+0xe524f7c0),
      ('product_cursor_restore',seed-112+112==seed),('product_padding_exact',pad==16*(top+1)),
      ('product_padding_bounds',z3.And(z3.UGE(pad,16),z3.ULE(pad,256))),('product_zero_adjustment',z3.Extract(15,0,seed-112+112-seed)==0)]
    out=[]
    for label,claim in claims:
        normalized=z3.simplify(claim,som=True);q=z3.Solver();q.set(timeout=60000);q.add(z3.Not(normalized));result=str(q.check());assert result=='unsat'
        out.append({'label':label,'original_claim_smt2':claim.sexpr(),'normalized_claim_smt2':normalized.sexpr(),'query':q.sexpr()+'\n(check-sat)\n','result':result,'timeout_ms':60000})
    return out


def main():
    code,banks,D=sources();reference=local_reference(code,banks,D);old=json.loads(read(ROOT/'fpsd1201_consumer_checks.json'));profiles=[]
    for mode in ['nested_retained','nested_canonical']:
        for j,p in enumerate(old['profiles']):
            profiles.append(Execute(p,j,mode,code,banks,D).run());print(json.dumps({'profiles':len(profiles),'mode':mode,'visits':len(profiles[-1]['source_visits'])}),flush=True)
    for d in direct_configurations():
        profiles.append(Execute(old['profiles'][0],None,'direct',code,banks,D,d).run())
        if len(profiles)%12==0:print(json.dumps({'profiles':len(profiles),'mode':'direct','visits':len(profiles[-1]['source_visits'])}),flush=True)
    queries=proofs();counts={'profiles':len(profiles),'retained_checkpoint_profiles':12,'canonicalized_checkpoint_profiles':12,'isolated_product_profiles':72,'prefix_instructions_rerun':0,
      **{k:sum(len(p[k])for p in profiles)for k in ['source_visits','source_reads','source_writes','PAC_models','product_points','caller_points']},
      'fresh_IDA_spans':2,'fresh_IDA_bytes':5168,'source_code_bytes':39500,'local_queries_unsat':len(queries)}
    e={'scope':__doc__,'code_spans':code,'profiles':profiles,'proofs':queries,'reference_file_check':reference,'verified_counts':counts,
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},'generator_sha256':SHA(Path(__file__).read_bytes()),
      'IDA_readback_sha256':SHA(read(ROOT/'fpsd1201_product_ida_readback.json').encode()),'whole_parent_replayed':False,
      'native_target_executed':False,'IDB_edit_operations_requested':False,'full_goal_complete':False}
    (ROOT/'fpsd1201_product_checks.json').write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
