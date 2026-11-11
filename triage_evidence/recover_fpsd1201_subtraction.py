#!/usr/bin/env python3
"""CoreFP signed in-place subtraction and original magnitude dependencies.

Private original-byte execution; no protected result or native API is supplied.
Nested cases stop immediately after the complete subtraction return. Direct
leaf fixtures test separate and aliased destinations with declared backing.
O(I+C*(B+F+V+P*J+R)) time and O(I+B+F+C*(V+J+P+R)) space;
SMT cost separate. Full outer arithmetic and native lineage remain open.
"""
import json,struct
from pathlib import Path
from hashlib import sha256
import z3
from unicorn import arm64_const as A
from recover_fpsd1201_comparison import Execute as Previous,sources as old_sources,configurations as old_configurations
from recover_fpsd1201_import import Execute as Earlier,local_reference,ROOT,OWNER,SP,FP,HALT,RAM
from verify_daemon_reader_record_payloads_publication import read

ENTRY=0x5e8158;SUB=0x1ec40;ADD=0x443bf4;IR=FP+0x100
FIRST=OWNER+0x800;SECOND=OWNER+0xa00;THIRD=OWNER+0xc00;L1=OWNER+0x1000;L2=OWNER+0x1800;L3=OWNER+0x2800
BASE=0x4b0cf050;K=0x1ac70ef2;MASK=0xffffffff;SHA=lambda b:sha256(b).hexdigest()
DEPS=['recover_fpsd1201_comparison.py','audit_fpsd1201_comparison.py','fpsd1201_comparison_checks.json',
 'fpsd1201_comparison_audit.json','fpsd1201_comparison_ida_readback.json','fpsd1201_shift_checks.json',
 'fpsd1201_operand_checks.json','fpsd1201_import_checks.json','fpsd1201_record_checks.json',
 'corefp_library_inventory.json','corefp_lookup_contracts.json','corefp_fixups_inventory.json']
ENTRIES=[ENTRY,SUB,ADD];EXITS=[0x5e8638,0x1f380,0x4441bc]
DEP_ENTRIES=[0x649430,0x624ff0,0x5dcd08];DEP_EXITS=[0x6496b0,0x625260,0x5dcec4]
STEPS=[0x1ef68,0x1ef8c,0x1f014,0x1f034,0x1f0f4,0x1f110,0x1f1e0,0x1f1f4,
 0x443ee0,0x443f00,0x443fb4,0x443fd0,0x4440c0,0x4440d8]


def sources():
    code,banks,D=old_sources();att=json.loads(read(ROOT/'fpsd1201_subtraction_ida_readback.json'))
    return code+[{**r,'role':role}for r,role in zip(att['spans'],['signed_subtraction','magnitude_difference','magnitude_addition'])],banks,D


def configurations():
    old=list(old_configurations())[:8]
    for c in old:yield {**c,'label':'subtracted_'+c['label']}
    base=old[0];values=[-((1<<96)-1),-(1<<64),-0xffffffff,-1,0,1,2,0xffffffff,1<<32,1<<64,(1<<96)-1]
    pairs=[(a,b)for a in values for b in values];w=(1<<2048)-1
    pairs.extend([(-1,w),(1,w),(-w,1),(w,-1),(w,w),(w,w-1),(w-1,w),(-w,-w)])
    for j,(a,b)in enumerate(pairs):yield {**base,'label':f'root_{j}','mode':'root','first_shex':hex(a),'second_shex':hex(b),'alias':'second','null_second':False}
    for j,v in enumerate(values):yield {**base,'label':f'self_{j}','mode':'root','first_shex':hex(v),'second_shex':hex(v),'alias':'self','null_second':False}
    yield {**base,'label':'zero_first_null_second','mode':'root','first_shex':'0x0','second_shex':'0x0','alias':'second','null_second':True}
    leafpairs=[(1,2),(2,1),(-1,2),(1,-2),(-2,-1),(0xffffffff,1),(1,0xffffffff),(w,1)]
    for mode in ['leaf_sub','leaf_add']:
        for j,(a,b)in enumerate(leafpairs):
            for alias in ['distinct','first','second']:yield {**base,'label':f'{mode}_{j}_{alias}','mode':mode,'first_shex':hex(a),'second_shex':hex(b),'alias':alias,'null_second':False}


class Execute(Previous):
    def __init__(self,c,code,banks,D):
        super().__init__({**c,'mode':'nested'},code[:14],banks,D);self.c=c;self.arithmetic_active=False
        for a,n in [(0x5e8000,4096),(0x1e000,8192),(0x443000,8192)]:self.u.mem_map(a,n)
        for r in code[14:]:
            a=int(r['start'],16);b=bytes.fromhex(r['bytes_hex']);self.u.mem_write(a,b);self.ranges.append((a,a+len(b)))
        self.arithmetic_points=[];self.dependency_points=[];self.carry_points=[];self.dependency_stack=[]
        if c['mode']!='nested':
            self.phase=c['mode']
            for d,p,v in [(FIRST,L1,int(c['first_shex'],16)),(SECOND,L2,int(c['second_shex'],16)),(THIRD,L3,0)]:
                n=(abs(v).bit_length()+31)//32;self.u.mem_write(d,struct.pack('<IIQ',91 if d==THIRD else 64,(BASE+(-n if v<0 else n))&MASK,p))
                for j in range(n):self.u.mem_write(p+j*4,(((abs(v)>>(32*j))&MASK)^K).to_bytes(4,'little'))
            second=0 if c['null_second']else FIRST if c['alias']=='self'else SECOND
            out={'distinct':THIRD,'first':FIRST,'second':SECOND,'self':FIRST}[c['alias']]
            m=(((IR&MASK)^0x309487ae)*0x87cfdb29)&MASK
            if c['mode']=='root':
                rm=((((IR&MASK)^0x7043a3fa)*0x4ecee2ad)&MASK)
                raw=struct.pack('<IIQQ',rm^0xf136,0xa5a5a5a5,FIRST,second);entry=ENTRY
            elif c['mode']=='leaf_sub':raw=struct.pack('<QQIIQ',FIRST,SECOND,(m+0x5c71)&MASK,0xa5a5a5a5,out);entry=SUB
            else:raw=struct.pack('<QQQII',FIRST,out,SECOND,m^0x99bf,0xa5a5a5a5);entry=ADD
            self.u.mem_write(IR,raw);self.setreg(0,IR);self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_PC,entry)
            self.initial=self.frame();self.initial_RAM=self.dump();self.direct_entry=entry
    def desc(self,a):
        if a==0:return None
        d=self.ram(a,16);p=int.from_bytes(d[8:],'little')
        return {'address':hex(a),'descriptor16_hex':d.hex(),'payload512_hex':self.ram(p,512).hex()if p else None}
    def arithmetic_point(self,pc):
        if pc in ENTRIES:
            r=self.reg(0);raw=self.ram(r,32)
            if not self.arithmetic_active:
                if pc==ENTRY:a,b,out=(int.from_bytes(raw[j:j+8],'little')for j in [8,16,16])
                elif pc==SUB:a,b,out=(int.from_bytes(raw[j:j+8],'little')for j in [0,8,24])
                else:a,b,out=(int.from_bytes(raw[j:j+8],'little')for j in [0,16,8])
                self.root_record=r;self.first=a;self.second=b;self.output=out;self.arithmetic_active=True
        e={'pc':hex(pc),'CPU':self.frame(),'root_record_pointer':hex(self.root_record),'root_record32_hex':self.ram(self.root_record,32).hex(),
          'first':self.desc(self.first),'second':self.desc(self.second),'output':self.desc(self.output)}
        if pc in ENTRIES:e.update({'argument_pointer':hex(self.reg(0)),'argument32_hex':self.ram(self.reg(0),32).hex()})
        self.arithmetic_points.append(e)
    def dependency_point(self,pc):
        if pc in DEP_ENTRIES:
            r=self.reg(0);self.dependency_stack.append((pc,r))
        else:
            entry,r=self.dependency_stack.pop();assert DEP_EXITS.index(pc)==DEP_ENTRIES.index(entry)
        raw=self.ram(r,32);a=int.from_bytes(raw[:8],'little');e={'pc':hex(pc),'CPU':self.frame(),'record_pointer':hex(r),'record32_hex':raw.hex(),'first':self.desc(a)}
        if pc in [0x649430,0x6496b0]:e['second']=self.desc(int.from_bytes(raw[16:24],'little'))
        self.dependency_points.append(e)
    def hook(self,u,pc,n,data):
        self.flush()
        if pc in ENTRIES+EXITS:self.arithmetic_point(pc)
        if self.arithmetic_active and pc in DEP_ENTRIES+DEP_EXITS:self.dependency_point(pc)
        if self.arithmetic_active and pc in STEPS:self.carry_points.append({'pc':hex(pc),'CPU':self.frame()})
        if pc in [HALT,0x14f9d78]:
            self.arithmetic_point(pc);self.stop='returned'if pc==HALT else'after_subtraction_return';self.terminal=self.frame()
            self.frontier=None if pc==HALT else{'pc':hex(pc),'instruction_executed':False,'completed_callee':hex(ENTRY)};u.emu_stop();return
        if self.arithmetic_active:return Earlier.hook(self,u,pc,n,data)
        super().hook(u,pc,n,data)
    def run(self):
        if self.c['mode']=='nested':p=super().run()
        else:
            self.u.emu_start(self.direct_entry,0,count=50000);self.flush();assert self.stop=='returned'
            p={'configuration':self.c,'initial':self.initial,'initial_RAM':self.initial_RAM,'source_visits':self.visits,
              'source_reads':self.reads,'source_writes':self.writes,'PAC_models':self.pac,'CPU_points':self.points,
              'terminal':self.terminal,'final_RAM':self.dump(),'stop_reason':self.stop,'frontier':None,
              'used_original_pointer_rows':[self.D[a]for a in sorted(self.used)],'native_effects':False,
              'import_points':[],'operand_points':[],'operand_controls':[],'shift_points':[],'copy_points':[],'compare_points':[],'limb_points':[]}
        assert not self.dependency_stack;p.update({'arithmetic_points':self.arithmetic_points,'dependency_points':self.dependency_points,'carry_points':self.carry_points});return p


def proofs():
    p,u,v,n=z3.BitVecs('record decoded_first decoded_second signed_count',32)
    bv=lambda x:z3.BitVecVal(x,32)
    raw=(((bv(0xb53439e4)|(p<<1))-p+bv(0xa565e30e))^bv(0x2ad9bf08))
    claims=[('root_pointer_mask',raw==(p^bv(0x7043a3fa))),
      ('negated_encoded_count',bv(2*BASE)-(bv(BASE)+n)==bv(BASE)-n),
      ('complement_codec',(u^bv(0xe538f10d))==~(u^bv(K)))]
    encoded=u-(bv(0x358e1de4)&(u<<1))+bv(K)
    claims.extend((f'limb_encoding_byte_{j}',z3.Extract(j*8+7,j*8,encoded)==z3.Extract(j*8+7,j*8,u^bv(K)))for j in range(4))
    c=z3.BitVec('carry',64);a=z3.ZeroExt(32,u);b=z3.ZeroExt(32,v)
    s=a+b+c;t=a+c-b+z3.BitVecVal(MASK,64);valid=z3.ULE(c,1)
    claims.extend([('sum_low_word',z3.Implies(valid,z3.Extract(31,0,s)==u+v+z3.Extract(31,0,c))),
      ('sum_carry_bound',z3.Implies(valid,z3.ULE(z3.LShR(s,32),1))),
      ('difference_low_word',z3.Implies(valid,z3.Extract(31,0,t)==u-v-(1-z3.Extract(31,0,c)))),
      ('difference_no_borrow',z3.Implies(valid,z3.LShR(t,32)==z3.If(z3.UGE(a+c,b+1),z3.BitVecVal(1,64),z3.BitVecVal(0,64))))])
    out=[]
    for name,claim in claims:
        q=z3.Solver();q.set(timeout=60000);q.add(z3.Not(claim));result=str(q.check());assert result=='unsat',(name,result)
        out.append({'label':name,'query':q.sexpr()+'\n(check-sat)\n','result':result,'timeout_ms':60000})
    return out


def main():
    code,banks,D=sources();f=local_reference(code,banks,D);queries=proofs();profiles=[]
    for c in configurations():
        profiles.append(Execute(c,code,banks,D).run())
        if len(profiles)%20==0:print(json.dumps({'completed_profiles':len(profiles)}),flush=True)
    counts={'profiles':len(profiles),'nested_profiles':sum(p['configuration']['mode']=='nested'for p in profiles),
      'isolated_root_profiles':sum(p['configuration']['mode']=='root'for p in profiles),
      'isolated_difference_profiles':sum(p['configuration']['mode']=='leaf_sub'for p in profiles),
      'isolated_addition_profiles':sum(p['configuration']['mode']=='leaf_add'for p in profiles),
      **{k:sum(len(p[k])for p in profiles)for k in ['source_visits','source_reads','source_writes','PAC_models','arithmetic_points','dependency_points','carry_points']},
      'fresh_IDA_spans':3,'fresh_IDA_bytes':4608,'source_code_bytes':26136,'local_queries_unsat':len(queries)}
    e={'scope':__doc__,'code_spans':code,'profiles':profiles,'proofs':queries,'reference_file_check':f,'verified_counts':counts,
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},'generator_sha256':SHA(Path(__file__).read_bytes()),
      'IDA_readback_sha256':SHA(read(ROOT/'fpsd1201_subtraction_ida_readback.json').encode()),'whole_parent_replayed':False,
      'native_target_executed':False,'IDB_edit_operations_requested':False,'full_goal_complete':False}
    (ROOT/'fpsd1201_subtraction_checks.json').write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
