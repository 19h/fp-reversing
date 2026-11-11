#!/usr/bin/env python3
"""CoreFP encoded-integer copy, comparison and continued context staging.

Private original-byte execution with complete leaf returns. Isolated records
are explicit diagnostic inputs; native ownership and whole-operation execution
are not inferred. O(I+C*(B+F+V+P*J+R)) time and
O(I+B+F+C*(V+J+P+R)) space; solver cost separate.
"""
import json,struct
from pathlib import Path
from hashlib import sha256
import z3
from unicorn import arm64_const as A
from recover_fpsd1201_shift import Execute as Previous,sources as old_sources,configurations as old_configurations
from recover_fpsd1201_operand import lift,CS
from recover_fpsd1201_import import Execute as Earlier,local_reference,ROOT,OWNER,SP,FP,HALT,RAM
from verify_daemon_reader_record_payloads_publication import read

COPY=0x649430;CMP=0x33abec;IR=FP+0x100;FIRST=OWNER+0x800;SECOND=OWNER+0xa00
L1=OWNER+0x1000;L2=OWNER+0x1400;MASK=0xffffffff;BASE=0x4b0cf050;K=0x1ac70ef2
SHA=lambda b:sha256(b).hexdigest()
DEPS=['recover_fpsd1201_shift.py','audit_fpsd1201_shift.py','fpsd1201_shift_checks.json','fpsd1201_shift_audit.json',
 'fpsd1201_shift_ida_readback.json','fpsd1201_operand_checks.json','fpsd1201_import_checks.json',
 'fpsd1201_record_checks.json','corefp_library_inventory.json','corefp_lookup_contracts.json','corefp_fixups_inventory.json']


def sources():
    code,banks,D=old_sources();att=json.loads(read(ROOT/'fpsd1201_comparison_ida_readback.json'))
    return code+[{**r,'role':role}for r,role in zip(att['spans'],['descriptor_copy','signed_compare'])],banks,D


def configurations():
    old=list(old_configurations())[:8]
    for c in old:yield {**c,'label':'copied_'+c['label']}
    base=old[0]
    for n in [0,1,2,3,4,5,7,8,31,32,33,63,64]:
        for sign in [-1,1]:
            for pattern in ['sequence','zero']:
                for same in [False,True]:yield {**base,'label':f'copy_{n}_{sign}_{pattern}_{same}','mode':'copy','count':n,'sign':sign,'pattern':pattern,'same_object':same}
    values=[-((1<<96)-1),-(1<<64),-0xffffffff,-1,0,1,2,0xffffffff,1<<32,1<<64,(1<<96)-1]
    pairs=[(a,b)for a in values for b in values];x=(1<<2047)+0x12345678
    pairs.extend([(x,x),(x,x+1),(x+1,x),(-x,-x),(-x,-x-1),(-x-1,-x)])
    for j,(a,b)in enumerate(pairs):yield {**base,'label':f'compare_{j}','mode':'compare','first_shex':hex(a),'second_shex':hex(b),'noncanonical':False}
    for j,(a,b)in enumerate([(1,0),(0,1),(-1,0),(0,-1)]):yield {**base,'label':f'noncanonical_zero_{j}','mode':'compare','first_shex':'0x0','second_shex':'0x0','noncanonical':True,'first_count':a,'second_count':b}


class Execute(Previous):
    def __init__(self,c,code,banks,D):
        super().__init__({**c,'mode':'nested'},code[:12],banks,D);self.c=c
        for a,n in [(0x649000,4096),(0x33a000,8192)]:self.u.mem_map(a,n)
        for r in code[12:]:
            a=int(r['start'],16);b=bytes.fromhex(r['bytes_hex']);self.u.mem_write(a,b);self.ranges.append((a,a+len(b)))
        self.copy_points=[];self.compare_points=[];self.limb_points=[]
        if c['mode']!='nested':
            self.phase=c['mode']
            if c['mode']=='copy':
                n=c['count'];self.u.mem_write(FIRST,struct.pack('<IIQ',64,(BASE+c['sign']*n)&MASK,L1 if n else 0))
                for j in range(n):
                    v=0 if c['pattern']=='zero'else(0x13579bdf+j*0x1020305)&MASK
                    self.u.mem_write(L1+4*j,(v^K).to_bytes(4,'little'))
                self.u.mem_write(SECOND,struct.pack('<IIQ',91,0xdeadbeef,L2 if n else 0))
                m=(((IR&MASK)^0x309487ae)*0x87cfdb29)&MASK
                self.u.mem_write(IR,struct.pack('<QIIQ',FIRST,(0x2f63-m)&MASK,0xa5a5a5a5,FIRST if c['same_object']else SECOND));entry=COPY
            else:
                for key,cp,d,p in [('first_shex','first_count',FIRST,L1),('second_shex','second_count',SECOND,L2)]:
                    v=int(c[key],16);n=(abs(v).bit_length()+31)//32;signed=(-n if v<0 else n)if not c['noncanonical']else c[cp]
                    self.u.mem_write(d,struct.pack('<IIQ',64,(BASE+signed)&MASK,p))
                    for j in range(max(n,abs(signed))):self.u.mem_write(p+4*j,(((abs(v)>>(32*j))&MASK)^K).to_bytes(4,'little'))
                m=(((IR&MASK)^0x302a1e77)*0xcae5b081)&MASK
                self.u.mem_write(IR,struct.pack('<QIIQII',FIRST,0xa5a5a5a5,0xa5a5a5a5,SECOND,(0x69d6-m)&MASK,0xa5a5a5a5));entry=CMP
            self.setreg(0,IR);self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_PC,entry)
            self.initial=self.frame();self.initial_RAM=self.dump()
    def descriptor(self,a):
        d=self.ram(a,16);p=int.from_bytes(d[8:],'little')
        return {'address':hex(a),'descriptor16_hex':d.hex(),'payload256_hex':self.ram(p,256).hex()if p else None}
    def leaf_point(self,pc):
        if pc in [COPY,CMP]:
            r=self.reg(0)
            if pc==COPY:self.copy_record=r
            else:self.compare_record=r
        r=self.copy_record if pc in [COPY,0x6496b0]else self.compare_record;raw=self.ram(r,32)
        e={'pc':hex(pc),'CPU':self.frame(),'record_pointer':hex(r),'record32_hex':raw.hex(),
          'first':self.descriptor(int.from_bytes(raw[:8],'little')),'second':self.descriptor(int.from_bytes(raw[16:24],'little'))}
        (self.copy_points if pc in [COPY,0x6496b0]else self.compare_points).append(e)
    def hook(self,u,pc,n,data):
        self.flush()
        if pc in [COPY,0x6496b0,CMP,0x33b0fc]:self.leaf_point(pc)
        if pc in [0x33af24,0x33afd0,0x33b02c,0x33b08c]:self.limb_points.append({'pc':hex(pc),'CPU':self.frame()})
        if pc==HALT:self.stop='returned';self.terminal=self.frame();u.emu_stop();return
        if self.c['mode']!='nested':return Earlier.hook(self,u,pc,n,data)
        super().hook(u,pc,n,data)
    def run(self):
        if self.c['mode']=='nested':p=super().run()
        else:
            self.u.emu_start(COPY if self.c['mode']=='copy'else CMP,0,count=50000);self.flush();assert self.stop=='returned'
            p={'configuration':self.c,'initial':self.initial,'initial_RAM':self.initial_RAM,'source_visits':self.visits,
              'source_reads':self.reads,'source_writes':self.writes,'PAC_models':self.pac,'CPU_points':self.points,
              'terminal':self.terminal,'final_RAM':self.dump(),'stop_reason':self.stop,'frontier':None,
              'used_original_pointer_rows':[self.D[a]for a in sorted(self.used)],'native_effects':False,
              'import_points':[],'operand_points':[],'operand_controls':[],'shift_points':[]}
        p.update({'copy_points':self.copy_points,'compare_points':self.compare_points,'limb_points':self.limb_points});return p


def proofs(code):
    p,w,n=z3.BitVecs('record encoded_limb count',32);bv=lambda v:z3.BitVecVal(v,32)
    rawmask=((p|bv(0x79866dff))+bv(0x86799200)-(p|bv(0x86799200)))^bv(0x4912ea51)
    cmpmask=((p+bv(0x3fd09f86)-((p&bv(0x3fd09f86))<<1))^bv(0x0ffa81f1))
    claims=[('copy_pointer_mask',rawmask==(p^bv(0x309487ae))),('compare_pointer_mask',cmpmask==(p^bv(0x302a1e77))),
      ('count_zero',((n+bv(BASE))+bv(0xb4f30fb0))==n)]
    ins={i.address:i for r in code for i in CS.disasm(bytes.fromhex(r['bytes_hex']),int(r['start'],16))}
    a,b=z3.BitVecs('encoded_second encoded_first',32)
    first=lift(ins,{'w3':bv(0x8011),'w5':a,'w21':b},0x33af24,0x33afd0)
    regs={'w16':bv(2),'w19':bv(0x4ee6),'w5':a,'w21':b,'w3':bv(0x8011),
      **{k:bv(v)for k,v in {'w7':0x4f23a7d1,'w23':0xb0dc582f,'w24':0x117763c2,'w25':0xee88325b,
      'w26':0xa8375087,'w27':0x57c8e19f,'w28':0xc1c66c16,'w30':0x3e3993ea,'w8':0x73367c85,'w20':0x8cc9837b}.items()}}
    second=lift(ins,regs,0x33b02c,0x33b08c)
    for phase,r in enumerate([first,second]):
        for reg,encoded in [('w16',a),('w17',b)]:
            constant=z3.simplify(z3.substitute(r[reg],(a,bv(K)),(b,bv(K)))).as_long()
            for j in range(4):claims.append((f'source_phase_{phase}_{reg}_byte_{j}',z3.Extract(8*j+7,8*j,r[reg])==z3.Extract(8*j+7,8*j,(encoded^bv(K))+bv(constant))))
    x,y,offset=z3.BitVecs('magnitude_second magnitude_first order_bias',32)
    rx,ry=x+offset,y+offset
    ordered=z3.If(z3.ULT(rx,offset)!=z3.ULT(ry,offset),z3.ULT(rx,offset),z3.UGT(rx,ry))
    claims.append(('rotated_unsigned_order',ordered==z3.UGT(x,y)))
    seed=z3.BitVec('cursor_seed',64);mix=seed*0x2e9d+1;top=z3.LShR(mix,60);pad=((top<<4)+31)&0x1f0
    claims.extend([('wrapper_padding_exact_u64',pad==((top+1)<<4)),
      ('wrapper_padding_bounds_u64',z3.And(z3.UGE(pad,16),z3.ULE(pad,256))),
      ('wrapper_padding_alignment_u64',(pad&15)==0)])
    out=[]
    for name,c in claims:
        q=z3.Solver();q.set(timeout=60000);q.add(z3.Not(c));r=str(q.check());assert r=='unsat',(name,r)
        out.append({'label':name,'query':q.sexpr()+'\n(check-sat)\n','result':r,'timeout_ms':60000})
    return out


def main():
    code,banks,D=sources();f=local_reference(code,banks,D);queries=proofs(code);profiles=[Execute(c,code,banks,D).run()for c in configurations()]
    counts={'profiles':len(profiles),'nested_profiles':sum(p['configuration']['mode']=='nested'for p in profiles),
      'isolated_copy_profiles':sum(p['configuration']['mode']=='copy'for p in profiles),'isolated_compare_profiles':sum(p['configuration']['mode']=='compare'for p in profiles),
      **{k:sum(len(p[k])for p in profiles)for k in ['source_visits','source_reads','source_writes','PAC_models','copy_points','compare_points','limb_points']},
      'fresh_IDA_spans':2,'fresh_IDA_bytes':1976,'source_code_bytes':21528,'local_queries_unsat':len(queries)}
    e={'scope':__doc__,'code_spans':code,'profiles':profiles,'proofs':queries,'reference_file_check':f,'verified_counts':counts,
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},'generator_sha256':SHA(Path(__file__).read_bytes()),
      'IDA_readback_sha256':SHA(read(ROOT/'fpsd1201_comparison_ida_readback.json').encode()),'whole_parent_replayed':False,
      'native_target_executed':False,'IDB_edit_operations_requested':False,'full_goal_complete':False}
    (ROOT/'fpsd1201_comparison_checks.json').write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
