#!/usr/bin/env python3
"""CoreFP signed-shift dispatcher and both limb paths, private execution only.

Original dependencies execute through complete primitive returns. Isolated
records are bounded diagnostic inputs; nested context patches retain their
earlier timing. No native API, protected result or whole-parent replay.
O(I+C*(B+F+V+P*J+R)) time and O(I+B+F+C*(V+J+P+R)) space;
solver cost separate. P*J is the retained PAC/read association search.
"""
import json,struct
from pathlib import Path
from hashlib import sha256
import z3
from unicorn import arm64_const as A
from recover_fpsd1201_operand import Execute as Previous,sources as old_sources,configurations as old_configurations,K,lift,CS
from recover_fpsd1201_import import Execute as Earlier,local_reference,ROOT,OWNER,SP,FP,HALT,RAM
from recover_fpsd1201_record import RECORD,OUT
from verify_daemon_reader_record_payloads_publication import read

ENTRY=0x5a600c;IR=FP+0x100;DESC=OWNER+0x800;LIMBS=OWNER+0x1000
MASK=0xffffffff;BASE=0x4b0cf050;SHA=lambda b:sha256(b).hexdigest()
DEPS=['recover_fpsd1201_operand.py','audit_fpsd1201_operand.py','fpsd1201_operand_checks.json',
 'fpsd1201_operand_audit.json','fpsd1201_operand_ida_readback.json','recover_fpsd1201_import.py',
 'audit_fpsd1201_import.py','recover_fpsd1201_record.py','audit_fpsd1201_record.py',
 'fpsd1201_import_checks.json','fpsd1201_record_checks.json','corefp_library_inventory.json',
 'corefp_lookup_contracts.json','corefp_fixups_inventory.json','probe_daemon_descriptor_source.py']
SPANS=[(0x5a6000,4096),(0x4be000,4096),(0x624000,8192),(0x5dc000,4096)]
ENTRIES=[ENTRY,0x5a6774,0x4be1cc,0x624ff0,0x5dcd08]
POINTS=ENTRIES+[0x5a69d4,0x4be418,0x625204,0x14f940c,HALT]


def sources():
    code,banks,D=old_sources();att=json.loads(read(ROOT/'fpsd1201_shift_ida_readback.json'))
    return code+[{**r,'role':role}for r,role in zip(att['spans'],['signed_shift','left_shift','right_shift','sign_query','zero_query'])],banks,D


def configurations():
    backed=[c for c in old_configurations()if c['backed']]
    for c in backed[:4]+backed[-4:]:yield {**c,'label':'continued_'+c['label']}
    base={**backed[0],'mode':'isolated'}
    for v in [0,1,0xffffffff,0x123456789abcdef012345678]:
        for sign in [-1,1]:
            for shift in [-129,-65,-64,-63,-33,-32,-31,-1,0,1,31,32,33,63,64,65,129]:
                yield {**base,'label':f'isolated_{v:x}_{sign}_{shift}','value_hex':hex(v),'sign':sign,'shift_s32':shift}


class Execute(Previous):
    def __init__(self,c,code,banks,D):
        super().__init__({**c,'mode':'nested'},code[:7],banks,D);self.c=c
        for a,n in SPANS:self.u.mem_map(a,n)
        for r in code[7:]:
            a=int(r['start'],16);b=bytes.fromhex(r['bytes_hex']);self.u.mem_write(a,b);self.ranges.append((a,a+len(b)))
        self.shift_points=[]
        if c['mode']=='isolated':
            self.phase='isolated';v=int(c['value_hex'],16);count=(v.bit_length()+31)//32
            self.u.mem_write(DESC,struct.pack('<IIQ',64,(BASE+c['sign']*count)&MASK,LIMBS))
            for j in range(count):self.u.mem_write(LIMBS+4*j,(((v>>(32*j))&MASK)^K).to_bytes(4,'little'))
            m=(((IR&MASK)^0x309487ae)*0x87cfdb29)&MASK
            self.u.mem_write(IR,struct.pack('<IIQ',(m+c['shift_s32']-0xa2eae272)&MASK,(m+0xc215)&MASK,DESC))
            self.setreg(0,IR);self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_PC,ENTRY)
            self.initial=self.frame();self.initial_RAM=self.dump()
    def shift_point(self,pc):
        if pc==ENTRY:
            self.shift_record=self.reg(0);self.shift_desc=int.from_bytes(self.ram(self.shift_record+8,8),'little')
        d=self.ram(self.shift_desc,16);p=int.from_bytes(d[8:],'little')
        e={'pc':hex(pc),'CPU':self.frame(),'root_record_pointer':hex(self.shift_record),
          'root_record16_hex':self.ram(self.shift_record,16).hex(),'descriptor_pointer':hex(self.shift_desc),
          'descriptor16_hex':d.hex(),'limb256_hex':self.ram(p,256).hex()}
        if pc in ENTRIES:e.update({'argument_pointer':hex(self.reg(0)),'argument24_hex':self.ram(self.reg(0),24).hex()})
        self.shift_points.append(e)
    def hook(self,u,pc,n,data):
        self.flush()
        if pc in POINTS:self.shift_point(pc)
        if pc==HALT:
            self.stop='returned';self.terminal=self.frame();u.emu_stop();return
        if pc==0x14f9408:return Earlier.hook(self,u,pc,n,data)
        if self.c['mode']=='isolated':return Earlier.hook(self,u,pc,n,data)
        super().hook(u,pc,n,data)
    def run(self):
        if self.c['mode']=='nested':p=super().run()
        else:
            self.u.emu_start(ENTRY,0,count=50000);self.flush();assert self.stop=='returned'
            p={'configuration':self.c,'initial':self.initial,'initial_RAM':self.initial_RAM,'source_visits':self.visits,
              'source_reads':self.reads,'source_writes':self.writes,'PAC_models':self.pac,'CPU_points':self.points,
              'terminal':self.terminal,'final_RAM':self.dump(),'stop_reason':self.stop,'frontier':None,
              'used_original_pointer_rows':[self.D[a]for a in sorted(self.used)],'native_effects':False,
              'import_points':[],'operand_points':[],'operand_controls':[]}
        p['shift_points']=self.shift_points;return p


def proofs(code):
    p,s,n,w=z3.BitVecs('record shift count limb',32);b=lambda x:z3.BitVecVal(x,32)
    m=((~(p^b(0xface52ec)))^b(0x35a52abd))*b(0x87cfdb29)
    left=(((p&b(0x6f28530a))*2-p+b(0x10d7acf5))^b(0x44f8136e))*b(0x4386951d)
    parent=(p^b(0x542fbf9b))*b(0x4386951d)
    right=((~(p^b(0x7c11f102)))^b(0xd7c1b166))*b(0x4386951d)
    claims=[('wrapper_pointer_codec',m==(p^b(0x309487ae))*b(0x87cfdb29)),
      ('signed_route_partition',z3.ULT(s-1,b(0x7fffffff))==(s>0)),
      ('left_child_mask_identity',left==parent),('right_child_mask_identity',right==parent),
      ('left_word_offset',z3.LShR(s^b(0x86b3c60e),5)^b(0x04359e30)==z3.LShR(s,5)),
      ('left_bit_offset',((s^b(0x86b3c60e))&31)^14==(s&31)),
      ('right_word_offset',z3.LShR(s^b(0x5092d4e4),5)^b(0x028496a7)==z3.LShR(s,5)),
      ('right_bit_offset',((s^b(0x5092d4e4))&31)^4==(s&31)),
      ('encoded_limb',w-(b(0x358e1de4)&(w<<1))+b(K)==(w^b(K))),
      ('caller_count_shift',((n<<5)^b(0xfdd77dde))+((n<<6)&b(0xfbaefb80))+b(0x5f3d9fb0)+b(0xa2eae272)==n<<5)]
    ins={i.address:i for r in code for i in CS.disasm(bytes.fromhex(r['bytes_hex']),int(r['start'],16))}
    r=lift(ins,{'w15':s+b(0x5d151d8e),'w16':b(0xa2eae271),'w0':b(0xc215)},0x5a61e4,0x5a6340)
    claims.extend(('source_left_amount_byte_'+str(j),z3.Extract(8*j+7,8*j,r['w15'])==z3.Extract(8*j+7,8*j,s^b(0x86b3c60e)))for j in range(4))
    r=lift(ins,{'w20':b(0x3e70),'w15':s+b(0x5d151d8e)},0x5a63f8,0x5a642c)
    ar=b(0xada7f272)-(s+b(0x5d151d8e))-r['w16']
    claims.append(('source_right_amount',ar==((-s)^b(0x5092d4e4))))
    out=[]
    for name,claim in claims:
        q=z3.Solver();q.set(timeout=60000);q.add(z3.Not(claim));v=str(q.check());assert v=='unsat',(name,v)
        out.append({'label':name,'result':v,'query':q.sexpr()+'\n(check-sat)\n','timeout_ms':60000})
    return out


def main():
    code,banks,D=sources();f=local_reference(code,banks,D);queries=proofs(code);profiles=[]
    for c in configurations():profiles.append(Execute(c,code,banks,D).run())
    counts={'profiles':len(profiles),'nested_profiles':sum(p['configuration']['mode']=='nested'for p in profiles),
      'isolated_profiles':sum(p['configuration']['mode']=='isolated'for p in profiles),
      **{k:sum(len(p[k])for p in profiles)for k in ['source_visits','source_reads','source_writes','PAC_models','shift_points']},
      'fresh_IDA_spans':5,'fresh_IDA_bytes':5700,'source_code_bytes':19552,'local_queries_unsat':len(queries)}
    e={'scope':__doc__,'code_spans':code,'profiles':profiles,'proofs':queries,'reference_file_check':f,'verified_counts':counts,
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},'generator_sha256':SHA(Path(__file__).read_bytes()),
      'IDA_readback_sha256':SHA(read(ROOT/'fpsd1201_shift_ida_readback.json').encode()),'whole_parent_replayed':False,
      'native_target_executed':False,'IDB_edit_operations_requested':False,'full_goal_complete':False}
    (ROOT/'fpsd1201_shift_checks.json').write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
