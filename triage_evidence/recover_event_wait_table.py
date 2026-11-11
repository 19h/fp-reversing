#!/usr/bin/env python3
"""Original event-wait table startup, sizing and publication contracts.

Source and private scalar proofs only. Startup invocation, option parsing,
allocator success, table lifetime and scheduler visibility remain premises.
O(B+I+P) source/locator time and space; SMT cost is separate. No target executes.
"""
import argparse
import json
import struct

import z3
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG
from kernel_native_reader import Kernel
from kext_port_tools import ROOT
from recover_kext_cold_init import pointer
from lskd_values_symbolic import Lift, resize, part, mem, cell
from verify_daemon_reader_record_payloads_publication import read, sha

INIT=0xfffffe000c6319e4
ENTRY=0xfffffe000cbebbf8
TABLE=0xfffffe0007e66df8
COUNT=0xfffffe0007e66e00
FUNCTIONS={'startup':INIT,'option_reader':0xfffffe000c5e48a4,'allocator':0xfffffe000bdc08e0,
           'registration_wrapper':0xfffffe000bd6dfdc,'wake_wrapper':0xfffffe000bd6e22c}
DEPS=['kernel_native_reader.py','kext_port_tools.py','recover_kext_cold_init.py',
      'resolve_kernel_collection_interfaces.py','lskd_values_symbolic.py',
      'verify_daemon_reader_record_payloads_publication.py','aes_event_registration_checks.json']


class StartupLift(Lift):
    def run(self,label):
        saved=self.c;row=next(r for r in saved['spans']if r['label']==label)
        cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
        insns=list(cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)))
        assert len(insns)*4==len(bytes.fromhex(row['bytes_hex']))
        for i in insns:
            self.pc=i.address;m,o=i.mnemonic,i.operands;d=i.reg_name(o[0].reg)
            if m=='adrp':self.write(d,o[1].imm);self.count+=1
            elif m in ['umulh','umull']:
                a=self.read(i.reg_name(o[1].reg));b=self.read(i.reg_name(o[2].reg))
                product=z3.ZeroExt(a.size(),a)*z3.ZeroExt(b.size(),b)
                self.write(d,z3.Extract(127,64,product)if m=='umulh'else product);self.count+=1
            elif m=='clz':
                a=self.read(i.reg_name(o[1].reg));n=a.size();v=resize(n,n)
                for bit in range(n):v=z3.If(z3.Extract(bit,bit,a)==1,resize(n-1-bit,n),v)
                self.write(d,v);self.count+=1
            elif m=='tst':
                n=self.width(d);self.equal=(self.operand(i,o[0],n)&self.operand(i,o[1],n))==0;self.count+=1
            elif m in ['lsl','lsr']and o[2].type==ARM64_OP_REG:
                n=self.width(d);a=self.read(i.reg_name(o[1].reg));shift=resize(self.read(i.reg_name(o[2].reg)),n)&(n-1)
                self.write(d,a<<shift if m=='lsl'else z3.LShR(a,shift));self.count+=1
            else:
                self.c={'spans':[{'label':label,'start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}
                super().run(label)
        self.c=saved;return self


def locators(k):
    """Bounded ADRP/nearby-STR candidates, not a complete alias-write census."""
    rows=[];seen=set();scans=[]
    for s in k.kernel['segments']:
        if s['name']not in ['__TEXT_EXEC','__TEXT_BOOT_EXEC','__KLD']:continue
        raw=k.read(s['address'],s['file_size']);pages=0
        for off in range(0,len(raw)-3,4):
            w=struct.unpack_from('<I',raw,off)[0]
            if w&0x9f000000!=0x90000000:continue
            imm=((w>>5)&0x7ffff)<<2|((w>>29)&3);imm-=((imm>>20)&1)<<21
            page=((s['address']+off)&~0xfff)+(imm<<12)
            if page!=TABLE&~0xfff:continue
            pages+=1;a=s['address']+off
            ins=list(k.cs.disasm(k.read(a,192),a));reg=ins[0].op_str.split(',')[0]
            for i in ins[1:]:
                if not(i.mnemonic.startswith('st')and any(f'[{reg}, #{hex(p&0xfff)}]'in i.op_str for p in [TABLE,COUNT])):continue
                if i.address in seen:continue
                seen.add(i.address);rows.append({'adrp':hex(a),'candidate_store':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str})
        scans.append({'segment':s['name'],'start':hex(s['address']),'bytes':len(raw),'aligned_words':len(raw)//4,'page_ADRP_candidates':pages})
    return {'window_B':192,'scope':'Kernel executable segments only; matching immediate offsets after a page ADRP. Register aliasing, other addressing forms and indirect writers are not closed.',
            'scans':scans,'candidates':rows}


def prove(capture):
    proofs={};pieces={}
    B=z3.BitVec('candidate_budget64',64);T=z3.BitVec('default_parameter32',32)
    Q=z3.BitVec('bucket_quotient64',64);C=z3.BitVec('leading_zeroes64',64)
    N=z3.BitVec('bucket_count32',32);J=z3.BitVec('bucket_index64',64)
    A=z3.BitVec('table_base64',64);R=z3.BitVec('allocator_result64',64)
    S=0x51000000
    def run(name,a,z,seeds,cells=()):
        obj=StartupLift(part(capture,name,a,z))
        for r,v in seeds.items():obj.seed(r,v)
        for at,n,v in cells:mem(obj,at,n,v)
        obj.run(name);assert obj.count==(z-a)//4
        pieces[name]={'start':hex(a),'end':hex(z),'instructions':obj.count};return obj
    def query(name,expression):proofs[name]=expression
    o=run('option_arguments',0xfffffe000c6319f8,0xfffffe000c631a1c,{'sp':S},[(0xfffffe0007f8b6e8,8,A)])
    query('option_arguments',z3.Or(o.read('x0')!=A+0x6c,o.read('x1')!=0xfffffe0007052e9a,o.read('x2')!=S+8,o.read('w3')!=8,o.read('w4')!=0,cell(o,S+8,8)!=0))
    o=run('default_budget',0xfffffe000c631a2c,0xfffffe000c631a58,{},[(0xfffffe000caa30c4,4,T)])
    p=T*24;f=z3.LShR(z3.ZeroExt(32,p)*resize(0xcccccccd,64),34)
    expected=(resize(f,32)+0x3fff)&0x7fffc000
    query('default_source_budget',o.read('x8')!=z3.ZeroExt(32,expected))
    query('default_budget_page_alignment',(o.read('x8')&0x3fff)!=0)
    query('default_budget_upper_bound',z3.UGT(o.read('x8'),0x7fffc000))
    query('default_nonzero_budget_domain',z3.And(o.read('x8')!=0,z3.Or(z3.ULT(o.read('x8'),24),z3.UGE(o.read('x8'),24*(1<<27)))))
    o=run('budget_quotient',0xfffffe000c631a58,0xfffffe000c631a68,{'x8':B})
    query('source_division_product',o.read('x8')!=resize(z3.Extract(127,68,z3.ZeroExt(64,B)*resize(0xaaaaaaaaaaaaaaab,128)),64))
    # Integer Euclidean-decomposition certificates avoid assuming a host divide.
    q,r=z3.Ints('euclidean_quotient euclidean_remainder')
    for name,width,divisor,magic,shift in [('u32_by5',32,5,0xcccccccd,34),('u64_by24',64,24,0xaaaaaaaaaaaaaaab,68)]:
        numerator=divisor*q+r
        query(name+'_magic_division',z3.And(q>=0,r>=0,r<divisor,numerator<(1<<width),(numerator*magic)/(1<<shift)!=q))
    o=run('quotient_clz',0xfffffe000c631a68,0xfffffe000c631a6c,{'x8':Q})
    z=o.read('x8')
    query('clz_zero',z3.And(Q==0,z!=64))
    query('clz_range',z3.UGT(z,64))
    # Each nonzero bit-length interval is checked separately, keeping all widths.
    for b in range(64):
        query('clz_interval_'+str(b),z3.And(z3.UGE(Q,1<<b),z3.ULE(Q,(1<<(b+1))-1),z!=63-b))
    o=run('count_publication',0xfffffe000c631a6c,0xfffffe000c631a7c,{'x8':C})
    count=z3.LShR(resize(0x80000000,32),resize(C,32)&31)
    query('count_publication',cell(o,COUNT,4)!=count)
    query('count_positive_power_two',z3.Or(count==0,(count&(count-1))!=0))
    o=run('allocation_extent',0xfffffe000c631a7c,0xfffffe000c631a94,{'x8':C})
    extent=resize(((resize(24,32)<<((~resize(C,32))&31))+0x3fff)&0xffffc000,32)
    query('allocation_extent',o.read('w1')!=extent)
    query('allocation_extent_page_alignment',(o.read('w1')&0x3fff)!=0)
    valid=z3.And(z3.UGE(C,37),z3.ULE(C,63))
    full=z3.ZeroExt(32,count)*24
    query('valid_extent_covers_buckets',z3.And(valid,z3.ULT(z3.ZeroExt(32,o.read('w1')),full)))
    query('valid_extent_slack',z3.And(valid,z3.UGE(z3.ZeroExt(32,o.read('w1'))-full,0x4000)))
    query('valid_count_checked_offset_bound',z3.And(valid,z3.UGT(count,1<<26)))
    o=run('allocation_arguments',0xfffffe000c631a94,0xfffffe000c631ab0,{'w1':N},[(0xfffffe0007f860a8,8,A)])
    query('allocation_arguments',z3.Or(o.read('x0')!=A,o.read('w1')!=N,o.read('x2')!=0,o.read('w3')!=0x200103,o.read('w4')!=0x11,o.read('x5')!=0))
    o=run('root_publication',0xfffffe000c631ab4,0xfffffe000c631abc,{'x1':R})
    query('root_publication',cell(o,TABLE,8)!=R)
    o=run('allocator_return_pair',0xfffffe000bdc1094,0xfffffe000bdc109c,{'w27':N,'x26':R})
    query('allocator_return_pair',z3.Or(o.read('w0')!=N,o.read('x1')!=R))
    o=run('record_address',0xfffffe000c631ad4,0xfffffe000c631ae0,{'x8':TABLE&~0xfff,'x9':J},[(TABLE,8,A)])
    query('record_address',o.read('x13')!=A+24*J)
    target=o.read('x13')
    o=run('record_pointer_guard',0xfffffe000c631ae0,0xfffffe000c631ae8,{'x11':A,'x13':target})
    mask=resize(0xffc0000000000000,64)
    query('record_same_region_no_poison',z3.And((A&mask)==(target&mask),z3.Not(o.equal)))
    query('valid_last_record_fits',z3.And(N!=0,z3.ULE(N,1<<26),z3.ULT(J,z3.ZeroExt(32,N)),z3.UGT(J*24+24,z3.ZeroExt(32,N)*24)))
    o=run('record_stores',0xfffffe000c631af0,0xfffffe000c631afc,{'x13':A,'d0':9,'w10':0x144})
    query('record_store_ledger',z3.Or(cell(o,A,8)!=9,cell(o,A+8,8)!=0,cell(o,A+16,8)!=0,cell(o,A+4,4)!=0x144))
    query('record_validity_bit',resize((0x144>>8)&1,32)!=1)
    o=run('record_advance',0xfffffe000c631afc,0xfffffe000c631b08,{'x9':J,'x19':COUNT&~0xfff},[(COUNT,4,N)])
    query('record_advance',z3.Or(o.read('x9')!=J+1,o.cmp_left!=J+1,o.cmp_right!=z3.ZeroExt(32,N)))
    o=run('special_queue_stores',0xfffffe000c631b14,0xfffffe000c631b34,{},[(0xfffffe000700dd78,8,12)])
    special=0xfffffe000cb4ff08
    query('special_queue_store_ledger',z3.Or(cell(o,special,8)!=12,cell(o,special+8,8)!=0,cell(o,special+16,8)!=0,cell(o,special+4,4)!=0x144))
    saved={}
    for name,expression in proofs.items():
        solver=z3.Solver();solver.set(timeout=15000);solver.add(expression);result=solver.check()
        assert result==z3.unsat,(name,str(result),solver.reason_unknown())
        saved[name]={'query':solver.to_smt2(),'result':str(result)}
    return saved,pieces


def build():
    k=Kernel();spans=[]
    for label,a in FUNCTIONS.items():
        row=k.function(a);row['label']=label;row['bytes_hex']=row.pop('bytes');spans.append(row)
    c={'spans':spans};proofs,pieces=prove(c)
    section=next(s for s in k.kernel['sections']if s['section']=='__init_entry_set')
    assert section['address']<=ENTRY<ENTRY+24<=section['address']+section['size']and(ENTRY-section['address'])%24==0
    raw=k.read(ENTRY,24);assert struct.unpack_from('<II',raw)==(14,0)and raw[16:]==bytes(8)
    callback=pointer(k,ENTRY+8);assert int(callback['target'],16)==INIT and callback['authenticated']
    locator=locators(k);assert {r['candidate_store']for r in locator['candidates']}=={'0xfffffe000c631a78','0xfffffe000c631ab8'}
    data={name:{'address':hex(a),'bytes_hex':k.read(a,n).hex()}for name,a,n in [
      ('option_name',0xfffffe0007052e9a,7),('parameter_file_word',0xfffffe000caa30c4,4),
      ('record_seed',0xfffffe000700dd70,8),('special_seed',0xfffffe000700dd78,8),('initial_count',COUNT,4)]}
    assert data['option_name']['bytes_hex']==b'wqsize\0'.hex()
    counts={'queries_unsat':len(proofs),'source_pieces':len(pieces),'source_lifted_instances':sum(r['instructions']for r in pieces.values()),
            'spans':len(spans),'instructions':sum(len(r['instructions'])for r in spans),'startup_entries':1,'writer_locator_candidates':2}
    counts['code_B']=counts['instructions']*4
    return {'scope':__doc__,'generator_sha256':sha(__file__),'kernel_collection_sha256':k.sha256,
      'dependencies':{p:sha(ROOT/p)for p in DEPS},'spans':spans,'proofs':proofs,'source_pieces':pieces,
      'startup_entry':{'section':section,'address':hex(ENTRY),'bytes_hex':raw.hex(),'callback':callback,'phase32':14,'rank32':0,'argument64':0},
      'data':data,'slots':{hex(a):pointer(k,a)for a in [TABLE,0xfffffe000cbebc00]},
      'exact_symbols':k.symbols(list(FUNCTIONS.values())+[0xfffffe0007f860a8]),'writer_locators':locator,'verified_counts':counts,
      'new_IDA_access':False,'new_native_execution':False,'new_IDB_mutations':False,'full_goal_complete':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--verify',action='store_true');args=parser.parse_args()
    out=build();p=ROOT/'event_wait_table_checks.json'
    if args.verify:assert json.loads(read(p))==out
    else:p.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps(out['verified_counts']),flush=True)
