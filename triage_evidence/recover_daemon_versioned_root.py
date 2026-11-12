#!/usr/bin/env python3
"""Whole daemon root admission, constructor paths and private allocator lifetime.

O(snapshot+prefix+cases*(visits+effects)) time/space;30 s/query.
Original bytes, declared records and malloc/free models; no native API/IPC.
"""
import copy,json
from pathlib import Path
from collections import Counter
import z3
from capstone.arm64_const import ARM64_OP_REG
from daemon_receive_tools import ROOT,IMAGE,FIXUPS,TABLE,CS
from daemon_callback_revisit_symbolic import Revisit,ALLOWED_CALLS
from lskd_values_symbolic import resize,mem,cell
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_daemon_versioned_header as H
P='daemon_versioned_root';ENTRY=0x10049f358;RET=0x100309d10;RETURN=0x7c200000;MALLOC=0x100455e58;FREE=0x1002dc500
PINS={**H.PINS,'daemon_versioned_header_checks.json':'0567208d2807a90c176f476e393f5123192143c3fa856a0e86cf380f74f06fe0',
 'daemon_versioned_header_audit.json':'8219f4c7a9289dce98e1b6438cfeef41df9d435c257dee5c7acd6d5e801a3bd8'}
DEPS=H.DEPS+['recover_daemon_versioned_header.py','audit_daemon_versioned_header.py','recover_daemon_callback_revisit.py','daemon_import_bindings.py']
SPECS=[('root_entry',ENTRY,0x10049f5b8),('initializer_call',0x1003af8fc,0x1003af9d4),('initializer',0x100455c30,0x100455e98),
 ('initializer_success',0x10031cb3c,0x10031cbc4),('initializer_return',0x1004b1d68,0x1004b1d80),('paired_pointer_gate',0x1001c00f8,0x1001c0128),('root_epilogue',0x100309cd8,0x100309d18)]

class Extra:
 def one(self,i):
  o=i.operands;self.pc=i.address;m=i.mnemonic
  if m=='ubfx':
   n=self.width(i.reg_name(o[0].reg));self.write(i.reg_name(o[0].reg),z3.LShR(self.operand(i,o[1],n),o[2].imm)&((1<<o[3].imm)-1));return
  if m=='sxtw':self.write(i.reg_name(o[0].reg),z3.SignExt(32,self.read(i.reg_name(o[1].reg))));return
  if m=='ands':
   n=self.width(i.reg_name(o[0].reg));x=self.operand(i,o[1],n)&self.operand(i,o[2],n);self.write(i.reg_name(o[0].reg),x);self.n=z3.Extract(n-1,n-1,x)==1;self.z=x==0;self.carry=self.overflow=z3.BoolVal(False);self.flag_change=True;return
  if m=='ldrb'and i.writeback:
   a=self.address(i,o[1]);base=i.reg_name(o[1].mem.base);old=self.read(base);self.write(i.reg_name(o[0].reg),self.load(a,1));self.write(base,old+o[2].imm);return
  if m in ['stp','ldp']and i.writeback:
   a=self.address(i,o[2]);base=i.reg_name(o[2].mem.base);old=self.read(base);n=self.width(i.reg_name(o[0].reg))//8
   for j in range(2):
    r=i.reg_name(o[j].reg)
    if m=='stp':self.store(z3.simplify(a+j*n),n,self.read(r),i.address)
    else:self.write(r,self.load(z3.simplify(a+j*n),n))
   self.write(base,old+o[3].imm if len(o)>3 else a);return
  if m=='ccmp':
   n=self.width(i.reg_name(o[0].reg));condition=self.condition(i.op_str.rsplit(',',1)[1].strip());a=self.operand(i,o[0],n);b=self.operand(i,o[1],n);self.flags(a,b,a-b,True)
   self.n,self.z,self.carry,self.overflow=[z3.simplify(z3.If(condition,x,z3.BoolVal(bool(o[2].imm&(1<<(3-j))))))for j,x in enumerate([self.n,self.z,self.carry,self.overflow])];return
  return super().one(i)

class Run(Extra,Revisit):pass
class Algebra(Extra,H.Algebra):pass

def source():
 return [{'name':n,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),'instructions':[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(IMAGE.read(a,b-a),a)]}for n,a,b in SPECS]

def inputs():
 pins,t=H.inputs()
 for name,digest in PINS.items():assert sha(ROOT/name)==digest,name;pins[name]=json.loads(read(ROOT/name))
 return pins,t

def key(record):
 v=Algebra();v.seed('x0',record);v.run_block(0x10049f4ac,0x10049f50c);return z3.simplify(v.read('x19'))

def configuration(epoch,name):
 f=0x6400004000+epoch*0x1000
 variants={'null_A':(0,16,False,True,True),'null_B':(0,16,True,False,True),'malloc_failure':(0,16,True,True,False),
 'clear1':(0,16,True,True,True),'clear2':(2,16,True,True,True),'clear6':(0x42,16,True,True,True),'prefix':(8,16,True,True,True),'extended':(0x28,16,True,True,True)}
 cap,count,a,b,allocation=variants[name]
 return {'epoch':epoch,'name':name,'frame_SP':hex(f),'entry_SP':hex(f+0x980),'record':hex(f+0x1800),'seed_cell':hex(f+0x1f00),'seed_u64':'0x1234','decoded_operation_u32':'0x871a','decoded_count_B':count,
  'input_A':hex(f+0x1c00)if a else '0x0','input_B':hex(f+0x1d00)if b else '0x0','input_extent_B':256,'input_fill_byte':0,'capabilities_u32':hex(cap),'malloc_success':allocation,'allocation':hex(0x6500100000+80000),'allocation_B':32,
  'fresh_private':{'address':hex(f-0x1000),'size_bytes':0x4000},'return_token':hex(RETURN)}

def put(v,a,n,x):
 for j,b in enumerate((x&((1<<(8*n))-1)).to_bytes(n,'little')):v.bytes[a+j]=z3.BitVecVal(b,8)

def overlay(v,c):
 f=int(c['frame_SP'],16);window=c['fresh_private'];a=int(window['address'],16)
 for at in range(a,a+window['size_bytes']):v.bytes.pop(at,None)
 r=int(c['record'],16);k=key(r).as_long();put(v,r,4,c['decoded_count_B']-k);put(v,r+4,4,k+int(c['decoded_operation_u32'],16));put(v,r+0x10,8,int(c['input_A'],16));put(v,r+0x18,8,int(c['input_B'],16));put(v,int(c['seed_cell'],16),8,int(c['seed_u64'],16));put(v,0x1010b6394,4,int(c['capabilities_u32'],16)^0xc49697f0)
 for pointer in ['input_A','input_B']:
  a=int(c[pointer],16)
  if a:
   for at in range(a,a+c['input_extent_B']):v.bytes[at]=z3.BitVecVal(c['input_fill_byte'],8)
 for n,x in {'sp':int(c['entry_SP'],16),'x0':r,'x1':int(c['seed_cell'],16),'x30':RETURN}.items():v.regs[v.key(n)]=z3.BitVecVal(x,64)
 v.steps=[];v.pool={};v.cache={};v.fixups=set();v.zero_reads=[];v.changed=set();v.definitions=[];v.origins={};v.unknown_inputs_used={}

def opaque(v,at,n):return z3.Concat(*[z3.BitVec('unknown_'+hex(at+j),8)for j in range(n-1,-1,-1)])

def model(v,c,pc,index):
 assert pc in [MALLOC,FREE];allocation=int(c['allocation'],16);r0=v.concrete(v.read('x0'),'API X0');slot=0x10109ff58 if pc==MALLOC else 0x10109ff30;name='malloc'if pc==MALLOC else'free';assert FIXUPS[slot]['target']=='libSystem/_'+name
 assert r0==(32 if pc==MALLOC else allocation)
 before={n:v.shape(v.read(n),8)for n in ['sp']+['x'+str(j)for j in range(18,30)]};origin=0x6900000000+index*0x1000
 for j in range(18):v.regs['x'+str(j)]=opaque(v,origin+j*8,8)
 for j in range(32):
  v.regs['q'+str(j)]=z3.Concat(opaque(v,origin+0x100+j*16,8),z3.Extract(63,0,v.read('q'+str(j))))if 8<=j<16 else opaque(v,origin+0x100+j*16,16)
 if pc==MALLOC:
  v.regs['x0']=z3.BitVecVal(allocation if c['malloc_success']else 0,64)
  if c['malloc_success']:
   for at in range(allocation,allocation+32):v.bytes.pop(at,None)
 v.regs['x30']=z3.BitVecVal(pc+4,64);v.n,v.z,v.carry,v.overflow=[z3.Bool('api_'+name+'_'+s)for s in ['N','Z','C','V']]
 assert before=={n:v.shape(v.read(n),8)for n in before}
 return {'pc':hex(pc),'bytes_hex':IMAGE.read(pc,4).hex(),'name':name,'after_source_visits':len(v.steps),'slot':hex(slot),'binding':FIXUPS[slot]['target'],'modifier16':hex(0x6aa4 if pc==MALLOC else 0x46a2),'argument_X0':hex(r0),
  'register_effects':{n:v.shape(v.read(n),16 if n.startswith('q')else 8)for n in ['x'+str(j)for j in range(18)]+['x30']+['q'+str(j)for j in range(32)]},'NZCV_unspecified':True,'preserved':before,'origin_base':hex(origin),'native_executed':False}

def obligations():
 R,F,N,OP,T,A,B=z3.BitVecs('root_record64 root_entrySP64 root_count32_wide root_operation32_wide root_seed64 root_A64 root_B64',64);qs=[]
 def add(n,p):qs.append((n,p))
 v=Algebra()
 for j in range(19,31):v.seed('x'+str(j),z3.BitVec('root_saved_x'+str(j),64))
 v.seed('sp',F);v.run_block(ENTRY+4,0x10049f37c);add('source_root_frame',z3.Or(v.read('sp')!=F-0x980,v.read('x29')!=F-0x10))
 k=key(R);x=R^0xadef4a231bdba15d;formula=((((x<<1)|0x3920867a64d1a5ec)-x+0xe36fbcc2cd972d0a)^0xde4326985541f84b)*0x83918153
 add('source_record_key64',k!=formula)
 add('record_count_and_operation_inverse',z3.Or(resize(resize(N,32)-resize(k,32)+resize(k,32),32)!=resize(N,32),resize(resize(k,32)+resize(OP,32)-resize(k,32),32)!=resize(OP,32)))
 v=Algebra();v.seed('x1',F);mem(v,F,8,T);v.run_block(0x10049f4a0,0x10049f4ac);add('root_seed_increment',cell(v,F,8)!=T+0xb0)
 v=Algebra();v.seed('x27',B);v.seed('x24',A);v.run_block(0x10049f530,0x10049f538);add('source_nonnull_pair_gate',v.z!=z3.Or(A==0,B==0))
 op=resize(OP,32);v=Algebra();v.seed('x29',R+0x98);v.seed('w16',op);v.run_block(0x1003af8fc,0x1003af940);raw=cell(v,R+0x10,4)
 d=Algebra();d.seed('x19',R);d.run_block(0x100455d64,0x100455d90)
 canonical=resize(R,32)^0xdc40790b;add('source_initializer_key_preproduct',d.read('w13')!=canonical)
 # Compose the proved preproduct lemma with the original multiply/decode tail.
 d.seed('w13',canonical);mem(d,R+0x10,4,raw);d.run_block(0x100455d90,0x100455da4)
 add('source_initializer_operation',d.read('w20')!=((op^0xb3e0)+0x8322))
 v=Algebra();v.seed('x0',A);v.seed('w20',0xb81c);v.run_block(0x100455e5c,0x100455e84);add('source_malloc_result_dispatch',v.read('w9')!=z3.If(A==0,z3.BitVecVal(0xb851,32),z3.BitVecVal(0xb81c,32)))
 v=Algebra();v.seed('x19',R);v.seed('x0',A);v.seed('w8',0x81b08586);mem(v,R+8,8,B);v.run_block(0x10031cb3c,0x10031cb8c)
 add('source_initializer_pair_and_header',z3.Or(cell(v,A,8)!=B+0x30,cell(v,A+8,4)!=0x8b3dc479,cell(v,A+12,4)!=0x8b3dc479,cell(v,A+16,4)!=0x8b3dc651,cell(v,A+20,4)!=0x4d8916dd,cell(v,A+24,4)!=0x8b3dc651,cell(v,B,8)!=A,cell(v,B+8,8)!=0))
 rows=[]
 for label,p in qs:
  s=z3.Solver();s.set(timeout=30000);s.add(p);r=str(s.check());assert r=='unsat',(label,r);rows.append({'label':label,'query':s.to_smt2(),'result':r})
 return rows

def verify_fixups(addresses):
 from recover_daemon_callback_revisit import verify_original_fixups
 from daemon_import_bindings import binding
 ordinary=[a for a in addresses if FIXUPS[a]['kind']=='bind']
 out=verify_original_fixups([a for a in addresses if a not in ordinary])
 for a in sorted(ordinary):
  row=binding(a);row.pop('library_path')
  out['records'].append(row)
 return out

def main():
 pins,old=inputs();ALLOWED_CALLS.update([0x100439874,0x100455c30]);base=Run.from_snapshot(pins['daemon_callback_revisit_snapshot.json']);epochs=[j for j,row in enumerate(old['steps'])if row['pc']=='0x100add594'];previous=0;cases=[];totals=Counter()
 for epoch,end in enumerate(epochs):
  H.advance(base,old['steps'][previous:end]);previous=end
  for name in ['null_A','null_B','malloc_failure','clear1','clear2','clear6','prefix','extended']:
   c=configuration(epoch,name);v=copy.copy(base);v.bytes=base.bytes.copy();v.regs=base.regs.copy();overlay(v,c);initial={n:v.shape(x,16 if n.startswith('q')else 8)for n,x in v.regs.items()};flags=sum(1<<(31-j)for j,x in enumerate([v.n,v.z,v.carry,v.overflow])if z3.is_true(x));models=[];start=ENTRY
   for attempt in range(3):
    b=v.run_revisit(start,limit=200000)
    if b['kind']=='before_uninspected_call'and int(b['pc'],16)in [MALLOC,FREE]:models.append(model(v,c,int(b['pc'],16),len(models)));start=int(b['pc'],16)+4;continue
    break
   assert b['kind']=='return_outside_source_image'and b['pc']==hex(RET)and b['target']==hex(RETURN),b
   assert not v.definitions
   counts={'source_visits':len(v.steps),'source_instructions':len(v.pool),'read_events':sum(e['kind']=='read'for r in v.steps for e in r['events']),'write_events':sum(e['kind']=='write'for r in v.steps for e in r['events']),'API_models':len(models)};totals.update(counts)
   trace={'steps':v.steps,'boundary':b,'source_pool':v.pool,'used_fixups':list(map(hex,sorted(v.fixups))),'initial_registers':initial,'initial_NZCV':flags}
   cases.append({'configuration':c,'prefix_source_visits':end,'trace':trace,'API_models':models,'counts':counts});print(json.dumps({'epoch':epoch,'name':name,**counts}),flush=True)
 used={int(a,16)for c in cases for a in c['trace']['used_fixups']};fixups=verify_fixups(used)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':H.THIN,'parent_pins':PINS,'dependencies':{n:sha(ROOT/n)for n in DEPS},'source_regions':source(),'source_fixups':fixups,'source_proofs':obligations(),'cases':cases,'verified_counts':{'cases':len(cases),'epochs':2,'variants':8,**dict(totals)},
  'prefix_reexecuted':False,'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'live_IDA_claim':False,'native_entry_admission_established':False,'complete_IOKit_buffer_join_established':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out['verified_counts']),flush=True)

if __name__=='__main__':main()
