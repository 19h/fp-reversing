#!/usr/bin/env python3
"""Selector21 constructor/private byte-emitter composition in sealed epochs.

O(snapshot + prefix + cases*(visits + byte effects)) time/space; fixed
30 s/SMT query. Private fixtures and logical PAC, zero native API/IPC.
"""
import base64,copy,json,zlib
from pathlib import Path
from collections import Counter
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,POOL,TABLE,qword
from daemon_context_transfer_symbolic import Transfer
from daemon_callback_revisit_symbolic import Revisit
from daemon_seed_material_symbolic import decode
from lskd_values_symbolic import Lift,resize,mem,cell
from verify_daemon_reader_record_payloads_publication import read,sha
P='daemon_versioned_header';ENTRY=0x100552dac;STOP=0x100552fa0;MASK=2**64-1
DEC=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);DEC.detail=True
THIN='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
PINS={
 'daemon_callback_revisit_snapshot.json':'1d2faacf9222f8ee22fbeff3fa13446c3890053a82ba778671547d74b8da70f2',
 'daemon_callback_revisit_profiles.json':'93b06846a3fd1be8cf6b2a7af2e44b1851567f19652a7ba32cbb40de6ac58793',
 'daemon_callback_revisit_contracts.json':'b60615ed22086048fffcd47959433bfd1fa7dfe9785d8d12b15f4e5056a14697',
 'daemon_callback_revisit_proofs.json':'f4bd0aa3d4664cdf20f9de1087b02980c9ef49dc5a986daa7215b9b8574118a5',
 'daemon_callback_revisit_checks.json':'088e652656533d0dc9f1cbb6c6ac59aac85f81078179b948dc903a2b7b7c0383',
 'daemon_callback_revisit_replays.json':'af159751dbb8b2bd7dc41cdabe77612370b98b1bb5b2f0e6e59b5437b6d88356',
 'versioned_request_abi_source.json':'43319db5d7d5471ded1d52b78319db4821b460088e407ccbb5a44091d9a6285d',
 'versioned_request_abi_checks.json':'2e5decc7fdc4c39fd5a3a01be9d6dced22749aea75c581ac2b0b458dafa86da0'}
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','daemon_callback_revisit_symbolic.py','daemon_context_transfer_symbolic.py',
 'daemon_seed_material_symbolic.py','daemon_entropy_return_symbolic.py','daemon_callback_simd.py','lskd_values_symbolic.py',
 'replay_daemon_callback_revisit.py','replay_daemon_context_transfer.py']
SPECS=[('constructor',ENTRY,STOP),('adapter',0x100add594,0x100add7fc),('inner_bias_key',0x100acdb14,0x100acdb54)]

def inputs():
 assert sha(SOURCE)==THIN
 out={}
 for name,digest in PINS.items():assert sha(ROOT/name)==digest,name;out[name]=json.loads(read(ROOT/name))
 p=out['daemon_callback_revisit_profiles.json'];b=zlib.decompress(base64.b64decode(p['payload_zlib_base64']))
 from hashlib import sha256
 assert sha256(b).hexdigest()==p['payload_sha256'];t=json.loads(b);assert not t['definitions']
 return out,t

def source():
 out=[]
 for name,lo,hi in SPECS:
  b=IMAGE.read(lo,hi-lo);ii=list(CS.disasm(b,lo));assert len(ii)*4==len(b)
  out.append({'name':name,'start':hex(lo),'end':hex(hi),'bytes_hex':b.hex(),'instructions':[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]})
 return out

class Algebra(Transfer):
 def __init__(self):Lift.__init__(self,{'spans':[]});self.written={}
 def write(self,n,v):return Lift.write(self,n,z3.simplify(v))
 def load(self,a,n):return Lift.load(self,a,n)
 def store(self,a,n,v,pc):return Lift.store(self,a,n,v,pc)
 def run_block(self,lo,hi):
  for i in DEC.disasm(IMAGE.read(lo,hi-lo),lo):
   self.pc=i.address
   if i.mnemonic=='sturh':self.store(self.address(i,i.operands[1]),2,self.read(i.reg_name(i.operands[0].reg)),i.address)
   else:self.one(i)
  return self

def obligations():
 R,F,C,T,O,D=z3.BitVecs('header_record64 header_frame64 header_state64 header_temp64 header_offset64 header_delta64',64)
 phase=z3.BitVec('header_phase32',32);K=z3.Extract(31,0,(R^0xeaae0ac9)*0x7398180b);qs=[]
 def add(n,p,premise=z3.BoolVal(True)):qs.append((n,z3.And(premise,p)))
 def run(lo,hi,seeds=(),memory=()):
  v=Algebra()
  for n,x in seeds:v.seed(n,x)
  for a,n,x in memory:mem(v,a,n,x)
  return v.run_block(lo,hi)
 v=run(ENTRY,0x100552ddc,[('sp',F),('x20',O),('w21',0x871a)])
 add('constructor_buffer_views_and_capacity',z3.Or(v.read('x22')!=F+0x5f0+O,cell(v,F+0x3f8,8)!=F+0x5f0+O,cell(v,F+0x480,8)!=F+0x600+O,cell(v,F+0x488,8)!=F+0x610+O,cell(v,F+0x3f0,8)!=552))
 v=run(0x100552ddc,0x100552e38,[('sp',F),('x29',R+0x98),('w21',phase)])
 key=phase+0x2c7f-cell(v,R+0x14,4)
 add('constructor_key_agreement_iff_low_bits_zero',(key==K)!=(R&5==0))
 add('aligned8_constructor_record_key',key!=K,R&7==0)
 add('aligned8_constructor_output_length_control',z3.Or(cell(v,R+8,8)!=F+0x2d4,resize(cell(v,R+0x10,2)-resize(K,16)-0x153b,16)!=4,cell(v,R+0x14,4)+K!=phase+0x2c7f),R&7==0)
 v=run(0x100acdb14,0x100acdb20,[('x1',T)],[(T,8,C-0xb0)])
 add('inner_bias_cancellation',cell(v,T,8)!=C)
 v=run(0x100add7d8,0x100add7e8,[('x20',0x70000000),('x19',0x70001000),('w21',resize(C,32))],[(0x70000000,4,resize(T,32))])
 delta=z3.ZeroExt(48,z3.Extract(15,0,T-C))<<4
 add('source_adapter_return_delta',cell(v,0x70001000,8)!=delta)
 add('delta_zero_iff_low16_equal',(delta==0)!=(z3.Extract(15,0,T)==z3.Extract(15,0,C)))
 add('delta_range_alignment',z3.Or(z3.UGT(delta,0xffff0),delta&15!=0))
 v=run(0x100552efc,0x100552f0c,[('sp',F)],[(F+0x5e0,8,D)])
 add('caller_frame_after_helper',v.read('sp')!=F+D)
 add('state_pointer_cell_same_iff_zero',((F+D+0x80)==F+0x80)!=(D==0))
 B=z3.BitVec('header_big_endian32',32)
 v=run(0x100552f0c,STOP,[('sp',F),('w21',0x871a)],[(F+0x2d4+j,1,z3.Extract(31-8*j,24-8*j,B))for j in range(4)])
 add('post_bytes_word_XOR_projection',z3.Or(len(v.stores)!=1,v.stores[0]['address']!=F+0x3b4,v.stores[0]['size_bytes']!=4,v.stores[0]['value']!=(B^0x8b3dc651)))
 rows=[]
 for n,p in qs:
  s=z3.Solver();s.set(timeout=30000);s.add(p);r=str(s.check());assert r=='unsat',(n,r);rows.append({'label':n,'query':s.to_smt2(),'result':r})
 # A nonzero low16 discrepancy moves the next frame; alignment is necessary.
 probes=[]
 for n,p in [('aligned4_insufficient_falsifier',z3.And(R&7==4,key!=K)),('nonzero_delta_moves_cell',z3.And(D==16,F+D+0x80!=F+0x80)),('aligned8_premise_nonempty',R&7==0)]:
  s=z3.Solver();s.set(timeout=30000);s.add(p);assert s.check()==z3.sat;probes.append({'label':n,'query':s.to_smt2(),'result':'sat','model':str(s.model())})
 return {'proofs':rows,'falsifiers_and_witnesses':probes}

def advance(v,rows):
 for row in rows:
  assert IMAGE.read(int(row['pc'],16),4).hex()==row['bytes_hex']
  for e in row['events']:
   a=int(e['address'],16);x=decode(e['value'],v.F)
   for k in range(e['size_bytes']):
    b=z3.simplify(z3.Extract(8*k+7,8*k,x))
    if e['kind']=='read'and a+k in v.bytes:assert z3.is_true(z3.simplify(v.bytes[a+k]==b)),(row['pc'],hex(a+k))
    v.bytes[a+k]=b
  for n,x in row['registers_after'].items():v.regs[v.key(n)]=decode(x,v.F)
  if 'NZCV_after'in row:v.n,v.z,v.carry,v.overflow=[z3.BoolVal(bool(row['NZCV_after']&(1<<(31-j))))for j in range(4)]

def fixture(epoch,layout):
 f=0x6400004000+layout*0x1000;off=[0,0x20,0x30][layout];fp=f+[0x1000,0x900,0x1100][layout]
 cells={0x80:0x1010b6380,0x2b0:0x1010c4670,0x108:qword(POOL+0x29c8)+0xffffffffaa591739,0x100:qword(POOL+0x4c18)+0xffffffff8af86dcd,0x288:qword(POOL+0x2b50)+0xfffffffff02ce87e,0x280:qword(POOL+0x30f8)-0xd45667}
 return {'epoch':epoch,'layout':layout,'frame_SP':hex(f),'record':hex(fp-0x98),'fill':{'address':hex(f-0x1000),'size_bytes':0x3000,'byte':0xa5},
  'u64_cells':{hex(f+k):hex(x&MASK)for k,x in cells.items()},'registers':{'sp':hex(f),'x29':hex(fp),'x20':hex(off),'x21':'0x871a','x23':hex(TABLE),'x26':'0x1010b9008'}}

def overlay(v,c):
 row=c['fill'];a=int(row['address'],16)
 for at in range(a,a+row['size_bytes']):v.bytes[at]=z3.BitVecVal(row['byte'],8)
 for at,value in c['u64_cells'].items():
  for j,b in enumerate(int(value,16).to_bytes(8,'little')):v.bytes[int(at,16)+j]=z3.BitVecVal(b,8)
 for n,x in c['registers'].items():v.regs[v.key(n)]=z3.BitVecVal(int(x,16),64)
 v.steps=[];v.pool={};v.fixups=set();v.zero_reads=[];v.changed=set();v.definitions=[];v.origins={};v.unknown_inputs_used={};v.cache={};v.values={}

class Constructor(Revisit):
 def one(self,i):
  assert i.address!=STOP,'declared stop before capability read'
  return super().one(i)

def main():
 pins,t=inputs();snap=pins['daemon_callback_revisit_snapshot.json'];base=Constructor.from_snapshot(snap);epochs=[j for j,row in enumerate(t['steps'])if row['pc']=='0x100add594'];assert len(epochs)==2
 cases=[];previous=0;totals=Counter()
 for epoch,end in enumerate(epochs):
  advance(base,t['steps'][previous:end]);previous=end
  for layout in range(3):
   v=copy.copy(base);v.bytes=base.bytes.copy();v.regs=base.regs.copy();overlay(v,fixture(epoch,layout));initial={n:v.shape(x,16 if n.startswith('q')else 8)for n,x in v.regs.items()};flags=sum(1<<(31-j)for j,x in enumerate([v.n,v.z,v.carry,v.overflow])if z3.is_true(x))
   boundary=v.run_revisit(ENTRY,limit=300000);assert boundary['pc']==hex(STOP)and boundary['reason']=='declared stop before capability read'and not boundary['uncommitted_events'],boundary
   boundary['kind']='declared_before_capability_read';boundary.pop('reason');boundary.pop('uncommitted_events')
   assert not v.definitions and not v.unknown_inputs_used
   trace={'steps':v.steps,'boundary':boundary,'source_pool':v.pool,'used_fixups':list(map(hex,sorted(v.fixups))),'initial_registers':initial,'initial_NZCV':flags}
   counts={'source_visits':len(v.steps),'source_instructions':len(v.pool),'read_events':sum(e['kind']=='read'for r in v.steps for e in r['events']),'write_events':sum(e['kind']=='write'for r in v.steps for e in r['events'])};totals.update(counts)
   cases.append({'configuration':fixture(epoch,layout),'prefix_source_visits':end,'trace':trace,'counts':counts});print(json.dumps({'epoch':epoch,'layout':layout,**counts}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':THIN,'parent_pins':PINS,'dependencies':{n:sha(ROOT/n)for n in DEPS},'source_regions':source(),'source_checks':obligations(),'cases':cases,'verified_counts':{'cases':len(cases),'epochs':len(epochs),'layouts':3,**dict(totals)},
  'prefix_reexecuted':False,'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'live_IDA_claim':False,'native_parent_frame_recovered':False,'complete_IOKit_buffer_join_established':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out['verified_counts']),flush=True)

if __name__=='__main__':main()
