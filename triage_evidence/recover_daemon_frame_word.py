#!/usr/bin/env python3
"""Conditional frame-word definition and actual ingress frontier.

O(text words+parent visits+control effects) time/space;30 s/SMT query.
Source-local private fixtures only; no native APIs, IPC, IDB writes or PAC.
"""
import json,struct,bisect
from pathlib import Path
from hashlib import sha256
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,TABLE,qword
from recover_daemon_iokit_census import text_section
from recover_rpc502_parser_ownership import starts
from verify_daemon_reader_record_payloads_publication import read,sha
from lskd_values_symbolic import mem,cell,resize
import recover_daemon_versioned_ingress as Parent
P='daemon_frame_word';MASK=(1<<64)-1
PINS={**Parent.PINS,'daemon_versioned_ingress_checks.json':'2d4969ed238a663b7a7593df603707f2e4057a9826d4557640906a3d4eb92438',
 'daemon_versioned_ingress_audit.json':'24c814b1edef1753d40600c9f03e8eb60efcd5c4cd3b1a3f2dba7c40091d6c4d'}
DEPS=Parent.DEPS+['recover_daemon_versioned_ingress.py']
SPECS=[('producer_predecessor',0x1003fd1d8,0x1003fd208),('conditional_writer',0x100530720,0x10053077c),
 ('less_than_continuation',0x100523774,0x1005237d8),('reader_prefix',0x10063735c,0x100637378),
 ('actual_field_predecessor',0x10063ac7c,0x10063ad58),('actual_reader_predecessor',0x1004712f4,0x10047135c)]
SLOTS=[0x10103f138,0x101071c78,0x10107d360,0x10108e220,0x10108e490,0x10105f2e8]
DEC=Parent.R.H.DEC

def inputs():
 assert sha(SOURCE)==Parent.R.H.THIN
 for n,d in PINS.items():assert sha(ROOT/n)==d,n
 return json.loads(read(ROOT/'daemon_versioned_ingress_checks.json'))

def source():
 out=[]
 for name,a,b in SPECS:
  raw=IMAGE.read(a,b-a);ii=list(CS.disasm(raw,a));assert len(ii)*4==len(raw)
  out.append({'name':name,'start':hex(a),'end':hex(b),'bytes_hex':raw.hex(),'instructions':[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]})
 return out

def census():
 a,n=text_section();raw=IMAGE.read(a,n);bounds,meta=starts();rows=[];forms={}
 for j,(w,)in enumerate(struct.iter_unpack('<I',raw)):
  if w&0x3e0!=0x3e0:continue
  off=width=extent=None;form=None
  if w&0x3b400000==0x39000000:
   width=16 if w&(1<<26)and w&(1<<23)else 1<<(w>>30);off=((w>>10)&4095)*width;extent=width;form='unsigned_immediate_STR'
  elif w&0xffc00000 in [0xad000000,0xad800000,0xac000000]:
   k=(w>>15)&127;off=(k-128 if k&64 else k)*16;width=16;extent=32;form='signed_pair_Q_store'
  if off is None or not(off<0x564 and 0x560<off+extent):continue
  pc=a+j*4;i=next(DEC.disasm(raw[j*4:j*4+4],pc));assert i.mnemonic in ['str','strb','strh','stp','stnp']
  m=i.operands[-1];assert i.reg_name(m.mem.base)=='sp'and not m.mem.index and m.mem.disp==off
  k=bisect.bisect_right(bounds,pc)-1;forms[form]=forms.get(form,0)+1
  rows.append({'pc':hex(pc),'bytes_hex':raw[j*4:j*4+4].hex(),'mnemonic':i.mnemonic,'operands':i.op_str,
   'form':form,'element_B':width,'extent_B':extent,'SP_displacement_B':off,'compiler_envelope':[hex(bounds[k]),hex(bounds[k+1])],
   'root_frame_ownership_established':False})
 return {'text_address':hex(a),'text_size_B':n,'text_sha256':sha256(raw).hexdigest(),'forms':forms,'candidates':rows,'LC_FUNCTION_STARTS':meta,
  'scope':'Aligned original __text unsigned-immediate scalar/SIMD STR with SP base and overlapping signed-offset/preindexed/nonallocating Q-pair stores only. Signed single/pre/post immediate displacements cannot reach +0x560 at widths <=16 B; non-Q pairs cannot reach it at their signed scaled bounds. Register-offset stores, SP aliases, other store families, changing SP epochs and other regions are outside this census. Compiler envelopes do not identify semantic frame ownership.'}

def actual(parent):
 out=[]
 for case in parent['cases']:
  c=case['configuration'];t=case['trace']['steps']
  if c['kind']!='caller'or c['name']not in ['prefix','extended']:continue
  f=int(c['caller_SP'],16)-0x9d0;at=f+0x560;reg=dict(case['trace']['initial_registers']);states={};writes=[];word_writes=[]
  for j,r in enumerate(t):
   pc=int(r['pc'],16);assert IMAGE.read(pc,4).hex()==r['bytes_hex']
   if pc in [0x10063ac7c,0x1004712f4,0x10063735c]:states[r['pc']]={k:reg[k]for k in ['sp','x8','x9','x10','x11','x12','x13','x20','x23']}
   for e in r['events']:
    if e['kind']!='write':continue
    a=int(e['address'],16);n=e['size_bytes']
    if a<at+4 and at<a+n:word_writes.append({'visit':j,'pc':r['pc'],**e})
    if a in [f+0x55c,f+0x3c4]:writes.append({'visit':j,'pc':r['pc'],'frame_offset_B':a-f,**e})
   reg.update(r['registers_after'])
  assert not word_writes and not any(r['pc']=='0x100530748'for r in t)
  assert [(w['pc'],w['value']['hex'])for w in writes]==[('0x10063ac9c','00000000'),('0x10063aca0','0c000000')]
  assert t[-1]['pc']=='0x100637368'and case['trace']['boundary']['pc']=='0x10063736c'
  e=t[-1]['events'][0];assert e['address']==hex(at)and e['size_bytes']==4
  terms=[{'origin':at+j-0x640000b520}for j in range(4)];assert e['value']=={'terms':terms}
  branches=[{'pc':r['pc'],'target':r['target'],'modifier16':r['modifier16']}for r in t[-100:]if 'target'in r]
  assert branches[-2:]==[{'pc':'0x10063ad54','target':'0x1004712f4','modifier16':'0x8897'},{'pc':'0x100471358','target':'0x10063735c','modifier16':'0xa50a'}]
  out.append({'epoch':c['epoch'],'variant':c['name'],'frame_SP':hex(f),'entry_states':states,'field_writes':writes,
   'tail_branches':branches,'unknown_read':e,'overlapping_prior_writes':word_writes,'candidate_writer_visited':False,
   'boundary':case['trace']['boundary'],'source_visits_checked':len(t),'native_defect_established':False})
 assert len(out)==4
 return out

def obligations():
 f=z3.BitVec('frame_word_SP64',64);a,b,c=z3.BitVecs('frame_word_value32 frame_word_limit32 frame_word_companion32',32);qs=[]
 v=Parent.Algebra();v.seed('sp',f);v.seed('w14',0x871a);v.seed('x23',TABLE);mem(v,f+0x4ec,4,a);mem(v,TABLE+0x6fb1*8,8,0x100530720);v.run_block(0x1003fd1d8,0x1003fd204)
 qs.append(('predecessor_phase_value_target',z3.Or(v.read('w10')!=0xa866,v.read('w20')!=a,v.read('x8')!=0x100530720)))
 v.seed('w11',c);mem(v,f+0x3c4,4,b);v.run_block(0x100530720,0x100530770)
 idx=z3.If(z3.ULT(a,b),z3.BitVecVal(0xa8b4,32),z3.BitVecVal(0xa866,32))
 qs.append(('writer_preserves_both_words',z3.Or(cell(v,f+0x560,4)!=a,cell(v,f+0x564,4)!=c)))
 qs.append(('unsigned_bound_selects_exact_indices',v.read('w10')!=idx))
 qs.append(('writer_phase_for_less_than_join',z3.Or(v.read('w8')!=0xa25,v.read('w9')!=0x2fa3)))
 # Both source-dispatched table outcomes are retained separately from the predicate.
 for index,target in [(0xa866,0x100537880),(0xa8b4,0x100523774)]:
  x=Parent.Algebra();x.seed('x23',TABLE);x.seed('w10',index);mem(x,TABLE+index*8,8,target);x.run_block(0x100530770,0x100530778)
  qs.append(('writer_table_target_'+hex(index),z3.Or(x.read('x10')!=target,x.read('x17')!=0x1ff5)))
 v=Parent.Algebra();v.seed('sp',f);v.seed('w8',0xa25);v.seed('w20',a);pointer=z3.BitVec('frame_word_owner64',64);mem(v,f+0x380,8,pointer);mem(v,f+0x2a0,8,0x871a);v.seed('x23',TABLE);mem(v,TABLE+0x4a7f*8,8,0x10063735c);v.run_block(0x100523774,0x1005237d4)
 qs.append(('less_than_continuation_reader_join',z3.Or(v.read('w9')!=0x871a,v.read('x10')!=0x10063735c,v.read('x17')!=0xa50a,cell(v,f+0x528,8)!=pointer)))
 v=Parent.Algebra();v.seed('sp',f);v.seed('w9',0x871a);mem(v,f+0x560,4,a);v.run_block(0x10063735c,0x100637374)
 qs.append(('reader_transformation_and_store',z3.Or(v.read('w9')!=0x8554,cell(v,f+0x258,4)!=a+0x2f95a328)))
 v=Parent.Algebra();v.seed('sp',f);v.seed('w13',0x7de7);v.seed('w10',b);v.seed('w11',0x8b3dc64d);v.seed('w12',a);v.run_block(0x10063ac7c,0x10063aca4)
 qs.append(('alternate_predecessor_writes_different_fields',z3.Or(cell(v,f+0x55c,4)!=a,cell(v,f+0x3c4,4)!=b)))
 v=Parent.Algebra();v.seed('sp',f);v.seed('w8',0xa1e);v.seed('w12',a);v.seed('x23',TABLE);mem(v,f+0x380,8,pointer);mem(v,TABLE+0x4a7f*8,8,0x10063735c);v.run_block(0x1004712f4,0x100471358)
 qs.append(('alternate_reader_join_and_owner_copy',z3.Or(v.read('w9')!=0x871a,v.read('x10')!=0x10063735c,v.read('x17')!=0xa50a,cell(v,f+0x508,8)!=pointer)))
 out=[]
 for n,p in qs:
  s=z3.Solver();s.set(timeout=30000);s.add(p);r=str(s.check());assert r=='unsat',(n,r);out.append({'label':n,'query':s.to_smt2(),'result':r})
 return out

class Control(Parent.Algebra):
 def load(self,a,n):
  v=super().load(a,n);self.events.append({'kind':'read','address':hex(number(a)),'size_B':n,'value':hex(number(v))});return v
 def store(self,a,n,v,pc):
  super().store(a,n,v,pc);self.events.append({'kind':'write','address':hex(number(a)),'size_B':n,'value':hex(number(resize(v,n*8)))})

def number(x):return z3.simplify(x).as_long()
def nzcv(v):return sum(1<<(31-j)for j,x in enumerate([v.n,v.z,v.carry,v.overflow])if z3.is_true(z3.simplify(x)))

def controls():
 out=[];values=[(0,12),(1,12),(11,12),(12,12),(13,12),(0xffffffff,12),(0x80000000,0xffffffff),(0xffffffff,0xffffffff),(0,0),(0xfffffffe,0xffffffff)]
 for epoch in range(2):
  for j,(a,b)in enumerate(values):
   f=0x7000004000+epoch*0x10000;c=[0,0x2a15b77c,0xdeadbeef][j%3];owner=0x7100000000+epoch*0x1000
   initial={'x'+str(k):((k+1)*0x111111111111111)&MASK for k in range(31)};initial.update(sp=f,x14=0x871a,x23=TABLE,x11=c)
   cells=[(f+0x4ec,4,a),(f+0x3c4,4,b),(f+0x380,8,owner),(f+0x2a0,8,0x871a)]+[(TABLE+k*8,8,qword(TABLE+k*8))for k in [0x6fb1,0xa866,0xa8b4,0x4a7f]]
   v=Control();v.events=[]
   for k,x in initial.items():v.seed(k,x)
   for at,n,x in cells:mem(v,at,n,x)
   v.n=v.z=v.carry=v.overflow=z3.BoolVal(False);trace=[];blocks=[(0x1003fd1d8,0x1003fd208),(0x100530720,0x10053077c)]
   if a<b:blocks.extend([(0x100523774,0x1005237d8),(0x10063735c,0x100637374)])
   for lo,hi in blocks:
    for i in DEC.disasm(IMAGE.read(lo,hi-lo),lo):
     before={k:number(x)for k,x in v.regs.items()};flags=nzcv(v);v.events=[];v.pc=i.address;r={'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic}
     if i.mnemonic=='braa':r.update(target=hex(number(v.read(i.reg_name(i.operands[0].reg)))),modifier16=hex(number(v.read('x17'))))
     else:v.one(i)
     r.update(registers_after={k:hex(number(x))for k,x in v.regs.items()if number(x)!=before.get(k)},events=list(v.events))
     if nzcv(v)!=flags:r['NZCV_after']=hex(nzcv(v))
     trace.append(r)
   target=0x100637374 if a<b else 0x100537880
   assert number(cell(v,f+0x560,4))==a and number(cell(v,f+0x564,4))==c
   if a<b:assert number(cell(v,f+0x258,4))==(a+0x2f95a328)&0xffffffff
   out.append({'epoch':epoch,'value_u32':hex(a),'limit_u32':hex(b),'companion_u32':hex(c),'less_than':a<b,'initial_registers':{k:hex(x)for k,x in initial.items()},'initial_NZCV':'0x0',
    'initial_cells':[{'address':hex(at),'size_B':n,'value':hex(x)}for at,n,x in cells],'trace':trace,'boundary':hex(target),'source_visits':len(trace),
    'native_admission_established':False,'actual_partial_fixture_resumed':False})
 return out

def main():
 parent=inputs();ss=source();cc=census();aa=actual(parent);qq=obligations();cases=controls()
 counts={'source_regions':len(ss),'source_instructions':sum(len(s['instructions'])for s in ss),'store_candidates':len(cc['candidates']),
  'actual_partial_cases':len(aa),'actual_visits_rechecked':sum(r['source_visits_checked']for r in aa),'queries_unsat':len(qq),'control_cases':len(cases),
  'control_visits':sum(c['source_visits']for c in cases),'less_than_controls':sum(c['less_than']for c in cases)}
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':Parent.R.H.THIN,'parent_pins':PINS,'dependencies':{n:sha(ROOT/n)for n in DEPS},
  'source_regions':ss,'source_fixups':Parent.R.verify_fixups(set(SLOTS)),'bounded_store_census':cc,'actual_frontiers':aa,'source_proofs':qq,'control_cases':cases,'verified_counts':counts,
  'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'live_IDA_claim':False,'actual_partial_fixture_resumed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)

if __name__=='__main__':main()
