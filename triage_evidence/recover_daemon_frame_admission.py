#!/usr/bin/env python3
"""Object-word lineage, unsigned admission gate and frame remainder writer.

O(parent visits+controls*effects) time/space;30 s/SMT query.
Declared source-local controls; no native API, IPC, IDB mutation or PAC.
"""
import json
from pathlib import Path
import z3
from daemon_receive_tools import ROOT,IMAGE,TABLE,qword
from verify_daemon_reader_record_payloads_publication import read,sha
from lskd_values_symbolic import mem,cell
import recover_daemon_frame_word as Parent
P='daemon_frame_admission';C=0x8b3dc651
PINS={**Parent.PINS,'daemon_frame_word_checks.json':'706e180b05604b5e1930b415a2acdb9f61ff78c41104be8ac3fee89e472c959b',
 'daemon_frame_word_audit.json':'f494b2c285e17e6568199152716fb286b7eaef37958c3e74c238b140ca09d951'}
DEPS=Parent.DEPS+['recover_daemon_frame_word.py']
SPECS=[('word_update',0x100461a30,0x100461c14),('word_commit',0x1004c5788,0x1004c57a8),
 ('gate_setup',0x1004c75a0,0x1004c761c),('unsigned_admission',0x10063ac7c,0x10063ad58),
 ('remainder_writer',0x10052249c,0x1005225b8),('reader_predecessor',0x1004712f4,0x10047135c),
 ('reader_before_load',0x10063735c,0x100637368),('other_remainder_copy',0x100524030,0x100524040)]
INDICES=[0x4a42,0x7de7,0x7e31,0x7a21,0x4a7f]
SLOTS=[TABLE+j*8 for j in INDICES]
DEC=Parent.DEC

def inputs():
 parent=Parent.inputs()
 for n,d in PINS.items():assert sha(ROOT/n)==d,n
 return parent

def source():
 out=[]
 for name,a,b in SPECS:
  raw=IMAGE.read(a,b-a);ii=list(DEC.disasm(raw,a));assert len(ii)*4==len(raw)
  out.append({'name':name,'start':hex(a),'end':hex(b),'bytes_hex':raw.hex(),'instructions':[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]})
 return out

def actual(parent):
 out=[]
 for case in parent['cases']:
  c=case['configuration']
  if c['kind']!='caller'or c['name']not in ['prefix','extended']:continue
  f=int(c['caller_SP'],16)-0x9d0;a=int(c['allocation'],16);reg=dict(case['trace']['initial_registers']);events=[];points={}
  for j,r in enumerate(case['trace']['steps']):
   assert IMAGE.read(int(r['pc'],16),4).hex()==r['bytes_hex']
   if r['pc']in ['0x100461a30','0x1004c75a0','0x10063ac7c']:points[r['pc']]={k:reg[k]for k in ['sp','x8','x9','x10','x11','x12','x13','x23']}
   for e in r['events']:
    at=int(e['address'],16)
    if at<a+0x14 and a+0x10<at+e['size_bytes']or at in [f+0x3ac,f+0x4ec,f+0x4ff,f+0x558,f+0x55c,f+0x560,f+0x3c4,f+0x5c]:events.append({'visit':j,'pc':r['pc'],**e})
   reg.update(r['registers_after'])
  writes=[e for e in events if e['kind']=='write'and int(e['address'],16)<a+0x14 and a+0x10<int(e['address'],16)+e['size_bytes']]
  assert [e['pc']for e in writes]==['0x10031cb80','0x1004c5798']
  raw=[]
  for e in writes:
   data=bytes.fromhex(e['value']['hex']);k=a+0x10-int(e['address'],16);raw.append(int.from_bytes(data[k:k+4],'little'))
  assert raw==[C,C-4]
  assert [(e['pc'],e['value']['hex'])for e in events if e['kind']=='write'and int(e['address'],16)==f+0x3ac]==[('0x100461c10','4dc63d8b')]
  assert [(e['pc'],e['value']['hex'])for e in events if e['kind']=='write'and int(e['address'],16)==f+0x4ff]==[('0x1004c75d4','01')]
  assert not any(e['kind']=='write'and int(e['address'],16)in [f+0x4ec,f+0x560]for e in events)
  def val(pc,k):return int.from_bytes(bytes.fromhex(points[pc][k]['hex']),'little')
  cls=2 if c['name']=='prefix'else 5
  assert val('0x1004c75a0','x8')==cls and val('0x1004c75a0','x9')==a and val('0x1004c75a0','x10')==0xadf4fdbf
  assert val('0x10063ac7c','x11')==C-4 and val('0x10063ac7c','x12')==0 and val('0x10063ac7c','x10')==12 and val('0x10063ac7c','x13')==0x7de7
  branches=[{'pc':r['pc'],'target':r['target'],'modifier16':r['modifier16']}for r in case['trace']['steps']if 'target'in r and r['pc']in ['0x1004c7618','0x10063ad54','0x100471358']]
  assert [r['target']for r in branches]==['0x10063ac7c','0x1004712f4','0x10063735c']
  out.append({'epoch':c['epoch'],'variant':c['name'],'frame_SP':hex(f),'object':hex(a),'object_word_raw_values':[hex(x)for x in raw],
   'decoded_comparison_word':hex(raw[-1]^C),'count_u32':0,'class_u32':cls,'selected_limit_u32':12,'entry_states':points,'events':events,'selected_branches':branches,
   'source_visits_checked':len(case['trace']['steps']),'partial_boundary':case['trace']['boundary'],'partial_case_resumed':False,'native_admission_established':False})
 assert len(out)==4
 return out

def obligations():
 f,a,p,b=z3.BitVecs('admission_frame64 admission_object64 admission_pointer64 admission_bank64',64);w,n,m,k=z3.BitVecs('admission_word32 admission_count32 admission_limit32 admission_class32',32);qs=[]
 v=Parent.Parent.Algebra();v.seed('sp',f);v.seed('w9',0x4a2);mem(v,f+0x60,8,a);mem(v,a+16,4,C);mem(v,f+0x5c,4,0x73113b31);v.run_block(0x100461a30,0x100461c14)
 qs.append(('source_tag_and_initial_word_produce_observed_update',z3.Or(cell(v,f+0x3ac,4)!=C-4,cell(v,f+0x498,8)!=a+16)))
 v.seed('w3',0x871a);v.run_block(0x1004c5788,0x1004c579c)
 qs.append(('source_commit_and_comparison_decoding',z3.Or(cell(v,a+16,4)!=C-4,(cell(v,a+16,4)^C)!=28)))
 v=Parent.Parent.Algebra();v.seed('sp',f);v.seed('w8',k);v.seed('w10',0xadf4fdbf);v.seed('x9',a);v.seed('x23',TABLE);mem(v,a+16,4,w);mem(v,SLOTS[0],8,0x10063ac7c);v.run_block(0x1004c75a0,0x1004c7618)
 width=z3.If(z3.UGT(k,1),z3.BitVecVal(12,32),z3.BitVecVal(0,32));flag=z3.If(z3.UGT(k,1),z3.BitVecVal(1,8),z3.BitVecVal(0,8))
 qs.append(('class_limit_flag_word_and_original_gate_target',z3.Or(v.read('w10')!=width,cell(v,f+0x4ff,1)!=flag,cell(v,f+0x558,4)!=w,cell(v,f+0x430,8)!=a+16,v.read('w12')!=0,v.read('w13')!=0x7de7,v.read('x8')!=0x10063ac7c,v.read('x17')!=0x3512)))
 v=Parent.Parent.Algebra()
 for reg,x in [('sp',f),('w13',0x7de7),('w11',w),('w12',n),('w10',m)]:v.seed(reg,x)
 v.run_block(0x10063ac7c,0x10063ad14)
 qs.append(('intermediate_xor_affine_word',v.read('w14')!=((w^C)-C)))
 v.run_block(0x10063ad14,0x10063ad40)
 qs.append(('overflow_aware_gate_is_unsigned_count_lt_decoded_word',(v.read('w14')!=0)!=z3.ULT(n,w^C)))
 v.run_block(0x10063ad40,0x10063ad4c)
 qs.append(('gate_indices_and_saved_inputs',z3.Or(v.read('w13')!=z3.If(z3.ULT(n,w^C),z3.BitVecVal(0x7e31,32),z3.BitVecVal(0x7de7,32)),cell(v,f+0x55c,4)!=n,cell(v,f+0x3c4,4)!=m,v.read('w9')!=0x4d6)))
 for index,target in [(0x7de7,0x10052249c),(0x7e31,0x1004712f4)]:
  v=Parent.Parent.Algebra();v.seed('x23',TABLE);v.seed('w13',index);mem(v,TABLE+index*8,8,target);v.run_block(0x10063ad4c,0x10063ad54)
  qs.append(('original_gate_table_target_'+hex(index),z3.Or(v.read('x13')!=target,v.read('x17')!=0x8897)))
 v=Parent.Parent.Algebra();v.seed('sp',f);v.seed('w9',0x4d6);v.seed('w10',m);v.seed('w11',w);v.seed('x23',TABLE)
 for at,size,x in [(f+0x380,8,a),(f+0x2a8,8,p),(f+0x2b0,8,b),(TABLE+0x7a21*8,8,0x10046a104)]:mem(v,at,size,x)
 v.run_block(0x10052249c,0x1005225b4)
 qs.append(('remainder_writer_and_preparation_edge',z3.Or(cell(v,f+0x4ec,4)!=m-(w^C),v.read('x26')!=a,v.read('x24')!=p,v.read('x25')!=b,v.read('x10')!=0x10046a104,v.read('x17')!=0xd50d)))
 v=Parent.Parent.Algebra();v.seed('sp',f);v.seed('w10',0xa866);v.seed('w11',w);v.seed('w20',m);mem(v,f+0x3c4,4,m);v.run_block(0x100530720,0x100530770)
 qs.append(('unchanged_zero_decoded_remainder_selects_equality_continuation',v.read('w10')!=0xa866))
 v=Parent.Parent.Algebra();v.seed('sp',f);v.seed('x9',a);mem(v,a,8,p);mem(v,f+0x348,4,w);v.run_block(0x100524030,0x100524040)
 qs.append(('other_source_copy_to_same_displacement',z3.Or(cell(v,f+0x4ec,4)!=w,cell(v,f+0x3a0,8)!=p)))
 out=[]
 for label,predicate in qs:
  s=z3.Solver();s.set(timeout=30000);s.add(predicate);result=str(s.check());assert result=='unsat',(label,result);out.append({'label':label,'query':s.to_smt2(),'result':result})
 return out

def controls():
 out=[]
 for epoch in range(2):
  for cls in [0,1,2,5,0xffffffff]:
   for decoded in [0,1,28,0xffffffff]:
    f=0x7000004000+epoch*0x10000;a=0x7100000000+epoch*0x1000;raw=decoded^C;width=12 if cls>1 else 0
    initial={'x'+str(j):((j+1)*0x111111111111111)&Parent.MASK for j in range(31)};initial.update(sp=f,x8=cls,x9=a,x10=0xadf4fdbf,x23=TABLE)
    cells=[(a+16,4,raw),(f+0x380,8,a),(f+0x2a8,8,0x100fc4230),(f+0x2b0,8,0x101031fa0)]+[(at,8,qword(at))for at in SLOTS]
    v=Parent.Control();v.events=[]
    for name,x in initial.items():v.seed(name,x)
    for at,size,x in cells:mem(v,at,size,x)
    v.n=v.z=v.carry=v.overflow=z3.BoolVal(False);trace=[];blocks=[SPECS[2][1:],SPECS[3][1:]]
    blocks+=([SPECS[5][1:],SPECS[6][1:]]if decoded else[SPECS[4][1:]])
    for lo,hi in blocks:
     for i in DEC.disasm(IMAGE.read(lo,hi-lo),lo):
      before={k:Parent.number(x)for k,x in v.regs.items()};flags=Parent.nzcv(v);v.events=[];v.pc=i.address;r={'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic}
      if i.mnemonic=='braa':r.update(target=hex(Parent.number(v.read(i.reg_name(i.operands[0].reg)))),modifier16=hex(Parent.number(v.read('x17'))))
      else:v.one(i)
      r.update(registers_after={k:hex(Parent.number(x))for k,x in v.regs.items()if Parent.number(x)!=before.get(k)},events=list(v.events))
      if Parent.nzcv(v)!=flags:r['NZCV_after']=hex(Parent.nzcv(v))
      trace.append(r)
    if not decoded:assert Parent.number(cell(v,f+0x4ec,4))==width
    out.append({'kind':'setup','epoch':epoch,'class_u32':hex(cls),'count_u32':'0x0','decoded_word_u32':hex(decoded),'raw_word_u32':hex(raw),'limit_u32':width,'reader_selected':bool(decoded),
     'initial_registers':{k:hex(x)for k,x in initial.items()},'initial_cells':[{'address':hex(at),'size_B':size,'value':hex(x)}for at,size,x in cells],
     'initial_NZCV':'0x0','trace':trace,'boundary':hex(0x100637368 if decoded else 0x10046a104),'source_visits':len(trace),
     'native_admission_established':False,'actual_partial_fixture_resumed':False})
 stress=[(0,0),(0,1),(1,0),(28,28),(27,28),(29,28),(0xffffffff,0),(0,0xffffffff),(0xffffffff,0xffffffff),(0x80000000,0xffffffff),(0xffffffff,0x80000000),(0x2bd2c71e,0x2bd2c71f),(0x2bd2c71f,0x2bd2c71e),(0x2bd2c71f,0x2bd2c71f)]
 for epoch in range(2):
  for count,decoded in stress:
   f=0x7000004000+epoch*0x10000;raw=decoded^C;initial={'x'+str(j):((j+1)*0x111111111111111)&Parent.MASK for j in range(31)};initial.update(sp=f,x10=12,x11=raw,x12=count,x13=0x7de7,x23=TABLE)
   cells=[(at,8,qword(at))for at in SLOTS];v=Parent.Control();v.events=[]
   for name,x in initial.items():v.seed(name,x)
   for at,size,x in cells:mem(v,at,size,x)
   v.n=v.z=v.carry=v.overflow=z3.BoolVal(False);trace=[]
   for i in DEC.disasm(IMAGE.read(0x10063ac7c,0xdc),0x10063ac7c):
    before={k:Parent.number(x)for k,x in v.regs.items()};flags=Parent.nzcv(v);v.events=[];v.pc=i.address;r={'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic}
    if i.mnemonic=='braa':r.update(target=hex(Parent.number(v.read(i.reg_name(i.operands[0].reg)))),modifier16=hex(Parent.number(v.read('x17'))))
    else:v.one(i)
    r.update(registers_after={k:hex(Parent.number(x))for k,x in v.regs.items()if Parent.number(x)!=before.get(k)},events=list(v.events))
    if Parent.nzcv(v)!=flags:r['NZCV_after']=hex(Parent.nzcv(v))
    trace.append(r)
   out.append({'kind':'gate','epoch':epoch,'class_u32':None,'count_u32':hex(count),'decoded_word_u32':hex(decoded),'raw_word_u32':hex(raw),'limit_u32':12,'reader_selected':count<decoded,
    'initial_registers':{k:hex(x)for k,x in initial.items()},'initial_cells':[{'address':hex(at),'size_B':size,'value':hex(x)}for at,size,x in cells],
    'initial_NZCV':'0x0','trace':trace,'boundary':hex(0x1004712f4 if count<decoded else 0x10052249c),'source_visits':len(trace),'native_admission_established':False,'actual_partial_fixture_resumed':False})
 return out

def main():
 parent=inputs();ss=source();aa=actual(parent);qq=obligations();cc=controls()
 counts={'source_regions':len(ss),'source_instructions':sum(len(s['instructions'])for s in ss),'actual_partial_cases':len(aa),'actual_visits_rechecked':sum(r['source_visits_checked']for r in aa),
  'queries_unsat':len(qq),'control_cases':len(cc),'control_visits':sum(c['source_visits']for c in cc),'setup_controls':sum(c['kind']=='setup'for c in cc),'gate_controls':sum(c['kind']=='gate'for c in cc),'reader_controls':sum(c['reader_selected']for c in cc)}
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':Parent.Parent.R.H.THIN,'parent_pins':PINS,'dependencies':{n:sha(ROOT/n)for n in DEPS},
  'source_regions':ss,'source_fixups':Parent.Parent.R.verify_fixups(set(SLOTS)),'actual_lineages':aa,'source_proofs':qq,'control_cases':cc,'verified_counts':counts,
  'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'live_IDA_claim':False,'actual_partial_fixture_resumed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)

if __name__=='__main__':main()
