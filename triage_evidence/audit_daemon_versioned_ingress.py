#!/usr/bin/env python3
"""Independent A64 replay of source ingress, adapter and unresolved reads.

O(prefix+patterns*(owner+snapshot+visits+effects)) time/space;30 s/query.
Prefixes are restored, native APIs/PAC never execute, unknowns stay unknown.
"""
import json
from pathlib import Path
from collections import Counter
import z3
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,IMAGE
from replay_daemon_callback_revisit import Replay
from replay_daemon_context_transfer import evaluate
from verify_daemon_reader_record_payloads_publication import read,sha
import audit_daemon_versioned_root as Parent
import recover_daemon_versioned_ingress as R

def scalar(s):return Parent.scalar(s)

def overlays(c):
 out={}
 for a,x in c['u64_cells'].items():out.update({int(a,16)+j:b for j,b in enumerate(int(x,16).to_bytes(8,'little'))})
 for n in ['input_A','input_B']:
  a=int(c[n],16)
  if a:out.update({at:c['input_fill_byte']for at in range(a,a+c['input_extent_B'])})
 raw=int(c['capabilities_u32'],16)^0xc49697f0;out.update({0x1010b6394+j:b for j,b in enumerate(raw.to_bytes(4,'little'))});return out

def status_controls():
 out=[];s=0x7000004000;pointer=0x1122334455667788;lo=0x1008c1710;hi=0x1008c1760
 for status in [0x8b3dc651,0x74c29d80,0x74c29d85,0x74c29d88]:
  u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);u.mem_map(lo&~4095,4096);u.mem_write(lo,IMAGE.read(lo,hi-lo));u.mem_map(s,0x2000);u.mem_write(s+0x9d8,R.TABLE.to_bytes(8,'little'));pages=set()
  for index in [0x5d32,0x5d45]:
   at=R.TABLE+index*8;page=at&~4095
   if page not in pages:u.mem_map(page,4096);pages.add(page)
   u.mem_write(at,R.qword(at).to_bytes(8,'little'))
  for reg,x in {'SP':s,'X8':status,'X19':0x5d32,'X11':pointer}.items():u.reg_write(getattr(ar,'UC_ARM64_REG_'+reg),x)
  visits=[];indices=[]
  def code(engine,a,n,d):
   assert bytes(engine.mem_read(a,4))==IMAGE.read(a,4);visits.append(a)
   if a==0x1008c1758:indices.append(engine.reg_read(ar.UC_ARM64_REG_X8))
  u.hook_add(uc.UC_HOOK_CODE,code);u.emu_start(lo,hi,count=20);index=0x5d45 if status==0x8b3dc651 else 0x5d32
  assert len(visits)==20 and indices==[index]and u.reg_read(ar.UC_ARM64_REG_X8)==R.qword(R.TABLE+index*8)and int.from_bytes(u.mem_read(s+0x16d0,8),'little')==pointer-0x480
  out.append({'status_u32':hex(status),'decoded_zero_gate':status==0x8b3dc651,'index':hex(index),'slot':hex(R.TABLE+index*8),'target':hex(R.qword(R.TABLE+index*8)),'source_visits':20,'native_target_executed':False})
 return out

class Check(Parent.Check):
 def __init__(self,snapshot,old,case,pattern):
  c=case['configuration']
  if c['kind']=='prefix':
   super().__init__(snapshot,old,case,pattern);self.snap={**snapshot,'boundary':{'pc':c['entry']}};return
  Replay.__init__(self,snapshot,case['trace'],pattern);self.case=case;self.model_cursor=0;self.retired=False;self.allocated=False
  self.u.mem_map(R.OWNER,R.EXTENT);self.pages.update(range(R.OWNER,R.OWNER+R.EXTENT,4096));raw=bytearray()
  for at in range(R.OWNER,R.OWNER+R.EXTENT):self.backing[at-self.F]=self.unknown_byte(at-self.F);raw.append(self.backing[at-self.F])
  self.u.mem_write(R.OWNER,bytes(raw));reg=dict(snapshot['logical_registers']);flags=int(snapshot['NZCV'],16);ram={}
  for row in old['steps'][:case['prefix_source_visits']]:
   assert IMAGE.read(int(row['pc'],16),4).hex()==row['bytes_hex']
   for e in row['events']:
    a=int(e['address'],16);data=evaluate(e['value'],self.backing);ram.update({a+j:b for j,b in enumerate(data)})
   reg.update(row['registers_after']);flags=row.get('NZCV_after',flags)
  self.write_ram(ram);self.write_ram(overlays(c))
  for n,s in reg.items():self.u.reg_write(getattr(ar,'UC_ARM64_REG_'+n.upper()),int.from_bytes(evaluate(s,self.backing),'little'))
  self.u.reg_write(ar.UC_ARM64_REG_NZCV,flags)
  for n,x in c['registers'].items():self.u.reg_write(getattr(ar,'UC_ARM64_REG_'+n.upper()),int(x,16))
  assert flags==case['trace']['initial_NZCV']
  for n,s in case['trace']['initial_registers'].items():assert self.register(n)==int.from_bytes(evaluate(s,self.backing),'little'),('initial',n)
  self.snap={**snapshot,'boundary':{'pc':c['entry']}}

def interfaces(case):
 c=case['configuration'];trace=case['trace'];b=trace['boundary'];calls=[{'pc':r['pc'],'target':r['target'],'modifier16':r['modifier16']}for r in trace['steps']if r['mnemonic']=='blraa']
 if c['kind']=='prefix':
  expected=0x10046fc5c if c['name']=='exclude47d'else R.R.ENTRY
  assert b['kind']=='before_uninspected_call'and int(b['target'],16)==expected and not calls and not case['API_models']
  return {'epoch':c['epoch'],'variant':c['name'],'entry':c['entry'],'call_PC':b['pc'],'actual_target':b['target'],'modifier16':b['modifier16'],'root_edge':expected==R.R.ENTRY,'all_checks_pass':True}
 s=int(c['caller_SP'],16);record=s+0x10cb8;seedcell=s+0xba18;ram=overlays(c);regs=dict(trace['initial_registers']);points={};events=[];models={m['after_source_visits']:m for m in case['API_models']};old_seed=None;temp=None;initial_temp=None
 def get(a,n):
  data=[ram[a+j]for j in range(n)];assert all(isinstance(x,int)for x in data),(hex(a),data)
  return int.from_bytes(bytes(data),'little')
 def val(n):return scalar(regs[n])
 for j,row in enumerate(trace['steps']):
  if j in models:regs.update(models[j]['register_effects'])
  pc=int(row['pc'],16)
  if pc in [0x10084cb04,R.ADAPTER,0x1004aca58,R.R.ENTRY,0x1006349bc,0x100552dac,0x1004aca5c,0x10084cb1c,0x1008c1758]:
   points[hex(pc)]={'visit':j,'registers':regs.copy()}
   if pc==0x10084cb04:assert val('x0')==record and val('x1')==seedcell;old_seed=get(seedcell,8)
   if pc==0x1004aca58:temp=val('x1');initial_temp=get(temp,8);assert val('x0')==record and val('sp')==temp and initial_temp==(old_seed-0xb0)&((1<<64)-1)
   if pc==R.R.ENTRY:
    k=Parent.record_key(record)&0xffffffff
    assert(get(record,4)+k)&0xffffffff==0x73113b31 and(get(record+4,4)-k)&0xffffffff==0x871a
    assert get(record+16,8)==int(c['input_A'],16)and get(record+24,8)==int(c['input_B'],16)
   if pc==0x1006349bc:assert val('x8')==0x73113b31
  for e in row['events']:
   a=int(e['address'],16);v=e['value'];data=list(bytes.fromhex(v['hex']))if'hex'in v else v['terms'];ram.update({a+k:x for k,x in enumerate(data)});events.append({'visit':j,'pc':row['pc'],**e})
  regs.update(row['registers_after'])
 assert calls[:2]==[{'pc':'0x10084cb04','target':hex(R.ADAPTER),'modifier16':'0xfbe5'},{'pc':'0x1004aca58','target':hex(R.R.ENTRY),'modifier16':'0xdbd5'}]
 new=(old_seed*0x2edd+1)&((1<<64)-1);reserve=16*((new>>60)+1);f=temp-0x980
 assert temp==s-64-reserve and get(0x1010b63e0,8)==new
 temp_writes=[e for e in events if e['kind']=='write'and int(e['address'],16)<temp+8 and temp<int(e['address'],16)+e['size_bytes']]
 assert [e['pc']for e in temp_writes]==['0x1004ac9a4','0x10049f4a8']and get(temp,8)==old_seed
 assert not any(r['pc']=='0x100478a04'for r in trace['steps'])
 out={'epoch':c['epoch'],'variant':c['name'],'caller_SP':hex(s),'record':hex(record),'record_count_tag_u32':'0x73113b31','record_operation_u32':'0x871a','caller_phase_u32':'0x6cf4','seed_global':'0x1010b63e0','old_seed_u64':hex(old_seed),'next_seed_u64':hex(new),'dynamic_reserve_B':reserve,'adapter_fixed_reserve_B':64,'temp':hex(temp),'temp_initial_u64':hex(initial_temp),'temp_final_u64':hex(get(temp,8)),'temp_writes':[e['pc']for e in temp_writes],'root_frame_SP':hex(f),'root_inner_record':hex(f+0x8d8),'calls':calls,'boundary':{'kind':b['kind'],'pc':b['pc']},'IOKit_call_executed':False,'all_checks_pass':True}
 if c['name']in ['prefix','extended']:
  assert b['kind']=='before_unresolved_source_effect'and b['pc']=='0x10063736c'and 'transformed private unknown'in b['reason']
  reads=[e for e in events if e['pc']=='0x100637368'and e['kind']=='read'];assert len(reads)==1 and reads[0]['address']==hex(f+0x560)and reads[0]['size_bytes']==4
  assert reads[0]['value']=={'terms':[{'origin':f+0x560+j-0x640000b520}for j in range(4)]}
  assert not any(e['kind']=='write'and int(e['address'],16)<f+0x564 and f+0x560<int(e['address'],16)+e['size_bytes']for e in events)
  assert len(case['API_models'])==1 and case['API_models'][0]['name']=='malloc'
  out.update(caller_result_read=False,allocator_retired=False,unresolved_frame_word=reads[0],unresolved_value_role='unknown; source origin retained, not initialized by this path')
 else:
  assert b['kind']=='declared_after_caller_status_selection'and b['pc']==hex(R.STOP)and b['SP']==hex(s)
  assert get(seedcell,8)==0 and scalar(points['0x10084cb1c']['registers']['x8'])==get(record+8,4)
  assert scalar(points['0x1008c1758']['registers']['x8'])==0x5d32 and get(s+0x16d0,8)==(-0x480)&((1<<64)-1)
  target=R.qword(R.TABLE+0x5d32*8);assert scalar(b['registers31'][8])==target
  out.update(caller_result_read=True,returned_word_u32=hex(get(record+8,4)),adapter_return_delta_B=0,caller_SP_adjustment_B=0,caller_zero_gate=False,caller_continuation_index='0x5d32',caller_continuation_target=hex(target),allocator_retired=any(m['name']=='free'for m in case['API_models']))
  if c['name']=='null_B':assert not case['API_models']and len(calls)==2
  elif c['name']=='malloc_failure':assert len(case['API_models'])==1 and len(calls)==3
  else:assert [m['name']for m in case['API_models']]==['malloc','free']
 return out

def main():
 pins,old=R.inputs();e=json.loads(read(ROOT/(R.P+'_checks.json')))
 assert e['generator_sha256']==sha(ROOT/('recover_'+R.P+'.py'))and e['parent_pins']==R.PINS and e['dependencies']=={n:sha(ROOT/n)for n in R.DEPS}and e['source_regions']==R.source()
 assert e['bounded_census']==R.census()and e['bank_rules']==R.banks()
 used={int(a,16)for case in e['cases']for a in case['trace']['used_fixups']};assert e['source_fixups']==R.R.verify_fixups(used)
 fresh=R.obligations();assert [r['label']for r in fresh]==[r['label']for r in e['source_proofs']]
 for row in e['source_proofs']:
  s=z3.Solver();s.set(timeout=30000);s.from_string(row['query']);assert str(s.check())==row['result']=='unsat'
 rows=[];joins=[];totals=Counter();counts=Counter()
 for case in e['cases']:
  c=case['configuration'];assert c==R.configuration(c['epoch'],c['name'])and old['steps'][case['prefix_source_visits']]['pc']=='0x100add594'
  joins.append(interfaces(case));counts.update(case['counts'])
  for pattern in [0,3]:
   row=Check(pins['daemon_callback_revisit_snapshot.json'],old,case,pattern).run();row.update(epoch=c['epoch'],variant=c['name']);rows.append(row);totals.update(row['verified_counts']);print(json.dumps({'epoch':c['epoch'],'variant':c['name'],'pattern':pattern,'source_visits':row['verified_counts']['source_visits']}),flush=True)
 verified={'cases':len(e['cases']),'epochs':2,'variants_per_epoch':10,**dict(counts)};assert verified==e['verified_counts']
 flags={k:False for k in ['prefix_reexecuted','native_target_executed','native_API_executed','IDB_mutated','live_IDA_claim','native_caller_admission_established','complete_IOKit_buffer_join_established','native_daemon_kext_pairing_established','full_goal_complete']}
 out={'scope':__doc__,'generator_sha256':e['generator_sha256'],'auditor_sha256':sha(Path(__file__)),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':R.R.H.THIN,'parent_pins':R.PINS,'dependencies':e['dependencies'],'verified_counts':verified,'source_proofs_unsat':len(fresh),'status_controls':status_controls(),'interface_joins':joins,'independent_replays':rows,'independent_totals':dict(totals),'all_checks_pass':True,**flags}
 (ROOT/(R.P+'_audit.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':verified,'independent_totals':dict(totals),'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
