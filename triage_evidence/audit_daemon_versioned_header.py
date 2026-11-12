#!/usr/bin/env python3
"""Independent original-byte A64 replays and constructor/helper interface audit.

Sealed prefixes are restored, not reexecuted. O(prefix + patterns*new visits
+ byte effects + snapshot) time/space; no native API/IPC or hardware PAC.
"""
import json,struct
from pathlib import Path
from collections import Counter
import z3
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,IMAGE,CS,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from replay_daemon_callback_revisit import Replay
from replay_daemon_context_transfer import evaluate
import recover_daemon_versioned_header as R

def scalar(shape):assert 'hex'in shape;return int.from_bytes(bytes.fromhex(shape['hex']),'little')

def alignment_controls():
 rows=[];lo,hi=0x100552ddc,0x100552e38
 for residue in range(8):
  u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);page=lo&~4095;u.mem_map(page,4096);u.mem_write(lo,IMAGE.read(lo,hi-lo))
  f=0x6400004000;r=f+0xf68+residue;u.mem_map(f,0x2000);u.reg_write(ar.UC_ARM64_REG_SP,f);u.reg_write(ar.UC_ARM64_REG_X29,r+0x98);u.reg_write(ar.UC_ARM64_REG_X21,0x871a);visits=[]
  def code(engine,a,n,d):assert bytes(engine.mem_read(a,4))==IMAGE.read(a,4);visits.append(hex(a))
  u.hook_add(uc.UC_HOOK_CODE,code);u.emu_start(lo,hi,count=(hi-lo)//4);assert len(visits)==(hi-lo)//4
  k=(((r&0xffffffff)^0xeaae0ac9)*0x7398180b)&0xffffffff;length=(int.from_bytes(u.mem_read(r+0x10,2),'little')-k-0x153b)&65535;control=(int.from_bytes(u.mem_read(r+0x14,4),'little')+k)&0xffffffff
  assert int.from_bytes(u.mem_read(r+8,8),'little')==f+0x2d4
  rows.append({'residue_mod8':residue,'record':hex(r),'decoded_length_B':length,'decoded_control_u32':hex(control),'source_visits':len(visits),'helper_executed':False,'native_target_executed':False})
 assert rows[0]['decoded_length_B']==4 and rows[0]['decoded_control_u32']=='0xb399'
 assert rows[4]['decoded_length_B']!=4 or rows[4]['decoded_control_u32']!='0xb399'
 return rows

class Check(Replay):
 def __init__(self,snapshot,old,case,pattern):
  super().__init__(snapshot,case['trace'],pattern);self.case=case;self.old=old
  reg=dict(snapshot['logical_registers']);flags=int(snapshot['NZCV'],16);ram={}
  for row in old['steps'][:case['prefix_source_visits']]:
   assert IMAGE.read(int(row['pc'],16),4).hex()==row['bytes_hex']
   for e in row['events']:
    a=int(e['address'],16);data=evaluate(e['value'],self.backing);assert len(data)==e['size_bytes']
    ram.update({a+k:b for k,b in enumerate(data)})
   reg.update(row['registers_after']);flags=row.get('NZCV_after',flags)
  # Prefix receipt effects are loader input, never counted as fresh execution.
  ordered=sorted(ram);j=0
  while j<len(ordered):
   a=ordered[j];k=j+1
   while k<len(ordered)and ordered[k]==ordered[k-1]+1:k+=1
   for page in range(a&~4095,(ordered[k-1]&~4095)+4096,4096):self.page(page)
   self.u.mem_write(a,bytes(ram[x]for x in ordered[j:k]));j=k
  c=case['configuration'];fill=c['fill'];self.u.mem_write(int(fill['address'],16),bytes([fill['byte']])*fill['size_bytes'])
  for a,x in c['u64_cells'].items():self.u.mem_write(int(a,16),int(x,16).to_bytes(8,'little'))
  for name,shape in reg.items():self.u.reg_write(getattr(ar,'UC_ARM64_REG_'+name.upper()),int.from_bytes(evaluate(shape,self.backing),'little'))
  self.u.reg_write(ar.UC_ARM64_REG_NZCV,flags)
  for name,x in c['registers'].items():self.u.reg_write(getattr(ar,'UC_ARM64_REG_'+name.upper()),int(x,16))
  assert flags==case['trace']['initial_NZCV']
  for name,shape in case['trace']['initial_registers'].items():assert self.register(name)==int.from_bytes(evaluate(shape,self.backing),'little'),('initial',name)
  self.snap={**snapshot,'boundary':{'pc':hex(R.ENTRY)}}

def interfaces(case):
 c=case['configuration'];f=int(c['frame_SP'],16);record=int(c['record'],16);regs=dict(case['trace']['initial_registers']);fill=c['fill'];ram={a:fill['byte']for a in range(int(fill['address'],16),int(fill['address'],16)+fill['size_bytes'])};points={};calls=[];events=[]
 for a,x in c['u64_cells'].items():ram.update({int(a,16)+j:b for j,b in enumerate(int(x,16).to_bytes(8,'little'))})
 def value(n):return scalar(regs[n])
 def get(a,n):return int.from_bytes(bytes(ram[a+j]for j in range(n)),'little')
 for j,row in enumerate(case['trace']['steps']):
  pc=int(row['pc'],16)
  if pc in [0x100552ef8,0x100add594,0x100add74c,0x100add7d4,0x100acdb14,0x100acdb1c,0x100add7d8,0x100add7e4,0x100552efc,0x100552f0c]:points[hex(pc)]={'visit':j,'registers':regs.copy()}
  if row['mnemonic']=='blraa':calls.append({'pc':row['pc'],'target':row['target'],'modifier16':row['modifier16']})
  for e in row['events']:
   a=int(e['address'],16);assert 'hex'in e['value'],'constructor depends on an unspecified byte';data=bytes.fromhex(e['value']['hex']);ram.update({a+k:b for k,b in enumerate(data)});events.append({'visit':j,'pc':row['pc'],**e})
  regs.update(row['registers_after'])
 assert [(r['pc'],r['target'])for r in calls]==[('0x100552ef8','0x100add594'),('0x100add7d4','0x100acd9c4'),('0x100b33030','0x10041a5e0'),('0x100a3c13c','0x100427514')]
 root=points['0x100552ef8'];rr=root['registers'];state=scalar(rr['x21']);assert state==0x871a
 assert scalar(rr['x0'])==record and scalar(rr['x1'])==f+0x5e0 and scalar(rr['x17'])==0x22a0
 k=((record&0xffffffff)^0xeaae0ac9)*0x7398180b&0xffffffff
 assert get(record+8,8)==f+0x2d4 and(get(record+0x10,2)-k-0x153b)&65535==4 and(get(record+0x14,4)+k)&0xffffffff==0xb399
 temp=scalar(points['0x100add74c']['registers']['sp']);old=scalar(points['0x100add74c']['registers']['x21']);new=(old*0x2ec5+1)&R.MASK;reserve=16*((new>>60)+1)
 assert temp==f-64-reserve and scalar(points['0x100add7d4']['registers']['x1'])==temp
 first=next(e for e in events if e['pc']=='0x100add74c'and e['kind']=='write');assert int(first['address'],16)==temp and scalar(first['value'])==(old-0xb0)&R.MASK
 start=points['0x100add74c']['visit'];end=points['0x100add7d8']['visit'];overlap=[e for e in events if start<=e['visit']<end and e['kind']=='write'and int(e['address'],16)<temp+8 and temp<int(e['address'],16)+e['size_bytes']]
 assert [e['pc']for e in overlap]==['0x100add74c','0x100acdb1c']and scalar(overlap[1]['value'])==old
 assert get(temp,8)==old and get(f+0x5e0,8)==0
 global_updates=[e for e in events if e['kind']=='write'and int(e['address'],16)==0x1010b8d78];assert len(global_updates)==1 and scalar(global_updates[0]['value'])==new
 source_seed=[e for e in events if e['kind']=='read'and e['visit']<root['visit']and e['size_bytes']==8 and int(e['address'],16)==0x1010b8d78];assert len(source_seed)==1 and scalar(source_seed[0]['value'])==old
 outputs=[e for e in events if e['pc']=='0x100a0ca74'and e['kind']=='write'];assert len(outputs)==4 and [int(e['address'],16)for e in outputs]==list(range(f+0x2d7,f+0x2d3,-1))and all(e['size_bytes']==1 for e in outputs)
 data=bytes(ram[f+0x2d4+j]for j in range(4));word=get(f+0x3b4,4);assert word==int.from_bytes(data,'big')^0x8b3dc651
 assert case['trace']['boundary']['SP']==hex(f)and get(f+0x80,8)==0x1010b6380 and get(f+0x3f0,8)==552
 offset=int(c['registers']['x20'],16)
 for off,expected in [(0x3f8,f+0x5f0+offset),(0x480,f+0x600+offset),(0x488,f+0x610+offset)]:assert get(f+off,8)==expected
 # The allocated552-byte construction view is untouched by this header helper.
 b=f+0x5f0+offset;writes=[e for e in events if e['kind']=='write'and int(e['address'],16)<b+552 and b<int(e['address'],16)+e['size_bytes']];assert not writes
 assert scalar(points['0x100552f0c']['registers']['sp'])==f
 counts=Counter();counts['authenticated_calls']=len(calls)
 for row in case['trace']['steps']:
  for e in row['events']:counts[e['kind']+'_events']+=1;counts[e['kind']+'_bytes']+=e['size_bytes']
  if row['mnemonic']in ['pacibsp','braa','blraa','retab','retaa']:counts['logical_PAC_transfers']+=1
 return {'epoch':c['epoch'],'layout':c['layout'],'frame_SP':hex(f),'record':hex(record),'seed_global':'0x1010b8d78','old_state_u64':hex(old),'new_state_u64':hex(new),'dynamic_reserve_B':reserve,'fixed_adapter_reserve_B':64,'temp':hex(temp),'temp_write_sites':[e['pc']for e in overlap],
  'decoded_output':hex(f+0x2d4),'decoded_length_B':4,'decoded_control_u32':'0xb399','output_bytes_hex':data.hex(),'word_u32':hex(word),'word_store_PC':'0x100552f9c','returned_delta_B':0,'capability_read_PC':hex(R.STOP),'next_state_pointer_cell':hex(f+0x80),
  'construction_buffer':hex(b),'construction_buffer_B':552,'construction_buffer_writes':0,'calls':calls,'counts':dict(counts),'all_checks_pass':True}

def main():
 pins,old=R.inputs();checks=json.loads(read(ROOT/(R.P+'_checks.json')));assert checks['parent_pins']==R.PINS and checks['source_regions']==R.source()and checks['generator_sha256']==sha(ROOT/('recover_'+R.P+'.py'))
 assert checks['dependencies']=={n:sha(ROOT/n)for n in R.DEPS}
 fresh=R.obligations()
 # Solver-local DAG identifiers and SAT model choices are not evidence identity.
 assert [v['label']for v in checks['source_checks']['proofs']]==[v['label']for v in fresh['proofs']]
 assert [v['label']for v in checks['source_checks']['falsifiers_and_witnesses']]==[v['label']for v in fresh['falsifiers_and_witnesses']]
 for row in checks['source_checks']['proofs']+checks['source_checks']['falsifiers_and_witnesses']:
  s=z3.Solver();s.set(timeout=30000);s.from_string(row['query']);assert str(s.check())==row['result']
 rows=[];totals=Counter();joins=[]
 for case in checks['cases']:
  c=case['configuration'];assert c==R.fixture(c['epoch'],c['layout']);assert old['steps'][case['prefix_source_visits']]['pc']=='0x100add594'
  joins.append(interfaces(case))
  for pattern in [0,3]:
   r=Check(pins['daemon_callback_revisit_snapshot.json'],old,case,pattern).run();r.update(epoch=c['epoch'],layout=c['layout']);rows.append(r);totals.update(r['verified_counts']);print(json.dumps({'epoch':c['epoch'],'layout':c['layout'],'pattern':pattern,'source_visits':r['verified_counts']['source_visits']}),flush=True)
 count={'cases':len(checks['cases']),'epochs':2,'layouts':3,'source_visits':sum(len(c['trace']['steps'])for c in checks['cases']),'source_instructions':sum(len(c['trace']['source_pool'])for c in checks['cases']),
  'read_events':sum(j['counts']['read_events']for j in joins),'write_events':sum(j['counts']['write_events']for j in joins)}
 assert count==checks['verified_counts']
 out={'scope':__doc__,'generator_sha256':checks['generator_sha256'],'auditor_sha256':sha(Path(__file__)),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':R.THIN,'parent_pins':R.PINS,'dependencies':checks['dependencies'],'verified_counts':count,'source_proofs_unsat':len(fresh['proofs']),'SAT_probes':len(fresh['falsifiers_and_witnesses']),
  'alignment_controls':alignment_controls(),'interface_joins':joins,'independent_replays':rows,'independent_totals':dict(totals),'prefix_reexecuted':False,'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'live_IDA_claim':False,'native_parent_frame_recovered':False,'complete_IOKit_buffer_join_established':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False,'all_checks_pass':True}
 (ROOT/(R.P+'_audit.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':count,'independent_totals':dict(totals),'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
