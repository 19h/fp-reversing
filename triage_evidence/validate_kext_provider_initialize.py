#!/usr/bin/env python3
"""Fresh startup replay, lock/epoch/byte oracle and source-produced table consumer.
O(visits+effects+source bytes), O(unique PCs+critical effects+RAM); bounded SMT.
"""
import hashlib,json,struct,subprocess
from collections import Counter
from unicorn import arm64_const as ar
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_kext_constructor_request import sha
from replay_kext_provider_initialize import Replay
from probe_kernel_vm_mig import Probe as Small,P,SP,HALT
from replay_kernel_vm_mig import Replay as SmallReplay
PREFIX='kext_provider_initialize';TABLE=P+0x21000;BASE=0xfffffe000cccda68;MASK=0xfffffe000ccceaf8;FLAG=0xfffffe000cccea88;LOCKCELL=0xfffffe000ccceab8;WARM=0xfffffe000ccca078
class Consumer(Small):
 def __init__(self,im,producer,address):
  super().__init__(im,'selector',{'id':0});self.entry=0xfffffe000a5b5154;self.allowed=[(self.entry,0xfffffe000a5b5184)];self.fixture(TABLE,bytes.fromhex(producer['final_table512_hex']));self.fixture(SP+0x98,struct.pack('<Q',BASE));self.input=address
  for a,n in [(BASE,8),(MASK,4)]:
   b=bytes.fromhex(producer['final_cells_hex'][hex(a)]);assert len(b)==n;self.ensure(a,n);self.u.mem_write(a,b);self.image_initial.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':'Exact source-produced initializer output from case0; component transfer, not native constructor reachability'})
  for j in range(31):self.set(j,0)
  self.set(11,address);self.set(13,MASK);self.set(30,HALT);self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def code(self,u,a,n,d):
  if a==0xfffffe000a5b5184:self.flush();return self.stop('after_masked_word_load')
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=100);self.flush();assert self.reason=='after_masked_word_load'
  return {'configuration':{'derived_address64':hex(self.input)},'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'private_RAM':{'address':hex(P),'size_bytes':0x100000,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'boundary':self.boundary,'native_target_executed':False,'hardware_PAC_executed':False}
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());prof=json.loads((ROOT/(PREFIX+'_profiles.json')).read_text());counts=Counter();totals=Counter();consumer_totals=Counter();lock_sites=[]
 for obj,name in [(src,'recover_'+PREFIX+'.py'),(prof,'probe_'+PREFIX+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
 for r in src['ranges']:assert im.k.read(int(r['start'],16),int(r['end'],16)-int(r['start'],16)).hex()==r['bytes_hex']
 for v in src['views']:assert im.k.read(int(v['address'],16),64).hex()==v['bytes64_hex']and im.pointer(int(v['name_pointer']['slot'],16))==v['name_pointer']
 for b in src['banks']:
  l=bytes.fromhex(b['left256_hex']);r=bytes.fromhex(b['right256_hex']);assert{n^r[l[n]^int(b['key'],16)]for n in range(256)}=={int(b['constant'],16)}and im.pointer(int(b['slot'],16))==b['original_pointer']
 for proof in src['proofs']:
  assert sha(ROOT/proof['path'])==proof['sha256'];q=subprocess.run(['z3',str(ROOT/proof['path'])],capture_output=True,text=True,check=True);assert q.stdout.strip()=='unsat'and not q.stderr
 assert len(prof['cases'])==4
 for j,row in enumerate(prof['cases']):
  c=row['configuration'];models=row['API_models'];success=j in [0,3];expected=0 if success else 0xffff5bd4;assert all(int(r['registers31'][0],16)==expected and r['SP']==hex(SP)for r in row['returns']);assert len(row['returns'])==(2 if c.get('repeat')else 1);counts['wrapper_returns_checked_by_oracle']+=len(row['returns'])
  cells=row['final_cells_hex'];assert int.from_bytes(bytes.fromhex(cells[hex(FLAG)]),'little')==(1 if success else 0)and int.from_bytes(bytes.fromhex(cells[hex(MASK)]),'little')==(255 if success else 0)and int.from_bytes(bytes.fromhex(cells[hex(BASE)]),'little')==(TABLE if success else 0)and cells[hex(WARM)]=='00'
  allocated={};depth={};alive={};generic_cursor=TABLE
  for m in models:
   sym=m['symbol'];args=[int(v,16)for v in m['arguments8']];result=int(m['return_value'],16);effects=m['memory_effects'];counts['API_'+sym]+=1
   if sym=='aligned_allocation_model':assert args[:2]==[16384,64]and result==P+0x10000 and not effects
   elif sym=='typed_allocation_model':assert args[0]==0xfffffe000847bea0 and result==P+0x20000 and not effects
   elif sym in ['data_allocation_model','generic_allocation_model']:
    fail=sym=='data_allocation_model'and args[0]==c.get('fail_data_size');assert result==(0 if fail else generic_cursor)and not effects
    if result:generic_cursor+=(args[0]+4095)&~4095;allocated[result]=args[0]
   elif sym=='lock_allocation_model':
    assert not effects
    if c.get('fail_lock'):assert result==0
    else:assert result and result not in depth;depth[result]=0;alive[result]=True
   elif sym in ['lock_model','unlock_model','lock_free_model']:
    assert args[0]in depth and alive[args[0]]and not effects and result==0
    if sym=='lock_model':assert depth[args[0]]==0;depth[args[0]]=1
    elif sym=='unlock_model':assert depth[args[0]]==1;depth[args[0]]=0
    else:assert depth[args[0]]==0;alive[args[0]]=False
   elif sym=='calendar_time_model':assert result==0 and len(effects)==2 and effects[0]['address']==hex(args[0])and effects[0]['after_hex']==struct.pack('<Q',1700000000).hex()and effects[1]['address']==hex(args[1])and effects[1]['after_hex']==struct.pack('<I',123456).hex()
   elif sym=='logger_no_effect_model':assert args[0]==0xfffffe000790caf5 and not effects
   else:
    assert sym=='free_no_effect_model'and not effects and result==0;pc=int(m['pc'],16)
    if pc==0xfffffe000c4ba368:assert args[:2]==[0xfffffe000847ba60,P+0x20000]
    elif pc==0xfffffe000c4b9a24:assert args[:2]==[P+0x10000,16384]
    elif pc==0xfffffe000c4ba84c:assert args[1]==29 and(args[0]==0 if c.get('fail_data_size')==29 else allocated[args[0]]==29)
    else:assert pc==0xfffffe000c4b94b8
  assert row['final_lock_owners']=={hex(a):{'depth':d,'alive':alive[a]}for a,d in depth.items()}and row['final_lock_depth']==0 and not any(depth.values());counts['distinct_lock_objects_checked']+=len(depth)
  table=bytearray(512);coverage=set();table_writes=[];flags=[];base_writes=[];mask_writes=[]
  for e in row['critical_effects']:
   a=int(e['address'],16);b=bytes.fromhex(e['after_hex'])
   if TABLE<=a<TABLE+512:
    assert a+len(b)<=TABLE+512;table[a-TABLE:a-TABLE+len(b)]=b;coverage.update(range(a,a+len(b)));table_writes.append(e)
   if a==FLAG and int.from_bytes(b,'little')==1:flags.append(e)
   if a==BASE:base_writes.append(e)
   if a==MASK:mask_writes.append(e)
   if len(b)==8 and int.from_bytes(b,'little')in depth:lock_sites.append({'case':j,'phase':e['phase'],'pc':e['pc'],'cell':e['address'],'lock':hex(int.from_bytes(b,'little'))})
  assert bytes(table).hex()==row['final_table512_hex']
  if success:
   assert len(coverage)==512 and len(base_writes)==1 and len(mask_writes)==1 and len(flags)==1;assert base_writes[0]['pc']=='0xfffffe000a66cb40'and mask_writes[0]['pc']=='0xfffffe000a66cbb0';assert max(e['source_visit_index']for e in table_writes)<flags[0]['source_visit_index']<row['returns'][0]['before_source_visit_index'];assert base_writes[0]['source_visit_index']<mask_writes[0]['source_visit_index']<flags[0]['source_visit_index'];counts['complete_table_bytes_checked']+=512;counts['table_before_ready_flag_cases']+=1
  else:assert not coverage and not base_writes and not mask_writes and not flags
  if c.get('repeat'):
   assert len(row['declared_call_transitions'])==1 and not any(e['phase']==1 for e in table_writes+flags+base_writes+mask_writes);counts['cached_table_reuses_checked']+=1
   assert not any(m['phase']==1 and m['symbol']in ['data_allocation_model','generic_allocation_model','calendar_time_model','logger_no_effect_model']for m in models)
  else:assert not row['declared_call_transitions']
  totals.update(Replay(im,row).run());print(json.dumps({'case':j,'fresh_replay':'pass','source_visits':row['fingerprints']['visits']['count']}),flush=True)
 producer=prof['cases'][0];table=bytes.fromhex(producer['final_table512_hex']);components=[];offsets=set()
 for address in [*range(0,256,8),1,7,0x123456789abcdef0,0xffffffffffffffff]:
  r=Consumer(im,producer,address).run();offset=(address+0x50)&0xf8;value=int.from_bytes(table[offset:offset+8],'little');assert int(r['boundary']['registers31'][13],16)==value and r['source_reads'][-1]['address']==hex(TABLE+offset)and r['source_reads'][-1]['bytes_hex']==table[offset:offset+8].hex()and not r['source_writes'];offsets.add(offset);consumer_totals.update(SmallReplay(im,r).run());components.append(r)
 assert len(offsets)==32;counts['consumer_components']=len(components);counts['consumer_aligned_offsets_checked']=32
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [PREFIX+'_source.json',PREFIX+'_profiles.json','replay_'+PREFIX+'.py','replay_kernel_vm_mig.py','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'source_recapture_match':True,'verified_counts':{'cases':4,'ranges':len(src['ranges']),'captured_instructions':sum(len(r['instructions'])for r in src['ranges']),'views':len(src['views']),'banks256':len(src['banks']),'proofs_unsat':1,**dict(counts)},'independent_A64_replay':dict(totals),'consumer_A64_replay':dict(consumer_totals),'consumer_profiles':components,'producer_table512_sha256':hashlib.sha256(table).hexdigest(),'lock_publication_sites':lock_sites,'all_checks_pass':True,'native_target_executed':False,'native_IPC_executed':False,'native_allocator_executed':False,'native_lock_executed':False,'native_clock_executed':False,'native_provider_start_executed':False,'continuous_native_constructor_established':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(PREFIX+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':out['verified_counts'],'independent_A64_replay':dict(totals),'consumer_A64_replay':dict(consumer_totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
