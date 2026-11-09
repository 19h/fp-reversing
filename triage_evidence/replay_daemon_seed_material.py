#!/usr/bin/env python3
"""A64 replay to the first input-dependent twist-table read, with four API
summaries. Compare every source effect and complete mixed state with compact
semantics. O(cases*(prefix+visits+events+SSA bytes)) time,O(largest trace)
space. External APIs, Mach/IOKit and authentication never execute.
"""
import hashlib,json
from pathlib import Path
from collections import Counter
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from replay_daemon_context_transfer import Replay,unpack,ENTRY,P
from replay_daemon_entropy_return import expr,concrete,ARRAY
from probe_daemon_arena_storage import Storage
CALL1=0x100409574;TIME=0x1002dc308;CALL2=0x1002dc3a0;CALL3=0x1002dc400
INPUTS=[
 {'name':'zero','seed1':0,'seconds':0,'microseconds':0,'seed2':0,'seed3':0,'time_status':0,'classification':'declared success outputs'},
 {'name':'small','seed1':1,'seconds':1,'microseconds':999999,'seed2':1,'seed3':1,'time_status':0,'classification':'declared success outputs'},
 {'name':'ones','seed1':0xffffffff,'seconds':0xffffffffffffffff,'microseconds':999999,'seed2':0xffffffff,'seed3':0x80000000,'time_status':0,'classification':'declared success outputs'},
 {'name':'reference','seed1':0x12345678,'seconds':0x0123456789abcdef,'microseconds':123456,'seed2':0x89abcdef,'seed3':0xfedcba98,'time_status':0,'classification':'declared success outputs'},
 {'name':'status_sensitivity','seed1':0x12345678,'seconds':0x0123456789abcdef,'microseconds':123456,'seed2':0x89abcdef,'seed3':0xfedcba98,'time_status':0xffffffff,'classification':'independent status/output sensitivity; native failure output behavior unknown'},
 {'name':'seconds_high_sensitivity','seed1':0x12345678,'seconds':0xfedcba9889abcdef,'microseconds':123456,'seed2':0x89abcdef,'seed3':0xfedcba98,'time_status':0,'classification':'declared outputs; identical low32 seconds'},
]

def compact(cfg,cursor):
 mask=0xffffffff;state=[cfg['seed1']]
 for i in range(1,624):state.append((0x6c078965*(state[-1]^(state[-1]>>30))+i)&mask)
 enc=0x5cf7672b;keys=[cfg['seed3']^enc,cfg['microseconds']^enc,(cfg['seconds']&mask)^enc,cfg['seed2']^enc];initial=keys.copy();i=1;j=0;d=cursor&mask
 for _ in range(624):
  state[i]=((state[i]^((state[i-1]^(state[i-1]>>30))*1664525))+((keys[j]^enc)&mask)+j)&mask;i+=1
  if i==624:state[0]=state[623];i=1
  j+=1
  if j==4:j=0;keys[0]^=d
  else:keys[j]^=(d+1)&mask
 for _ in range(623):
  state[i]=((state[i]^((state[i-1]^(state[i-1]>>30))*1566083941))-i)&mask;i+=1
  if i==624:state[0]=state[623];i=1
 state[0]=0x80000000;assert keys==initial;return state,keys

class MaterialReplay(Replay):
 def __init__(self,c,prefix,entropy,material,cfg,pattern):
  self.prefix=prefix;self.entropy=entropy;self.material=material;self.cfg=cfg;self.api_stage=0;self.models=[];self.values=None
  n=len(prefix['steps']);self.positions=[n,n+len(entropy['steps'])]+[n+len(entropy['steps'])+x['after_source_visits']for x in material['api_models'][1:]];assert len(self.positions)==4
  trace={'steps':prefix['steps']+entropy['steps']+material['steps'],'boundary':material['boundary'],'origins':material['origins']};super().__init__(c,trace,pattern)
 def initialize_values(self):
  symbols={name:bits for d in self.material['definitions']for name,bits in d['expression']['symbols']if not name.startswith('value_')}
  for action in [self.entropy['api_effects']]+[m['register_effects']for m in self.material['api_models']]:
   for shape in action.values():symbols.update({n:b for n,b in shape.get('symbols',[])if not n.startswith('value_')})
  values={}
  for name,bits in symbols.items():
   if name.startswith('incoming_d'):values[name]=self.fullreg('q'+name[len('incoming_d'):])&((1<<64)-1)
   else:values[name]=(0 if self.pattern==0 else int.from_bytes(hashlib.sha256(name.encode()).digest(),'little'))&((1<<bits)-1)
  values.update(api_entropy_u32=self.cfg['seed1'],api_time_status32=self.cfg['time_status'],api_time_seconds64=self.cfg['seconds'],api_time_microseconds32=self.cfg['microseconds'],api_second_entropy32=self.cfg['seed2'],api_third_entropy32=self.cfg['seed3'])
  for d in self.material['definitions']:assert d['name']not in values;values[d['name']]=expr(d['expression'],values)
  self.values=values;self.actions=[{'pc':hex(CALL1),'events':[],'register_effects':self.entropy['api_effects'],'argument_count':0}]+self.material['api_models'];self.actions=concrete(self.actions,values);self.trace={'steps':self.prefix['steps']+concrete(self.entropy['steps'],values)+concrete(self.material['steps'],values),'boundary':concrete(self.material['boundary'],values),'origins':self.material['origins']}
 def code(self,u,a,n,d):
  if not(self.forward and self.api_stage<4 and self.index==self.positions[self.api_stage]):return super().code(u,a,n,d)
  self.finish();assert a in [CALL1,TIME,CALL2,CALL3]and a==[CALL1,TIME,CALL2,CALL3][self.api_stage]and bytes(u.mem_read(a,4))==IMAGE.read(a,4)and self.reg(8)==0x7c100000 and self.reg(17)==(0x9298 if a==TIME else 0x2692)
  if self.api_stage==0:self.initialize_values()
  m=self.actions[self.api_stage];assert m['pc']==hex(a)
  preserved=lambda:{'SP':hex(self.fullreg('sp')),'X18_to_X29':[hex(self.reg(j))for j in range(18,30)],'D8_to_D15_low64':[hex(self.fullreg('q'+str(j))&((1<<64)-1))for j in range(8,16)]}
  before=preserved()
  if a==TIME:assert self.reg(0)==self.F+0x680 and self.reg(1)==0 and not any(self.known[self.F+0x680-P:self.F+0x690-P])
  for event in m['events']:
   assert event['kind']=='write';at=int(event['address'],16);raw=bytes.fromhex(event['value']['hex']);u.mem_write(at,raw);self.known[at-P:at-P+len(raw)]=bytes([1])*len(raw);self.prov[at-P:at-P+len(raw)]=bytes([2])*len(raw)
  for reg,shape in m['register_effects'].items():u.reg_write(getattr(ar,'UC_ARM64_REG_'+reg.upper()),int.from_bytes(bytes.fromhex(shape['hex']),'little'))
  u.reg_write(ar.UC_ARM64_REG_NZCV,0 if self.pattern==0 else 0xf0000000);after=preserved();assert before==after
  self.models.append({'pc':hex(a),'argument_count':m['argument_count'],'declared_memory_writes':m['events'],'preserved_before':before,'preserved_after':after,'native_target_executed':False});self.api_stage+=1;return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
 def run_material(self):
  Storage.run(self)
  for o in self.trace['origins']:
   off=o['offset'];at=self.F+off;assert self.known[at-P]==0;self.backing[off]=0 if self.pattern==0 else(off*73+19)&255;self.u.mem_write(at,bytes([self.backing[off]]))
  self.forward=True;self.forward_done=False;self.u.emu_start(ENTRY,0,count=len(self.trace['steps'])+30);assert self.forward_done and self.api_stage==4 and self.index==len(self.trace['steps'])and len(self.backing)==112
  ev=next(e for s in self.material['steps']if s['pc']=='0x1002dc418'for e in s['events']if e['kind']=='read');cursor=int.from_bytes(bytes.fromhex(ev['value']['hex']),'little');state,keys=compact(self.cfg,cursor);expected=b''.join(w.to_bytes(4,'little')for w in state);raw=bytes(self.u.mem_read(ARRAY,2496));assert raw==expected,('compact state mismatch',self.cfg['name'],next((i for i,(a,b)in enumerate(zip(raw,expected))if a!=b),None))
  actual_keys=bytes(self.u.mem_read(self.F+0x670,16));assert actual_keys==b''.join(w.to_bytes(4,'little')for w in keys);assert self.fullreg('x13')in [self.F+0x6d8,self.F+0x6dc]
  out=bytes(self.u.mem_read(self.F+0x680,16));mask=bytes(self.known[self.F+0x680-P:self.F+0x690-P]);assert mask==bytes([1])*12+bytes(4)and out[:12]==self.cfg['seconds'].to_bytes(8,'little')+self.cfg['microseconds'].to_bytes(4,'little')
  return {'input':self.c,'values':self.cfg,'pattern':self.pattern,'verified_counts':dict(self.counts),'API_models':self.models,'cursor_source_pointer':hex(cursor),'cursor_low32':hex(cursor&0xffffffff),'mixed_state':{'address':hex(ARRAY),'words':624,'bytes':2496,'sha256':hashlib.sha256(raw).hexdigest(),'head_u32':[hex(x)for x in state[:4]],'tail_u32':[hex(x)for x in state[-4:]]},'material_record':{'address':hex(self.F+0x670),'bytes_hex':actual_keys.hex(),'all_four_encoded_words_restored':True},'time_output':{'address':hex(self.F+0x680),'bytes_hex':out.hex(),'known_mask_hex':mask.hex(),'padding_stays_unknown':True},'frontier':{'pc':self.trace['boundary']['pc'],'candidate_table_addresses':[hex(self.F+0x6d8),hex(self.F+0x6dc)],'selected_read_address':hex(self.fullreg('x13')),'unexecuted':True},'native_target_executed':False,'native_entropy_or_time_executed':False}

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=json.loads((ROOT/'daemon_seed_material_profiles.json').read_text());prior=json.loads((ROOT/'daemon_context_transfer_profiles.json').read_text());entropy=json.loads((ROOT/'daemon_entropy_return_profiles.json').read_text());base=json.loads((ROOT/'daemon_arena_storage_profiles.json').read_text());rows=[]
 for context in p['cases']:
  index=context['prior_case_index'];prefix=unpack(next(x for x in prior['cases']if x['prior_case_index']==index));ent=unpack(next(x for x in entropy['cases']if x['prior_case_index']==index));t=unpack(context);jobs=[(x,[0,3][i%2])for i,x in enumerate(INPUTS[:4])]+[(INPUTS[3],0)]
  if index in [0,17]:jobs.extend((x,3)for x in INPUTS[4:])
  for cfg,pattern in jobs:
   r=MaterialReplay(base['cases'][index]['input'],prefix,ent,t,cfg,pattern).run_material();r['prior_case_index']=index;rows.append(r);print(json.dumps({'case':index,'values':cfg['name'],'pattern':pattern,'completed':len(rows),'visits':r['verified_counts']['source_visits']}),flush=True)
 deps=['daemon_seed_material_profiles.json','daemon_context_transfer_profiles.json','daemon_entropy_return_profiles.json','daemon_arena_storage_profiles.json','replay_daemon_context_transfer.py','replay_daemon_entropy_return.py','probe_daemon_arena_storage.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_seed_material_replays.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'replays':len(rows),'source_visits':sum(r['verified_counts']['source_visits']for r in rows)}),flush=True)
if __name__=='__main__':main()
