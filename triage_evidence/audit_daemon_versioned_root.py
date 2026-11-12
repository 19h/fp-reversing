#!/usr/bin/env python3
"""Independent A64 audit of root admission and modeled allocation lifetime.

O(prefix+patterns*(snapshot+source visits+effects)) time/space;30 s/query.
Prefixes are restored. Native calls, IPC and hardware PAC never execute.
"""
import json
from pathlib import Path
from collections import Counter
import z3
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,IMAGE,CS,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from replay_daemon_callback_revisit import Replay
from replay_daemon_context_transfer import evaluate
import recover_daemon_versioned_root as R

def scalar(s):
 assert 'hex'in s,s
 return int.from_bytes(bytes.fromhex(s['hex']),'little')

def record_key(r):
 x=r^0xadef4a231bdba15d
 return (((((x<<1)|0x3920867a64d1a5ec)-x+0xe36fbcc2cd972d0a)^0xde4326985541f84b)*0x83918153)&((1<<64)-1)

def overlay_cells(c):
 r=int(c['record'],16);k=record_key(r);out={}
 def put(a,n,x):out.update({a+j:b for j,b in enumerate((x&((1<<(8*n))-1)).to_bytes(n,'little'))})
 put(r,4,c['decoded_count_B']-k);put(r+4,4,k+int(c['decoded_operation_u32'],16));put(r+16,8,int(c['input_A'],16));put(r+24,8,int(c['input_B'],16))
 put(int(c['seed_cell'],16),8,int(c['seed_u64'],16));put(0x1010b6394,4,int(c['capabilities_u32'],16)^0xc49697f0)
 for n in ['input_A','input_B']:
  a=int(c[n],16)
  if a:out.update({j:c['input_fill_byte']for j in range(a,a+c['input_extent_B'])})
 return out

class Check(Replay):
 def __init__(self,snapshot,old,case,pattern):
  super().__init__(snapshot,case['trace'],pattern);self.case=case;self.model_cursor=0;self.retired=False;self.allocated=False
  reg=dict(snapshot['logical_registers']);flags=int(snapshot['NZCV'],16);ram={}
  for row in old['steps'][:case['prefix_source_visits']]:
   assert IMAGE.read(int(row['pc'],16),4).hex()==row['bytes_hex']
   for e in row['events']:
    a=int(e['address'],16);data=evaluate(e['value'],self.backing);assert len(data)==e['size_bytes'];ram.update({a+j:b for j,b in enumerate(data)})
   reg.update(row['registers_after']);flags=row.get('NZCV_after',flags)
  self.write_ram(ram)
  c=case['configuration'];w=c['fresh_private'];a=int(w['address'],16);data=bytearray()
  for at in range(a,a+w['size_bytes']):
   off=at-self.F;self.backing[off]=self.unknown_byte(off);data.append(self.backing[off])
  self.u.mem_write(a,bytes(data));self.write_ram(overlay_cells(c))
  for n,s in reg.items():self.u.reg_write(getattr(ar,'UC_ARM64_REG_'+n.upper()),int.from_bytes(evaluate(s,self.backing),'little'))
  for n,x in {'SP':int(c['entry_SP'],16),'X0':int(c['record'],16),'X1':int(c['seed_cell'],16),'X30':R.RETURN,'NZCV':flags}.items():self.u.reg_write(getattr(ar,'UC_ARM64_REG_'+n),x)
  assert flags==case['trace']['initial_NZCV']
  for n,s in case['trace']['initial_registers'].items():assert self.register(n)==int.from_bytes(evaluate(s,self.backing),'little'),('initial',n)
  self.snap={**snapshot,'boundary':{'pc':hex(R.ENTRY)}}

 def unknown_byte(self,off):return (off*73+19)&255 if self.pattern==3 else(off*17+0x65)&255

 def write_ram(self,ram):
  ordered=sorted(ram);j=0
  while j<len(ordered):
   a=ordered[j];k=j+1
   while k<len(ordered)and ordered[k]==ordered[k-1]+1:k+=1
   for page in range(a&~4095,(ordered[k-1]&~4095)+4096,4096):self.page(page)
   self.u.mem_write(a,bytes(ram[x]for x in ordered[j:k]));j=k

 def code(self,u,a,n,d):
  models=self.case['API_models']
  if self.model_cursor<len(models)and self.index==models[self.model_cursor]['after_source_visits']:
   self.finish();m=models[self.model_cursor];assert a==int(m['pc'],16)and bytes(u.mem_read(a,4)).hex()==m['bytes_hex']==IMAGE.read(a,4).hex()
   ins=next(CS.disasm(IMAGE.read(a,4),a));assert ins.mnemonic=='blraa';target,modifier=[s.strip()for s in ins.op_str.split(',')]
   assert self.register(target)==0x7c100000 and self.register(modifier)==int(m['modifier16'],16)
   assert FIXUPS[int(m['slot'],16)]['target']==m['binding']and self.register('X0')==int(m['argument_X0'],16)
   for reg,s in m['preserved'].items():assert self.register(reg)==int.from_bytes(evaluate(s,self.backing),'little')
   for s in m['register_effects'].values():
    for term in s.get('terms',[]):
     if isinstance(term,dict):self.backing.setdefault(term['origin'],self.unknown_byte(term['origin']))
   if m['name']=='malloc'and self.case['configuration']['malloc_success']:
    assert not self.allocated;self.allocated=True
    base=int(self.case['configuration']['allocation'],16);data=bytearray()
    for at in range(base,base+32):self.backing[at-self.F]=self.unknown_byte(at-self.F);data.append(self.backing[at-self.F])
    self.u.mem_write(base,bytes(data))
   if m['name']=='free':assert self.allocated and not self.retired;self.retired=True
   for reg,s in m['register_effects'].items():u.reg_write(getattr(ar,'UC_ARM64_REG_'+reg.upper()),int.from_bytes(evaluate(s,self.backing),'little'))
   u.reg_write(ar.UC_ARM64_REG_NZCV,0xf0000000 if self.pattern==3 else 0);u.reg_write(ar.UC_ARM64_REG_PC,a+4);self.model_cursor+=1;self.counts['API_models_checked']+=1;return
  return super().code(u,a,n,d)

 def live(self,a,n):
  base=int(self.case['configuration']['allocation'],16)
  if a<base+32 and base<a+n:assert self.allocated and not self.retired,'source access outside modeled allocation lifetime'

 def read(self,u,access,a,n,value,d):self.live(a,n);return super().read(u,access,a,n,value,d)
 def write(self,u,access,a,n,value,d):self.live(a,n);return super().write(u,access,a,n,value,d)
 def run(self):
  out=super().run();assert self.model_cursor==len(self.case['API_models']);out['modeled_retirement_checked']=self.retired;return out

def interfaces(case):
 c=case['configuration'];f=int(c['frame_SP'],16);r=int(c['record'],16);allocation=int(c['allocation'],16);regs=dict(case['trace']['initial_registers']);ram=overlay_cells(c);calls=[];points={};events=[];gates=[];models={m['after_source_visits']:m for m in case['API_models']}
 def value(n):return scalar(regs[n])
 def get(a,n):
  b=[ram[a+j]for j in range(n)];assert all(isinstance(x,int)for x in b),(hex(a),b)
  return int.from_bytes(bytes(b),'little')
 selected=[0x10049f37c,0x1003af998,0x10031cb8c,0x100552dac,0x100552ef8,0x100552fa0,0x1004bfb58,0x1001c0104]
 for j,row in enumerate(case['trace']['steps']):
  if j in models:regs.update(models[j]['register_effects'])
  pc=int(row['pc'],16)
  if pc in selected:
   p={'visit':j,'registers':regs.copy()};points[hex(pc)]=p
   if pc==0x10031cb8c:
    pair=f+0x698;assert get(pair,8)==allocation and get(pair+8,8)==0
    assert get(allocation,8)==pair+0x30 and [get(allocation+k,4)for k in [8,12,16,20,24]]==[0x8b3dc479,0x8b3dc479,0x8b3dc651,0x4d8916dd,0x8b3dc651]
   if pc==0x1001c0104:gates.append({'address':hex(value('x9')),'value':hex(value('x19'))})
  if row['mnemonic']=='blraa':calls.append({'pc':row['pc'],'target':row['target'],'modifier16':row['modifier16']})
  for e in row['events']:
   a=int(e['address'],16);s=e['value'];data=list(bytes.fromhex(s['hex']))if'hex'in s else s['terms'];assert len(data)==e['size_bytes'];ram.update({a+k:b for k,b in enumerate(data)});events.append({'visit':j,'pc':row['pc'],**e})
  regs.update(row['registers_after'])
 assert scalar(points['0x10049f37c']['registers']['sp'])==f and scalar(points['0x10049f37c']['registers']['x29'])==f+0x970
 assert get(int(c['seed_cell'],16),8)==int(c['seed_u64'],16)+0xb0
 boundary=case['trace']['boundary'];assert boundary['SP']==c['entry_SP']and boundary['target']==hex(R.RETURN)and boundary['pc']==hex(R.RET)
 returned=[e for e in events if e['pc']=='0x100309cd8'and e['kind']=='write'];assert len(returned)==1 and returned[0]['address']==hex(r+8)and returned[0]['size_bytes']==4
 for j in range(19,30):assert boundary['registers31'][j]==case['trace']['initial_registers']['x'+str(j)]
 assert not any(row['pc']=='0x100478a04'for row in case['trace']['steps'])
 result={'epoch':c['epoch'],'variant':c['name'],'root_entry':hex(R.ENTRY),'frame_SP':hex(f),'root_FP':hex(f+0x970),'caller_record':hex(r),'inner_record':hex(f+0x8d8),'seed_increment_u64':'0xb0','returned_word_u32':hex(get(r+8,4)),'return_boundary':hex(R.RET),'API_models':[{k:m[k]for k in ['pc','name','argument_X0','slot','binding','modifier16']}for m in case['API_models']],'calls':calls,'constructor_executed':bool(points.get('0x100552dac')),'native_API_executed':False,'IOKit_call_executed':False,'all_checks_pass':True}
 if c['name'].startswith('null_'):assert not calls and not case['API_models']
 elif c['name']=='malloc_failure':assert len(calls)==1 and len(case['API_models'])==1 and not result['constructor_executed']
 else:
  assert [m['name']for m in case['API_models']]==['malloc','free']and case['API_models'][1]['argument_X0']==c['allocation']
  rr=points['0x100552dac']['registers'];assert scalar(rr['sp'])==f and scalar(rr['x20'])==16 and scalar(rr['x21'])==0x871a
  assert get(f+0x2a0,4)==0x871a and get(f+0x80,8)==0x1010b6380 and get(f+0x3f0,8)==552
  b=f+0x600
  for off,expected in [(0x3f8,b),(0x480,b+16),(0x488,b+32)]:assert get(f+off,8)==expected
  assert scalar(points['0x100552fa0']['registers']['sp'])==f
  assert {'pc':'0x1003af998','target':'0x100455c30','modifier16':'0xe280'}in calls
  assert any(x['pc']=='0x1004bfb58'and x['target']=='0x100439874'for x in calls)
  mode={0:1,2:2,0x42:6,8:2,0x28:5}[int(c['capabilities_u32'],16)];assert get(f+0x37c,4)==mode
  owned_writes=[e for e in events if e['kind']=='write'and int(e['address'],16)<allocation+32 and allocation<int(e['address'],16)+e['size_bytes']]
  defined=set()
  for e in owned_writes:defined.update(range(max(allocation,int(e['address'],16)),min(allocation+32,int(e['address'],16)+e['size_bytes'])))
  assert defined==set(range(allocation,allocation+32))
  initializer=[e for e in owned_writes if int(e['pc'],16)in [0x10031cb60,0x10031cb6c,0x10031cb80,0x10031cb84]]
  initialized=set()
  for e in initializer:initialized.update(range(int(e['address'],16),int(e['address'],16)+e['size_bytes']))
  assert initialized==set(range(allocation,allocation+28))
  overwrite=[e for e in owned_writes if e['pc']=='0x10028db6c']
  assert len(overwrite)==32 and all(e['size_bytes']==1 for e in overwrite)and [int(e['address'],16)for e in overwrite]==list(range(allocation+31,allocation-1,-1))
  # No read consumes the four initially unspecified trailing bytes.
  seen=set(initialized)
  for e in events:
   a=int(e['address'],16);overlap=set(range(max(a,allocation),min(a+e['size_bytes'],allocation+32)))
   if e['kind']=='read':assert overlap<=seen
   else:seen.update(overlap)
  free=case['API_models'][1]
  assert not any(e['visit']>=free['after_source_visits']and int(e['address'],16)<allocation+32 and allocation<int(e['address'],16)+e['size_bytes']for e in events)
  assert gates==[{'address':hex(f+0x6a0),'value':'0x0'},{'address':hex(f+0x698),'value':hex(allocation)}]
  coverage=set();prior=set();cut=points['0x100552dac']['visit']
  for e in events:
   if e['kind']!='write':continue
   a=int(e['address'],16);span=set(range(max(a,b),min(a+e['size_bytes'],b+552)));coverage.update(span)
   if e['visit']<cut:prior.update(span)
  result.update(construction_buffer=hex(b),construction_capacity_B=552,construction_view_written_B=len(coverage),construction_view_written_before_constructor_B=len(prior),working_mode=mode,allocation_initialized_B=len(initialized),initializer_unwritten_tail_B=4,retirement_overwrite_B=32,retirement_overwrite_PC='0x10028db6c',retirement_overwrite_hex=''.join(e['value']['hex']for e in reversed(overwrite)),modeled_retirement_exact=True,post_retirement_owner_accesses=0,paired_pointer_gates=gates)
 return result

def main():
 pins,old=R.inputs();e=json.loads(read(ROOT/(R.P+'_checks.json')))
 assert e['generator_sha256']==sha(ROOT/('recover_'+R.P+'.py'))and e['parent_pins']==R.PINS and e['source_regions']==R.source()and e['dependencies']=={n:sha(ROOT/n)for n in R.DEPS}
 used={int(a,16)for case in e['cases']for a in case['trace']['used_fixups']};assert e['source_fixups']==R.verify_fixups(used)
 fresh=R.obligations();assert [r['label']for r in fresh]==[r['label']for r in e['source_proofs']]
 for row in e['source_proofs']:
  s=z3.Solver();s.set(timeout=30000);s.from_string(row['query']);assert str(s.check())==row['result']=='unsat'
 rows=[];joins=[];totals=Counter();counts=Counter()
 for case in e['cases']:
  c=case['configuration'];assert c==R.configuration(c['epoch'],c['name'])and old['steps'][case['prefix_source_visits']]['pc']=='0x100add594'
  joins.append(interfaces(case));counts.update(case['counts'])
  for pattern in [0,3]:
   out=Check(pins['daemon_callback_revisit_snapshot.json'],old,case,pattern).run();out.update(epoch=c['epoch'],variant=c['name']);rows.append(out);totals.update(out['verified_counts']);print(json.dumps({'epoch':c['epoch'],'variant':c['name'],'pattern':pattern,'source_visits':out['verified_counts']['source_visits']}),flush=True)
 verified={'cases':len(e['cases']),'epochs':2,'variants':8,**dict(counts)};assert verified==e['verified_counts']
 out={'scope':__doc__,'generator_sha256':e['generator_sha256'],'auditor_sha256':sha(Path(__file__)),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':R.H.THIN,'parent_pins':R.PINS,'dependencies':e['dependencies'],'verified_counts':verified,'source_proofs_unsat':len(fresh),'interface_joins':joins,'independent_replays':rows,'independent_totals':dict(totals),'all_checks_pass':True,
 'prefix_reexecuted':False,'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'live_IDA_claim':False,'native_entry_admission_established':False,'complete_IOKit_buffer_join_established':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False}
 (ROOT/(R.P+'_audit.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':verified,'independent_totals':dict(totals),'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
