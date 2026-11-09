#!/usr/bin/env python3
"""Path-sensitive u32 auxiliary dispatcher from a declared source cutpoint.
The mode, fixed record/frame/table bases and source-written prefix cells are
component premises. Alternative auxiliaries do not change a frozen execution.
O(visits + BV solver resources) time, O(states*defined cells + DAGs) space.
No native target, API, PAC authentication or unknown-pointer assignment.
"""
import json
import z3
from daemon_receive_tools import ROOT,IMAGE,FIXUPS,SOURCE
from capture_daemon_record720 import sha
from daemon_arena_lifetime_symbolic import LifetimeFlags
from daemon_cleanup_return_symbolic import CS
from daemon_digest_output_access import key
from daemon_import_bindings import binding
from recover_daemon_object_clock import sections
from validate_daemon_record720_spill import parse_value
AUX=z3.BitVec('output_base_aux32',32)
SPILLS={0xd79bc5de:0x100b74138,0xbad70e19:0x10064cea8,0x2be18a5d:0x10097c778,0x7bed772d:0x100b2cf64,0xeedd0b20:0x100a2e3a0}
def route_condition(route):
 return z3.And(z3.UGE(AUX,0x38acbb2a),z3.ULE(AUX,0x7fffffff))if route==0x7bed772d else AUX==route
class Split(Exception):
 def __init__(self,e,role):self.e=e;self.role=role
class Stop(Exception):
 def __init__(self,d):self.d=d

def context():
 d=json.loads((ROOT/'daemon_descriptor_producers_profiles.json').read_text());p=d['cases'][24];cp=next(c for c in p['checkpoints']if c['pc']=='0x1006583b0');limit=cp['source_visit_index'];ram={}
 for g in p['initial_private_fixtures']+p['initial_image_fixtures']:
  for j,b in enumerate(bytes.fromhex(g['bytes_hex'])):ram[int(g['address'],16)+j]=z3.BitVecVal(b,8)
 for e in p['source_writes']:
  if e['source_visit_index']>=limit:break
  for j,b in enumerate(bytes.fromhex(e['after_hex'])):ram[int(e['address'],16)+j]=z3.BitVecVal(b,8)
 R=int(p['record_address'],16);K=int(cp['registers31'][11],16)&0xffffffff
 for j in range(4):ram[R+20+j]=z3.Extract(j*8+7,j*8,AUX+K)
 defined={'x'+str(j)for j in [0,1,2,3,5,8,9,10,11,12,13,14,15,16,17,19,20,25,26,27,28,29,30]};regs={'x'+str(j):z3.BitVecVal(int(cp['registers31'][j],16),64)if 'x'+str(j)in defined else z3.BitVec('output_base_initial_x%d'%j,64)for j in range(31)};regs['sp']=z3.BitVecVal(int(cp['SP'],16),64)
 return p,cp,ram,regs

def unique(e,path,pc,role):
 e=z3.simplify(e)
 if z3.is_bv_value(e):return e.as_long()
 s=z3.Solver();s.set(timeout=10000);s.add(path);assert s.check()==z3.sat;v=s.model().eval(e,model_completion=True);s.add(e!=v)
 if s.check()==z3.unsat:return v.as_long()
 raise Split(e,role)

def explore(continue_tag=None):
 p,cp,ram,regs=context();input_variables=[];unknown={};F=int(cp['SP'],16)
 if continue_tag is not None:
  at=int(p['boundary']['registers31'][2],16)
  for j in range(8):
   name='output_base_input_byte_%d'%j;ram[at+j]=z3.BitVec(name,8);input_variables.append({'address':hex(at+j),'variable':name})
 initial_ram=ram.copy();initial_regs=regs.copy();frameset=(0x6800000000,0x6800100000);initial={'pc':int(cp['pc'],16),'ram':ram,'regs':regs,'flags':[z3.Bool('output_base_entry_NZCV_'+n)for n in ['N','Z','C','V']],'path':z3.BoolVal(True)if continue_tag is None else route_condition(continue_tag),'steps':[],'effects':[],'edges':[]};todo=[initial];done=[];globalvisits=0
 while todo:
  s=todo.pop();pc=s['pc'];i=next(CS.disasm(IMAGE.read(pc,4),pc))
  if pc==0x100badfc0 or(pc in [0x10027147c,0x10064cea8,0x10075e378,0x10097c778,0x100a2e3a0,0x100b2cf64,0x100b74138,0x10095f074]and not(continue_tag is not None and pc==SPILLS[continue_tag])):
   s['boundary']={'pc':hex(pc),'kind':'before_allocator_cutpoint'if pc==0x100badfc0 else'before_candidate_spill'if pc!=0x10095f074 else'before_output_store','instruction':i.mnemonic+' '+i.op_str};done.append(s);continue
  if len(s['steps'])>=1000:s['boundary']={'pc':hex(pc),'kind':'instruction_limit'};done.append(s);continue
  events=[];pending_stores=[]
  class V(LifetimeFlags):
   def load(self,a,n):
    at=unique(a,s['path'],pc,'read_address')
    if at in FIXUPS and n==8:
     t=FIXUPS[at]['target']
     if isinstance(t,str):raise Stop({'pc':hex(pc),'kind':'before_import_pointer','slot':hex(at),'target':t,'binding':binding(at)})
     val=z3.BitVecVal(t,64)
    else:
     bs=[]
     for j in range(n):
      if at+j in s['ram']:b=s['ram'][at+j]
      elif continue_tag is not None and F<=at+j<F+0xdf50:
       here=at+j
       if here not in unknown:unknown[here]=z3.BitVec('output_base_frame_byte_%x'%here,8)
       b=unknown[here]
      elif frameset[0]<=at+j<frameset[1]:raise Stop({'pc':hex(pc),'kind':'before_undefined_private_read','address':hex(at),'size_bytes':n})
      elif any(g['segment']=='__DATA'and g['start']<=at+j<g['start']+g['size_bytes']for g in sections()):raise Stop({'pc':hex(pc),'kind':'before_undefined_global_read','address':hex(at),'size_bytes':n})
      else:
       try:b=z3.BitVecVal(IMAGE.read(at+j,1)[0],8)
       except ValueError:raise Stop({'pc':hex(pc),'kind':'before_unowned_read','address':hex(at),'size_bytes':n})
      bs.append(b)
     val=z3.Concat(*reversed(bs))if n>1 else bs[0]
    events.append({'pc':hex(pc),'kind':'read','address':hex(at),'size_bytes':n,'expression':val.sexpr()});return val
   def store(self,a,n,val,atpc):
    at=unique(a,s['path'],pc,'write_address')
    if not frameset[0]<=at<at+n<=frameset[1]:raise Stop({'pc':hex(pc),'kind':'before_unowned_write','address':hex(at),'size_bytes':n})
    events.append({'pc':hex(pc),'kind':'write','address':hex(at),'size_bytes':n,'expression':val.sexpr()});pending_stores.append((at,n,val))
  v=V({'spans':[{'label':'one','start':hex(pc),'bytes_hex':bytes(i.bytes).hex()}]});v.regs=s['regs'].copy();v.negative,v.equal,v.carry,v.overflow=s['flags'];v.pc=pc
  try:
   if i.mnemonic=='braa':
    target=unique(v.read(i.op_str.split(',')[0].strip()),s['path'],pc,'branch_target');mod=unique(v.read(i.op_str.split(',')[1].strip()),s['path'],pc,'modifier');assert events==[];last=next(e for e in reversed(s['effects'])if e['kind']=='read'and e['size_bytes']==8 and e['expression']==z3.BitVecVal(target,64).sexpr());slot=int(last['address'],16);w=int.from_bytes(IMAGE.read(slot,8),'little');assert FIXUPS[slot]['target']==target and w>>63==1 and(w>>32)&65535==mod and(w>>48)&7==0;s['edges'].append({'pc':hex(pc),'slot':hex(slot),'target':hex(target),'modifier':hex(mod)});nextpc=target
   elif i.mnemonic.startswith(('bl','ret'))or i.mnemonic in ['b','br','svc','hvc']:raise Stop({'pc':hex(pc),'kind':'before_control_interface','instruction':i.mnemonic+' '+i.op_str})
   else:v.run('one');nextpc=pc+4
  except Split as split:
   solver=z3.Solver();solver.set(timeout=10000);solver.add(s['path']);choices=[]
   while len(choices)<=8 and solver.check()==z3.sat:
    n=solver.model().eval(split.e,model_completion=True).as_long();choices.append(n);solver.add(split.e!=n)
   if len(choices)>8:s['boundary']={'pc':hex(pc),'kind':'nonfinite_'+split.role,'expression':split.e.sexpr()};done.append(s);continue
   assert choices
   for n in choices:todo.append({**s,'pc':pc,'path':z3.And(s['path'],split.e==n),'steps':s['steps'].copy(),'effects':s['effects'].copy(),'edges':s['edges'].copy(),'ram':s['ram'].copy()})
   continue
  except Stop as e:s['boundary']=e.d;done.append(s);continue
  s['regs']=v.regs;s['flags']=[v.negative,v.equal,v.carry,v.overflow]
  for at,n,val in pending_stores:
   for j in range(n):s['ram'][at+j]=z3.Extract(j*8+7,j*8,val)
  s['effects']+=events;s['steps'].append([pc,bytes(i.bytes).hex()]);s['pc']=nextpc;globalvisits+=1;todo.append(s)
  assert len(todo)+len(done)<128 and globalvisits<10000
 rows=[]
 for s in done:
  solver=z3.Solver();solver.add(s['path']);assert solver.check()==z3.sat;sample=solver.model().eval(AUX,model_completion=True).as_long();rows.append({'boundary':s['boundary'],'path_condition':z3.simplify(s['path']).sexpr(),'aux_sample':hex(sample),'steps':s['steps'],'effects':s['effects'],'edges':s['edges'],'end_GPR_expressions':{n:z3.simplify(x).sexpr()for n,x in s['regs'].items()}})
 return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{'daemon_descriptor_producers_profiles.json':sha(ROOT/'daemon_descriptor_producers_profiles.json'),'daemon_arena_lifetime_symbolic.py':sha(ROOT/'daemon_arena_lifetime_symbolic.py')},'unavailable_frame_byte_variables':[{'address':hex(a),'variable':b.decl().name()}for a,b in sorted(unknown.items())],'borrowed_input_byte_variables':input_variables,'continuation_tag':hex(continue_tag)if continue_tag is not None else None,'continuation_tag_is_representative_only':continue_tag==0x7bed772d,'continuation_rule':route_condition(continue_tag).sexpr()if continue_tag is not None else None,'component_context':{'known_GPRs':{n:hex(v.as_long())for n,v in initial_regs.items()if z3.is_bv_value(v)},'symbolic_GPRs':{n:v.sexpr()for n,v in initial_regs.items()if not z3.is_bv_value(v)},'initial_bytes':[{'address':hex(a),'expression':b.sexpr()}for a,b in sorted(initial_ram.items())],'frame_owner':{'address':hex(F),'size_bytes':0xdf50}},'component_entry_PC':cp['pc'],'component_record':p['record_address'],'component_SP':cp['SP'],'upstream_aux_fixed_in_original_caller':'0x2be18a5d','alternative_aux_values_are_new_component_premises':True,'paths':rows,'native_target_executed':False,'full_goal_complete':False}
if __name__=='__main__':
 r=explore();(ROOT/'daemon_output_base_dispatch.json').write_text(json.dumps(r,indent=2)+'\n')
 rows=[]
 for tag in SPILLS:
  e=explore(tag);rows.append(e);print(hex(tag),[(x['boundary'],len(x['steps']))for x in e['paths']],flush=True)
 (ROOT/'daemon_output_base_branches.json').write_text(json.dumps({'scope':'Five distinct auxiliary branches, symbolic borrowed input and missing frame bytes; no native or frozen-path replacement.','generator_sha256':sha(__file__),'dependencies':{'daemon_output_base_dispatch.json':sha(ROOT/'daemon_output_base_dispatch.json')},'cases':rows,'native_target_executed':False,'full_goal_complete':False},indent=2)+'\n')
