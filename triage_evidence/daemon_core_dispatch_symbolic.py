#!/usr/bin/env python3
"""Path-sensitive operation dispatch from its first source use. One symbolic
u32 operation replaces an explicit unread entry argument. Other entry/global
state is the captured private baseline. Stop before unavailable input, runtime
state, calls/returns or unsupported semantics; no native/API/PAC execution.
O(visits + BV/solver resources) time, O(states*defined cells + DAGs) space.
"""
import json,re
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from capture_daemon_record720 import sha
from daemon_arena_lifetime_symbolic import LifetimeFlags
from daemon_output_base_dispatch import CS,Split,Stop,unique
from recover_daemon_object_clock import sections
from daemon_import_bindings import binding
OP=z3.BitVec('core_dispatch_operation32',32)
def symbolic_names(e):
 todo=[e];seen=set();names=set()
 while todo:
  x=todo.pop()
  if x.get_id()in seen:continue
  seen.add(x.get_id())
  if z3.is_const(x)and x.decl().kind()==z3.Z3_OP_UNINTERPRETED:names.add(x.decl().name())
  todo.extend(x.children())
 return names

def explore():
 src=json.loads((ROOT/'daemon_core_dispatch_source.json').read_text());ctx=src['context'];ram={int(r['address'],16):z3.BitVecVal(r['value'],8)for r in src['known_bytes']};regs={n:z3.BitVecVal(int(v,16),64)for n,v in ctx['known_GPRs'].items()};R=int(src['protected_record'],16);K=(((R&0xffffffff)^0xeaae0ac9)*0x7398180b)&0xffffffff
 for j in range(4):ram[R+12+j]=z3.Extract(j*8+7,j*8,OP^K)
 bits=int(ctx['NZCV'],16)>>28;flags=[z3.BoolVal(bool(bits&(1<<j)))for j in[3,2,1,0]];F=int(ctx['SP'],16);E=F+src['frame_owner']['size_bytes'];B=int(src['borrowed_argument_record'],16);writable=[s for s in sections()if s['segment']=='__DATA'];initial_ram=ram.copy();todo=[{'pc':int(src['entry_PC'],16),'ram':ram,'regs':regs,'flags':flags,'path':z3.BoolVal(True),'steps':[],'effects':[],'edges':[],'direct_edges':[]}];done=[];visits=0;exports={};bindings={}
 while todo:
  s=todo.pop();pc=s['pc'];i=next(CS.disasm(IMAGE.read(pc,4),pc));events=[];pending=[]
  if len(s['steps'])>=5000:s['boundary']={'pc':hex(pc),'kind':'instruction_limit'};done.append(s);continue
  class V(LifetimeFlags):
   def load(self,a,n):
    names=symbolic_names(z3.simplify(a))
    if names-{'core_dispatch_operation32'}:raise Stop({'pc':hex(pc),'kind':'before_export_address_read','address_expression':z3.simplify(a).sexpr(),'size_bytes':n,'export_variables':sorted(names-{'core_dispatch_operation32'})})
    at=unique(a,s['path'],pc,'read_address')
    if all(at+j in s['ram']for j in range(n)):
     bs=[s['ram'][at+j]for j in range(n)];val=z3.Concat(*reversed(bs))if n>1 else bs[0]
    elif at in FIXUPS and n==8:
     target=FIXUPS[at]['target']
     if isinstance(target,str):
      name='core_export_address_'+re.sub('[^a-zA-Z0-9_]','_',target)
      if name not in exports:exports[name]=z3.BitVec(name,64);bindings[name]={'variable':name,'symbol':target,'binding':binding(at)}
      if not binding(at)['weak_import']:s['path']=z3.And(s['path'],exports[name]!=0)
      val=exports[name]+binding(at)['total_addend']
     else:val=z3.BitVecVal(target,64)
    else:
     bs=[]
     for j in range(n):
      here=at+j
      if here in s['ram']:b=s['ram'][here]
      elif B<=here<B+4096:raise Stop({'pc':hex(pc),'kind':'before_borrowed_argument_read','address':hex(at),'size_bytes':n,'candidate_record_base':hex(B),'record_relative_offset_bytes':at-B,'minimum_accessed_endpoint_bytes':at-B+n,'known_owner_extent':False})
      elif 0x6800000000<=here<0x6800100000:raise Stop({'pc':hex(pc),'kind':'before_undefined_private_read','address':hex(at),'size_bytes':n,'first_missing_byte':hex(here),'frame_relative_offset_bytes':at-F})
      elif any(g['start']<=here<g['start']+g['size_bytes']for g in writable):raise Stop({'pc':hex(pc),'kind':'before_unavailable_runtime_global','address':hex(at),'size_bytes':n})
      else:
       try:b=z3.BitVecVal(IMAGE.read(here,1)[0],8)
       except ValueError:raise Stop({'pc':hex(pc),'kind':'before_unowned_read','address':hex(at),'size_bytes':n})
      bs.append(b)
     val=z3.Concat(*reversed(bs))if n>1 else bs[0]
    events.append({'pc':hex(pc),'kind':'read','address':hex(at),'size_bytes':n,'expression':val.sexpr()});return val
   def store(self,a,n,val,atpc):
    names=symbolic_names(z3.simplify(a))
    if names-{'core_dispatch_operation32'}:raise Stop({'pc':hex(pc),'kind':'before_export_address_write','address_expression':z3.simplify(a).sexpr(),'size_bytes':n,'export_variables':sorted(names-{'core_dispatch_operation32'})})
    at=unique(a,s['path'],pc,'write_address')
    if not(F<=at<at+n<=E or R<=at<at+n<=R+32 or any(g['start']<=at<at+n<=g['start']+g['size_bytes']for g in writable)):
     raise Stop({'pc':hex(pc),'kind':'before_unowned_write','address':hex(at),'size_bytes':n,'expression':val.sexpr(),'candidate_record_relative_offset':at-B if B<=at<B+4096 else None})
    events.append({'pc':hex(pc),'kind':'write','address':hex(at),'size_bytes':n,'expression':val.sexpr()});pending.append((at,n,val))
  v=V({'spans':[{'label':'one','start':hex(pc),'bytes_hex':bytes(i.bytes).hex()}]});v.regs=s['regs'].copy();v.negative,v.equal,v.carry,v.overflow=s['flags'];v.pc=pc
  try:
   if i.mnemonic=='braa':
    target_expr=v.read(i.op_str.split(',')[0].strip());names=symbolic_names(z3.simplify(target_expr))
    if names-{'core_dispatch_operation32'}:raise Stop({'pc':hex(pc),'kind':'before_imported_control_transfer','target_expression':z3.simplify(target_expr).sexpr()})
    target=unique(target_expr,s['path'],pc,'branch_target');modifier=unique(v.read(i.op_str.split(',')[1].strip()),s['path'],pc,'modifier');slotrow=next((e for e in reversed(s['effects'])if e['kind']=='read'and e['size_bytes']==8 and int(e['address'],16)in FIXUPS and FIXUPS[int(e['address'],16)]['target']==target),None)
    if slotrow is None or int(slotrow['address'],16)not in FIXUPS:raise Stop({'pc':hex(pc),'kind':'before_unresolved_branch_origin','target':hex(target)})
    slot=int(slotrow['address'],16);word=int.from_bytes(IMAGE.read(slot,8),'little');assert FIXUPS[slot]['target']==target and word>>63==1 and(word>>32)&65535==modifier and(word>>48)&7==0;s['edges'].append({'pc':hex(pc),'slot':hex(slot),'target':hex(target),'modifier':hex(modifier)});nextpc=target
   elif i.mnemonic=='b'or i.mnemonic.startswith('b.')or i.mnemonic in['cbz','cbnz','tbz','tbnz']:
    if i.mnemonic=='b':cond=z3.BoolVal(True);target=i.operands[0].imm
    elif i.mnemonic.startswith('b.'):cond=v.condition(i.mnemonic[2:]);target=i.operands[0].imm
    else:
     value=v.read(i.reg_name(i.operands[0].reg));cond=value==0 if i.mnemonic in['cbz','cbnz']else(value&(1<<i.operands[1].imm))==0;target=i.operands[1 if i.mnemonic in['cbz','cbnz']else 2].imm
     if i.mnemonic in['cbnz','tbnz']:cond=z3.Not(cond)
    nextpc=unique(z3.If(cond,z3.BitVecVal(target,64),z3.BitVecVal(pc+4,64)),s['path'],pc,'direct_branch_target');s['direct_edges'].append({'pc':hex(pc),'target':hex(nextpc),'condition':cond.sexpr()})
   elif i.mnemonic.startswith(('bl','ret'))or i.mnemonic in['br','svc','hvc']:
    raise Stop({'pc':hex(pc),'kind':'before_control_interface','instruction':i.mnemonic+' '+i.op_str,'argument_GPRs':{n:z3.simplify(v.read(n)).sexpr()for n in ['x0','x1','x2','x3']}})
   else:v.run('one');nextpc=pc+4
  except Split as split:
   solver=z3.Solver();solver.set(timeout=10000);solver.add(s['path']);choices=[]
   while len(choices)<=8 and solver.check()==z3.sat:
    number=solver.model().eval(split.e,model_completion=True).as_long();choices.append(number);solver.add(split.e!=number)
   if len(choices)>8:s['boundary']={'pc':hex(pc),'kind':'nonfinite_'+split.role,'expression':split.e.sexpr()};done.append(s);continue
   assert choices
   for number in choices:todo.append({**s,'path':z3.And(s['path'],split.e==number),'steps':s['steps'].copy(),'effects':s['effects'].copy(),'edges':s['edges'].copy(),'direct_edges':s['direct_edges'].copy(),'ram':s['ram'].copy()})
   continue
  except Stop as stop:s['boundary']=stop.d;done.append(s);continue
  except AssertionError as error:
   if error.args and isinstance(error.args[0],tuple)and error.args[0][0]=='unsupported symbolic instruction':s['boundary']={'pc':hex(pc),'kind':'before_unsupported_instruction','instruction':i.mnemonic+' '+i.op_str};done.append(s);continue
   raise
  s['regs']=v.regs;s['flags']=[v.negative,v.equal,v.carry,v.overflow]
  for at,n,val in pending:
   for j in range(n):s['ram'][at+j]=z3.Extract(j*8+7,j*8,val)
  s['effects']+=events;s['steps'].append([pc,bytes(i.bytes).hex()]);s['pc']=nextpc;todo.append(s);visits+=1;assert len(todo)+len(done)<256 and visits<200000
 rows=[]
 for s in done:
  solver=z3.Solver();solver.add(s['path']);assert solver.check()==z3.sat;sample=solver.model().eval(OP,model_completion=True).as_long();rows.append({'path_condition':z3.simplify(s['path']).sexpr(),'operation_sample':hex(sample),'boundary':s['boundary'],'steps':s['steps'],'effects':s['effects'],'edges':s['edges'],'direct_edges':s['direct_edges'],'end_GPR_expressions':{n:z3.simplify(value).sexpr()for n,value in s['regs'].items()}})
 return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_core_dispatch_source.json','daemon_arena_lifetime_symbolic.py','daemon_output_base_dispatch.py']},'export_variables':list(bindings.values()),'initial_bytes':[{'address':hex(a),'expression':value.sexpr()}for a,value in sorted(initial_ram.items())],'entry_context':ctx,'entry_PC':src['entry_PC'],'paths':rows,'native_target_executed':False,'full_goal_complete':False}
if __name__=='__main__':
 r=explore();(ROOT/'daemon_core_dispatch_symbolic.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps([{'sample':p['operation_sample'],'visits':len(p['steps']),'boundary':p['boundary']}for p in r['paths']]),flush=True)
