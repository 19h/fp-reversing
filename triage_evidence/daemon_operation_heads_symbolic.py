#!/usr/bin/env python3
"""Symbolic borrowed-record heads in the source-established dispatcher epoch.
Unavailable input/global bytes retain explicit variables; unknown addresses or
frame cells stop execution. Each head stops before its first call/branch.
O(source visits + BV/solver resources) time/space. No native calls or IPC.
"""
import json,re
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from daemon_output_base_dispatch import CS,Split,Stop,unique
from daemon_arena_lifetime_symbolic import LifetimeFlags
from daemon_core_dispatch_symbolic import symbolic_names
from prove_daemon_core_dispatch import setup,OP
from recover_daemon_object_clock import sections
from capture_daemon_record720 import sha
from validate_daemon_record720_spill import parse_value
from daemon_import_bindings import binding
B=0x6800001000
def analyze():
 source=json.loads((ROOT/'daemon_operation_heads_source.json').read_text());base=json.loads((ROOT/'daemon_core_dispatch_source.json').read_text());parent,v,env,conditions=setup();F=int(base['context']['SP'],16);E=F+0x10dd0;writable=[r for r in sections()if r['segment']=='__DATA'];rows=[]
 for spec in source['handlers']:
  op=int(spec['operation32'],16);p=parent['paths'][spec['parent_path_index']]
  for label in ['null','nonnull']if op==0x8f7506ee else['any']:
   variables=v.copy();borrowed={};globals_={};imports=[];steps=[];effects=[];known={int(r['address'],16):z3.BitVecVal(r['value'],8)for r in base['known_bytes']};repl=[(OP,z3.BitVecVal(op,32))];regs={n:z3.simplify(z3.substitute(parse_value(x,64,v),*repl))for n,x in p['end_GPR_expressions'].items()};initial_regs=regs.copy()
   for e in p['effects']:
    if e['kind']=='write':
     val=z3.substitute(parse_value(e['expression'],e['size_bytes']*8,v),*repl);at=int(e['address'],16)
     for j in range(e['size_bytes']):known[at+j]=z3.Extract(8*j+7,8*j,val)
   initial=known.copy();flags=[z3.Bool('head_entry_'+n)for n in ['N','Z','C','V']];variables.update({x.decl().name():x for x in flags});pc=int(p['boundary']['pc'],16);path=env
   if label!='any':
    ptr=z3.BitVec('head_%08x_pointer8'%op,64);variables[ptr.decl().name()]=ptr;path=z3.And(path,ptr==0 if label=='null'else ptr!=0)
    for j in range(8):known[B+8+j]=z3.Extract(8*j+7,8*j,ptr)
   class V(LifetimeFlags):
    def load(self,a,n):
     nonlocal path
     at=unique(a,path,pc,'head_read_address');bs=[]
     for j in range(n):
      here=at+j
      if here in known:b=known[here]
      elif B<=here<B+0x48:
       name='head_%08x_input_%02x'%(op,here-B);b=z3.BitVec(name,8);variables[name]=b;borrowed[here]=name;known[here]=b
      elif F<=here<E:raise Stop({'pc':hex(pc),'kind':'before_undefined_frame_read','address':hex(at),'size_bytes':n})
      elif any(s['start']<=here<s['start']+s['size_bytes']for s in writable):
       name='head_global_%x'%here;b=z3.BitVec(name,8);variables[name]=b;globals_[here]=name;known[here]=b
      elif here in FIXUPS and n==8 and j==0:
       target=FIXUPS[here]['target']
       if isinstance(target,str):
        name='core_export_address_'+re.sub('[^a-zA-Z0-9_]','_',target);variables.setdefault(name,z3.BitVec(name,64));bd=binding(here);imports.append({'variable':name,'symbol':target,'binding':bd})
        if not bd['weak_import']:path=z3.And(path,variables[name]!=0)
        val=variables[name]+bd['total_addend']
       else:val=z3.BitVecVal(target,64)
       effects.append({'pc':hex(pc),'kind':'read','address':hex(at),'size_bytes':n,'expression':val.sexpr()});return val
      else:
       try:b=z3.BitVecVal(IMAGE.read(here,1)[0],8)
       except ValueError:raise Stop({'pc':hex(pc),'kind':'before_unowned_read','address':hex(at),'size_bytes':n})
      bs.append(b)
     val=z3.Concat(*reversed(bs))if n>1 else bs[0];effects.append({'pc':hex(pc),'kind':'read','address':hex(at),'size_bytes':n,'expression':val.sexpr()});return val
    def store(self,a,n,val,atpc):
     at=unique(a,path,pc,'head_write_address')
     if not F<=at<at+n<=E:raise Stop({'pc':hex(pc),'kind':'before_nonframe_write','address':hex(at),'size_bytes':n})
     effects.append({'pc':hex(pc),'kind':'write','address':hex(at),'size_bytes':n,'expression':val.sexpr()})
     for j in range(n):known[at+j]=z3.Extract(8*j+7,8*j,val)
   boundary=None
   for count in range(512):
    i=next(CS.disasm(IMAGE.read(pc,4),pc));m=V({'spans':[{'label':'one','start':hex(pc),'bytes_hex':bytes(i.bytes).hex()}]});m.regs=regs.copy();m.negative,m.equal,m.carry,m.overflow=flags;m.pc=pc
    if i.mnemonic in ['braa','blraa']:
     target=m.read(i.op_str.split(',')[0].strip());modifier=m.read(i.op_str.split(',')[1].strip());args={n:z3.simplify(m.read(n)).sexpr()for n in ['x0','x1','x2','x3']};boundary={'pc':hex(pc),'kind':'before_'+i.mnemonic,'target_expression':z3.simplify(target).sexpr(),'modifier_expression':z3.simplify(modifier).sexpr(),'argument_GPRs':args};break
    try:m.run('one')
    except Stop as stop:boundary=stop.d;break
    except Split as split:boundary={'pc':hex(pc),'kind':'before_nonunique_'+split.role,'expression':split.e.sexpr()};break
    regs=m.regs;flags=[m.negative,m.equal,m.carry,m.overflow];steps.append([pc,bytes(i.bytes).hex()]);pc+=4
   assert boundary is not None
   input_reads=[e for e in effects if e['kind']=='read'and B<=int(e['address'],16)<B+0x48];rows.append({'operation32':hex(op),'path_class':label,'parent_path_index':spec['parent_path_index'],'entry_PC':p['boundary']['pc'],'path_condition':path.sexpr(),'borrowed_byte_variables':[{'address':hex(a),'relative_offset_bytes':a-B,'variable':n}for a,n in sorted(borrowed.items())],'unavailable_global_byte_variables':[{'address':hex(a),'variable':n}for a,n in sorted(globals_.items())],'new_export_variables':imports,'pointer_variable':ptr.decl().name()if label!='any'else None,'variable_widths':{n:x.size()if z3.is_bv(x)else'Bool'for n,x in variables.items()},'initial_bytes':[{'address':hex(a),'expression':z3.simplify(x).sexpr()}for a,x in sorted(initial.items())],'initial_GPR_expressions':{n:z3.simplify(x).sexpr()for n,x in initial_regs.items()},'steps':steps,'effects':effects,'input_reads':input_reads,'minimum_head_input_endpoint_bytes':max((int(e['address'],16)-B+e['size_bytes']for e in input_reads),default=0),'boundary':boundary,'end_GPR_expressions':{n:z3.simplify(x).sexpr()for n,x in regs.items()},'native_input_extent_known':False})
 return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_operation_heads_source.json','daemon_core_dispatch_source.json','daemon_core_dispatch_symbolic.json','daemon_arena_lifetime_symbolic.py','prove_daemon_core_dispatch.py']},'cases':rows,'native_target_executed':False,'host_API_executed':False,'new_port_emission_established':False,'full_goal_complete':False}
if __name__=='__main__':
 r=analyze();(ROOT/'daemon_operation_heads_symbolic.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps([{'op':x['operation32'],'class':x['path_class'],'visits':len(x['steps']),'input_endpoint':x['minimum_head_input_endpoint_bytes'],'boundary':x['boundary']}for x in r['cases']]),flush=True)
