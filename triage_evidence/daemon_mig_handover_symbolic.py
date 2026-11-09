#!/usr/bin/env python3
"""Original copy-helper execution and post-copy handover in the retained frame.
Borrowed bytes/cached cursor remain symbolic. Only the source-attested copy
call is entered; stop before the next call or operation-specific branch.
O(visits + BV/solver resources) time/space. No native APIs, PAC or IPC execute.
"""
import json,re
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from daemon_output_base_dispatch import CS,Stop,Split,unique
from daemon_arena_lifetime_symbolic import LifetimeFlags
from prove_daemon_operation_heads import variables,predicate
from daemon_operation_heads_symbolic import B
from recover_daemon_object_clock import sections
from validate_daemon_record720_spill import parse_value
from capture_daemon_record720 import sha
from daemon_import_bindings import binding
from lskd_values_symbolic import resize
F=0x680004f230;E=0x6800060000;HELPER=0x10046f89c
def analyze():
 parent=json.loads((ROOT/'daemon_operation_heads_symbolic.json').read_text());writable=[s for s in sections()if s['segment']=='__DATA'];rows=[]
 for old in parent['cases']:
  if old['operation32']not in ['0xad952088','0xa70e6eb4']:continue
  op=int(old['operation32'],16)
  for label in ['allnonnull','anynull']if op==0xa70e6eb4 else['any']:
   vs=variables(old);ram={int(r['address'],16):parse_value(r['expression'],8,vs)for r in old['initial_bytes']};borrowed={int(r['address'],16):r['variable']for r in old['borrowed_byte_variables']};globals_={int(r['address'],16):r['variable']for r in old['unavailable_global_byte_variables']};imports=old['new_export_variables'].copy()
   for a,n in {**borrowed,**globals_}.items():ram[a]=vs[n]
   for e in old['effects']:
    if e['kind']=='write':
     at=int(e['address'],16);val=parse_value(e['expression'],e['size_bytes']*8,vs)
     for j in range(e['size_bytes']):ram[at+j]=z3.Extract(8*j+7,8*j,val)
   initial=ram.copy();regs={n:parse_value(x,64,vs)for n,x in old['end_GPR_expressions'].items()};initial_regs=regs.copy();flags=[z3.Bool('handover_entry_'+n)for n in ['N','Z','C','V']];vs.update({x.decl().name():x for x in flags});path=predicate(old['path_condition'],vs)
   if op==0xa70e6eb4:
    pointers=[z3.Concat(*[ram[B+off+j]for j in reversed(range(8))])for off in [0,56,64]];nonnull=z3.And(*[p!=0 for p in pointers]);path=z3.And(path,nonnull if label=='allnonnull'else z3.Not(nonnull))
   pc=int(old['boundary']['pc'],16);steps=[];effects=[];edges=[];direct=[];return_to=None;copy_entry=None;copy_return=None;copies=[]
   class V(LifetimeFlags):
    def load(self,a,n):
     nonlocal path
     at=unique(a,path,pc,'handover_read_address')
     if all(at+j in ram for j in range(n)):bs=[ram[at+j]for j in range(n)];val=z3.Concat(*reversed(bs))if n>1 else bs[0]
     elif at in FIXUPS and n==8:
      t=FIXUPS[at]['target']
      if isinstance(t,str):
       name='core_export_address_'+re.sub('[^a-zA-Z0-9_]','_',t);vs.setdefault(name,z3.BitVec(name,64));bd=binding(at);imports.append({'variable':name,'symbol':t,'binding':bd});val=vs[name]+bd['total_addend']
       if not bd['weak_import']:path=z3.And(path,vs[name]!=0)
      else:val=z3.BitVecVal(t,64)
     else:
      bs=[]
      for j in range(n):
       here=at+j
       if here in ram:b=ram[here]
       elif B<=here<B+72:name='head_%08x_input_%02x'%(op,here-B);b=z3.BitVec(name,8);vs[name]=b;borrowed[here]=name;ram[here]=b
       elif F<=here<E:raise Stop({'pc':hex(pc),'kind':'before_undefined_frame_read','address':hex(at),'size_bytes':n})
       elif any(s['start']<=here<s['start']+s['size_bytes']for s in writable):name='head_global_%x'%here;b=z3.BitVec(name,8);vs[name]=b;globals_[here]=name;ram[here]=b
       else:
        try:b=z3.BitVecVal(IMAGE.read(here,1)[0],8)
        except ValueError:raise Stop({'pc':hex(pc),'kind':'before_unowned_read','address':hex(at),'size_bytes':n})
       bs.append(b)
      val=z3.Concat(*reversed(bs))if n>1 else bs[0]
     effects.append({'pc':hex(pc),'kind':'read','address':hex(at),'size_bytes':n,'expression':val.sexpr()});return val
    def store(self,a,n,val,atpc):
     val=resize(val,n*8)
     at=unique(a,path,pc,'handover_write_address')
     if not(F<=at<at+n<=E or at==0x6800064018 and n==4):raise Stop({'pc':hex(pc),'kind':'before_nonframe_write','address':hex(at),'size_bytes':n})
     effects.append({'pc':hex(pc),'kind':'write','address':hex(at),'size_bytes':n,'expression':val.sexpr()})
     for j in range(n):ram[at+j]=z3.Extract(8*j+7,8*j,val)
   boundary=None
   for count in range(2048):
    i=next(CS.disasm(IMAGE.read(pc,4),pc));m=V({'spans':[{'label':'one','start':hex(pc),'bytes_hex':bytes(i.bytes).hex()}]});m.regs=regs.copy();m.negative,m.equal,m.carry,m.overflow=flags;m.pc=pc;nextpc=pc+4
    try:
     if i.mnemonic in ['braa','blraa']:
      target=m.read(i.op_str.split(',')[0].strip());modifier=m.read(i.op_str.split(',')[1].strip())
      if i.mnemonic=='blraa'and z3.is_true(z3.simplify(target==HELPER)):
       assert i.mnemonic=='blraa'and z3.is_true(z3.simplify(target==HELPER))and z3.is_true(z3.simplify(modifier==0x34a1));slot=0x10109fc88;raw=int.from_bytes(IMAGE.read(slot,8),'little');assert FIXUPS[slot]['target']==HELPER and raw>>63==1 and(raw>>32)&65535==0x34a1;return_to=pc+4;copy_entry={'PC':hex(pc),'slot':hex(slot),'target':hex(HELPER),'SP':z3.simplify(m.read('sp')).sexpr(),'source':z3.simplify(m.read('x0')).sexpr(),'destination':z3.simplify(m.read('x1')).sexpr(),'count':z3.simplify(m.read('x2')).sexpr(),'saved_preserved_GPRs':{n:z3.simplify(m.read(n)).sexpr()for n in ['x19','x20','x21','x22','x23','x24','x25','x26','x27','x28','x29']}};edges.append({'pc':hex(pc),'target':hex(HELPER),'slot':hex(slot),'modifier':'0x34a1','kind':'blraa'});m.seed('x30',return_to);nextpc=HELPER
      elif i.mnemonic=='braa':
       t=unique(target,path,pc,'branch_target');mod=unique(modifier,path,pc,'branch_modifier');previous=next(e for e in reversed(old['effects']+effects)if e['kind']=='read'and e['size_bytes']==8 and int(e['address'],16)in FIXUPS and FIXUPS[int(e['address'],16)]['target']==t);slot=int(previous['address'],16);raw=int.from_bytes(IMAGE.read(slot,8),'little');assert raw>>63==1 and(raw>>32)&65535==mod and(raw>>48)&7==0;edges.append({'pc':hex(pc),'target':hex(t),'slot':hex(slot),'modifier':hex(mod),'kind':'braa'});nextpc=t
      else:boundary={'pc':hex(pc),'kind':'before_'+i.mnemonic,'target_expression':z3.simplify(target).sexpr(),'modifier_expression':z3.simplify(modifier).sexpr(),'argument_GPRs':{n:z3.simplify(m.read(n)).sexpr()for n in ['x0','x1','x2','x3']}};break
     elif i.mnemonic=='ret':
      assert return_to is not None and unique(m.read('x30'),path,pc,'return_target')==return_to;copy_return={'PC':hex(pc),'target':hex(return_to),'SP':z3.simplify(m.read('sp')).sexpr(),'preserved_GPRs':{n:z3.simplify(m.read(n)).sexpr()for n in copy_entry['saved_preserved_GPRs']}};copies.append({'entry':copy_entry,'return':copy_return});nextpc=return_to;return_to=None
     elif i.mnemonic in ['retab','retaa']:
      boundary={'pc':hex(pc),'kind':'before_'+i.mnemonic,'return_target_expression':z3.simplify(m.read('x30')).sexpr(),'SP_expression':z3.simplify(m.read('sp')).sexpr()};break
     elif i.mnemonic=='b'or i.mnemonic.startswith('b.')or i.mnemonic in ['cbz','cbnz','tbz','tbnz']:
      if i.mnemonic=='b':cond=z3.BoolVal(True);t=i.operands[0].imm
      elif i.mnemonic.startswith('b.'):cond=m.condition(i.mnemonic[2:]);t=i.operands[0].imm
      else:
       value=m.read(i.reg_name(i.operands[0].reg));cond=value==0 if i.mnemonic in ['cbz','cbnz']else(value&(1<<i.operands[1].imm))==0;t=i.operands[1 if i.mnemonic in ['cbz','cbnz']else 2].imm
       if i.mnemonic in ['cbnz','tbnz']:cond=z3.Not(cond)
      nextpc=unique(z3.If(cond,z3.BitVecVal(t,64),z3.BitVecVal(pc+4,64)),path,pc,'direct_branch_target');direct.append({'pc':hex(pc),'target':hex(nextpc),'condition':cond.sexpr()})
     else:m.run('one')
    except Stop as stop:boundary=stop.d;break
    except Split as split:boundary={'pc':hex(pc),'kind':'before_nonunique_'+split.role,'expression':split.e.sexpr()};break
    regs=m.regs;flags=[m.negative,m.equal,m.carry,m.overflow];steps.append([pc,bytes(i.bytes).hex()]);pc=nextpc
   assert boundary is not None and copy_return is not None
   rows.append({'operation32':hex(op),'path_class':label,'parent_head_class':old['path_class'],'parent_path_index':old['parent_path_index'],'entry_PC':old['boundary']['pc'],'path_condition':path.sexpr(),'variable_widths':{n:x.size()if z3.is_bv(x)else'Bool'for n,x in vs.items()},'borrowed_byte_variables':[{'address':hex(a),'relative_offset_bytes':a-B,'variable':n}for a,n in sorted(borrowed.items())],'unavailable_global_byte_variables':[{'address':hex(a),'variable':n}for a,n in sorted(globals_.items())],'new_export_variables':imports,'initial_bytes':[{'address':hex(a),'expression':z3.simplify(x).sexpr()}for a,x in sorted(initial.items())],'initial_GPR_expressions':{n:z3.simplify(x).sexpr()for n,x in initial_regs.items()},'copy_calls':copies,'steps':steps,'effects':effects,'edges':edges,'direct_edges':direct,'boundary':boundary,'end_GPR_expressions':{n:z3.simplify(x).sexpr()for n,x in regs.items()},'final_defined_bytes':[{'address':hex(a),'expression':z3.simplify(x).sexpr()}for a,x in sorted(ram.items())]})
 return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_mig_handover_source.json','daemon_operation_heads_symbolic.json','daemon_arena_lifetime_symbolic.py','prove_daemon_operation_heads.py']},'cases':rows,'native_target_executed':False,'host_API_executed':False,'new_port_emission_established':False,'full_goal_complete':False}
if __name__=='__main__':
 r=analyze();(ROOT/'daemon_mig_handover_symbolic.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps([{'op':c['operation32'],'class':c['path_class'],'visits':len(c['steps']),'boundary':c['boundary']}for c in r['cases']]),flush=True)
