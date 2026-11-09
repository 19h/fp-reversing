#!/usr/bin/env python3
"""Rebuild source/SMT obligations and replay fresh continuous entry-to-frontier
A64 witnesses. CPU replay and checkpoint capture share Unicorn; the dispatcher
lift uses Z3 scalar semantics. Fake export addresses are test inputs only.
O(cases*visits + BV solver resources) time, O(one map/journal + DAGs) space.
No imported call, protected return, native task port, daemon or kernel executes.
"""
import copy,json
from collections import Counter
import z3
from daemon_receive_tools import ROOT,IMAGE,FIXUPS,CS
from capture_daemon_record720 import sha
from capture_daemon_core_dispatch import capture
from daemon_core_dispatch_symbolic import explore
from prove_daemon_core_dispatch import setup,obligations,OP
from validate_daemon_record720_spill import parse_value
from replay_daemon_descriptor_producers import Replay,IMPORTS,FIXPAGES,ar
from daemon_import_bindings import binding

class FreshReplay(Replay):
 def __init__(self,p,pattern,exports):self.exports=exports;super().__init__(p,pattern=pattern)
 def ensure(self,a,n=1):
  before=self.pages.copy();super().ensure(a,n)
  for pg in self.pages-before:
   for at,r in FIXPAGES[pg]:
    if r['target']in self.exports:
     val=(self.exports[r['target']]+binding(at)['total_addend'])&((1<<64)-1);self.u.mem_write(at,val.to_bytes(8,'little'))

def witness(parent,path,op,variant,d,v):
 p=copy.deepcopy(parent);limit=d['source_checkpoint_visits'];p['source_visits']=p['source_visits'][:limit];p['source_reads']=[e for e in p['source_reads']if e['source_visit_index']<limit];p['source_writes']=[e for e in p['source_writes']if e['source_visit_index']<limit];p['logical_edges']=[e for e in p['logical_edges']if e['source_visit_index']<limit]
 exports={r['symbol']:(IMPORTS[r['symbol']]+variant*0x10000000)&((1<<64)-1)for r in d['symbolic']['export_variables']};values=[(OP,z3.BitVecVal(op,32))]+[(v[r['variable']],z3.BitVecVal(exports[r['symbol']],64))for r in d['symbolic']['export_variables']]
 def ev(s,bits):
  x=z3.simplify(z3.substitute(parse_value(s,bits,v),*values));assert z3.is_bv_value(x),x;return x.as_long()
 R=int(parent['record_address'],16);K=(((R&0xffffffff)^0xeaae0ac9)*0x7398180b)&0xffffffff
 fixture=next(r for r in p['initial_private_fixtures']if r['address']==hex(R));raw=bytearray.fromhex(fixture['bytes_hex']);raw[12:16]=(op^K).to_bytes(4,'little');fixture['bytes_hex']=raw.hex();p['configuration']={**p['configuration'],'fresh_operation32':hex(op),'fresh_export_variant':variant};effects=iter(path['effects']);pending=next(effects,None);edges=iter(path['edges']);edge=next(edges,None)
 for j,(pc,rawhex)in enumerate(path['steps'],limit):
  p['source_visits'].append({'pc':hex(pc),'bytes_hex':rawhex,'image':'daemon'})
  while pending is not None and pending['pc']==hex(pc):
   e=pending;n=e['size_bytes'];row={'pc':hex(pc),'address':e['address'],'size_bytes':n,'source_visit_index':j};payload=ev(e['expression'],n*8).to_bytes(n,'little').hex();row['bytes_hex'if e['kind']=='read'else'after_hex']=payload;p['source_reads'if e['kind']=='read'else'source_writes'].append(row);pending=next(effects,None)
  if edge is not None and edge['pc']==hex(pc):p['logical_edges'].append({**edge,'source_visit_index':j});edge=next(edges,None)
 assert pending is None and edge is None
 regs=path['end_GPR_expressions'];p['boundary']={'pc':path['boundary']['pc'],'SP':hex(ev(regs['sp'],64)),'registers31':[hex(ev(regs['x'+str(j)],64))for j in range(31)]};p['entry_PC']=parent['entry_PC'];p['source_visits'][0]['image']='daemon'
 rep=FreshReplay(p,variant%4,exports);out=rep.run()
 for name in ['q8','q9','q10','q11']:
  if name in regs:assert rep.reg(name)==ev(regs[name],128)
 return {'operation32':hex(op),'export_address_variant':variant,'private_physical_pattern':variant%4,'path_index':d['path_index'],'boundary':path['boundary'],'replay':out}

def main():
 source=json.loads((ROOT/'daemon_core_dispatch_source.json').read_text());symbolic=json.loads((ROOT/'daemon_core_dispatch_symbolic.json').read_text());proofs=json.loads((ROOT/'daemon_core_dispatch_proofs.json').read_text());assert capture()==source and explore()==symbolic
 d,v,env,predicates=setup();qs,meta=obligations();assert meta==proofs['metadata']and len(qs)==len(proofs['proofs']);proof_checks=0
 for (name,q),row in zip(qs,proofs['proofs'],strict=True):
  assert name==row['name']
  for f,h in [('original_file','original_sha256'),('file','sha256')]:
   file=ROOT/row[f];assert sha(file)==row[h];s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_file(str(file)));assert s.check()==z3.unsat;proof_checks+=1
  s=z3.Solver();s.set(timeout=30000);s.add(q);assert s.check()==z3.unsat
 parent=json.loads((ROOT/'daemon_shared_roots_profiles.json').read_text())['cases'][0];ops={0,0xffffffff,0x80000000,0x7fffffff,0x22f7b5a9,0x22f7b5aa}
 for path in symbolic['paths']:ops.add(int(path['operation_sample'],16))
 for route in meta['routes']:
  for k in ['operation_low_u32','operation_high_u32']:
   x=int(route[k],16);ops.update([(x-1)&0xffffffff,x,(x+1)&0xffffffff])
 rows=[];totals=Counter();boundaries=Counter()
 for op in sorted(ops):
  matches=[]
  for j,q in enumerate(predicates):
   s=z3.Solver();s.add(env,q,OP==op);r=s.check();assert r!=z3.unknown
   if r==z3.sat:matches.append(j)
  assert len(matches)==1;index=matches[0];path=symbolic['paths'][index]
  for variant in range(4):
   row=witness(parent,path,op,variant,{'source_checkpoint_visits':source['operation_unread_prefix_source_visits'],'symbolic':symbolic,'path_index':index},v);rows.append(row);totals.update(row['replay']['verified_counts']);boundaries[path['boundary']['pc']]+=1
   print(hex(op),variant,index,'pass',flush=True)
 source_checks=[]
 for pc,mnemonic,operands in [(0x100006adc,'mov','w15, #0xb5aa'),(0x100006ae0,'movk','w15, #0x22f7, lsl #16'),(0x100006ae4,'eor','w15, w16, w15'),(0x100006ae8,'stp','w17, w15, [sp, #0x30]')]:
  raw=IMAGE.read(pc,4);ins=next(CS.disasm(raw,pc));assert(ins.mnemonic,ins.op_str)==(mnemonic,operands);source_checks.append({'pc':hex(pc),'bytes_hex':raw.hex(),'mnemonic':mnemonic,'operands':operands})
 imports=[]
 for path in symbolic['paths']:
  if path['boundary']['pc']in ['0x1005a8618','0x1005aaf60']:
   slot=0x1010a0478;word=int.from_bytes(IMAGE.read(slot,8),'little');assert word>>63==1 and(word>>32)&65535==0x5278 and(word>>48)&7==0;imports.append({'call_PC':path['boundary']['pc'],'slot':hex(slot),'binding':binding(slot),'native_call_executed':False})
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_core_dispatch_source.json','daemon_core_dispatch_symbolic.json','daemon_core_dispatch_proofs.json','capture_daemon_core_dispatch.py','daemon_core_dispatch_symbolic.py','prove_daemon_core_dispatch.py','replay_daemon_descriptor_producers.py','daemon_shared_roots_profiles.json']},'verified_counts':{'symbolic_paths':len(predicates),'operation_values':len(ops),'fresh_continuous_A64_cases':len(rows),'rebuilt_obligations':len(qs),'accepted_SMT_files':proof_checks,'opaque_export_variables':len(symbolic['export_variables']),'logging_call_bindings_checked':len(imports),'registration_constructor_instructions_checked':len(source_checks)},'independent_A64_totals':dict(totals),'boundary_counts':dict(boundaries),'fresh_replay_cases':rows,'logging_call_bindings':imports,'registration_constructor_source_checks':source_checks,'checkpoint_and_replay_share_Unicorn':True,'symbolic_dispatch_uses_separate_Z3_scalar_semantics':True,'native_import_contents_assigned':False,'native_target_executed':False,'host_API_executed':False,'new_port_emission_established':False,'idb_mutated':False,'all_checks_pass':True,'full_goal_complete':False};(ROOT/'daemon_core_dispatch_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':out['verified_counts'],'A64_totals':dict(totals),'boundaries':dict(boundaries),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
