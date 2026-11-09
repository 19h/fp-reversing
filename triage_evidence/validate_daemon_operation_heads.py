#!/usr/bin/env python3
"""Fresh continuous entry-to-head-frontier A64 replay plus constructor slice
and store checks, original/source/SMT readback and retained counterexamples.
O(cases*source visits + artifact bytes + solver resources) time; O(one CPU map,
journal + expression DAGs) space. No native API, call frontier or IPC executes.
"""
import copy,json
from collections import Counter
import z3
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,IMAGE
from capture_daemon_record720 import sha
from capture_daemon_operation_heads import capture
from daemon_operation_heads_symbolic import analyze,B
from prove_daemon_operation_heads import obligations,variables,predicate
from validate_daemon_record720_spill import parse_value
from validate_daemon_core_dispatch import FreshReplay
from replay_daemon_descriptor_producers import IMPORTS

def continuous(case,variant):
 parent=json.loads((ROOT/'daemon_shared_roots_profiles.json').read_text())['cases'][0];src=json.loads((ROOT/'daemon_core_dispatch_source.json').read_text());dispatch=json.loads((ROOT/'daemon_core_dispatch_symbolic.json').read_text());path=dispatch['paths'][case['parent_path_index']];p=copy.deepcopy(parent);limit=src['operation_unread_prefix_source_visits'];op=int(case['operation32'],16);v=variables(case);replacements=[]
 data=bytearray((0 if variant==0 else 255 if variant==1 else(j*73+variant*19)&255)for j in range(72))
 if case['pointer_variable']:
  ptr=0 if case['path_class']=='null'else(1 if variant==0 else int.from_bytes(data[8:16],'little')or 1);data[8:16]=ptr.to_bytes(8,'little');replacements.append((v[case['pointer_variable']],z3.BitVecVal(ptr,64)))
 for r in case['borrowed_byte_variables']:replacements.append((v[r['variable']],z3.BitVecVal(data[r['relative_offset_bytes']],8)))
 globvalues={int(r['address'],16):(0 if variant==0 else(variant*61+int(r['address'],16)*17)&255)for r in case['unavailable_global_byte_variables']}
 for r in case['unavailable_global_byte_variables']:replacements.append((v[r['variable']],z3.BitVecVal(globvalues[int(r['address'],16)],8)))
 exports={r['symbol']:IMPORTS[r['symbol']]+variant*0x10000000 for r in dispatch['export_variables']+case['new_export_variables']}
 for r in dispatch['export_variables']+case['new_export_variables']:replacements.append((v[r['variable']],z3.BitVecVal(exports[r['symbol']],64)))
 replacements.append((v['core_dispatch_operation32'],z3.BitVecVal(op,32)))
 for n in ['N','Z','C','V']:replacements.append((v['head_entry_'+n],z3.BoolVal(False)))
 def ev(s,n):
  value=z3.simplify(z3.substitute(parse_value(s,n,v),*replacements));assert z3.is_bv_value(value),value;return value.as_long()
 p['initial_private_fixtures'].append({'address':hex(B),'bytes_hex':data.hex()})
 for a,b in globvalues.items():p['initial_image_fixtures'].append({'address':hex(a),'bytes_hex':bytes([b]).hex()})
 R=int(p['record_address'],16);K=(((R&0xffffffff)^0xeaae0ac9)*0x7398180b)&0xffffffff;fixture=next(r for r in p['initial_private_fixtures']if r['address']==hex(R));raw=bytearray.fromhex(fixture['bytes_hex']);raw[12:16]=(op^K).to_bytes(4,'little');fixture['bytes_hex']=raw.hex();p['configuration']={**p['configuration'],'head_operation':hex(op),'input_variant':variant,'head_path_class':case['path_class']};p['source_visits']=p['source_visits'][:limit]
 for name in ['source_reads','source_writes','logical_edges']:p[name]=[e for e in p[name]if e['source_visit_index']<limit]
 for segment in [path,case]:
  effects=iter(segment['effects']);effect=next(effects,None);edges=iter(segment.get('edges',[]));edge=next(edges,None)
  for pc,rawhex in segment['steps']:
   j=len(p['source_visits']);p['source_visits'].append({'pc':hex(pc),'bytes_hex':rawhex,'image':'daemon'})
   while effect is not None and effect['pc']==hex(pc):
    e=effect;n=e['size_bytes'];row={'pc':hex(pc),'address':e['address'],'size_bytes':n,'source_visit_index':j};row['bytes_hex'if e['kind']=='read'else'after_hex']=ev(e['expression'],n*8).to_bytes(n,'little').hex();p['source_reads'if e['kind']=='read'else'source_writes'].append(row);effect=next(effects,None)
   if edge is not None and edge['pc']==hex(pc):p['logical_edges'].append({**edge,'source_visit_index':j});edge=next(edges,None)
  assert effect is None and edge is None
 regs=case['end_GPR_expressions'];p['boundary']={'pc':case['boundary']['pc'],'SP':hex(ev(regs['sp'],64)),'registers31':[hex(ev(regs['x'+str(j)],64))for j in range(31)]};s=z3.Solver();s.add(predicate(case['path_condition'],v));s.add(*[a==b for a,b in replacements]);assert s.check()==z3.sat
 replay=FreshReplay(p,variant%4,exports);result=replay.run();return {'operation32':hex(op),'path_class':case['path_class'],'input_variant':variant,'input_bytes_hex':data.hex(),'boundary':case['boundary']['pc'],'replay':result}

def constructor_case(candidate,op,FP,phase,store=True):
 c=candidate['record_constructor'];u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);pages=set();count=0
 def ensure(a):
  pg=a&~4095
  if pg not in pages:u.mem_map(pg,4096);u.mem_write(pg,IMAGE.read(pg,4096)if 0x100000000<=pg<0x102000000 else bytes([0xA5])*4096);pages.add(pg)
 for j in range(31):u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),(j*0x7398180b+0x12345678)&((1<<64)-1))
 u.reg_write(ar.UC_ARM64_REG_X29,FP);u.reg_write(ar.UC_ARM64_REG_X19,phase)
 for r in c['projection']:
  pc=int(r['pc'],16);assert IMAGE.read(pc,4).hex()==r['bytes_hex'];ensure(pc);u.emu_start(pc,0,count=1);count+=1
 values=[u.reg_read(getattr(ar,'UC_ARM64_REG_X'+r[1:]))&0xffffffff for r in [c['tag_register'],c['operation_register']]];P=(FP+c['record_relative_to_FP_bytes'])&((1<<64)-1);K=(((P&0xffffffff)^0xeaae0ac9)*0x7398180b)&0xffffffff;tag=(phase+0x1d7b)&0xffffffff if op==0xa70e6eb4 else 0x6cf4;match=values==[tag^K,op^K]
 if store:
  assert match and FP&15==0;ensure(P);ensure(P+15);pc=int(c['store_PC'],16);ensure(pc);u.emu_start(pc,0,count=1);assert bytes(u.mem_read(P+8,8))==b''.join(x.to_bytes(4,'little')for x in values);count+=1
 return {'literal_PC':candidate['pc'],'FP':hex(FP),'phase32':hex(phase),'decoded_fields_match':match,'store_executed':store,'A64_instructions':count}

def main():
 source=json.loads((ROOT/'daemon_operation_heads_source.json').read_text());symbolic=json.loads((ROOT/'daemon_operation_heads_symbolic.json').read_text());proofs=json.loads((ROOT/'daemon_operation_heads_proofs.json').read_text());assert capture()==source and analyze()==symbolic;qs,meta=obligations();assert meta==proofs['metadata']and len(qs)==len(proofs['proofs']);file_checks=0
 for (name,q),r in zip(qs,proofs['proofs'],strict=True):
  assert name==r['name'];s=z3.Solver();s.set(timeout=30000);s.add(q);assert s.check()==z3.unsat,(name,s.reason_unknown())
  for file,hashkey in [('file','sha256'),('original_file','original_sha256')]:
   p=ROOT/r[file];assert sha(p)==r[hashkey];s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_file(str(p)));assert s.check()==z3.unsat,(name,file,s.reason_unknown());file_checks+=1
  print(name,'rebuilt and read back',flush=True)
 constructors=[];rejected=[];phases=[0,0xffffffff,0x4f79,0x4f78,0x4f7a,0x80000000,0x12345678,0x6cf4];byname={}
 for head in source['handlers']:
  op=int(head['operation32'],16)
  for candidate in head['literal_candidates']:
   if 'record_constructor'not in candidate:continue
   byname['constructor_'+candidate['pc'][2:]]=(candidate,op)
   for j,phase in enumerate(phases):row=constructor_case(candidate,op,0x6800064000+(j%4)*64,phase);assert row['decoded_fields_match'];constructors.append(row)
 for r in proofs['full_FP_domain_probes']:
  p=ROOT/r['file'];assert sha(p)==r['sha256'];s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_file(str(p)));assert str(s.check())==r['result']
  if r['result']=='sat':
   candidate,op=byname[r['name']];row=constructor_case(candidate,op,int(r['FP_counterexample'],16),int(r['phase_counterexample'],16),False);assert not row['decoded_fields_match']and int(row['FP'],16)&15;rejected.append(row)
 rows=[];totals=Counter()
 for case in symbolic['cases']:
  for variant in range(8):
   row=continuous(case,variant);rows.append(row);totals.update(row['replay']['verified_counts']);print(case['operation32'],case['path_class'],variant,'continuous CPU pass',flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_operation_heads_source.json','daemon_operation_heads_symbolic.json','daemon_operation_heads_proofs.json','capture_daemon_operation_heads.py','daemon_operation_heads_symbolic.py','prove_daemon_operation_heads.py','validate_daemon_core_dispatch.py','replay_daemon_descriptor_producers.py','daemon_shared_roots_profiles.json']},'verified_counts':{'operation_heads':4,'symbolic_classes':len(symbolic['cases']),'MIG_wrapper_constructor_links':sum(len(r['MIG_request_IDs'])for r in meta['constructors']),'source_constructor_sites':len(constructors)//8,'source_constructor_projection_instructions':sum(meta['projection_instruction_counts'].values()),'source_obligations_rebuilt':len(qs),'accepted_SMT_files':file_checks,'full_FP_domain_probe_files':len(proofs['full_FP_domain_probes']),'rejected_full_FP_counterexamples_replayed':len(rejected),'constructor_store_cases':len(constructors),'constructor_A64_instructions':sum(r['A64_instructions']for r in constructors+rejected),'fresh_continuous_A64_cases':len(rows)},'independent_A64_totals':dict(totals),'constructor_cases':constructors,'rejected_full_FP_cases':rejected,'fresh_replay_cases':rows,'symbolic_heads_use_Z3_scalar_semantics':True,'CPU_replay_uses_Unicorn':True,'native_target_executed':False,'host_API_executed':False,'idb_mutated':False,'new_port_emission_established':False,'native_input_extent_known':False,'upstream_nested_phase_proved':False,'later_auxiliary_epoch_join_proved':False,'all_checks_pass':True,'full_goal_complete':False};(ROOT/'daemon_operation_heads_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':out['verified_counts'],'A64_totals':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
