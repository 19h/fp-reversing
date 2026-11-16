#!/usr/bin/env python3
"""Capacity/extent/source proofs and whole-state producer/caller checks.
O(source + query DAG + visits + journals + RAM) construction/space; solver
search separate, 30 s/query. No native boot, storage allocation or IPC.
"""
import json
from collections import Counter
import z3
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read,sha
from lskd_values_symbolic import resize
from audit_kernel_retirement_magazines import Model as Parent,DEC
import recover_kernel_magazine_bootstrap as R
import probe_kernel_magazine_bootstrap as CPU
from replay_kernel_magazine_bootstrap import Replay

class Model(Parent):
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.mnemonic not in ['ldumax','umull']:
    old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one');self.e,self.c=old_e,old_c;continue
   if self.next is not None:self.edge_checks.append(self.next==i.address)
   self.next=resize(i.address+4,64);self.pc=i.address;self.visited.add(i.address);self.count+=1
   if i.mnemonic=='umull':
    o=i.operands;self.write(i.reg_name(o[0].reg),z3.ZeroExt(32,self.read(i.reg_name(o[1].reg)))*z3.ZeroExt(32,self.read(i.reg_name(o[2].reg))))
   else:
    assert i.op_str=='w8, w8, [x9]';at=self.read('x9');old=self.load(at,4);incoming=self.read('w8');self.store(at,4,z3.If(z3.UGE(old,incoming),old,incoming),i.address);self.write('w8',old)
  return self

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs=[];coverage=[]
 def local():v=Model(e);v.regions=[];return v
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(c) for c in v.edge_checks],bad))
  s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label)
  s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for([*common,counter]),counter);result=s.check();assert result==z3.unsat,(label,result,s.reason_unknown())
  proofs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV','query':s.to_smt2()})
  coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,'linked_edge_obligations':len(v.edge_checks),
   'checked_read_store_rewrites':list(v.separation_rewrites.values())});print(label,flush=True)
 v=local();v.regions=[(0xfffffe0007ef8bf0,4),(R.COUNT,4)];last=v.load(0xfffffe0007ef8bf0,4);v.enter('cpu_count')
 prove('cpu_count_is_input_plus_one_modulo_u32',v,v.load(R.COUNT,4)!=last+1)
 v=local();v.regions=[(0xfffffe0007f8b6e8,8)];base=v.load(0xfffffe0007f8b6e8,8);v.enter('presence_request')
 prove('policy_calls_presence_parser_with_null_output_and_zero_sizes',v,z3.Or(v.read('x0')!=base+0x6c,v.read('x1')!=0xfffffe0007053327,
  v.read('x2')!=0,v.read('x3')!=0,v.read('x4')!=0,v.read('x30')!=0xfffffe000c631ff0,v.next!=R.PARSER))
 v=local();v.regions=[(R.COUNT,4)];count=v.load(R.COUNT,4);result=z3.BitVec('MB_presence_result32',32);v.seed('x20',0xfffffe0007e66000);v.seed('w0',result);v.enter('presence_gate')
 prove('only_zero_presence_result_selects_capacity_heuristic',v,z3.Or(v.read('x8')!=z3.ZeroExt(32,count),v.next!=z3.If(result==0,resize(0xfffffe000c6320e4,64),resize(0xfffffe000c631ff8,64))))
 v=local();count=z3.BitVec('MB_count32',32);v.seed('w8',count);v.enter('cpu_threshold')
 prove('capacity14_path_requires_unsigned_count_at_least10',v,v.next!=z3.If(z3.ULT(count,10),resize(0xfffffe000c63218c,64),resize(0xfffffe000c6320ec,64)))
 for label,value in [('capacity14',14),('capacity10',10)]:
  v=local();v.regions=[(R.CAP,2)];v.enter(label);prove(label+'_exact_u16_publication',v,v.load(R.CAP,2)!=value)
 v=local();v.regions=[(0xfffffe000cb29cb4,4)];feature=v.load(0xfffffe000cb29cb4,4);v.enter('feature_gate')
 prove('small_count_feature_zero_preserves_existing_capacity',v,v.next!=z3.If(feature==0,resize(0xfffffe000c631ff8,64),resize(0xfffffe000c632198,64)))
 v=local();v.regions=[(R.CAP,2)];capacity=v.load(R.CAP,2);v.enter('view_request');extent=16+(z3.ZeroExt(48,capacity)<<3)
 prove('magazine_zone_request_exact_name_extent_flags_dynamic_id_and_null_setup',v,z3.Or(v.read('x0')!=0xfffffe000705354e,v.read('x1')!=extent,
  v.read('x2')!=0x2000000002000020,v.read('x3')!=0xffff,v.read('x4')!=0,v.read('x30')!=0xfffffe000c63261c,v.next!=R.CREATE))
 w=local();w.seed('x1',extent);w.enter('create_size_gate')
 prove('all_u16_capacities_pass_size_gate_iff_at_most4094',w,w.next!=z3.If(z3.ULE(capacity,4094),resize(0xfffffe000bd772e0,64),resize(0xfffffe000bd77a20,64)))
 v=local();v.regions=[(R.COUNT,4),(R.VIEW,8)];count=v.load(R.COUNT,4);view=z3.BitVec('MB_returned_view64',64);v.seed('x0',view);v.enter('view_publish')
 prove('publish_exact_creator_view_and_double_count_modulo_u32',v,z3.Or(v.load(R.VIEW,8)!=view,v.read('w8')!=count<<1))
 v=local();view=z3.BitVec('MB_view_lower64',64);v.seed('x0',view);v.enter('view_lower')
 prove('view_normalization_lower_bound_is_unsigned',v,v.next!=z3.If(z3.ULT(view,R.ARRAY),resize(0xfffffe000c632650,64),resize(0xfffffe000c632640,64)))
 v=local();view=z3.BitVec('MB_view_upper64',64);v.seed('x0',view);v.enter('view_upper')
 prove('view_normalization_upper_bound_is_inclusive',v,v.next!=z3.If(z3.ULE(view,0xfffffe000cb0ba00),resize(0xfffffe000c632654,64),resize(0xfffffe000c632650,64)))
 v=local();view=z3.BitVec('MB_indirect_view64',64);v.regions=[(view,8)];expected=v.load(view,8);v.seed('x0',view);v.enter('view_indirect')
 prove('outside_direct_interval_loads_leading_zone_pointer',v,v.read('x0')!=expected)
 v=local();zone=z3.BitVec('MB_floor_zone64',64);v.regions=[(zone,192)];old=v.load(zone+0xb0,4);count=z3.BitVec('MB_floor_count32',32);v.seed('x0',zone);v.seed('w8',count<<1);v.enter('minimum_floor');floor=(count<<1)&0xfffe
 prove('minimum_floor_is_unsigned_max_of_old_and_even_low16_double_count',v,z3.Or(v.load(zone+0xb0,4)!=z3.If(z3.UGE(old,floor),old,floor),v.read('w8')!=old))
 v=local();ident=z3.BitVec('MB_dynamic_id16',16);v.seed('w21',ident);v.enter('dynamic_id')
 prove('fresh_dynamic_slot_uses_reserved_count_and_prepares_increment',v,z3.Or(v.read('x22')!=R.ARRAY+192*z3.ZeroExt(48,ident),v.read('w8')!=z3.ZeroExt(16,ident)+1))
 v=local();zone=z3.BitVec('MB_extent_zone64',64);v.regions=[(zone,192)];extent=z3.BitVec('MB_rounded_extent64',64);span=z3.BitVec('MB_span64',64);v.seed('x22',zone);v.seed('x25',extent);v.seed('x9',span);v.enter('extent_store')
 prove('creator_publishes_low16_extent_and_span_in_16KiB_units',v,z3.Or(v.load(zone+0x34,2)!=z3.Extract(15,0,extent),v.read('x8')!=z3.LShR(span,14)))
 v=local();zone=z3.BitVec('MB_self_zone64',64);v.regions=[(zone,192)];v.seed('x22',zone);v.enter('view_self')
 prove('creator_leading_view_points_to_same_zone',v,v.load(zone,8)!=zone)
 v=local();zone=z3.BitVec('MB_cache_zone64',64);v.regions=[(zone,192),(R.CAP,2),(0xfffffe0007e66e38,4)];extent=v.load(zone+0x34,2);capacity=v.load(R.CAP,2);budget=v.load(0xfffffe0007e66e38,4);v.seed('x0',zone);v.enter('cache_bound');den=z3.ZeroExt(16,extent)*z3.ZeroExt(16,capacity);q=z3.If(den==0,resize(0,32),z3.UDiv(budget,den))
 prove('cache_budget_bound_uses_same_capacity_extent_and_A64_zero_division',v,v.load(zone+0x7e,2)!=z3.If(z3.ULT(q,32767),resize(q,16),resize(32767,16)))
 v=local();v.enter('cache_request')
 prove('cache_storage_request_uses_ready_slot2_context_64_bytes_flags3f',v,z3.Or(v.read('x0')!=0xfffffe000caeb600,v.read('x1')!=64,v.read('x2')!=0x3f,v.next!=0xfffffe000bd71a20))
 # The typed magazine requests share the source-created leading view.
 for label,offset in [('current_magazine',8),('spare_magazine',16)]:
  view,cache=z3.BitVecs('MB_'+label+'_view64 MB_'+label+'_cache64',64)
  row=next(s for s in e['spans'] if s['label']==label);a=int(row['start'],16);raw=bytes.fromhex(row['bytes_hex'])
  cut={'spans':[{'label':'request','start':hex(a),'bytes_hex':raw[:16].hex()}],'reused_caller_spans':[]}
  u=Model(cut);u.regions=[(R.VIEW,8),(view,16)];u.setmem(R.VIEW,8,view);u.seed('x22',0xfffffe0007e66000);z=u.load(view,8);st=u.load(view+8,8);u.enter('request')
  prove(label+'_exact_typed_allocation_request',u,z3.Or(u.read('x0')!=z,u.read('x1')!=st,u.read('x2')!=0x8004,u.next!=0xfffffe000bd75c64))
  cut={'spans':[{'label':'install','start':hex(a+16),'bytes_hex':raw[16:].hex()}],'reused_caller_spans':[]};u=Model(cut);u.regions=[(cache,64)];ptr=z3.BitVec('MB_'+label+'_ordinary_return64',64);u.seed('x0',ptr);u.seed('x24',cache);u.enter('install')
  prove(label+'_installs_return_plus16_without_local_null_gate',u,u.load(cache+offset,8)!=ptr+16)
 separations=[]
 for p in json.loads(read(ROOT/'kernel_zone_bitmap_release_audit.json'))['rechecked_separation_lemmas']:
  solver=z3.Solver();solver.set(timeout=30000);solver.add(*z3.parse_smt2_string(p['query']));assert solver.check()==z3.unsat
  separations.append({'label':p['label'],'query':p['query'],'result':'unsat','source_artifact_sha256':sha(ROOT/'kernel_zone_bitmap_release_audit.json')})
 from kernel_vm_mig_tools import Image
 image=Image();components=[];replays=[];totals=Counter()
 for c in CPU.policies():
  row=CPU.Probe(image,'policy',c).run();row['independent_oracle_checks']=CPU.oracle(row);components.append(row);r=Replay(image,row).run();replays.append(r);totals.update(r)
 for policy_index in [0,3,4,10,14,24,25,26,27,28]:
  parent=components[policy_index];row=CPU.Probe(image,'publish',{'policy_component':policy_index},parent).run();row['independent_oracle_checks']=CPU.oracle(row,parent);publish_index=len(components);components.append(row);r=Replay(image,row,parent).run();replays.append(r);totals.update(r)
  if row['boundary']['kind']=='magazine_view_published_and_floor_updated':
   cache=CPU.Probe(image,'cache',{'publication_component':publish_index},row).run();cache['independent_oracle_checks']=CPU.oracle(cache,row);components.append(cache);r=Replay(image,cache,row).run();replays.append(r);totals.update(r)
 negative=[]
 for mode,index,pc in [('policy',4,0xfffffe000c6320f4),('publish',0,0xfffffe000c632620),('cache',29,0xfffffe000bd77c54)]:
  parent=None if mode=='policy' else components[index];c=CPU.policies()[index] if mode=='policy' else {};row=CPU.Probe(image,mode,c,parent,pc).run()
  try:CPU.oracle(row,parent)
  except AssertionError as failure:negative.append({'component':row,'oracle_rejection':failure.args[0][0]})
  else:raise AssertionError('changed source accepted')
 proved={p for c in coverage for p in c['PCs']};assert proved=={i['ea'] for s in e['spans'] for i in s['instructions']}
 source={i['ea'] for f in e['functions'] for i in f['instructions']};visited={v['pc'] for c in components for v in c['source_visits']}
 independent={'source_queries_unsat':len(proofs),'rechecked_separation_lemmas_unsat':len(separations),'proved_source_PCs':len(proved),'proof_instruction_instances':sum(c['instruction_instances'] for c in coverage),
  'linked_edge_obligations':sum(c['linked_edge_obligations'] for c in coverage),'checked_read_store_rewrites':sum(len(c['checked_read_store_rewrites']) for c in coverage),
  'components':len(components),'component_source_visits':sum(len(c['source_visits']) for c in components),'executed_source_PCs':len(visited&source),
  'independent_oracle_checks':sum(len(c['independent_oracle_checks']) for c in components),'changed_source_controls':len(negative)}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_magazine_bootstrap.py'),
  'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':R.SCOPE,
  'source_proofs':proofs,'rechecked_separation_lemmas':separations,'coverage':coverage,'components':components,'independent_replays':replays,'independent_replay_totals':dict(totals),'negative_controls':negative,
  'unexecuted_source_PCs':sorted(source-visited),'independent_totals':independent,'conditional_kernel_magazine_bootstrap_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True);print(json.dumps(a['independent_replay_totals']),flush=True)
