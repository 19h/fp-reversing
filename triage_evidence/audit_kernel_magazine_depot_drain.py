#!/usr/bin/env python3
"""Drain arithmetic, caller flag contracts and whole-state components.
O(instruction instances + query DAG + component RAM/journals) construction
and space; solver search separate, 30 s/query. Native effects unexecuted.
"""
import json
import z3
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read,sha
from lskd_values_symbolic import resize
from audit_kernel_zone_bitmap_release import Model
import recover_kernel_magazine_depot_drain as R
import probe_kernel_magazine_depot_drain as CPU

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs=[];coverage=[]
 def local():
  v=Model(e);v.cache=z3.BitVec('DD_cache64',64);v.desc=z3.BitVec('DD_descriptor64',64)
  v.regions.extend([(v.zone,192),(v.cache,64),(v.desc,24)])
  v.seed('x0',v.zone);v.seed('x19',v.desc);return v
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(c) for c in v.edge_checks],bad))
  s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label)
  s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for([*common,counter]),counter);r=s.check();assert r==z3.unsat,(label,r,s.reason_unknown())
  proofs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV','query':s.to_smt2()})
  coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,
   'linked_edge_obligations':len(v.edge_checks),'checked_read_store_rewrites':list(v.separation_rewrites.values())})
 v=local();v.regions.append((R.COUNT,4));base=z3.BitVec('DD_cache_base64',64);count=v.load(resize(R.COUNT,64),4);v.seed('x9',base);v.enter('bound_sum')
 end=base+(z3.ZeroExt(32,count)<<14)
 prove('all_base64_count32_exact_modular_end_and_zero_flag',v,z3.Or(v.read('x17')!=end,v.equal!=(end==0)))
 v=local();control=z3.BitVec('DD_control32',32);v.seed('w20',control);v.enter('retention')
 prove('all_control32_exact_wrapping_full_and_empty_retention',v,z3.Or(v.read('w23')!=z3.LShR(control+1,1),v.read('w24')!=z3.LShR(control,1)))
 for name,offset,reg,skip,take in [('full_gate',0x18,'w23',0xfffffe000bd74b0c,0xfffffe000bd74aa8),('empty_gate',0x1c,'w24',0xfffffe000bd74b80,0xfffffe000bd74b24)]:
  v=local();old=v.load(v.cache+offset,4);keep=z3.BitVec('DD_'+name+'_keep32',32);v.seed('x16',v.cache);v.seed(reg,keep);v.enter(name)
  prove(name+'_extracts_exactly_when_unsigned_count_exceeds_keep',v,z3.Or(v.read('w9')!=old-keep,v.next!=z3.If(z3.ULE(old,keep),resize(skip,64),resize(take,64))))
 for name,offset,source in [('full_add',0,'w9'),('empty_add',4,'w9')]:
  v=local();old=v.load(v.desc+offset,4);amount=z3.BitVec('DD_'+name+'_amount32',32);v.seed(source,amount);v.enter(name)
  prove(name+'_descriptor_count_addition_modulo_u32',v,v.load(v.desc+offset,4)!=old+amount)
 v=local();control=z3.BitVec('DD_boundary_original_control32',32);v.seed('w20',control);v.enter('full_boundary_gate')
 prove('boundary_reset_tests_original_control_not_derived_retention',v,v.next!=z3.If(control!=0,resize(0xfffffe000bd74ae4,64),resize(0xfffffe000bd74ae0,64)))
 v=local();v.seed('x16',v.cache);v.seed('x11',v.cache+0x20);v.enter('full_boundary_reset')
 prove('zero_control_boundary_reset_points_to_cache_head_cell',v,v.load(v.cache+0x28,8)!=v.cache+0x20)
 v=local();current,end=z3.BitVecs('DD_current64 DD_end64',64);v.seed('x9',current);v.seed('x16',end);v.enter('end_compare')
 prove('raw_unsigned_end_comparison_controls_iteration',v,v.next!=z3.If(z3.UGE(current,end),resize(0xfffffe000bd74bd4,64),resize(0xfffffe000bd74a6c,64)))
 v=local();current=z3.BitVec('DD_before_advance64',64);v.seed('x16',current);v.enter('advance');nxt=current+16384
 prove('cache_step_is_modular_16384_with_zero_wrap_branch',v,z3.Or(v.read('x17')!=nxt,v.next!=z3.If(nxt!=0,resize(0xfffffe000bd74a30,64),resize(0xfffffe000bd74bb8,64))))
 v=local();v.seed('x19',v.zone);flags=v.load(v.zone+0x3c,4);v.enter('maintenance_flag_gate')
 prove('maintenance_bit2_gate_before_quota_drain',v,v.next!=z3.If((flags&4)==0,resize(0xfffffe000bd784c4,64),resize(0xfffffe000bd78330,64)))
 v=local();v.seed('x19',v.zone);flags=z3.BitVec('DD_maintenance_loaded_flags32',32);v.seed('w8',flags);v.enter('maintenance_flag_clear')
 prove('maintenance_source_clear_changes_only_bit2',v,v.load(v.zone+0x3c,4)!=(flags&0xfffffffb))
 v=local();quota=v.load(v.zone+0x7c,2);v.seed('x19',v.zone);v.enter('maintenance_request')
 prove('maintenance_passes_u16_quota_zone_and_stack_descriptor',v,z3.Or(v.read('x0')!=v.zone,v.read('x1')!=z3.ZeroExt(48,quota),v.read('x2')!=v.sp0+0x70,v.next!=R.DRAIN,v.read('x30')!=0xfffffe000bd78348))
 v=local();count=z3.BitVec('DD_bulk_count32',32);v.seed('w1',count);v.enter('bulk_zero_gate')
 prove('bulk_zero_count_bypasses_slot_processing',v,v.next!=z3.If(count==0,resize(0xfffffe000bd74f78,64),resize(0xfffffe000bd74c14,64)))
 v=local();array,index=z3.BitVecs('DD_bulk_array64 DD_bulk_index64',64);slot=array+(index<<3);v.regions.append((slot,8))
 old=v.load(slot,8);v.seed('x2',array);v.seed('x20',index);v.enter('bulk_slot_clear')
 prove('bulk_reads_and_clears_selected_slot_before_metadata_validation',v,z3.Or(v.read('x9')!=old,v.load(slot,8)!=0))
 v=local();old=v.load(v.zone+0xa8,4);count=z3.BitVec('DD_bulk_completion_count32',32);v.seed('w1',count);v.enter('bulk_available_add')
 prove('bulk_completion_adds_original_count_to_zone_available_modulo_u32',v,v.load(v.zone+0xa8,4)!=old+count)
 compositions=[];k=z3.Int('DD_u16_maintenance_quota');s=z3.Solver();s.set(timeout=30000)
 s.add(k>=0,k<=65535,(k+1)/2+k/2!=k);assert s.check()==z3.unsat
 compositions.append({'label':'maintenance_u16_full_and_empty_retention_sum_equals_quota','result':'unsat','query':s.to_smt2()})
 from kernel_vm_mig_tools import Image
 image=Image();components=[]
 for c in CPU.configurations():
  row=CPU.Probe(image,c).run();row['independent_oracle_checks']=CPU.oracle(row);components.append(row)
 negative=[]
 for pc in [0xfffffe000bd74ab0,0xfffffe000bd74b04]:
  row=CPU.Probe(image,{'mode':'drain','control':0,'cpus':1,'pattern':'mixed','seed':False},pc).run()
  try:CPU.oracle(row)
  except AssertionError as failure:negative.append({'component':row,'oracle_rejection':failure.args[0][0]})
  else:raise AssertionError('changed source count store accepted')
 source={i['ea'] for i in e['functions'][0]['instructions']};visited={v['pc'] for c in components for v in c['source_visits']};proved={p for c in coverage for p in c['PCs']}
 assert proved=={i['ea'] for s in e['spans'] for i in s['instructions']}
 totals={'source_queries_unsat':len(proofs),'composition_queries_unsat':len(compositions),'proved_source_PCs':len(proved),
  'proof_instruction_instances':sum(c['instruction_instances'] for c in coverage),'linked_edge_obligations':sum(c['linked_edge_obligations'] for c in coverage),
  'components':len(components),'component_source_visits':sum(len(c['source_visits']) for c in components),
  'drain_component_PCs':len(source&visited),'unexecuted_drain_PCs':len(source-visited),
  'original_cache_lock_entries':sum(int(x['cache'],16)!=0 for c in components for x in c['drain_lock_boundaries']),
  'independent_oracle_checks':sum(len(c['independent_oracle_checks']) for c in components),'changed_store_controls':len(negative)}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
  'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':R.SCOPE,
  'source_proofs':proofs,'composition_proofs':compositions,'coverage':coverage,'components':components,'negative_controls':negative,
  'unexecuted_drain_PCs':sorted(source-visited),'independent_totals':totals,
  'conditional_kernel_magazine_depot_drain_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
