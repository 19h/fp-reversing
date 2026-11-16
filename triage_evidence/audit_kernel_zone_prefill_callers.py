#!/usr/bin/env python3
"""Source-cut proofs, partition oracle, and changed-store controls.
O(source instances + query DAG + replay journals/RAM) construction/space;
SMT search separate (30 s/query). No native execution or database effects.
"""
import json
import z3
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read,sha
from lskd_values_symbolic import resize
from audit_kernel_zone_bitmap_release import Model
import recover_kernel_zone_prefill_callers as R
import probe_kernel_zone_prefill_callers as CPU

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs=[];coverage=[]
 def local():
  v=Model(e);v.regions.append((v.zone,192));v.seed('x0',v.zone);v.seed('x19',v.zone);return v
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(c) for c in v.edge_checks],bad))
  s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label)
  s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for([*common,counter]),counter);r=s.check();assert r==z3.unsat,(label,r,s.reason_unknown())
  proofs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV','query':s.to_smt2()})
  coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,
   'linked_edge_obligations':len(v.edge_checks),'checked_read_store_rewrites':list(v.separation_rewrites.values())})
 v=local();q=v.load(v.zone+0x7c,2);v.enter('quota_gate')
 prove('quota_u16_zero_skips_provider_phase',v,v.next!=z3.If(q==0,resize(0xfffffe000bd73234,64),resize(0xfffffe000bd7312c,64)))
 v=local();flags=v.load(v.zone+0x3c,4);v.enter('quota_clear')
 prove('provider_phase_clears_quota_and_sets_only_flag_bit2',v,z3.Or(v.load(v.zone+0x7c,2)!=0,v.load(v.zone+0x3c,4)!=(flags|4)))
 for name,offset in [('count_A',0x48),('count_B',0x4c)]:
  v=local();amount=z3.BitVec('PF_'+name+'_amount32',32);old=v.load(v.zone+offset,4);v.seed('w8',amount);v.enter(name)
  prove(name+'_addition_is_exact_modulo_u32',v,v.load(v.zone+offset,4)!=old+amount)
 v=local();old=z3.BitVec('PF_saved_available_count32',32);v.seed('w23',old);v.enter('boolean')
 prove('return_W0_is_exact_zero_or_one_from_saved_count',v,v.read('x0')!=z3.If(old==0,resize(0,64),resize(1,64)))
 v=local();result=z3.BitVec('PF_small_refill_result64',64);v.seed('x0',result);v.enter('small_result')
 prove('small_nonnull_refill_result_bypasses_wait_arm',v,v.next!=z3.If(result!=0,resize(0xfffffe000bd7ac70,64),resize(0xfffffe000bd7ac58,64)))
 v=local();count=v.load(v.zone+0xa8,4);v.enter('small_count')
 prove('small_null_result_wait_arm_requires_zero_zone_a8',v,v.next!=z3.If(count!=0,resize(0xfffffe000bd7ac68,64),resize(0xfffffe000bd7ac60,64)))
 v=local();v.enter('small_arm')
 prove('small_arm_request_passes_zone_and_records_return_site',v,z3.Or(v.read('x0')!=v.zone,v.read('x30')!=0xfffffe000bd7ac68,v.next!=R.ARM))
 v=local();v.enter('small_sentinel')
 prove('small_after_optional_arm_selects_all_ones_result_then_unlock_join',v,z3.Or(v.read('x20')!=resize(-1,64),v.next!=0xfffffe000bd7abfc))
 from kernel_vm_mig_tools import Image
 image=Image();components=[]
 for c in CPU.configurations():
  row=CPU.Probe(image,c).run();row['independent_oracle_checks']=CPU.oracle(row);components.append(row)
 negative=[]
 for pc,configuration in [(0xfffffe000bd7312c,{'mode':'prefill','quota':4,'a':1,'b':1,'old':0,'reserve':0}),
  (0xfffffe000bd73250,{'mode':'prefill','quota':0,'a':0,'b':0,'old':1,'reserve':2})]:
  row=CPU.Probe(image,configuration,pc).run()
  try:CPU.oracle(row)
  except AssertionError as failure:
   negative.append({'component':row,'oracle_rejection':failure.args[0][0]})
  else:raise AssertionError('changed source store accepted')
 selected={i['ea'] for s in e['spans'] for i in s['instructions']};proved={p for c in coverage for p in c['PCs']};assert proved==selected
 source={i['ea'] for i in e['functions'][0]['instructions']};visited={v['pc'] for c in components for v in c['source_visits']}
 totals={'source_queries_unsat':len(proofs),'proved_source_PCs':len(proved),'proof_instruction_instances':sum(c['instruction_instances'] for c in coverage),
  'linked_edge_obligations':sum(c['linked_edge_obligations'] for c in coverage),'components':len(components),
  'component_source_visits':sum(len(c['source_visits']) for c in components),'prefill_component_PCs':len(source&visited),
  'unexecuted_prefill_PCs':len(source-visited),'independent_oracle_checks':sum(len(c['independent_oracle_checks']) for c in components),
  'changed_store_controls':len(negative)}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
  'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':R.SCOPE,
  'source_proofs':proofs,'coverage':coverage,'components':components,'negative_controls':negative,
  'unexecuted_prefill_PCs':sorted(source-visited),'independent_totals':totals,
  'conditional_kernel_zone_prefill_callers_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
