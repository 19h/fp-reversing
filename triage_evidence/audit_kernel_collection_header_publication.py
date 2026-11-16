#!/usr/bin/env python3
"""Publisher source proofs, finite CPU contracts and independent replay.
Linear source/journal/RAM work; SMT search separate,30 s/query.
"""
import json
from collections import Counter
import z3
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_kernel_timeout_execution import Model
from lskd_values_symbolic import resize
import recover_kernel_collection_header_publication as R
import probe_kernel_collection_header_publication as CPU
from replay_kernel_collection_header_publication import oracle,Replay
def source_proofs(e):
 proofs=[];coverage=[]
 def cut(v,a,b):
  f=next(f for f in e['functions'] if int(f['start'],16)<=a<b<=int(f['end'],16));off=a-int(f['start'],16);v.e=v.c={'spans':[{'label':'cut','start':hex(a),'bytes_hex':bytes.fromhex(f['bytes'])[off:off+b-a].hex()}]};return v.enter('cut')
 def fresh():
  v=Model(e);v.regions=[(R.MAP,24),(R.SLOT,96)]
  for j,value in enumerate([0,1,3]):v.setmem(R.MAP+8*j,8,value)
  for j in range(12):v.setmem(R.SLOT+8*j,8,z3.BitVec('KC_bank_'+str(j),64))
  return v
 def prove(label,v,bad):
  common=v.owned();counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad));s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label);s.add(*v.bindings_for([*common,counter]),counter);assert s.check()==z3.unsat,(label,s.reason_unknown());proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True});coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instructions':v.count,'linked_edges':len(v.edge_checks)});print('proved',label,flush=True)
 kind=z3.BitVec('KC_kind64',64);low=z3.Extract(31,0,kind);v=fresh();v.seed('x0',kind);cut(v,0xfffffe000c6626f4,0xfffffe000c662700);prove('kind_low32_accepts_only1_2_3',v,v.next!=z3.If(z3.And(z3.UGE(low,1),z3.ULE(low,3)),resize(0xfffffe000c662700,64),resize(0xfffffe000c662904,64)))
 pointer,slide,upper=z3.BitVecs('KC_header64 KC_slide64 KC_upper64',64)
 for kind,index in [(1,0),(2,1),(3,3)]:
  v=fresh();before=[v.load(R.SLOT+8*j,8) for j in range(12)];v.seed('x8',kind-1);v.seed('x1',pointer);v.seed('x2',slide);cut(v,0xfffffe000c662700,0xfffffe000c662768);expected=list(before);expected[index]=pointer;expected[4+index]=slide;prove('kind'+str(kind)+'_publishes_header_and_slide_preserving_other_banks',v,z3.Or(*[v.load(R.SLOT+8*j,8)!=value for j,value in enumerate(expected)]))
  v=fresh();v.seed('x0',(upper&0xffffffff00000000)|kind);expected=v.load(R.SLOT+8*index,8);lr=v.read('x30');cut(v,R.GET,0xfffffe000c5e565c);prove('kind'+str(kind)+'_getter_uses_mapped_bank_and_returns',v,z3.Or(v.read('x0')!=expected,v.next!=lr,z3.BoolVal(bool(v.stores))))
 v=fresh();v.seed('x8',0);v.seed('x2',slide);cut(v,0xfffffe000c6627b8,0xfffffe000c6627e0);prove('empty_segment_minimum_publishes_slide_minus1',v,v.load(R.SLOT+64,8)!=slide-1)
 vm=z3.BitVec('KC_kernel_segment_VM64',64);v=fresh();v.regions.append((R.KHEADER+0x38,8));v.setmem(R.KHEADER+0x38,8,vm);v.seed('x8',R.KHEADER);cut(v,0xfffffe000c6605c8,0xfffffe000c6605e0);prove('boot_prefix_derives_slide_and_root_header_pointer',v,z3.Or(v.read('x19')!=R.KHEADER-vm,v.read('x20')!=R.HEADER+(R.KHEADER-vm)))
 return proofs,coverage
def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();im=Image();proofs,coverage=source_proofs(e);components=[];totals=Counter()
 for c in CPU.cases(e):
  setter_index=len(components);setter=CPU.Probe(im,e,c).run();setter['independent_oracle']=oracle(setter);setter['independent_replay']=Replay(im,setter).run();components.append(setter);totals.update(setter['independent_replay'])
  getter=CPU.Probe(im,e,c,'get',bytes.fromhex(setter['final_banks_hex'])).run();getter['setter_component_index']=setter_index;getter['independent_oracle']=oracle(getter);getter['independent_replay']=Replay(im,getter).run();assert getter['initial_banks_hex']==setter['final_banks_hex'];components.append(getter);totals.update(getter['independent_replay'])
 negative=[];c=CPU.cases(e)[2]
 for pc in [0xfffffe000c662744,0xfffffe000c6627dc]:
  row=CPU.Probe(im,e,c,mutate=pc).run()
  try:oracle(row)
  except AssertionError as error:reason=list(error.args[0])
  else:raise AssertionError(('mutated_source_accepted',hex(pc)))
  negative.append({'source_word_mutated_to_NOP':hex(pc),'configuration':c,'oracle_rejection':reason,'all_initial_fields_match':all(row[k]==components[4][k] for k in ['configuration','initial_registers31','initial_SP','initial_banks_hex']),'boundary':row['boundary']});print('rejected',hex(pc),flush=True)
 assert all(c['all_initial_fields_match'] for c in negative)
 vm=int.from_bytes(bytes.fromhex(e['kernel_first_segment_VM_address']['bytes_hex']),'little');slide=(R.KHEADER-vm)&((1<<64)-1);root=(R.HEADER+slide)&((1<<64)-1);assert slide==0 and root==R.HEADER
 stats={'components':len(components),'setter_cases':35,'getter_cases':35,'normal_returns':sum(c['boundary']['returned'] for c in components),'invalid_kind_boundaries':sum(not c['boundary']['returned'] for c in components),'source_visits':sum(len(c['source_visits']) for c in components),'source_queries_unsat':len(proofs),'proof_instruction_instances':sum(c['instructions'] for c in coverage),'proof_distinct_PCs':len({p for c in coverage for p in c['PCs']}),'semantic_checks':sum(len(c['independent_oracle']['checks']) for c in components),'producer_consumer_bank_links':35,'changed_source_controls':len(negative),'native_target_executions':0,'continuous_startup_visits_added':0}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_collection_header_publication.py'),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'scope':R.SCOPE,'source_proofs':proofs,'proof_coverage':coverage,'components':components,'negative_controls':negative,'pinned_boot_prefix_result':{'kernel_header_VM_address':hex(vm),'slide':hex(slide),'collection_header':hex(root),'full_boot_initializer_executed':False},'independent_totals':stats,'independent_replay_totals':dict(totals),'prior_continuous_startup_unchanged':True,'native_target_executed':False,'full_goal_complete':False}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
