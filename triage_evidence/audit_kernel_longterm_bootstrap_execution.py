#!/usr/bin/env python3
"""Finite post-lock timer execution, source queries and integer bounds.
Linear source/journal/RAM work; interval sorting and SMT search separate.
"""
import json
from collections import Counter
from hashlib import sha256
import z3
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from lskd_values_symbolic import resize
from audit_kernel_timeout_execution import Model
import recover_kernel_longterm_bootstrap_execution as R
import probe_kernel_longterm_bootstrap_execution as CPU
from replay_kernel_longterm_bootstrap_execution import oracle,Replay,prefix,B

def reciprocal_bounds():
 out=[]
 for label,D,s,C,nmax,preshift in [('u32_seconds',1000000000,64,0x44b82fa0a,(1<<32)-1,0),('u64_seconds',1953125,75,0x44b82fa09b5a53,(1<<55)-1,9),('frequency_scale',3125,39,0xa7c5ac5,(1<<27)-1,5),('display_milliseconds',1000000,82,0x431bde82d7b634db,(1<<64)-1,0)]:
  E=C*D-(1<<s);assert 0<=E<D and nmax*E<(1<<s)
  out.append({'label':label,'divisor_after_preshift':D,'preshift_bits':preshift,'multiplier':C,'right_shift_bits':s,'maximum_shifted_input':nmax,'multiplier_excess':E,'maximum_error_numerator':nmax*E,'strict_error_bound':1<<s,'exact_unsigned_quotient':True})
 return {'lemma':'For n=q*D+r, 0<=r<D, C*D=2^s+E and 0<=n*E<2^s imply floor(n*C/2^s)=q. Divisors before pre-shift are exactly divisible by 2^preshift.','bounds':out}

def source_proofs(e):
 proofs=[];coverage=[]
 def cut(v,a,b,linked=False):
  f=next(f for f in e['functions'] if int(f['start'],16)<=a<b<=int(f['end'],16));off=a-int(f['start'],16);v.e=v.c={'spans':[{'label':'cut','start':hex(a),'bytes_hex':bytes.fromhex(f['bytes'])[off:off+b-a].hex()}]};return v.run('cut') if linked else v.enter('cut')
 def new():v=Model(e);v.regions=[];return v
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad));s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label);s.add(*v.bindings_for([*common,counter]),counter);assert s.check()==z3.unsat,(label,s.reason_unknown());proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV'});coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,'linked_edge_obligations':len(v.edge_checks)})
 value=z3.BitVec('LT_value32',32);wide=z3.BitVec('LT_wide64',64);freq=z3.BitVec('LT_frequency32',32)
 v=new();v.regions=[(0xfffffe000ca92100,8)];v.setmem(v.sp0+12,4,value);v.seed('sp',v.sp0);v.seed('x19',0xfffffe000ca92000);cut(v,0xfffffe000bd64ef8,0xfffffe000bd64f14);prove('present_option_zero_disables_otherwise_scales_u32_by1000000',v,v.load(0xfffffe000ca92100,8)!=z3.If(value==0,resize((1<<64)-1,64),z3.ZeroExt(32,value)*1000000))
 v=new();v.seed('x8',wide);cut(v,0xfffffe000bd64f44,0xfffffe000bd64f5c);product=z3.ZeroExt(64,wide)*0x431bde82d7b634db;prove('display_reciprocal_machine_expression',v,v.read('x8')!=z3.Extract(63,0,z3.LShR(product,82)))
 v=new();v.seed('w10',freq);cut(v,0xfffffe000bd6504c,0xfffffe000bd6505c);prove('frequency_scale_product',v,v.read('x9')!=z3.ZeroExt(32,z3.LShR(freq,5))*0xa7c5ac5)
 v=new();v.seed('x9',wide);cut(v,0xfffffe000bd650ac,0xfffffe000bd650b0);prove('frequency_scale_final_shift39',v,v.read('x9')!=z3.LShR(wide,39))
 daif=z3.BitVec('LT_join_DAIF64',64);phase=z3.BitVec('LT_join_phase32',32);v=new();v.regions=[(0xfffffe0007f8b5f0,4)];v.seed('x8',daif);v.setmem(0xfffffe0007f8b5f0,4,phase);cut(v,0xfffffe000c48faf8,0xfffffe000c48fb08);cut(v,0xfffffe000c48f920,0xfffffe000c48f934,True);prove('early_phase_logging_join_is_independent_of_every_DAIF_value',v,z3.Or(v.read('w24')!=1,v.read('x8')!=0xfffffe0007f34000,v.read('w9')!=phase),[z3.ULT(phase,19)])
 return proofs,coverage

def preservation(row,im):
 old=B.B.B.hydrate(json.loads(read(ROOT/(R.B.P+'_audit.json')))['components'][0],im);new=prefix(B.B.B.hydrate(row,im));keys=['source_visits','source_reads','source_writes','API_models','logical_effects','original_call_entries','original_API_entries','original_API_returns','callback_entries','callback_returns','final_private_RAM','final_image_globals','final_vectors','final_system'];assert all(old[k]==new[k] for k in keys),[k for k in keys if old[k]!=new[k]]
 assert all(old['boundary'][k]==new['boundary'][k] for k in ['pc','registers31','SP','NZCV']);wanted=old['final_page_sha256'];actual=new['final_page_sha256'];assert wanted.keys()<=actual.keys() and all(actual[p]==h for p,h in wanted.items())
 for p in actual.keys()-wanted.keys():assert actual[p]==sha256(im.logical_page(int(p,16))).hexdigest()
 return {'prior_audit_sha256':sha(ROOT/(R.B.P+'_audit.json')),'compared_fields':keys+['boundary_pc','boundary_GPR31','boundary_SP','boundary_NZCV'],'exact_match':True,'known_original_page_hashes_exact_match':True,'additional_original_page_bytes':4096*len(actual.keys()-wanted.keys()),'call_frame_epochs':0,'new_callback_result_models':0}

def audit(cached=()):
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();im=Image();proofs,coverage=source_proofs(e);bounds=reciprocal_bounds();static=[]
 for f in e['functions']:assert im.k.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes'];static.append('body_'+f['start'])
 for r in e['records']+e['strings']:assert im.k.read(int(r['address'],16),len(bytes.fromhex(r['bytes_hex']))).hex()==r['bytes_hex'];static.append('record_'+r['address'])
 old=json.loads(read(ROOT/(R.B.P+'_checks.json')));assert e['functions'][:len(old['functions'])]==old['functions'];assert im.pointer(0xfffffe000caab078)==e['log_counter_bank_pointer'];components=[];totals=Counter()
 for index,c in enumerate(CPU.cases()):
  if index<len(cached):
   row=B.B.B.hydrate(cached[index],im);assert all(row['configuration'][k]==c[k] for k in ['label','boot_text','CPUs'])
  else:row=CPU.Probe(im,c).run()
  row['independent_oracle']=oracle(row,e);row['independent_replay']=Replay(im,row).run();totals.update(row['independent_replay']);components.append(B.B.B.publication_row(row,im));(ROOT/(R.P+'_audit.json')).write_text(json.dumps({'components':components,'partial_producer_checkpoint':True},indent=2)+'\n');print('main',c['label'],row['boundary']['pc'],len(row['source_visits']),flush=True)
 kept=preservation(components[0],im);negative=[]
 for label,pc in [('callback_publication',0xfffffe000bd65030),('frequency_scale_publication',0xfffffe000bd650bc)]:
  row=CPU.Probe(im,CPU.cases()[0],pc).run();positive=B.B.B.hydrate(components[0],im);keys=['configuration','entry_PC','entry_SP','entry_registers31','entry_NZCV','initial_private_RAM','initial_private_fixtures','initial_image_fixtures','initial_image_pages'];assert all(row[k]==positive[k] for k in keys)
  try:oracle(row,e)
  except AssertionError as error:rejection=list(error.args[0])
  else:raise AssertionError(('changed_source_accepted',hex(pc)))
  journal={k:row[k] for k in ['source_visits','source_reads','source_writes','final_private_RAM']};negative.append({'label':label,'source_word_mutated_to_NOP':hex(pc),'original_bytes_hex':im.k.read(pc,4).hex(),'replacement_bytes_hex':'1f2003d5','all_initial_fields_match':True,'same_positive_initial_fields':keys,'source_visits':len(row['source_visits']),'boundary':row['boundary'],'oracle_rejection':rejection,'journal_canonical_sha256':sha256(json.dumps(journal,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'full_control_journal_retained':False});print('control_rejected',label,flush=True)
 visited={v['pc'] for c in components for v in c['source_visits']};assert visited<={i['ea'] for f in e['functions'] for i in f['instructions']} and not visited&{i['ea'] for f in e['functions'] for i in f['instructions'] if i['mnemonic'] in ['opaque','udf']};assert hex(R.CPU) not in visited
 stats={'components':len(components),'completed_timer_initializers':sum(c['longterm_initializer_returned'] for c in components),'logging_system_register_frontiers':sum(c['logging_system_register_frontier'] is not None for c in components),'source_queries_unsat':len(proofs),'integer_reciprocal_bounds':len(bounds['bounds']),'proved_source_PCs':len({p for c in coverage for p in c['PCs']}),'proof_instruction_instances':sum(c['instruction_instances'] for c in coverage),'linked_edge_obligations':sum(c['linked_edge_obligations'] for c in coverage),'source_visits':sum(len(c['source_visits']) for c in components),'executed_source_PCs':len(visited),'static_checks':len(static),'callbacks_returned_per_case':1029,'changed_source_controls':len(negative),'timer_semantic_checks':sum(len(c['independent_oracle']['checks']) for c in components),'timer_bytes_compared':sum(c['independent_oracle']['mutable_bytes_compared'] for c in components),'call_frame_epochs':0,'new_callback_result_models':0,'new_system_register_values':0,'native_target_executions':0}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_longterm_bootstrap_execution.py'),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'scope':R.SCOPE,'kernel_collection_sha256':im.k.sha256,'source_proofs':proofs,'proof_coverage':coverage,'integer_reciprocal_bounds':bounds,'static_checks':static,'components':components,'negative_controls':negative,'prior_published_checkpoint_preservation':kept,'independent_totals':stats,'independent_replay_totals':dict(totals),'conditional_kernel_longterm_bootstrap_execution_contract_established':True,'native_target_executed':False,'hardware_PAC_executed':False,'matched_FairPlay_transaction_established':False,'full_goal_complete':False}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
