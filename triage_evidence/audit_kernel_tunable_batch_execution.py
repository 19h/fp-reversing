#!/usr/bin/env python3
"""Finite original callback execution, independent contracts and fresh replay.
Linear construction in source/formula DAG/journals/RAM; timeline O(J log J).
SMT search separate, 30 s/query. No target execution or new return model.
"""
import json
from collections import Counter
from hashlib import sha256
import z3
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_kernel_startup_registry_abi import Model,source_proofs as prior_proofs,semantic_count as prior_count
from lskd_values_symbolic import resize
import recover_kernel_tunable_batch_execution as R
import probe_kernel_tunable_batch_execution as CPU
from replay_kernel_tunable_batch_execution import oracle,Replay,first_row,static_contracts,publication_row

def source_proofs(e):
 proofs=[];coverage=[]
 def local():v=Model(e);v.regions=[];return v
 def cut(v,a,b,linked=False):
  f=next(f for f in e['functions'] if int(f['start'],16)<=a<b<=int(f['end'],16));off=a-int(f['start'],16)
  v.e=v.c={'spans':[{'label':'cut','start':hex(a),'bytes_hex':bytes.fromhex(f['bytes'])[off:off+b-a].hex()}]};return v.run('cut') if linked else v.enter('cut')
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad));s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label)
  s.add(*v.bindings_for([*common,counter]),counter);result=s.check();assert result==z3.unsat,(label,str(result),s.reason_unknown())
  proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV'});coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,'linked_edge_obligations':len(v.edge_checks)});print(label,flush=True)
 descriptor=R.B.BASE;boot_slot=0xfffffe0007f8b6e8;parser=R.B.B.B.O.PARSE
 key,dst,boot,lr=z3.BitVecs('TB_key64 TB_destination64 TB_bootargs64 TB_LR64',64);size=z3.BitVec('TB_size32',32);flag=z3.BitVec('TB_string8',8)
 def option():
  v=local();v.regions=[(descriptor,24),(boot_slot,8)];v.setmem(descriptor,8,key);v.setmem(descriptor+8,8,dst);v.setmem(descriptor+16,4,size);v.setmem(descriptor+21,1,flag);v.setmem(boot_slot,8,boot);v.seed('x0',descriptor);v.seed('x30',lr);return v
 v=option();cut(v,R.OPTION+4,R.OPTION+28);prove('compact_descriptor_loads_and_string_bit_branch',v,z3.Or(v.read('x1')!=key,v.read('x2')!=dst,v.read('x3')!=z3.ZeroExt(32,size),v.next!=z3.If(flag&1==0,resize(0xfffffe000c630708,64),resize(0xfffffe000c6306fc,64))))
 v=option();cut(v,R.OPTION+4,0xfffffe000c630708);prove('string_tail_parser_capacity_flag_and_original_LR',v,z3.Or(v.next!=parser,v.read('x0')!=boot+0x6c,v.read('x1')!=key,v.read('x2')!=dst,v.read('x3')!=z3.ZeroExt(32,size),v.read('x4')!=1,v.read('x30')!=lr),[flag&1!=0])
 v=option();cut(v,R.OPTION+4,0xfffffe000c6306fc);cut(v,0xfffffe000c630708,0xfffffe000c630728,True);prove('numeric_parser_ABI_and_saved_descriptor',v,z3.Or(v.next!=parser,v.read('x0')!=boot+0x6c,v.read('x1')!=key,v.read('x2')!=dst,v.read('x3')!=z3.ZeroExt(32,size),v.read('x4')!=0,v.read('x19')!=descriptor,v.read('x30')!=0xfffffe000c630728),[flag&1==0])
 result=z3.BitVec('TB_parser_result32',32);v=local();v.seed('w0',result);cut(v,0xfffffe000c630728,0xfffffe000c63072c);prove('absent_numeric_option_skips_normalization',v,v.next!=z3.If(result==0,resize(0xfffffe000c630748,64),resize(0xfffffe000c63072c,64)))
 v=local();v.regions=[(descriptor,24)];v.setmem(descriptor+20,1,flag);v.seed('x19',descriptor);cut(v,0xfffffe000c63072c,0xfffffe000c630734);prove('normalization_is_guarded_by_descriptor_bit0',v,v.next!=z3.If(flag&1==0,resize(0xfffffe000c630748,64),resize(0xfffffe000c630734,64)))
 value=z3.BitVec('TB_boolean_byte8',8);v=local();v.regions=[(descriptor,24),(descriptor+64,1)];v.setmem(descriptor+8,8,descriptor+64);v.setmem(descriptor+64,1,value);v.seed('x19',descriptor);cut(v,0xfffffe000c630734,0xfffffe000c630748);prove('present_numeric_normalization_only_stores_canonical_low_byte',v,v.load(descriptor+64,1)!=z3.If(value!=0,resize(1,8),resize(0,8)))
 pointer=z3.BitVec('TB_pointer64',64);ordinal=z3.BitVec('TB_ordinal16',16);v=local();thread=descriptor+0x200;v.regions=[(descriptor,8),(thread,0x1ba)];v.setmem(descriptor,8,pointer);v.setmem(thread+0x1b8,2,ordinal);v.seed('x0',descriptor);v.seed('x8',pointer);v.seed('x9',thread);cut(v,0xfffffe000c62a024,0xfffffe000c62a030);prove('per_CPU_adjustment_uses_full_u16_ordinal_and_shift14_mod64',v,v.load(descriptor,8)!=pointer-(z3.ZeroExt(48,ordinal)<<14))
 selector=z3.BitVec('TB_SFI_selector32',32);v=local();v.seed('w8',selector);cut(v,0xfffffe000c62f2b8,0xfffffe000c62f2c0);prove('SFI_selector_bound_is_unsigned_less_than18',v,v.next!=z3.If(z3.UGE(selector,18),resize(0xfffffe000c62f31c,64),resize(0xfffffe000c62f2c0,64)))
 v=local();v.seed('w8',selector);cut(v,0xfffffe000c62f2c0,0xfffffe000c62f2e4);prove('SFI_bounded_slot_has_stride96_and_no_poison_selection',v,v.read('x9')!=0xfffffe000cadce28+z3.ZeroExt(32,selector)*96,[z3.ULT(selector,18)])
 previous=z3.BitVec('TB_SFI_previous_handler64',64);slot=0xfffffe000cadce28;v=local();v.regions=[(slot,96)];v.setmem(slot+0x48,8,previous);v.seed('x9',slot);cut(v,0xfffffe000c62f2e4,0xfffffe000c62f2ec);prove('SFI_nonnull_handler_selects_duplicate_diagnostic',v,v.next!=z3.If(previous!=0,resize(0xfffffe000c62f33c,64),resize(0xfffffe000c62f2ec,64)))
 handler,label1,label2=z3.BitVecs('TB_handler64 TB_label1_64 TB_label2_64',64);v=local();v.regions=[(descriptor,32),(slot,96)];v.setmem(descriptor+8,8,handler);v.setmem(descriptor+16,8,label1);v.setmem(descriptor+24,8,label2);v.seed('x0',descriptor);v.seed('x9',slot);cut(v,0xfffffe000c62f2ec,0xfffffe000c62f310);prove('SFI_registration_flags_and_three_pointer_fields',v,z3.Or(v.load(slot+0x24,4)!=0,v.load(slot+0x28,4)!=1,v.load(slot+0x48,8)!=handler,v.load(slot+0x50,8)!=label1,v.load(slot+0x58,8)!=label2))
 frequency=z3.BitVec('TB_frequency32',32);v=local();v.regions=[(R.B.RATIO,4),(0xfffffe000cb62e78,16)];v.setmem(R.B.RATIO,4,frequency);cut(v,R.TIMER+4,0xfffffe000c62f48c);prove('timer_words_are5000_and_unsigned_reciprocal_product_shift38',v,z3.Or(v.load(0xfffffe000cb62e78,4)!=5000,v.load(0xfffffe000cb62e80,8)!=z3.LShR(z3.ZeroExt(32,frequency)*0x51eb851f,38)))
 chosen=z3.BitVec('TB_chosen_value32',32);v=local();v.regions=[(descriptor,4),(0xfffffe0007ef8e68,2)];v.setmem(descriptor,4,chosen);v.setmem(v.sp0+0x10,8,descriptor);cut(v,0xfffffe000c63ae00,0xfffffe000c63ae24);prove('admitted_chosen_property_sets_present_and_zero_value_bytes',v,z3.Or(v.load(0xfffffe0007ef8e68,1)!=1,v.load(0xfffffe0007ef8e69,1)!=z3.If(chosen==0,resize(1,8),resize(0,8))))
 uuid=z3.BitVecs(' '.join('TB_UUID_byte'+str(j) for j in range(16)),8);v=local();v.regions=[(descriptor,16)];v.seed('x0',descriptor);v.seed('x1',dst)
 for j,value in enumerate(uuid):v.setmem(descriptor+j,1,value)
 cut(v,R.UUID,R.STOP+4);stack=v.sp0-0x90;prove('UUID_formatter_has16_zeroextended_stack_arguments_capacity37_and_exact_target',v,z3.Or(v.next!=R.FORMAT,v.read('x0')!=dst,v.read('x1')!=37,v.read('x2')!=0xfffffe00070d7f36,v.read('x30')!=R.STOP+4,*[v.load(stack+8*j,8)!=z3.ZeroExt(56,value) for j,value in enumerate(uuid)]))
 return proofs,coverage

def semantic_count(o):return len(o['checks'])+prior_count(o['first_callback_contracts'])+sum(len(o[k]['checks']) for k in ['tree_API_contracts','option_API_contracts','copy_contracts','string_contracts'])

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,coverage=source_proofs(e);retained,retained_coverage=prior_proofs(e);image=Image();static=static_contracts(e,image);components=[];totals=Counter()
 for c in CPU.cases():
  row=CPU.Probe(image,c).run();row['independent_oracle']=oracle(row,e);q=Replay(image,row).run();totals.update(q);row['independent_replay']=q;components.append(row);print(c['label'],len(row['source_visits']),flush=True)
 old=json.loads(read(ROOT/(R.B.P+'_audit.json')))['components'][0];new=first_row(components[0]);cut=components[0]['first_callback_boundary'];keys=['source_visits','source_reads','source_writes','API_models','original_API_entries','original_API_returns','final_private_RAM','final_image_globals','final_vectors','logical_effects']
 assert all(old[k]==new[k] for k in keys)
 assert all(old['boundary'][k]==new['boundary'][k] for k in ['pc','registers31','SP','NZCV']) and old['final_system']==cut['system']
 preservation={'prior_audit_sha256':sha(ROOT/(R.B.P+'_audit.json')),'prior_component':old['configuration']['label'],'compared_fields':keys+['boundary_pc','boundary_GPR31','boundary_SP','boundary_NZCV','all_logical_system_registers'],'exact_match':True,'new_storage_declared_before_main_entry':True,'extra_eager_replay_pages_checked_against_original_logical_image':True}
 controls=[]
 for case_index,pc in [(1,0xfffffe000c630744),(2,0xfffffe000c62a02c)]:
  row=CPU.Probe(image,CPU.cases()[case_index],pc).run();positive=components[case_index];initial_keys=['configuration','entry_PC','entry_SP','entry_NZCV','entry_registers31','initial_vectors','initial_system','initial_private_RAM','initial_private_fixtures','initial_image_fixtures','initial_image_pages'];assert all(row[k]==positive[k] for k in initial_keys)
  try:oracle(row,e)
  except AssertionError as error:rejection=error.args[0]
  else:raise AssertionError(('changed_source_accepted',hex(pc)))
  journal={k:row[k] for k in ['source_visits','source_reads','source_writes','final_image_globals']};digest=sha256(json.dumps(journal,sort_keys=True,separators=(',',':')).encode()).hexdigest()
  controls.append({'configuration':row['configuration'],'source_word_mutated_to_NOP':hex(pc),'original_bytes_hex':image.k.read(pc,4).hex(),'replacement_bytes_hex':'1f2003d5','same_positive_initial_fields':initial_keys,'all_initial_fields_match':True,'source_visits':len(row['source_visits']),'boundary':row['boundary'],'oracle_rejection':rejection,'journal_canonical_sha256':digest,'full_control_journal_retained':False,'control_journal_rebuilt_by_delivery_verifier':True});print('rejected_control',hex(pc),rejection,flush=True)
 visited={v['pc'] for c in components for v in c['source_visits']};source={i['ea'] for f in e['functions'] for i in f['instructions']};assert visited<=source and not visited&{i['ea'] for f in e['functions'] for i in f['instructions'] if i['mnemonic'] in ['opaque','udf']}
 assert not visited&set(e['SFI_handler_targets']+e['SFI_shared_targets']) and hex(R.FORMAT) not in visited and hex(R.B.INIT) not in visited
 stats={'source_queries_unsat':len(proofs),'retained_registry_queries_rebuilt':len(retained),'proved_source_PCs':len({pc for q in coverage for pc in q['PCs']}),'proof_instruction_instances':sum(q['instruction_instances'] for q in coverage),'linked_edge_obligations':sum(q['linked_edge_obligations'] for q in coverage),'components':len(components),'source_visits':sum(len(c['source_visits']) for c in components),'executed_source_PCs':len(visited),'changed_source_controls':len(controls),'independent_semantic_checks':sum(semantic_count(c['independent_oracle']) for c in components),'static_contracts':len(static['checks']),'original_API_entries':sum(len(c['original_API_entries']) for c in components),'original_API_returns':sum(len(c['original_API_returns']) for c in components),'original_registry_callbacks_returned':sum(len(c['callback_returns']) for c in components),'registry_callbacks_returned_per_case':368,'registry_callback_entries_per_case':369,'mutable_region_count_per_case':len(components[0]['final_image_globals']),'mutable_region_bytes_per_case':sum(len(bytes.fromhex(r['bytes_hex'])) for r in components[0]['final_image_globals']),'callback_output_and_final_global_bytes_compared':sum(c['independent_oracle']['mutable_bytes_compared'] for c in components),'private_nonstack_bytes_checked':sum(c['independent_oracle']['private_nonstack_bytes_checked'] for c in components),'call_frame_epochs':0,'new_callback_result_models':0,'native_target_executions':0}
 components=[publication_row(c,image) for c in components]
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_tunable_batch_execution.py'),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'scope':R.SCOPE,'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'source_proofs':proofs,'retained_source_proofs_rebuilt':retained,'proof_coverage':coverage,'retained_proof_coverage':retained_coverage,'independent_static_contracts':static,'components':components,'negative_controls':controls,'prior_published_checkpoint_preservation':preservation,'independent_totals':stats,'independent_replay_totals':dict(totals),'executed_function_coverage':[{'start':f['start'],'captured_words':len(f['instructions']),'executed_unique_PCs':len({i['ea'] for i in f['instructions']}&visited)} for f in e['functions']],'conditional_kernel_tunable_batch_execution_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True);print(json.dumps(a['independent_replay_totals']),flush=True)
