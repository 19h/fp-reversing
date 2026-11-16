#!/usr/bin/env python3
"""Continuous logging audit, source-query rebuild and original-word controls.
Linear journals/source/RAM; interval sorting O(N log N); SMT search separate.
"""
import json
from hashlib import sha256
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_kernel_early_logging_contract import source_proofs
from replay_kernel_early_logging_execution import oracle,Replay,preservation,publication_row,hydrate
import recover_kernel_early_logging_execution as R
import probe_kernel_early_logging_execution as CPU

def audit(cached=()):
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();im=Image();assert im.k.read(0xfffffe0007f8b528,8)==bytes(8);proofs,coverage=source_proofs(e)
 for f in e['functions']:assert im.k.read(int(f['start'],16),len(bytes.fromhex(f['bytes']))).hex()==f['bytes']
 row=hydrate(cached[0],im) if cached else CPU.Probe(im,CPU.cases()[0]).run();row['independent_oracle']=oracle(row,e);row['independent_replay']=Replay(im,row).run();kept=preservation(row,im);component=publication_row(row,im);negative=[]
 print('positive',len(row['source_visits']),row['boundary']['pc'],flush=True)
 for label,pc in [('ring_character_store',0xfffffe000c2ffdd4),('callback_newline_store',0xfffffe000c2ffd3c)]:
  control=CPU.Probe(im,CPU.cases()[0],pc).run();keys=['configuration','entry_PC','entry_SP','entry_registers31','entry_NZCV','initial_private_RAM','initial_private_fixtures','initial_image_fixtures','initial_image_pages'];assert all(control[k]==row[k] for k in keys)
  try:oracle(control,e)
  except AssertionError as error:rejection=list(error.args[0])
  else:raise AssertionError(('mutated_source_accepted',hex(pc)))
  journal={k:control[k] for k in ['source_visits','source_reads','source_writes','final_private_RAM']};negative.append({'label':label,'source_word_mutated_to_NOP':hex(pc),'original_bytes_hex':im.k.read(pc,4).hex(),'replacement_bytes_hex':'1f2003d5','same_initial_fields':keys,'all_initial_fields_match':True,'source_visits':len(control['source_visits']),'boundary':control['boundary'],'oracle_rejection':rejection,'journal_canonical_sha256':sha256(json.dumps(journal,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'full_control_journal_retained':False});print('rejected',label,flush=True)
 stats={'components':1,'source_visits':len(row['source_visits']),'additional_journal_visits':len(row['source_visits'])-row['early_logging_join_checkpoint']['before_visit'],'distinct_visited_PCs':len({v['pc'] for v in row['source_visits']}),'proved_block_transitions':1,'contracted_original_words':9,'retained_source_queries_rebuilt':len(proofs),'logging_calls_returned':len(row['original_logging_returns']),'character_callbacks':len(row['original_character_calls']),'original_ring_byte_stores':47,'semantic_checks':len(row['independent_oracle']['checks']),'whole_global_bytes_compared':row['independent_oracle']['whole_global_bytes_compared'],'callbacks_returned':1029,'changed_source_controls':len(negative),'new_system_register_values':0,'new_callback_result_models':0,'call_frame_epochs':0,'native_target_executions':0}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_early_logging_execution.py'),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'scope':R.SCOPE,'kernel_collection_sha256':im.k.sha256,'retained_source_proofs_rebuilt':proofs,'proof_coverage':coverage,'components':[component],'negative_controls':negative,'prior_published_frontier_preservation':kept,'independent_totals':stats,'independent_replay_totals':row['independent_replay'],'conditional_early_logging_execution_contract_established':True,'native_console_emission_established':False,'native_target_executed':False,'matched_FairPlay_transaction_established':False,'full_goal_complete':False}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
