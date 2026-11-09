#!/usr/bin/env python3
"""Fresh A64 replay, rebuilt original-source predicates and SDK contracts.
API output writes are separate declared effects at their actual call epoch.
O(profile visits + artifact bytes + solver/compiler resources) time;
O(one CPU map + journals + BV DAGs) space. No native target/framework/IPC.
"""
import json
from collections import Counter
import z3
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from validate_daemon_record40_consumer import Fresh as Parent
from recover_daemon_entitlement_result import recover
from prove_daemon_entitlement_result import obligations
class Fresh(Parent):
 def code(self,u,a,n,d):
  model=self.models.get(self.seq)
  if model and model.get('memory_models'):
   self.finish()
   for e in model['memory_models']:
    at=int(e['address'],16);nbytes=e['size_bytes'];assert bytes(u.mem_read(at,nbytes)).hex()==e['before_hex'];assert len(bytes.fromhex(e['after_hex']))==nbytes;u.mem_write(at,bytes.fromhex(e['after_hex']));self.counts['declared_API_output_words_checked']+=1
  return super().code(u,a,n,d)
def main():
 p=json.loads((ROOT/'daemon_entitlement_result_profiles.json').read_text());c=json.loads((ROOT/'daemon_entitlement_result_contracts.json').read_text());proof=json.loads((ROOT/'daemon_entitlement_result_proofs.json').read_text());assert p['generator_sha256']==sha(ROOT/'probe_daemon_entitlement_result.py')and recover()==c;qs,counts=obligations();assert counts==proof['source_lift_counts']and len(qs)==len(proof['proofs']);files=0
 for (name,q),row in zip(qs,proof['proofs'],strict=True):
  assert name==row['name'];s=z3.Solver();s.set(timeout=30000);s.add(q);assert s.check()==z3.unsat
  for f,h in [('file','sha256'),('original_file','original_sha256')]:
   assert sha(ROOT/row[f])==row[h];s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_file(str(ROOT/row[f])));assert s.check()==z3.unsat;files+=1
 expected={'null_no_error':('00','5b',[('0x100376a04','0x680000a000'),('0x1003ecb40','0x6800009000')]),'null_with_error':('00','5b',[('0x1004be234','0x680000d000'),('0x100376a04','0x680000a000'),('0x1003ecb40','0x6800009000')]),'value_with_error':('00','5b',[('0x100496084','0x680000b000'),('0x1004be234','0x680000d000'),('0x100376a04','0x680000a000'),('0x1003ecb40','0x6800009000')]),'value_wrong_type':('00','5b',[('0x100496084','0x680000b000'),('0x100376a04','0x680000a000'),('0x1003ecb40','0x6800009000')]),'boolean_false':('00','5c',[('0x100496084','0x680000b000'),('0x100376a04','0x680000a000'),('0x1003ecb40','0x6800009000')]),'boolean_true':('01','5c',[('0x100496084','0x680000b000'),('0x100376a04','0x680000a000'),('0x1003ecb40','0x6800009000')])}
 rows=[];totals=Counter();modes=Counter();returns=0;typepairs=0
 for j,(profile,ledger)in enumerate(zip(p['cases'],c['profile_ledgers'],strict=True)):
  mode=profile['configuration']['query_result_model'];modes[mode]+=1;assert profile['fixture_PC_transitions']==0
  for r in profile['source_reads']:
   if 'known_mask_hex'in r:assert all(bytes.fromhex(r['known_mask_hex']))
  replay=Fresh(profile,(j+1)%4);row=replay.run();assert row['all_checks_pass'];rows.append(row);totals.update(row['verified_counts']);R=int(profile['record_address'],16)
  if mode=='value_untyped':
   assert profile['boundary']['pc']=='0x10030acb0'and profile['boundary']['detail']['symbol']=='CoreFoundation/_CFBooleanGetTypeID'and ledger['final_marker_hex']is None and not ledger['cleanup_requests']
  else:
   flag,marker,cleanup=expected[mode];assert profile['boundary']['kind']=='returned_to_original_caller'and bytes(replay.u.mem_read(R+8,1)).hex()==marker and bytes(replay.u.mem_read(0x6800051f2f,1)).hex()==flag;assert (ledger['final_flag_hex'],ledger['final_marker_hex'])==(flag,marker);assert [(e['pc'],e['object'])for e in ledger['cleanup_requests']]==cleanup;assert ledger['caller_predicate_if_evaluated']==(mode!='boolean_true');returns+=1
  if mode in ['value_wrong_type','boolean_false','boolean_true']:
   models=profile['API_model_events'];A=next(int(e['return_value'],16)for e in models if e['symbol']=='CoreFoundation/_CFBooleanGetTypeID');B=next(int(e['return_value'],16)for e in models if e['symbol']=='CoreFoundation/_CFGetTypeID');assert (A==B)==(mode!='value_wrong_type');assert (A&0xffffffff)==(B&0xffffffff);typepairs+=1
  print(mode,profile['source_index'],'fresh A64 pass',flush=True)
 assert len(rows)==28 and all(n==4 for n in modes.values())and len(modes)==7 and returns==24 and typepairs==12 and totals['declared_API_output_words_checked']==28
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_entitlement_result_profiles.json','daemon_entitlement_result_contracts.json','daemon_entitlement_result_proofs.json','probe_daemon_entitlement_result.py','recover_daemon_entitlement_result.py','prove_daemon_entitlement_result.py','daemon_entitlement_result_sdk.c','daemon_entitlement_result_sdk.ll','validate_daemon_record40_consumer.py','replay_daemon_descriptor_producers.py']},'verified_counts':{'source_obligations_rebuilt':len(qs),'accepted_SMT_files':files,'profile_cases':len(rows),'profile_scenarios':len(modes),'original_caller_returns':returns,'unmodeled_type_API_frontiers':4,'64bit_type_model_pairs':typepairs,'unique_visited_source_instructions':len(c['unique_visited_source']),'SDK_compile_exit':0},'independent_A64_totals':dict(totals),'fresh_replay_cases':rows,'scenario_counts':dict(modes),'native_framework_calls_executed':False,'native_entitlement_value_observed':False,'native_authorization_outcome_established':False,'hardware_PAC_executed':False,'idb_mutated':False,'new_port_emission_established':False,'full_goal_complete':False,'all_checks_pass':True};(ROOT/'daemon_entitlement_result_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':out['verified_counts'],'A64_totals':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
