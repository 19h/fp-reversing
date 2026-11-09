#!/usr/bin/env python3
"""Independent fresh A64 replay of the caller continuation and bounded
second-query stages; rebuild source/SDK/contracts and both forms of each
local proof. API output effects preserve prior definedness masks and epochs.
O(profile visits + source/artifact bytes + solver/compiler resources) time;
O(one CPU map + journals + DAGs) space. No native target/framework/IPC.
"""
import json
from collections import Counter
import z3
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from validate_daemon_record40_consumer import Fresh as Parent
from recover_daemon_entitlement_flow import recover,snapshot,FILES
from prove_daemon_entitlement_flow import obligations
class Fresh(Parent):
 def code(self,u,a,n,d):
  model=self.models.get(self.seq)
  if model and model.get('memory_models'):
   self.finish()
   for e in model['memory_models']:
    at=int(e['address'],16);size=e['size_bytes'];prior=bytes(u.mem_read(at,size));before=bytes.fromhex(e['before_hex']);mask=bytes.fromhex(e.get('before_known_mask_hex','01'*size));assert len(prior)==len(before)==len(mask)==size and all(not k or x==y for x,y,k in zip(prior,before,mask));after=bytes.fromhex(e['after_hex']);assert len(after)==size;u.mem_write(at,after);self.counts['declared_API_output_effects_checked']+=1;self.counts['declared_API_prior_undefined_bytes']+=sum(k==0 for k in mask)
  return super().code(u,a,n,d)
def main():
 c=json.loads((ROOT/'daemon_entitlement_flow_contracts.json').read_text());proof=json.loads((ROOT/'daemon_entitlement_flow_proofs.json').read_text());assert recover()==c;qs,counts=obligations();assert counts==proof['source_lift_counts']and len(qs)==len(proof['proofs']);files=0
 for (name,q),row in zip(qs,proof['proofs'],strict=True):
  assert name==row['name'];s=z3.Solver();s.set(timeout=30000);s.add(q);assert s.check()==z3.unsat,(name,s.reason_unknown())
  for f,h in [('file','sha256'),('original_file','original_sha256')]:
   assert sha(ROOT/row[f])==row[h];s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_file(str(ROOT/row[f])));assert s.check()==z3.unsat,(name,f,s.reason_unknown());files+=1
 groups={n:json.loads((ROOT/n).read_text())for n in FILES};old=json.loads((ROOT/'daemon_entitlement_result_profiles.json').read_text());previous={(c['configuration']['query_result_model'],c['source_index']):c for c in old['cases']};scriptnames=['probe_daemon_entitlement_flow.py','probe_daemon_entitlement_audit.py','probe_daemon_secondary_identity.py'];rows=[];totals=Counter();group_counts=Counter();state_writers=0;prefixes=0;audits=0;string_frontiers=task_frontiers=query_frontiers=null_markers=0;token_instances=0;PID_reads=0
 for name,script in zip(FILES,scriptnames,strict=True):
  p=groups[name];assert p['generator_sha256']==sha(ROOT/script)
  for dep,h in p['dependencies'].items():assert sha(ROOT/dep)==h,(name,dep)
  for j,profile in enumerate(p['cases']):
   mode=profile['configuration']['query_result_model'];env=profile['source_index'];prior=previous[(mode,env)];cut=len(prior['source_visits']);assert profile['source_visits'][:cut]==prior['source_visits'];assert [e for e in profile['source_reads']if e['source_visit_index']<cut]==prior['source_reads'];assert [e for e in profile['source_writes']if e['source_visit_index']<cut]==prior['source_writes'];assert profile['API_model_events'][:len(prior['API_model_events'])]==prior['API_model_events'];prefixes+=1;assert profile['fixture_PC_transitions']==0
   for e in profile['source_reads']:
    if 'known_mask_hex'in e:assert all(bytes.fromhex(e['known_mask_hex']))
    if e['address']=='0x6800054f8c':PID_reads+=1
   r=Fresh(profile,(j+1)%4);row=r.run();assert row['all_checks_pass'];rows.append({'group':name,**row});totals.update(row['verified_counts']);group_counts[name]+=1
   if mode=='value_untyped':assert profile['continuation_entry']is None and profile['boundary']['pc']=='0x10030acb0';continue
   assert profile['continuation_entry']['source_visit_index']==cut;branch=next(e for e in profile['logical_edges']if e['pc']=='0x1004c467c');assert branch['target']==('0x1004b3e6c'if mode=='boolean_true'else'0x1004b4f2c')
   state=[e for e in profile['source_writes']if e['pc']=='0x1004b3ea0'];assert len(state)==int(mode=='boolean_true')
   if state:
    assert state[0]['address']=='0x6800055d0c'and state[0]['after_hex']=='02000000';join=next(e for e in profile['logical_edges']if e['pc']=='0x1004b3eb0');assert join['target']=='0x1004b4f2c'and join['modifier']=='0xeb1c';state_writers+=1
   original=next(e['original_token']['bytes_hex']for e in profile['API_model_events']if 'original_token'in e);token=snapshot(profile,0x680005b2f0,32);assert token['known_mask_hex']=='01'*32 and token['defined_bytes_hex']==original;token_instances+=1
   if name==FILES[0]:
    assert profile['boundary']['pc']=='0x1004b503c'and profile['boundary']['detail']['symbol']=='libbsm/_audit_token_to_au32';assert r.reg('x0')==0x680005b2f0 and r.reg('x6')==0x6800054f8c and bytes(r.u.mem_read(r.reg('SP'),8))==bytes(8);assert all(r.reg('x'+str(k))==0 for k in [1,2,3,4,5,7])
   else:
    audit=next(e for e in profile['API_model_events']if e['symbol']=='libbsm/_audit_token_to_au32');effect=audit['memory_models'][0];assert effect['before_known_mask_hex']=='00'*4 and int.from_bytes(bytes.fromhex(effect['after_hex']),'little')==int(profile['configuration']['PID_output_model_word'],16);audits+=1
    assert snapshot(profile,0x680005f56e,16)['defined_bytes_hex']==b'fairplay-client\0'.hex();call=next(e for e in profile['source_calls']if e['pc']=='0x1004b52b4');record=snapshot(profile,0x680005fee8,40,call['source_visit_index']);data=bytes.fromhex(record['defined_bytes_hex']);assert int.from_bytes(data[:8],'little')==0x680005b310 and int.from_bytes(data[8:12],'little')^(((0x5fee8^0x7a9247f6)*0x31b6b333)&0xffffffff)==0xab91 and int.from_bytes(data[16:24],'little')==0x68000504b0 and int.from_bytes(data[32:40],'little')==0x680005f56e
    assert snapshot(profile,0x680005b310,32)['defined_bytes_hex']==original;token_instances+=1
    if name==FILES[1]:assert profile['boundary']['pc']=='0x1000141c4'and profile['boundary']['detail']['symbol']=='CoreFoundation/_CFStringCreateWithCStringNoCopy'and r.reg('x1')==0x680005f56e and r.reg('w2')==0x600;string_frontiers+=1
    else:
     sub=profile['configuration']['secondary_string_model']
     if sub=='null':
      marker=next(e for e in profile['source_writes']if e['pc']=='0x100067240');assert marker['address']=='0x680005ff00'and marker['after_hex']=='31';assert profile['boundary']['pc']=='0x100570148'and profile['boundary']['detail']['symbol']=='libSystem/_malloc'and r.reg('x0')==32;null_markers+=1
     else:
      dst=snapshot(profile,0x680004f168,32);assert dst['known_mask_hex']=='01'*32 and dst['defined_bytes_hex']==original;token_instances+=1
      if sub=='nonnull':assert profile['boundary']['pc']=='0x1000622e8'and profile['boundary']['detail']['symbol']=='Security/_SecTaskCreateWithAuditToken'and r.reg('x1')==0x680004f168;task_frontiers+=1
      else:
       assert sub=='nonnull_task'and profile['boundary']['pc']=='0x1002382e8'and profile['boundary']['detail']['symbol']=='Security/_SecTaskCopyValueForEntitlement';assert r.reg('x0')==0x6800012000 and r.reg('x1')==0x6800011000 and r.reg('x2')==0x680004f188 and bytes(r.u.mem_read(r.reg('x2'),8))==bytes(8);query_frontiers+=1
   print(name,mode,env,profile['configuration'].get('secondary_string_model'),'fresh A64 pass',flush=True)
 assert group_counts==Counter({FILES[0]:28,FILES[1]:12,FILES[2]:12})and len(rows)==52 and prefixes==52 and state_writers==20 and audits==24 and string_frontiers==12 and task_frontiers==4 and query_frontiers==4 and null_markers==4 and PID_reads==0
 deps=FILES+['daemon_entitlement_result_profiles.json','daemon_entitlement_flow_contracts.json','daemon_entitlement_flow_proofs.json','probe_daemon_entitlement_flow.py','probe_daemon_entitlement_audit.py','probe_daemon_secondary_identity.py','recover_daemon_entitlement_flow.py','prove_daemon_entitlement_flow.py','validate_daemon_record40_consumer.py','replay_daemon_descriptor_producers.py','daemon_entitlement_flow_sdk.c','daemon_entitlement_flow_sdk.s'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':{'source_obligations_rebuilt':len(qs),'accepted_SMT_files':files,'profile_cases':len(rows),'profile_groups':3,'prior_source_prefixes_preserved':prefixes,'conditional_state_bit_writers':state_writers,'declared_PID_output_effects':audits,'second_string_frontiers':string_frontiers,'second_task_frontiers':task_frontiers,'second_entitlement_query_frontiers':query_frontiers,'second_NULL_marker_to_malloc_frontiers':null_markers,'token_copy_argument_instances':token_instances,'PID_output_source_reads_before_boundaries':PID_reads,'bank_byte_inputs':768,'unique_visited_source_instructions':len(c['unique_visited_source']),'SDK_compile_exit':0},'independent_A64_totals':dict(totals),'fresh_replay_cases':rows,'native_framework_calls_executed':False,'native_entitlement_value_observed':False,'native_authorization_outcome_established':False,'hardware_PAC_executed':False,'idb_mutated':False,'new_port_emission_established':False,'full_goal_complete':False,'all_checks_pass':True};(ROOT/'daemon_entitlement_flow_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':out['verified_counts'],'A64_totals':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
