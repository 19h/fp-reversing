#!/usr/bin/env python3
"""Fresh A64 source replay, predecessor-prefix preservation, exact key/object
epochs, mixed state-mask attribution and bridge status checks. Rebuild SDK,
contracts and both SMT forms. O(profile/source/artifact bytes + solver/compiler
resources) time, O(one CPU map + journals + BV DAGs) space. No native APIs.
"""
import json
from collections import Counter
import z3
from daemon_receive_tools import ROOT,IMAGE
from daemon_output_base_dispatch import CS
from capture_daemon_record720 import sha
from recover_daemon_boolean_chain import recover,FILES
from prove_daemon_boolean_chain import obligations
from validate_daemon_entitlement_flow import Fresh
from recover_daemon_entitlement_flow import snapshot
def main():
 c=json.loads((ROOT/'daemon_boolean_chain_contracts.json').read_text());proof=json.loads((ROOT/'daemon_boolean_chain_proofs.json').read_text());assert recover()==c;qs,counts=obligations();assert counts==proof['source_lift_counts']and len(qs)==len(proof['proofs']);files=0
 for (name,q),row in zip(qs,proof['proofs'],strict=True):
  assert name==row['name'];s=z3.Solver();s.set(timeout=30000);s.add(q);assert s.check()==z3.unsat
  for f,h in [('file','sha256'),('original_file','original_sha256')]:
   assert sha(ROOT/row[f])==row[h];s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_file(str(ROOT/row[f])));assert s.check()==z3.unsat;files+=1
 # The selector fragments are separated by bank code which preserves these inputs.
 for a,z,keep in [(0x100458888,0x1004588c0,{'w10','x10','w11','x11','w26','x26'}),(0x1004588d0,0x1004588e0,{'w10','x10','w11','x11'})]:
  for ins in CS.disasm(IMAGE.read(a,z-a),a):assert not({ins.reg_name(r)for r in ins.regs_access()[1]}&keep),(hex(ins.address),ins.mnemonic,ins.op_str)
 groups={n:json.loads((ROOT/n).read_text())for n in FILES};prior=json.loads((ROOT/'daemon_secondary_result_type_profiles.json').read_text());parents={(e['configuration']['query_result_model'],e['source_index']):e for e in prior['cases']if e['configuration']['secondary_type_model']=='number_success'};rows=[];totals=Counter();modes=Counter();keys=Counter();adapters=returned=open_queries=audits=releases=0;marker_counts=Counter();final_states=Counter();prefixes=0;statuses=0
 for group,script in zip(FILES,['probe_daemon_boolean_chain.py','probe_daemon_boolean_mixed.py'],strict=True):
  p=groups[group];assert p['generator_sha256']==sha(ROOT/script)
  for n,h in p['dependencies'].items():assert sha(ROOT/n)==h
  for j,profile in enumerate(p['cases']):
   mode=profile['configuration']['Boolean_chain_model'];first=profile['configuration']['query_result_model'];env=profile['source_index'];modes[mode]+=1;old=parents[(first,env)];cut=len(old['source_visits']);assert profile['source_visits'][:cut]==old['source_visits'];assert [e for e in profile['source_reads']if e['source_visit_index']<cut]==old['source_reads'];assert [e for e in profile['source_writes']if e['source_visit_index']<cut]==old['source_writes'];assert profile['API_model_events'][:len(old['API_model_events'])]==old['API_model_events'];prefixes+=1;assert profile['fixture_PC_transitions']==0
   for e in profile['source_reads']:
    if 'known_mask_hex'in e:assert all(bytes.fromhex(e['known_mask_hex']))
   r=Fresh(profile,(j+1)%4);row=r.run();assert row['all_checks_pass'];rows.append({'group':group,**row});totals.update(row['verified_counts']);entries=profile['Boolean_adapters'];assert len(entries)==(1 if mode=='query_frontier'else 2);prior_objects=set()
   for index,entry in enumerate(entries):
    adapters+=1;name=['FairPlay-CoreML-Client','FairPlay-Classic-Client'][index];assert entry['index']==index and entry['key']==c['keys'][name];keys[name]+=1;assert entry['record_address']=='0x680004f1a0'and entry['SP']=='0x680004f150';models=[profile['API_model_events'][i]for i in entry['API_event_indices']];base=0x6800020000+index*0x1000
    for e in models:
     assert e['Boolean_adapter_index']==index
     if e['symbol']=='Security/_SecTaskCreateWithAuditToken':assert e['audit_argument']['bytes_hex']==e['original_token']['bytes_hex']and e['audit_argument']['known_mask_hex']=='01'*32;audits+=1
     if e['symbol']=='CoreFoundation/_CFRelease':assert int(e['arguments8'][0],16)!=0;releases+=1
    ctor=next(e for e in models if e['symbol']=='CoreFoundation/_CFStringCreateWithCStringNoCopy');assert ctor['arguments8'][1]==entry['key']['address']and ctor['arguments8'][2]=='0x600';objects={int(e['return_value'],16)for e in models if e['symbol']in ['CoreFoundation/_CFStringCreateWithCStringNoCopy','Security/_SecTaskCreateWithAuditToken','Security/_SecTaskCopyValueForEntitlement']and int(e['return_value'],16)!=0};assert not(objects&prior_objects);prior_objects|=objects;assert objects<={base+0x100,base+0x200,base+0x300}
    if mode=='query_frontier':
     assert'return_source_visit_index'not in entry and profile['boundary']['pc']=='0x1002b7728'and profile['boundary']['detail']['symbol']=='Security/_SecTaskCopyValueForEntitlement';assert r.reg('x0')==base+0x200 and r.reg('x1')==base+0x100 and r.reg('x2')==0x680004f0e0;assert bytes(r.u.mem_read(r.reg('x2'),8))==bytes(8);open_queries+=1
    else:
     expected_marker='5b'if mode in ['string_null','task_null','query_null']else'5c';take=mode=='boolean_true'or(mode=='coreml_only'and index==0)or(mode=='classic_only'and index==1);assert entry['marker']['bytes_hex']==expected_marker and entry['marker']['known_mask_hex']=='01'and entry['flag']['bytes_hex']==('01'if take else'00')and entry['flag']['known_mask_hex']=='01';marker_counts[expected_marker]+=1;returned+=1
   if mode!='query_frontier':
    expected=(0xa if first=='boolean_true'else 8)|(1 if mode in ['boolean_true','coreml_only']else 0)|(2 if mode in ['boolean_true','classic_only']else 0);state=int.from_bytes(bytes(r.u.mem_read(0x6800055d0c,4)),'little');assert state==expected;final_states[hex(state)]+=1;write=next(e for e in profile['source_writes']if e['pc']=='0x100345634');assert int.from_bytes(bytes.fromhex(write['after_hex']),'little')==expected;phase=next(e for e in profile['source_reads']if e['pc']=='0x1003455f0');assert int.from_bytes(bytes.fromhex(phase['bytes_hex']),'little')==0xb3d4;status=next(e for e in profile['source_writes']if e['pc']=='0x1003fdcfc');read=next(e for e in profile['source_reads']if e['pc']=='0x1007f7a88');assert status['address']==read['address']=='0x680005fef0'and status['size_bytes']==read['size_bytes']==4 and status['after_hex']==read['bytes_hex']=='51c63d8b';assert profile['boundary']['pc']=='0x100570148'and profile['boundary']['detail']['symbol']=='libSystem/_malloc'and r.reg('x0')==32;statuses+=1
   print(first,mode,env,'fresh A64 pass',flush=True)
 assert len(rows)==32 and prefixes==32 and adapters==60 and returned==56 and open_queries==4 and audits==52 and releases==120 and statuses==28 and keys==Counter({'FairPlay-CoreML-Client':32,'FairPlay-Classic-Client':28})and marker_counts==Counter({'5b':24,'5c':32})
 deps=FILES+['daemon_boolean_chain_contracts.json','daemon_boolean_chain_proofs.json','probe_daemon_boolean_chain.py','probe_daemon_boolean_mixed.py','recover_daemon_boolean_chain.py','prove_daemon_boolean_chain.py','validate_daemon_entitlement_flow.py','daemon_secondary_result_type_profiles.json','daemon_boolean_chain_sdk.c','daemon_boolean_chain_sdk.ll'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':{'source_obligations_rebuilt':len(qs),'accepted_SMT_files':files,'profile_cases':len(rows),'prior_source_prefixes_preserved':prefixes,'Boolean_adapter_entries':adapters,'Boolean_adapter_returns':returned,'Boolean_query_frontiers':open_queries,'audit_argument_instances':audits,'new_adapter_release_requests':releases,'encoded_zero_bridge_returns':statuses,'CoreML_key_instances':keys['FairPlay-CoreML-Client'],'Classic_key_instances':keys['FairPlay-Classic-Client'],'marker_5B_returns':marker_counts['5b'],'marker_5C_returns':marker_counts['5c'],'bank_byte_inputs':512,'unique_visited_source_instructions':len(c['unique_visited_source']),'SDK_compile_exit':0},'independent_A64_totals':dict(totals),'mode_counts':dict(modes),'final_state_counts':dict(final_states),'fresh_replay_cases':rows,'native_target_executed':False,'native_framework_calls_executed':False,'native_entitlement_values_observed':False,'native_authorization_outcome_established':False,'hardware_PAC_executed':False,'idb_mutated':False,'new_port_emission_established':False,'full_goal_complete':False,'all_checks_pass':True};(ROOT/'daemon_boolean_chain_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':out['verified_counts'],'A64_totals':dict(totals),'states':dict(final_states),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
