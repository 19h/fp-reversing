#!/usr/bin/env python3
"""Fresh A64 replay, source-prefix preservation, rebuilt SDK/contracts and
both forms of local source proofs. Check exact error/number output epochs,
undefined-byte masks, markers, cleanup, state bits and unresolved owner stops.
O(profile/source/artifact bytes + solver/compiler resources) time;
O(one private CPU map + journals + BV DAGs) space. No native target/IPC.
"""
import json
from collections import Counter
import z3
from daemon_receive_tools import ROOT,IMAGE
from capture_daemon_record720 import sha
from validate_daemon_entitlement_flow import Fresh
from recover_daemon_secondary_result import recover,FILES
from recover_daemon_entitlement_flow import snapshot
from prove_daemon_secondary_result import obligations
def main():
 c=json.loads((ROOT/'daemon_secondary_result_contracts.json').read_text());proof=json.loads((ROOT/'daemon_secondary_result_proofs.json').read_text());assert recover()==c;qs,counts=obligations();assert counts==proof['source_lift_counts']and len(qs)==len(proof['proofs']);files=0
 for (name,q),row in zip(qs,proof['proofs'],strict=True):
  assert name==row['name'];s=z3.Solver();s.set(timeout=30000);s.add(q);assert s.check()==z3.unsat
  for f,h in [('file','sha256'),('original_file','original_sha256')]:
   assert sha(ROOT/row[f])==row[h];s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_file(str(ROOT/row[f])));assert s.check()==z3.unsat,(name,f);files+=1
 groups={n:json.loads((ROOT/n).read_text())for n in FILES};priortrue=json.loads((ROOT/'daemon_entitlement_flow_string_profiles.json').read_text());priorfalse=json.loads((ROOT/'daemon_entitlement_flow_audit_profiles.json').read_text());parents={('boolean_true',e['source_index']):e for e in priortrue['cases']if e['configuration']['secondary_string_model']=='nonnull_task'};parents.update({('boolean_false',e['source_index']):e for e in priorfalse['cases']if e['configuration']['query_result_model']=='boolean_false'});rawparents={(e['configuration']['query_result_model'],e['source_index']):e for e in groups[FILES[0]]['cases']if e['configuration']['secondary_result_model']=='value_untyped'};rows=[];totals=Counter();boundaries=Counter();markers=Counter();modes=Counter();prefixes=0;number_outputs=0;cleanup=0;third=0;type_pairs=0
 for group,script in zip(FILES,['probe_daemon_secondary_result.py','probe_daemon_secondary_types.py'],strict=True):
  p=groups[group];assert p['generator_sha256']==sha(ROOT/script)
  for n,h in p['dependencies'].items():assert sha(ROOT/n)==h
  for j,profile in enumerate(p['cases']):
   first=profile['configuration']['query_result_model'];env=profile['source_index'];mode=profile['configuration'].get('secondary_type_model',profile['configuration']['secondary_result_model']);modes[mode]+=1;prior=(parents if group==FILES[0]else rawparents)[(first,env)];cut=len(prior['source_visits']);assert profile['source_visits'][:cut]==prior['source_visits'];assert [e for e in profile['source_reads']if e['source_visit_index']<cut]==prior['source_reads'];assert [e for e in profile['source_writes']if e['source_visit_index']<cut]==prior['source_writes'];assert profile['API_model_events'][:len(prior['API_model_events'])]==prior['API_model_events'];prefixes+=1;assert profile['fixture_PC_transitions']==0
   for e in profile['source_reads']:
    if 'known_mask_hex'in e:assert all(bytes.fromhex(e['known_mask_hex']))
   r=Fresh(profile,(j+1)%4);row=r.run();assert row['all_checks_pass'];rows.append({'group':group,**row});totals.update(row['verified_counts']);b=profile['boundary'];boundaries[b['pc']]+=1;query=next(e for e in profile['API_model_events']if e['pc']=='0x1002382e8');qcut=query['source_visit_index'];writes=[e for e in profile['source_writes']if e['address']=='0x680005ff00'and e['source_visit_index']>qcut]
   for model in profile['API_model_events']:
    if model['source_visit_index']>qcut and model['symbol']=='CoreFoundation/_CFRelease':assert int(model['arguments8'][0],16)!=0;cleanup+=1
   if mode in ['null_no_error','null_with_error','value_with_error','wrong_type','number_fail','number_success']:
    assert len(writes)==1;expected='32'if mode=='number_success'else'31';assert writes[0]['pc']=='0x100067240'and writes[0]['after_hex']==expected;markers[expected]+=1
    if mode=='number_success':
     state=next(e for e in profile['source_writes']if e['pc']=='0x1007f797c');assert state['after_hex']==('0a000000'if first=='boolean_true'else'08000000');assert b['pc']=='0x10033376c'and b['detail']['symbol']=='CoreFoundation/_CFStringCreateWithCStringNoCopy'and r.reg('x1')==0x100fd5565 and r.reg('w2')==0x600;call=next(e for e in profile['source_calls']if e['pc']=='0x10034547c');R=int(call['arguments8'][0],16);record=snapshot(profile,R,40,call['source_visit_index']);data=bytes.fromhex(record['defined_bytes_hex']);assert int.from_bytes(data[:8],'little')==0x100fd5565 and int.from_bytes(data[32:40],'little')==0x680004f178;original=next(e['original_token']['bytes_hex']for e in profile['API_model_events']if'original_token'in e);assert snapshot(profile,0x680004f178,32,call['source_visit_index'])['defined_bytes_hex']==original;third+=1
    elif first=='boolean_true':assert b['pc']=='0x100570148'and b['detail']['symbol']=='libSystem/_malloc'and r.reg('x0')==32
    else:
     assert b['pc']=='0x10057a774'and b['kind']=='before_unmapped_owner_write'and not any(e['pc']=='0x10057a774'for e in profile['source_writes']);ptr=int.from_bytes(bytes(r.u.mem_read(0x680004f230+0x1a30,8)),'little');assert r.reg('x9')==ptr==int(b['detail']['address'],16)
   else:
    assert not writes;expected={'value_untyped':'0x10003b330','number_frontier':'0x10000b734','string_frontier':'0x10014c658'}[mode];assert b['pc']==expected
    if mode=='number_frontier':assert r.reg('x0')==0x6800013000 and r.reg('x1')==3 and r.reg('x2')==0x68000504b0
    if mode=='string_frontier':assert r.reg('x0')==0x6800013000 and r.reg('x1')==0x680004f1a0 and r.reg('x2')==32 and r.reg('x3')==0x600
   if mode in ['number_fail','number_success']:
    model=next(e for e in profile['API_model_events']if e['symbol']=='CoreFoundation/_CFNumberGetValue');effect=model['memory_models'][0];value=[0,1,0x80000000,0xffffffff][env];assert effect['before_known_mask_hex']=='00'*4 and int.from_bytes(bytes.fromhex(effect['after_hex']),'little')==value and model['return_value']==('0x1'if mode=='number_success'else'0x0');number_outputs+=1
   for e in profile['source_reads']:assert not(int(e['address'],16)<0x68000504b4 and int(e['address'],16)+e['size_bytes']>0x68000504b0)
   if group==FILES[1]:
    num=next(int(e['return_value'],16)for e in profile['API_model_events']if e['symbol']=='CoreFoundation/_CFNumberGetTypeID');actual=next(int(e['return_value'],16)for e in profile['API_model_events']if e['symbol']=='CoreFoundation/_CFGetTypeID'and e['source_visit_index']>qcut);assert (num&0xffffffff)==(actual&0xffffffff)and(num==actual)==(mode not in ['wrong_type','string_frontier']);type_pairs+=1
   print(group,first,mode,env,'fresh A64 pass',flush=True)
 assert len(rows)==60 and prefixes==60 and number_outputs==16 and third==8 and type_pairs==28 and markers==Counter({'31':36,'32':8})and boundaries==Counter({'0x10057a774':18,'0x100570148':18,'0x10003b330':8,'0x10000b734':4,'0x10014c658':4,'0x10033376c':8})
 deps=FILES+['daemon_secondary_result_contracts.json','daemon_secondary_result_proofs.json','probe_daemon_secondary_result.py','probe_daemon_secondary_types.py','recover_daemon_secondary_result.py','prove_daemon_secondary_result.py','validate_daemon_entitlement_flow.py','recover_daemon_entitlement_flow.py','daemon_entitlement_flow_string_profiles.json','daemon_entitlement_flow_audit_profiles.json','daemon_secondary_result_sdk.c','daemon_secondary_result_sdk.ll'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':{'source_obligations_rebuilt':len(qs),'accepted_SMT_files':files,'profile_cases':len(rows),'prior_source_prefixes_preserved':prefixes,'modeled_numeric_output_effects':number_outputs,'numeric_output_source_reads_before_boundaries':0,'marker_31_returns':markers['31'],'marker_32_returns':markers['32'],'unknown_owner_write_frontiers':18,'allocation_frontiers':18,'number_type_frontiers':8,'number_conversion_frontiers':4,'string_conversion_frontiers':4,'next_CoreML_key_frontiers':third,'modeled_64bit_type_pairs':type_pairs,'secondary_release_requests':cleanup,'unique_visited_source_instructions':len(c['unique_visited_source']),'SDK_compile_exit':0},'independent_A64_totals':dict(totals),'boundary_counts':dict(boundaries),'fresh_replay_cases':rows,'native_framework_calls_executed':False,'native_entitlement_value_observed':False,'native_authorization_outcome_established':False,'hardware_PAC_executed':False,'idb_mutated':False,'new_port_emission_established':False,'full_goal_complete':False,'all_checks_pass':True};(ROOT/'daemon_secondary_result_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':out['verified_counts'],'A64_totals':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
