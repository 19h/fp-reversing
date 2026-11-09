#!/usr/bin/env python3
"""Rebuild source/SDK/contracts, remeasure separate pure host-libc vectors,
solve both source-proof forms, preserve predecessor source epochs and freshly
replay private caller profiles. Exhaustive isolated end-byte CPU check.
O(profile/source/artifact bytes + solver/compiler resources + 256*16) time;
O(one CPU map + journals + BV DAGs) space. No native daemon/framework/IPC.
"""
import json
from collections import Counter
import z3,unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,IMAGE
from capture_daemon_record720 import sha
from capture_daemon_secondary_string_reference import capture
from recover_daemon_secondary_string import recover
from recover_daemon_entitlement_flow import snapshot
from prove_daemon_secondary_string import obligations
from validate_daemon_entitlement_flow import Fresh
def byte_gate():
 start,end=0x1000094e4,0x100009524;u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);page=start&~4095;u.mem_map(page,4096);u.mem_write(page,IMAGE.read(page,4096));P=0x6900000000;u.mem_map(P,4096);count=0
 for byte in range(256):
  value=(0x123456789abcdef0+byte*0x8b3dc651)&((1<<64)-1);u.mem_write(P,bytes([byte]));u.reg_write(ar.UC_ARM64_REG_X9,P);u.reg_write(ar.UC_ARM64_REG_X19,0);u.reg_write(ar.UC_ARM64_REG_X20,0x38f8);u.reg_write(ar.UC_ARM64_REG_X0,value);u.emu_start(start,end,count=17);assert u.reg_read(ar.UC_ARM64_REG_PC)==end and u.reg_read(ar.UC_ARM64_REG_X9)==(0x1f1e if byte==0 else 0x1f11)and u.reg_read(ar.UC_ARM64_REG_X0)==value;count+=1
 return {'byte_inputs':count,'source_visits':count*16,'original_bytes_sha256':__import__('hashlib').sha256(IMAGE.read(start,end-start)).hexdigest()}
def main():
 p=json.loads((ROOT/'daemon_secondary_string_profiles.json').read_text());c=json.loads((ROOT/'daemon_secondary_string_contracts.json').read_text());reference=json.loads((ROOT/'daemon_secondary_string_reference.json').read_text());proof=json.loads((ROOT/'daemon_secondary_string_proofs.json').read_text());assert capture()==reference and recover()==c and p['generator_sha256']==sha(ROOT/'probe_daemon_secondary_string.py');qs,counts=obligations();assert counts==proof['source_lift_counts']and len(qs)==len(proof['proofs']);files=0
 for (name,q),row in zip(qs,proof['proofs'],strict=True):
  assert name==row['name'];s=z3.Solver();s.set(timeout=30000);s.add(q);assert s.check()==z3.unsat,(name,s.reason_unknown())
  for f,h in [('file','sha256'),('original_file','original_sha256')]:
   assert sha(ROOT/row[f])==row[h];s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_file(str(ROOT/row[f])));assert s.check()==z3.unsat,(name,f,s.reason_unknown());files+=1
 old=json.loads((ROOT/'daemon_secondary_result_profiles.json').read_text());parents={(e['configuration']['query_result_model'],e['source_index']):e for e in old['cases']if e['configuration']['secondary_result_model']=='value_untyped'};old=json.loads((ROOT/'daemon_secondary_result_type_profiles.json').read_text());deep={(e['configuration']['query_result_model'],e['source_index']):e for e in old['cases']if e['configuration']['secondary_type_model']=='string_frontier'};refs={e['name']:e for e in reference['cases']};rows=[];totals=Counter();markers=Counter();boundaries=Counter();prefixes=deep_prefixes=parses=writes=0;nulls=0;errno_references=0
 def prefix(profile,prior):
  cut=len(prior['source_visits']);assert profile['source_visits'][:cut]==prior['source_visits'];assert [e for e in profile['source_reads']if e['source_visit_index']<cut]==prior['source_reads'];assert [e for e in profile['source_writes']if e['source_visit_index']<cut]==prior['source_writes'];assert profile['API_model_events'][:len(prior['API_model_events'])]==prior['API_model_events']
 for j,profile in enumerate(p['cases']):
  case=profile['configuration']['string_case'];first=profile['configuration']['query_result_model'];env=profile['source_index'];key=(first,env);prefix(profile,parents[key]);prefixes+=1
  if key in deep:prefix(profile,deep[key]);deep_prefixes+=1
  for e in profile['source_reads']:
   if 'known_mask_hex'in e:assert all(bytes.fromhex(e['known_mask_hex']))
  assert profile['fixture_PC_transitions']==0;r=Fresh(profile,(j+1)%4);row=r.run();assert row['all_checks_pass'];rows.append(row);totals.update(row['verified_counts']);boundary=profile['boundary'];boundaries[boundary['pc']]+=1;converted=next(e for e in profile['API_model_events']if e['pc']=='0x10014c658');parser=next((e for e in profile['API_model_events']if e['pc']=='0x10000a2e8'),None);out=[e for e in profile['source_writes']if e['pc']=='0x100073fdc'];marker=[e for e in profile['source_writes']if e['pc']=='0x100067240'];assert converted['arguments8'][1:4]==['0x680004f1a0','0x20','0x600']
  if case=='parser_frontier':
   assert parser is None and not out and not marker and boundary['pc']=='0x10000a2e8'and boundary['detail']['symbol']=='libSystem/_strtol';assert r.reg('x0')==0x680004f1a0 and r.reg('x1')==0x680004f190 and r.reg('x2')==10
  else:
   ref=refs.get(case,refs['positive']);expected=case!='conversion_fail'and case!='end_null'and ref['end_byte']==0;assert len(marker)==1 and marker[0]['after_hex']==('32'if expected else'31');markers[marker[0]['after_hex']]+=1
   if case=='conversion_fail':assert parser is None and converted['return_value']=='0x0'and not converted.get('memory_models')
   else:
    assert converted['return_value']=='0x1'and parser is not None and parser['arguments8'][:3]==['0x680004f1a0','0x680004f190','0xa'];raw=bytes.fromhex(ref['NUL_inclusive_hex']);at=parser['source_visit_index'];assert snapshot(profile,0x680004f1a0,len(raw),at)['defined_bytes_hex']==raw.hex();assert parser['return_value']==ref['return_bits64'];effect=parser['memory_models'][0];end=0 if case=='end_null'else 0x680004f1a0+ref['end_offset_bytes'];assert effect['address']=='0x680004f190'and effect['size_bytes']==8 and int.from_bytes(bytes.fromhex(effect['after_hex']),'little')==end;parses+=1;nulls+=case=='end_null'
    if case not in ['end_null']and ref['errno']!=0:errno_references+=1
   if expected:
    assert len(out)==1 and out[0]['address']=='0x68000504b0'and out[0]['size_bytes']==4 and int.from_bytes(bytes.fromhex(out[0]['after_hex']),'little')==(int(ref['return_bits64'],16)&0xffffffff);assert boundary['pc']=='0x10033376c'and boundary['detail']['symbol']=='CoreFoundation/_CFStringCreateWithCStringNoCopy'and r.reg('x1')==0x100fd5565;state=next(e for e in profile['source_writes']if e['pc']=='0x1007f797c');assert state['after_hex']==('0a000000'if first=='boolean_true'else'08000000');writes+=1
   else:
    assert not out
    if first=='boolean_true':assert boundary['pc']=='0x100570148'and boundary['detail']['symbol']=='libSystem/_malloc'and r.reg('x0')==32
    else:assert boundary['pc']=='0x10057a774'and boundary['kind']=='before_unmapped_owner_write'
  print(first,case,env,'fresh A64 pass',flush=True)
 assert len(rows)==32 and prefixes==32 and deep_prefixes==20 and parses==24 and writes==18 and nulls==2 and errno_references==6 and markers==Counter({'32':18,'31':10})and boundaries==Counter({'0x10033376c':18,'0x10057a774':5,'0x100570148':5,'0x10000a2e8':4});cpu=byte_gate();assert cpu['byte_inputs']==256
 deps=['daemon_secondary_string_profiles.json','daemon_secondary_string_reference.json','daemon_secondary_string_contracts.json','daemon_secondary_string_proofs.json','capture_daemon_secondary_string_reference.py','probe_daemon_secondary_string.py','recover_daemon_secondary_string.py','prove_daemon_secondary_string.py','validate_daemon_entitlement_flow.py','daemon_secondary_result_profiles.json','daemon_secondary_result_type_profiles.json','daemon_secondary_string_sdk.c','daemon_secondary_string_sdk.ll'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':{'source_obligations_rebuilt':len(qs),'accepted_SMT_files':files,'profile_cases':len(rows),'prior_source_prefixes_preserved':prefixes,'deeper_String_prefixes_preserved':deep_prefixes,'host_reference_vectors_remeasured':len(refs),'declared_parser_returns':parses,'counterfactual_NULL_end_pointer_cases':nulls,'nonzero_errno_reference_cases':errno_references,'four_byte_output_stores':writes,'marker_32_returns':markers['32'],'marker_31_returns':markers['31'],'parser_frontiers':4,'unknown_owner_write_frontiers':5,'allocation_frontiers':5,'next_CoreML_key_frontiers':18,'unique_visited_source_instructions':len(c['unique_visited_source']),'SDK_compile_exit':0},'independent_A64_totals':dict(totals),'isolated_end_byte_CPU':cpu,'fresh_replay_cases':rows,'host_libc_reference_executed':True,'native_target_executed':False,'native_framework_calls_executed':False,'matching_daemon_runtime_established':False,'native_authorization_outcome_established':False,'hardware_PAC_executed':False,'idb_mutated':False,'new_port_emission_established':False,'full_goal_complete':False,'all_checks_pass':True};(ROOT/'daemon_secondary_string_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':out['verified_counts'],'A64_totals':dict(totals),'byte_CPU':cpu,'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
