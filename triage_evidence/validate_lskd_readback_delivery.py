#!/usr/bin/env python3
"""Readback delivery gates: fresh output identity, source slots and field roles.

O(total pinned bytes+C*(V+E)+I+256R) time, O(largest source/JSON) space,
plus solver-dependent checking (30 s/query). No target/API/heap/IPC executes.
"""
import hashlib,json,re,struct
from collections import Counter
from pathlib import Path
import z3
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_carrier_control import span
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
from lskd_readback_symbolic import queries
from lskd_readback_codec_symbolic import queries as codec_queries
from probe_lskd_request import OBJECT,PARAM,OTHER_OUT
from probe_lskd_response import RESPONSE
BASE=ROOT.parent
BASELINE_SHA='6b9ec64511fa61cc1d4b52301ad9d27a5ebdbfb5075706c6e601f920b3f5c45d'
EXPECTED={'bounded_source_spans': 36, 'additional_controller_cells': 6, 'relifted_local_proofs_unsat': 8, 'fresh_cases': 343, 'source_visits': 1049089, 'source_byte_checks': 4196356, 'source_write_epochs': 108970, 'read_epochs': 207649, 'discarded_probe_read_epochs': 343, 'byte_reconstructed_cases': 343, 'preceding_complete_prefixes_equal': 343, 'FP64_contexts_preserved': 343, 'register_only_models': 1730, 'original_authenticated_edges': 3348, 'unexecuted_next_calls': 60, 'original_additional_field_returns': 156, 'source_raw8_outputs': 120, 'AVD_zero_context_error_returns': 12, 'AVD_nonzero_context_helper_boundaries': 12, 'source_BE32_outputs': 36, 'source_stream_free_preparations': 24, 'original_query_method_returns': 12}

def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def proof_check(c,obj,query_function):
 qs,lifts=query_function(c);assert lifts==obj['source_lift_counts']and[n for n,q in qs]==[q['name']for q in obj['proofs']]
 for(name,q),row in zip(qs,obj['proofs']):
  op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256']and row['result']=='unsat';original=z3.parse_smt2_string(op.read_text());assert len(original)==1
  for f in[z3.simplify(q),z3.simplify(original[0]),z3.Xor(z3.simplify(q),z3.simplify(original[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(f);assert str(s.check())=='unsat',name
 return len(qs),sum(lifts.values())
def main():
 assert sha(ROOT/'lskd_readback_prior_manifest.json')==BASELINE_SHA;baseline=read('lskd_readback_prior_manifest.json');assert len(baseline['files'])==1837
 c=read('lskd_readback_contracts.json');p=read('lskd_readback_profiles.json');fresh=read('lskd_readback_replays.json');checks=read('lskd_readback_checks.json');proof=read('lskd_readback_proofs.json');aux=read('lskd_readback_auxiliary.json');preserve=read('lskd_readback_preservation.json');correction=read('lskd_readback_flag_correction.json')
 for obj,name in[(c,'recover_lskd_readback.py'),(p,'probe_lskd_readback.py'),(fresh,'validate_lskd_readback.py'),(checks,'validate_lskd_readback.py'),(proof,'prove_lskd_readback.py'),(aux,'recover_lskd_readback_auxiliary.py'),(preserve,'validate_lskd_readback_preservation.py'),(correction,'validate_lskd_readback_flag_correction.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert correction['all_checks_pass']and correction['complete_draft_reconstruction_matches']and len(correction['corrected_flags'])==24 and correction['profile_cases_with_identical_source_events_and_other_fields']==343
 assert checks['all_checks_pass']and preserve['all_checks_pass']and checks['verified_counts']==EXPECTED;assert sha(ROOT/'lskd_readback_replays.json')==checks['fresh_replays_sha256']and p['cases']==fresh['cases'];assert len(fresh['cases'])==343;del p
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');assert k.sha256==c['kernel_collection_sha256']==checks['kernel_collection_sha256']==aux['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe';assert sha(SOURCE)==c['source_sha256']==checks['source_sha256']==aux['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now)and IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex']
 assert len(c['spans'])==36 and function(k,e,int(c['query_caller_static']['start'],16))==c['query_caller_static'];assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 for b in aux['bank_rules']:
  l,r=int(b['left'],16),int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(r,256).hex()==b['right256_hex'];now=selected(l,r,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(now[n]==b[n]for n in now)and pointer(k,int(b['slot'],16))==b['original_pointer']
 assert len(aux['bank_rules'])==9 and all(b['inputs_checked']==256 for b in aux['bank_rules'])
 for ptr in aux['original_bank_roots']+checks['original_authenticated_slots']+[aux['typed_free_metadata']['name_pointer']]:assert pointer(k,int(ptr['slot'],16))==ptr
 v=aux['typed_free_metadata'];raw=k.read(int(v['address'],16),64);assert raw.hex()==v['original64_hex']==c['typed_free_view']['original64_hex'];assert struct.unpack_from('<II',raw,40)==(100,160)and raw[:16]==bytes(16);assert k.read(int(v['name_pointer']['target'],16),80).split(b'\0')[0].decode()==v['name']=='site.LSKDDispatchStream'
 for o in v['equal_original64_views']:assert k.read(int(o['address'],16),64).hex()==o['original64_hex']==raw.hex()
 local_n,local_i=proof_check(c,proof,queries);codec_n,codec_i=proof_check(c,aux,codec_queries);assert(local_n,codec_n,local_i+codec_i)==(8,7,123)
 cf=aux['packing_alignment_counterexample'];assert sha(ROOT/cf['file'])==cf['sha256']and cf['result']=='sat'and int(cf['stack_pointer64'],16)&15;qs,_=codec_queries(c);q=next(q for name,q in qs if name=='u32_outer_record_pack');unrestricted=q.arg(1);retained=z3.parse_smt2_string((ROOT/cf['file']).read_text());assert len(retained)==1;s=z3.Solver();s.set(timeout=30000);s.add(z3.Xor(unrestricted,retained[0]));assert str(s.check())=='unsat';s=z3.Solver();s.set(timeout=30000);s.add(unrestricted,z3.BitVec('readback_stack_address64',64)==int(cf['stack_pointer64'],16),z3.BitVec('readback_tag32',32)==int(cf['tag32'],16));assert str(s.check())=='sat'

 counts=Counter();roles=Counter()
 for r in fresh['cases']:
  case=r['input'];label=case.get('provider',case.get('caller'));assert r['initial_fp_callee_saved64']==r['final_fp_callee_saved64']
  for flag in['undefined_private_value_reads','native_API_executed','native_heap_executed','native_request_execution_executed','native_business_operation_executed','complete_native_business_operation_executed','random_backend_executed','stop_helper_executed','external_IPC_emission_proved','full_goal_complete','native_object_free_executed']:assert not r[flag],flag
  for model in r['models']:assert not model['target_executed']and not model['memory_effects_modeled']
  getters=[x for x in r['readback_returns']if x['target']in['0xfffffe000a50eccc','0xfffffe000a55132c']]
  if label in['query','vault','avd','allowed']:
   expected=[(0x65,0x13180000)]if label=='query'else[(0x7e,0x13579bdf)]if label=='allowed'else[(0x8b,OTHER_OUT)]if label=='vault'else[(t,PARAM+o)for t,o in[(0x6b,0),(0x6c,0xa0),(0x89,0x60),(0x8a,0xbc)]]
   assert len(getters)==len(expected)
   for x,(tag,value)in zip(getters,expected):
    raw=bytes.fromhex(x['snapshots']['record']['bytes_hex']);R=int(x['snapshots']['record']['address'],16);assert int.from_bytes(bytes.fromhex(x['snapshots']['value']['bytes_hex']),'little')==value;is_u32=x['target']=='0xfffffe000a55132c';assert struct.unpack_from('<I',raw,24 if is_u32 else 16)[0]==0x5e561849;roles[hex(tag)]+=1
    if is_u32:
     K=((R^0xae0701e7)*0x952f3cb7)&0xffffffff;assert(struct.unpack_from('<I',raw)[0]+K)&0xffffffff==0x26c and(struct.unpack_from('<H',raw,4)[0]-K-0x5def)&65535==tag
    else:
     K=((R^0xefb8ef0d)*0xe384f389)&0xffffffff;assert struct.unpack_from('<I',raw)[0]^K==0x2ea
   if label=='query':
    assert r['source_execution_wrapper_returned']and r['source_query_success_executed']and r['query_method_return_executed']and r['boundary']['registers31'][0]=='0x13180000'and r['boundary']['SP']==r['entry_SP'];counts['query_complete_method_returns']+=1
    metadata=next(x for x in r['readback_returns']if x['target']=='0xfffffe000a54f50c');assert metadata['snapshots']['value']['bytes_hex']=='5b1b0000';counts['query_operation_readbacks']+=1
    for x in r['readback_calls']:
     if x['target']=='0xfffffe000a50e170':assert int(x['SP'],16)&15==0;counts['aligned_u32_outer_calls']+=1
     if x['target']=='0xfffffe000a560468':
      R=int(x['record']['address'],16);b=bytes.fromhex(x['record']['bytes_hex']);K=((R^0xddd14603)*0xb90ee68b)&0xffffffff;assert struct.unpack_from('<I',b)[0]^K==0x75e;end=next(z['source_visit_index']for z in r['readback_returns']if z['target']==x['target']and z['source_visit_index']>x['source_visit_index']);writes=[z for z in r['source_writes']if x['source_visit_index']<z['source_visit_index']<end and z['pc']=='0xfffffe000a5258e0'];assert len(writes)==1 and int(writes[0]['address'],16)==R+16 and writes[0]['after_hex']=='7c2c7c7b';counts['cleanup_record_successes']+=1
    outer=[x for x in r['readback_returns']if x['target']in['0xfffffe000a50e8a8','0xfffffe000a50e170','0xfffffe000a50d088']];assert len(outer)==4 and all(x['registers31'][0]=='0x0'for x in outer);counts['outer_normalized_success_returns']+=4
   if label=='avd':
    common=r['value_bridge_returns'][0];value=common['value_output'];loads=[z for z in r['source_reads']if z['pc']=='0xfffffe000a595890'];assert len(loads)==1;load=loads[0];assert load['address']==value['address']and load['bytes_hex']==value['bytes_hex']==struct.pack('<Q',case['context64']).hex();a=int(load['address'],16);assert not any(common['source_visit_index']<=z['source_visit_index']<load['source_visit_index']and int(z['address'],16)<a+8 and a<int(z['address'],16)+z['size_bytes']for z in r['source_writes']);branch=next(x for x in r['readback_branches']if x['pc']=='0xfffffe000a595908');assert branch['target']==('0xfffffe000a5354cc'if case['context64']else'0xfffffe000a5289a0');counts['AVD_context_source_epoch_links']+=1
  else:assert not getters
 assert dict(roles)=={'0x8b':24,'0x6b':24,'0x6c':24,'0x89':24,'0x8a':24,'0x7e':24,'0x65':12},dict(roles);assert dict(counts)=={'AVD_context_source_epoch_links':24,'query_complete_method_returns':12,'query_operation_readbacks':12,'aligned_u32_outer_calls':12,'cleanup_record_successes':24,'outer_normalized_success_returns':48}
 allowed={r['path']:r for r in preserve['allowed_existing_changes']};assert len(allowed)==6 and preserve['prior_artifacts_checked']==1837 and preserve['unchanged_prior_artifacts']==1831
 for row in baseline['files']:
  path=BASE/row['path'];assert sha(path)==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
  if row['path']not in allowed:assert path.stat().st_size==row['size_bytes']
 for row in baseline['inputs_preserved']:
  path=BASE/row['path'];assert path.stat().st_size==row['size_bytes']and sha(path)==row['sha256']
 links=0
 for name in['lskd_readback_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   path=Path(target.split('#',1)[0]);path=path if path.is_absolute()else BASE/path;assert path.exists()or path in[ROOT/'lskd_readback_quality_gates.json',ROOT/'lskd_readback_source_identity.json'],(name,target);links+=1
 report=(BASE/'lskd_readback_report.md').read_text()
 for term in['LR10','QG7','1049089','4196356','207649','108970','1730','3348','2304','123','1837','1831','unknown','0xfffffe000a517dd0','0xfffffe000a54e220','0x13180000','0x7B7C2C7C','16-byte','counterexample','copy','Mach']:assert term in report,term
 identity={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'kernel_collection_sha256':k.sha256,'kext_sha256':sha(SOURCE),'kernel_uuid':k.kernel['uuid'],'fileset_uuid':e['uuid'],'source_spans':[{n:s[n]for n in['label','start','end','sha256','compiler_start','compiler_end']}for s in c['spans']],'exact_symbols':c['exact_symbols'],'typed_free_metadata':v,'additional_mutable_globals':c['additional_mutable_globals'],'packing_alignment_counterexample':cf,'original_authenticated_slots':checks['original_authenticated_slots'],'bank_rules':aux['bank_rules'],'field_role_counts':dict(roles),'delivery_counts':dict(counts),'contracts_sha256':sha(ROOT/'lskd_readback_contracts.json'),'native_object_free_executed':False,'native_target_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_readback_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 counts_out={**EXPECTED,**dict(counts),'additional_codec_proofs_unsat':7,'total_source_proof_pairs':15,'total_lifted_instruction_instances':123,'exhaustive_bank_rules':9,'bank_byte_input_checks':2304,'corrected_query_summary_flags':24,'draft_source_and_other_fields_equal_cases':343,'retained_alignment_counterexamples':1}
 evidence=['Factual source/interface analysis.','LR1-LR10 list dependencies and falsification probes, including explicit alignment and unexecuted native effects.','Readback/query return/cleanup/AVD split and bounded next interfaces covered; broad goal remains active.','Widths, byte extents, exact counts, source codecs and complexity explicit.','Alignment counterexample resolved by an explicit premise; status namespaces and local/external/native scope remain separate.','Original bytes/names/chains,343 fresh byte-audited cases,343 preceding prefixes,15 re-lifted proof pairs and9 exhaustive banks.','Impact-labeled continuation table.'];outputs=['lskd_readback_contracts.json','lskd_readback_profiles.json','lskd_readback_replays.json','lskd_readback_checks.json','lskd_readback_proofs.json','lskd_readback_auxiliary.json','lskd_readback_preservation.json','lskd_readback_flag_correction.json'];quality={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{j}':{'status':'pass_for_increment'if j==3 else'pass','evidence':s}for j,s in enumerate(evidence,1)},'verified_counts':counts_out,'field_role_counts':dict(roles),'source_lift_counts':{**proof['source_lift_counts'],**aux['source_lift_counts']},'prior_artifacts_checked':1837,'unchanged_prior_artifacts':1831,'inputs_preserved':baseline['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'lskd_readback_source_identity.json'),'model_memory_writes':0,'native_object_free_executed':False,'native_target_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_readback_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'scoped_quality_gates_pass':True,'fresh_cases':343,'source_proof_pairs':15,'query_method_returns':12,'prior_artifacts_checked':1837,'checked_links':links,'delivery_counts':dict(counts),'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
