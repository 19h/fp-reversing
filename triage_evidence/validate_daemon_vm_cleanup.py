#!/usr/bin/env python3
"""Rebuild contracts and both SMT forms; independently replay daemon/cache
source with explicit API/trap/callback models. Frozen-prefix, ownership,
request-layout and exact transport/return-boundary checks.
O(source/artifact bytes + visits + KC fixups + solver/compiler resources)
time; O(one CPU map + KC metadata + largest profile + BV DAGs) space.
No native VM/free/kernel/IPC or matched-daemon-runtime claim.
"""
import json,struct
from collections import Counter
import z3
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from recover_daemon_vm_cleanup import recover,FILES
from prove_daemon_vm_cleanup import obligations
from validate_daemon_entitlement_flow import Fresh
from recover_daemon_entitlement_flow import snapshot
from bootpolicy_cache_reader import Cache
from replay_vm_cache_transport import Replay
F=0x680004f230;OBJ=0x6800030000
def key(p,with_status=False):
 c=p['configuration'];return(c['query_result_model'],c['client_bit_plan'],p['source_index'])+((c['VM_cleanup_return_model'],)if with_status else())
def main():
 c=json.loads((ROOT/'daemon_vm_cleanup_contracts.json').read_text());proof=json.loads((ROOT/'daemon_vm_cleanup_proofs.json').read_text());assert recover()==c;qs,counts,domains=obligations();assert counts==proof['source_lift_counts']and domains==proof['daemon_proof_domains']and len(qs)==len(proof['proofs']);files=0
 for(name,q),row in zip(qs,proof['proofs'],strict=True):
  assert name==row['name'];s=z3.Solver();s.set(timeout=30000);s.add(q);assert s.check()==z3.unsat
  for f,h in [('file','sha256'),('original_file','original_sha256')]:
   assert sha(ROOT/row[f])==row[h];s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_file(str(ROOT/row[f])));assert s.check()==z3.unsat;files+=1
 parents={key(p):p for p in json.loads((ROOT/'daemon_client_object_cleanup_profiles.json').read_text())['cases']};groups={n:json.loads((ROOT/n).read_text())for n in FILES};vmparents={key(p,True):p for p in groups[FILES[0]]['cases']};rows=[];totals=Counter();prefixes=vmreturns=frees=0;states=Counter();bounds=Counter();postfree_access=0
 for group,script in zip(FILES,['probe_daemon_vm_cleanup.py','probe_daemon_vm_retire.py'],strict=True):
  data=groups[group];assert data['generator_sha256']==sha(ROOT/script)
  for n,h in data['dependencies'].items():assert sha(ROOT/n)==h
  for j,p in enumerate(data['cases']):
   old=(parents if group==FILES[0]else vmparents)[key(p,group!=FILES[0])];cut=len(old['source_visits']);assert p['source_visits'][:cut]==old['source_visits']and[e for e in p['source_reads']if e['source_visit_index']<cut]==old['source_reads']and[e for e in p['source_writes']if e['source_visit_index']<cut]==old['source_writes']and p['API_model_events'][:len(old['API_model_events'])]==old['API_model_events'];prefixes+=1;assert p['fixture_PC_transitions']==0
   for e in p['source_reads']:
    if'known_mask_hex'in e:assert all(bytes.fromhex(e['known_mask_hex']))
   r=Fresh(p,(j+1)%4);row=r.run();assert row['all_checks_pass'];rows.append({'group':group,**row});totals.update(row['verified_counts']);b=p['boundary'];bounds[b['pc']]+=1;vm=next(e for e in p['API_model_events']if e['pc']=='0x1004776c0');assert vm['symbol']=='libSystem/_vm_deallocate'and vm['slot']=='0x1010a00f8'and vm['modifier']=='0x3893'and vm['arguments8'][1:3]==['0x0','0x0']and vm['return_value']==p['configuration']['VM_cleanup_return_model'];vmreturns+=1;assert snapshot(p,F+0x44a4,4)['defined_bytes_hex']=='699dc274';states[snapshot(p,F+0x6adc,4)['defined_bytes_hex']]+=1
   if group==FILES[0]:assert b['pc']=='0x100541bec'and b['detail']['symbol']=='libSystem/_free'and r.reg('x0')==OBJ
   else:
    free=next(e for e in p['API_model_events']if e['pc']=='0x100541bec');assert free['symbol']=='libSystem/_free'and free['slot']=='0x10109ff30'and free['modifier']=='0x46a2'and int(free['arguments8'][0],16)==OBJ;assert len(p['source_retirements'])==1 and not p['source_retirements'][0]['native_free_executed'];frees+=1
    for e in p['source_reads']+p['source_writes']:
     if e['source_visit_index']>free['source_visit_index']:
      a=int(e['address'],16);postfree_access+=int(a<OBJ+32 and a+e['size_bytes']>OBJ)
    assert b['pc']=='0x10057a774'and b['kind']=='before_unmapped_owner_write'and not any(e['pc']=='0x10057a774'for e in p['source_visits'])and'client_object_final'not in p
   print(group,p['configuration']['VM_cleanup_return_model'],p['source_index'],'fresh A64 pass',flush=True)
 cacheprofiles=json.loads((ROOT/'daemon_vm_cleanup_cache_profiles.json').read_text());assert cacheprofiles['generator_sha256']==sha(ROOT/'probe_vm_cache_transport.py');cache=Cache();ct=Counter();cbounds=Counter();requests=loggers=0
 for j,p in enumerate(cacheprofiles['profiles']):
  result=Replay(cache,p).run();ct.update(result);cbounds[p['stop_reason']]+=1;args=[int(v,16)for v in p['initial_args']];reply=int(p['input_seeds']['reply_name_model'],16);status=p['input_seeds']['trap_results'];assert not p['native_target_executed']and not p['target_host_operations_executed'];trap=next(e for e in p['events']if e['kind']=='intercepted_svc');assert trap['x16_signed']==-12 and[int(v,16)for v in trap['args'][:3]]==args
  for model in p['callback_models']:
   if model['name']=='private_syscall_logger':assert[int(v,16)for v in model['arguments8'][:6]]==[0x20,args[0]&0xffffffff,args[1],args[2],0,0];loggers+=1
  if p['request']:
   q=p['request'];raw=bytes.fromhex(q['bytes_hex']);assert raw==struct.pack('<6I',0x1513,48,args[0]&0xffffffff,reply,0,4801)+bytes.fromhex('0000000001000000')+struct.pack('<2Q',*args[1:]);assert status==[0x10000003]and p['stop_reason']=='mach2_request_frontier';e=p['events'][-1];assert e['pc']=='0x180547c1c'and e['request_bytes_hex']==raw.hex();want=[int(q['buffer'],16),0x200000003,0x3000001513,(reply<<32)|(args[0]&0xffffffff),4801<<32,reply<<32,44,0];assert[int(v,16)for v in q['arguments8']]==[int(v,16)for v in e['arguments8']]==want;requests+=1
  elif status is None:assert p['stop_reason']=='svc_boundary'
  else:assert p['stop_reason']=='returned'and int(p['events'][-1]['x0'],16)==status[0]
 assert len(rows)==96 and prefixes==96 and vmreturns==96 and frees==48 and postfree_access==0 and totals['source_visits']==450384 and bounds==Counter({'0x100541bec':48,'0x10057a774':48})and totals['uninterpreted_probe_read_bytes']==0
 assert len(cacheprofiles['profiles'])==30 and requests==6 and loggers==15 and ct['source_visits_checked']==1206 and cbounds==Counter({'returned':18,'svc_boundary':6,'mach2_request_frontier':6})
 components=json.loads((ROOT/'daemon_vm_cleanup_kernel_components.json').read_text());assert components['generator_sha256']==sha(ROOT/'probe_vm_kernel_ranges.py')and components['kernel_sha256']==c['kernel']['sha256']and components['case_count']==2048 and components['page_shift_values']==256 and components['source_visits']==20480 and components['all_checks_pass'];assert{e['page_shift_byte']for e in components['cases']}==set(range(256))
 for e in components['cases']:
  address,size=int(e['address'],16),int(e['size'],16);mask=(1<<(e['page_shift_byte']&31))-1;total=(address+size)&((1<<64)-1);first=address&~mask;last=(total+mask)&((1<<64)-1)&~mask;assert int(e['sum'],16)==total and e['sum_carry']==int(address+size>=(1<<64))and int(e['start'],16)==first and int(e['end'],16)==last and e['end_at_most_start']==(last<=first)
 deps=FILES+['daemon_vm_cleanup_cache_profiles.json','daemon_vm_cleanup_kernel_components.json','daemon_vm_cleanup_contracts.json','daemon_vm_cleanup_proofs.json','probe_daemon_vm_cleanup.py','probe_daemon_vm_retire.py','probe_vm_cache_transport.py','probe_vm_kernel_ranges.py','recover_daemon_vm_cleanup.py','prove_daemon_vm_cleanup.py','replay_vm_cache_transport.py','validate_daemon_entitlement_flow.py','daemon_client_object_cleanup_profiles.json','daemon_vm_cleanup_sdk.c','daemon_vm_cleanup_sdk.ll'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':{'source_obligations_rebuilt':len(qs),'accepted_SMT_files':files,'daemon_profiles':96,'prior_source_prefixes_preserved':prefixes,'modeled_VM_returns':vmreturns,'modeled_free_requests':frees,'post_free_source_accesses':postfree_access,'cache_profiles':30,'cache_trap12_boundaries':30,'cache_MIG_request_frontiers':requests,'cache_logger_models':loggers,'daemon_universal_return_contexts':len(domains),'kernel_range_component_cases':2048,'kernel_range_source_visits':20480,'kernel_page_shift_values':256,'unique_daemon_source_instructions':len(c['unique_visited_source']),'cache_original_functions':len(c['cache']['functions']),'kernel_original_functions':len(c['kernel']['functions']),'SDK_compile_exit':0},'independent_A64_totals':dict(totals),'independent_cache_A64_totals':dict(ct),'daemon_boundary_counts':dict(bounds),'cache_boundary_counts':dict(cbounds),'daemon_final_state_counts':dict(states),'fresh_daemon_replays':rows,'native_target_executed':False,'native_VM_or_free_executed':False,'native_IPC_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'daemon_runtime_version_match_established':False,'native_port_right_or_emission_observed':False,'full_goal_complete':False,'all_checks_pass':True};(ROOT/'daemon_vm_cleanup_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':out['verified_counts'],'daemon_A64':dict(totals),'cache_A64':dict(ct),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
