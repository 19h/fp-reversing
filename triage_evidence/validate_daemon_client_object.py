#!/usr/bin/env python3
"""Rebuild original-source contracts and both SMT forms; independently replay
80 continuous profiles with altered undefined backing. Verify frozen prefixes,
allocation epochs/definedness, exact initialization, borrowed fields and stops.
O(profile/source/artifact bytes + solver/compiler resources) time;
O(one private CPU map + journals + BV DAGs) space. No native target or IPC.
"""
import json
from collections import Counter
import z3
from daemon_receive_tools import ROOT,IMAGE
from daemon_output_base_dispatch import CS
from capture_daemon_record720 import sha
from recover_daemon_client_object import recover,FILES
from prove_daemon_client_object import obligations
from recover_daemon_entitlement_flow import snapshot
from validate_daemon_entitlement_flow import Fresh
P=0x6800000000;F=0x680004f230
def written_registers(ins):
 # This Capstone encoding incorrectly marks CMP's first operand written.
 # SUBS XZR,X10,#0 changes NZCV only; the local BV proof also checks X10.
 if ins.address==0x10055972c:
  assert bytes(ins.bytes).hex()=='5f0100f1'and ins.mnemonic=='cmp'and ins.op_str=='x10, #0'
  return {'nzcv'}
 return {ins.reg_name(r)for r in ins.regs_access()[1]}
def main():
 c=json.loads((ROOT/'daemon_client_object_contracts.json').read_text());proof=json.loads((ROOT/'daemon_client_object_proofs.json').read_text());assert recover()==c;qs,counts=obligations();assert counts==proof['source_lift_counts']and len(qs)==len(proof['proofs']);files=0
 for (name,q),row in zip(qs,proof['proofs'],strict=True):
  assert name==row['name'];s=z3.Solver();s.set(timeout=30000);s.add(q);assert s.check()==z3.unsat
  for f,h in [('file','sha256'),('original_file','original_sha256')]:
   assert sha(ROOT/row[f])==row[h];s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_file(str(ROOT/row[f])));assert s.check()==z3.unsat;files+=1
 old=[]
 for n in ['daemon_boolean_chain_profiles.json','daemon_boolean_chain_mixed_profiles.json']:old+=json.loads((ROOT/n).read_text())['cases']
 plans={'neither':'boolean_false','both':'boolean_true','coreml_only':'coreml_only','classic_only':'classic_only'};parents={(p['configuration']['query_result_model'],p['configuration']['Boolean_chain_model'],p['source_index']):p for p in old};groups={n:json.loads((ROOT/n).read_text())for n in FILES};objects={(p['configuration']['query_result_model'],p['configuration']['client_bit_plan'],p['source_index']):p for p in groups[FILES[0]]['cases']if p['configuration']['client_object_allocation']=='nonnull'};pairs={(p['configuration']['query_result_model'],p['configuration']['client_bit_plan'],p['source_index']):p for p in groups[FILES[1]]['cases']if p['configuration']['client_pair_allocation']=='null'};rows=[];totals=Counter();bounds=Counter();states=Counter();prefixes=allocs=init32=init16=0;borrowed=vm_calls=0;state_reads=numeric_reads=0
 for a,z,keep in [(0x100477654,0x100477690,{'x0','w0','x1','w1','x8','w8','x20','w20'}),(0x100477698,0x1004776a0,{'x0','w0','x1','w1','x8','w8','x11','w11','x19','w19'}),(0x1004776a8,0x1004776c0,{'x0','w0','x1','w1','x2','w2'})]:
  for ins in CS.disasm(IMAGE.read(a,z-a),a):assert not(written_registers(ins)&keep),(hex(ins.address),ins.mnemonic,ins.op_str)
 for a,z,keep in [(0x100559710,0x10055975c,{'x9','w9'}),(0x10055972c,0x10055975c,{'x10','w10'}),(0x100500a1c,0x100500a44,{'x9','w9','x10','w10'}),(0x1006997a4,0x1006997cc,{'x9','w9','x10','w10'})]:
  for ins in CS.disasm(IMAGE.read(a,z-a),a):assert not(written_registers(ins)&keep),(hex(ins.address),ins.mnemonic,ins.op_str)
 for group,script in zip(FILES,['probe_daemon_client_object.py','probe_daemon_client_pair.py','probe_daemon_client_cleanup.py'],strict=True):
  data=groups[group];assert data['generator_sha256']==sha(ROOT/script)
  for n,h in data['dependencies'].items():assert sha(ROOT/n)==h
  for j,p in enumerate(data['cases']):
   cfg=p['configuration'];first,plan,env=cfg['query_result_model'],cfg['client_bit_plan'],p['source_index'];parent=parents[(first,plans[plan],env)]if group==FILES[0]else(objects if group==FILES[1]else pairs)[(first,plan,env)];cut=len(parent['source_visits']);assert p['source_visits'][:cut]==parent['source_visits'];assert[e for e in p['source_reads']if e['source_visit_index']<cut]==parent['source_reads'];assert[e for e in p['source_writes']if e['source_visit_index']<cut]==parent['source_writes'];assert p['API_model_events'][:len(parent['API_model_events'])]==parent['API_model_events'];prefixes+=1;assert p['fixture_PC_transitions']==0
   for e in p['source_reads']:
    if'known_mask_hex'in e:assert all(bytes.fromhex(e['known_mask_hex']))
   r=Fresh(p,(j+1)%4);row=r.run();assert row['all_checks_pass'];rows.append({'group':group,**row});totals.update(row['verified_counts']);b=p['boundary'];bounds[b['pc']]+=1;allocation=p['client_object_allocations'];assert len(allocation)==(1 if group==FILES[0]else 2);allocs+=len(allocation);firstcut=allocation[0]['source_visit_index'];models=[e for e in p['API_model_events']if e['pc']in ['0x100570148','0x100699858']];assert len(models)==len(allocation)
   expected=(0xa if first=='boolean_true'else 8)|(1 if plan in ['coreml_only','both']else 0)|(2 if plan in ['classic_only','both']else 0);assert int.from_bytes(bytes(r.u.mem_read(F+0x6adc,4)),'little')==expected;states[hex(expected)]+=1
   for k,(event,a)in enumerate(zip(models,allocation,strict=True)):
    size=[32,16][k];assert event['symbol']=='libSystem/_malloc'and event['slot']=='0x10109ff58'and event['modifier']=='0x6aa4'and int(event['arguments8'][0],16)==size==a['size_bytes'];assert event['return_value']==a['returned_address']and not event.get('memory_models')and not a['native_allocator_executed']and not a['contents_initially_defined'];at=int(a['returned_address'],16)
    if at:assert at==P+[0x30000,0x31000][k]and snapshot(p,at,size,a['source_visit_index'])['known_mask_hex']=='00'*size
   for e in p['source_reads']:
    if e['source_visit_index']>=firstcut:
     at=int(e['address'],16);end=at+e['size_bytes'];state_reads+=int(at<F+0x6ae0 and end>F+0x6adc);numeric_reads+=int(at<F+0x1284 and end>F+0x1280)
   if cfg['client_object_allocation']=='null':
    assert b['pc']=='0x10057a774'and b['kind']=='before_unmapped_owner_write';assert snapshot(p,F+0x44a4,4)['defined_bytes_hex']=='859dc274';assert r.reg('x9')==int.from_bytes(bytes.fromhex(snapshot(p,F+0x1a30,8)['defined_bytes_hex']),'little');assert not any(e['pc']=='0x10057a774'for e in p['source_visits']);continue
   init32+=1;obj=p['client_object_final'];expected32=bytes(8)+bytes.fromhex('51c63d8b')*3+bytes.fromhex('dc16894d51c63d8b');assert obj['known_mask_hex']=='01'*28+'00'*4 and bytes.fromhex(obj['bytes_hex'])[:28]==expected32 and bytes(r.u.mem_read(P+0x30000,28))==expected32
   writes=[e for e in p['source_writes']if P+0x30000<=int(e['address'],16)<P+0x30020];assert sum(e['size_bytes']for e in writes)==28 and set(e['pc']for e in writes)=={'0x1005596c4','0x1005596d0','0x1005596dc','0x1005596e0'};assert snapshot(p,F+0x3650,8)['defined_bytes_hex']==(P+0x30000).to_bytes(8,'little').hex()
   B=bytes.fromhex(snapshot(p,P+0x1000,72)['defined_bytes_hex']);root=int.from_bytes(B[:8],'little');length=int.from_bytes(B[8:12],'little');assert int.from_bytes(bytes.fromhex(snapshot(p,F+0x3818,8)['defined_bytes_hex']),'little')==root and int.from_bytes(bytes.fromhex(snapshot(p,F+0x7550,4)['defined_bytes_hex']),'little')==(length^0x8b3dc651)and snapshot(p,F+0x4d50,8)['defined_bytes_hex']=='00'*8;borrowed+=1
   if group==FILES[0]:assert b['pc']=='0x100699858'and b['detail']['symbol']=='libSystem/_malloc'and r.reg('x0')==16
   elif group==FILES[2]:
    assert b['pc']=='0x1004776c0'and b['kind']=='before_unmodeled_import_call'and b['detail']['symbol']=='libSystem/_vm_deallocate'and b['detail']['modifier']=='0x3893';assert r.reg('x0')==int(cfg['cleanup_task_word_model'],16)and r.reg('x1')==r.reg('x2')==0;assert snapshot(p,F+0x1930,8)['defined_bytes_hex']==(P+0x30000).to_bytes(8,'little').hex();read=next(e for e in p['source_reads']if e['pc']=='0x100477644');assert read['size_bytes']==4;assert snapshot(p,F+0x9d0,8)['defined_bytes_hex']=='f46c000000000000';vm_calls+=1
   elif cfg['client_pair_allocation']=='null':
    assert b['pc']=='0x100477644'and b['kind']=='before_unavailable_imported_data'and b['detail']['symbol']=='libSystem/_mach_task_self_';assert snapshot(p,F+0x1930,8)['defined_bytes_hex']==(P+0x30000).to_bytes(8,'little').hex()
   else:
    init16+=1;assert p['client_pair_final']['known_mask_hex']=='01'*16 and p['client_pair_final']['bytes_hex']=='00'*16 and bytes(r.u.mem_read(P+0x31000,16))==bytes(16);assert b['pc']=='0x100670470'and b['kind']=='before_unmapped_owner_access'and int(b['detail']['address'],16)==(root+6)&((1<<64)-1)and length>9;assert not any(e['pc']=='0x100670470'for e in p['source_visits'])
   print(first,plan,env,cfg['client_object_allocation'],cfg.get('client_pair_allocation'),'fresh A64 pass',flush=True)
 assert len(rows)==80 and prefixes==80 and allocs==128 and init32==64 and init16==16 and borrowed==64 and vm_calls==16 and state_reads==numeric_reads==0 and bounds==Counter({'0x10057a774':16,'0x100699858':16,'0x100477644':16,'0x100670470':16,'0x1004776c0':16})and totals['uninterpreted_probe_read_bytes']==0
 deps=FILES+['daemon_client_object_contracts.json','daemon_client_object_proofs.json','probe_daemon_client_object.py','probe_daemon_client_pair.py','probe_daemon_client_cleanup.py','recover_daemon_client_object.py','prove_daemon_client_object.py','validate_daemon_entitlement_flow.py','daemon_boolean_chain_profiles.json','daemon_boolean_chain_mixed_profiles.json','daemon_client_object_sdk.c','daemon_client_object_sdk.ll'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':{'source_obligations_rebuilt':len(qs),'accepted_SMT_files':files,'profile_cases':len(rows),'prior_source_prefixes_preserved':prefixes,'declared_allocation_requests':allocs,'object32_initializers':init32,'pair16_initializers':init16,'borrowed_span_contexts':borrowed,'VM_deallocate_call_frontiers':vm_calls,'post_allocation_state_reads':state_reads,'post_allocation_numeric_reads':numeric_reads,'unique_visited_source_instructions':len(c['unique_visited_source']),'original_dispatch_edges':len(c['dispatch_edges']),'SDK_compile_exit':0},'independent_A64_totals':dict(totals),'boundary_counts':dict(bounds),'final_state_counts':dict(states),'fresh_replay_cases':rows,'native_target_executed':False,'native_allocator_executed':False,'native_framework_calls_executed':False,'native_authorization_outcome_established':False,'hardware_PAC_executed':False,'idb_mutated':False,'new_port_emission_established':False,'full_goal_complete':False,'all_checks_pass':True};(ROOT/'daemon_client_object_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':out['verified_counts'],'A64_totals':dict(totals),'boundaries':dict(bounds),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
