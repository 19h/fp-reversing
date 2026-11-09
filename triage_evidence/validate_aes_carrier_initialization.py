#!/usr/bin/env python3
"""Independent original-source/scan recapture, fresh A64 and initialization oracles.
O(image+text+visits+effects), O(image+journals+private RAM); no native effects.
"""
import json,re,hashlib
from collections import Counter
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT,CS
from recover_aes_command_gate import sha
from replay_aes_carrier_initialization import Replay
from validate_aes_provider_queue import read,val
P='aes_carrier_initialization';RAM=0x6500000000;POOL=RAM+0x14000;PGATE=RAM+0x1c000;CARRIERS=[RAM+0x30000+j*0x100 for j in range(32)];CMD=CARRIERS[-1];VIEW=0xfffffe000858a4a8;COUNTER=0xfffffe000cb5b638
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());external=json.loads((ROOT/'aes_command_pool_profiles.json').read_text());counts=Counter();totals=Counter();records=[]
 for obj,script in [(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(script,n)
  for key in ['native_target_executed','native_IPC_executed','native_allocation_executed','hardware_PAC_executed','authentic_completion_status_established','idb_mutated','full_goal_complete']:assert obj[key]is False
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==43 and sum(len(r['instructions'])for r in src['functions'])==2507 and len(src['additional_slots'])==3
 for r in src['functions']:
  a=int(r['start'],16);b=im.k.read(a,int(r['end'],16)-a);assert b.hex()==r.get('bytes_hex',r.get('bytes'))and im.k.symbols([a])[r['start']]==r['exact_symbols']
 for s in src['additional_slots']:
  p=s['pointer'];assert im.pointer(int(p['slot'],16))==p and im.k.symbols([int(p['target'],16)])[p['target']]==s['exact_symbols']and s['exact_symbols']
 view=src['typed_view'];assert view['bytes_hex']==im.k.read(VIEW,64).hex()and view['encoded_size_low24']==144 and view['runtime_zone_identity_established']is False
 ref=src['separately_versioned_reference'];assert ref['sha256']=='3a7bcfed6b5062574a33ac59e15dd97fc8c8a80cc45b37c67f52f5f112c739d9'and ref['matched_collection_source_revision_established']is False and any(e['text']=='Z_ZERO          = 0x0004,'for e in ref['enum_excerpt']);counts['separately_versioned_reference_identity_checked']=1
 hits=[]
 for t in src['status_scan']:
  a=int(t['start'],16);raw=im.k.read(a,t['size_bytes']);assert raw.hex()==t['bytes_hex']and hashlib.sha256(raw).hexdigest()==t['sha256'];ins=list(CS.disasm(raw,a));assert len(ins)==t['instruction_count']and sum(i.size for i in ins)==len(raw)
  rows=[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins if re.search(r'#0x78(?![0-9a-f])',i.op_str)];assert rows==t['literal_0x78_operand_hits']and t['alias_or_indirect_writer_closure_established']is False;hits+=rows
 assert len(hits)==4 and [e['pc']for e in hits]==['0xfffffe000abfd1a8','0xfffffe000abfd3fc','0xfffffe000abfd630','0xfffffe000abfe61c']and all(e['mnemonic']=='ldr'for e in hits[:3])and hits[3]['operands']=='q0, [sp, #0x78]'
 counts.update(scan_text_sections=2,scan_instructions=8210,literal_0x78_operand_hits=4,non_stack_literal_status_reads=3)
 rows=prof['cases'];assert len(rows)==16
 for j,row in enumerate(rows):
  c=row['configuration'];models=row['API_models'];writes=row['source_writes'];assert row['initial_private_fixtures'][:44]==external['cases'][0]['final_objects']and len(row['final_objects'])==44;counts['source_actor_snapshot_transfers_checked']+=1
  for key in ['native_target_executed','native_IPC_executed','native_allocation_executed','hardware_PAC_executed','authentic_completion_status_established','idb_mutated','full_goal_complete']:assert row[key]is False
  for mi,m in enumerate(models):
   args=[int(a,16)for a in m['arguments8']];result=int(m['return_value'],16);sym=m['symbol'];expected=[hex(((r+1)*0x123456789abcdef)^(mi+1)*0x8b3dc651)for r in range(18)];expected[0]=hex(result)
   assert m['after_registers31'][:18]==expected and int(m['after_NZCV'],16)==(0xf0000000 if(mi+1)&1 else 0)and m['native_effects_executed']is False
   if sym=='typed_command_backend_zero_model':
    assert j==15 and args[:2]==[VIEW,4]and result==CARRIERS[counts['typed_backend_zero_models_checked']];effects=m['memory_effects'];assert len(effects)==1 and effects[0]['address']==hex(result)and effects[0]['before_hex']=='5a'*144 and effects[0]['after_hex']=='00'*144;counts['typed_backend_zero_models_checked']+=1
   else:
    assert not m['memory_effects']
    if sym=='command_class_bookkeeping_model':assert args[0]==0xfffffe000cce14e0 and result==0
    elif sym=='on_thread_model':assert args[0]==RAM+0x13000 and result==1
    else:assert sym in ['close_gate_no_effect_model','open_gate_no_effect_model']and args[0]==RAM+0x13000 and result==0
   counts['API_'+sym]+=1
  if c['stage']=='frontier':
   size=c['requested_bytes'];assert not models and row['boundary']['kind']=='before_allocation_backend'and len(row['allocation_frames'])==1 and len(row['backend_frontiers'])==1 and not row['constructor_frames']and int.from_bytes(bytes.fromhex(row['final_counter_hex']),'little')==0
   f=row['backend_frontiers'][0]
   if size<=144:assert f['pc']=='0xfffffe000bcfeb8c'and f['arguments4'][:2]==[hex(VIEW),'0x4'];counts['typed_size_boundary_cases_checked']+=1
   else:assert f['pc']=='0xfffffe000bcfe5b8'and f['arguments4']==['0xfffffe0007f36938',hex(size),'0x41004','0x0'];counts['fallback_u64_size_boundary_cases_checked']+=1
  elif c['stage']=='constructor':
   assert row['boundary']['kind']=='returned'and row['boundary']['registers31'][0]==hex(CMD)and len(row['constructor_frames'])==1 and row['constructor_frames'][0]['before144_hex']==('%02x'%c['initial_byte'])*144 and int.from_bytes(bytes.fromhex(row['final_counter_hex']),'little')==0
   final=read(row,CMD,144);initial=bytes([c['initial_byte']])*144;assert final[:8]==int(src['derived_command_vptr'],16).to_bytes(8,'little')and final[8:12]==(1).to_bytes(4,'little')and final[12:]==initial[12:]
   assert not row['allocation_frames']and not row['backend_frontiers'];counts['constructor_tail_preservation_cases_checked']+=1
   assert any(e['pc']=='0xfffffe000c51fb60'and e['address']==hex(CMD+8)and e['after_hex']=='01000000'for e in writes)
  else:
   assert j==15 and row['boundary']['kind']=='after_registration_component'and len(row['allocation_frames'])==32 and len(row['command_allocations'])==32 and len(row['constructor_frames'])==32 and len(models)==160
   assert all(e['arguments2']==[hex(VIEW),'0x90']for e in row['allocation_frames'])and all(e['before144_hex']=='00'*144 for e in row['constructor_frames'])
   assert int.from_bytes(bytes.fromhex(row['final_counter_hex']),'little')==32*144
   counter=[e for e in writes if e['address']==hex(COUNTER)];assert len(counter)==32 and all(e['pc']=='0xfffffe000c445918'and int.from_bytes(bytes.fromhex(e['after_hex']),'little')==(k+1)*144 for k,e in enumerate(counter));counts['source_accounting_additions_checked']=32
   assert val(row,POOL+0x10)==CARRIERS[-1]and val(row,POOL+0x18)==CARRIERS[0]and val(row,PGATE+0x48)==0
   for k,a in enumerate(CARRIERS):
    assert val(row,a)==int(src['derived_command_vptr'],16)and val(row,a+8,4)==1 and val(row,a+0x78,4)==0
    assert val(row,a+0x10)==(CARRIERS[k-1]if k else POOL+0x10)and val(row,a+0x18)==(CARRIERS[k+1]if k<31 else POOL+0x10)
    assert not any(int(e['address'],16)<=a+0x78<int(e['address'],16)+e['size_bytes']for e in writes)
   counts['source_constructed_seed_carriers_checked']=32
  totals.update(Replay(im,row).run());records.append({'case':j,'configuration':c,'source_visits':len(row['source_visits']),'API_models':len(models),'boundary':row['boundary']['kind'],'allocation_counter_bytes':int.from_bytes(bytes.fromhex(row['final_counter_hex']),'little')});print(json.dumps({**records[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=16,functions=43,captured_instructions=2507,additional_slots=3)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [P+'_source.json',P+'_profiles.json','aes_command_pool_profiles.json','validate_aes_provider_queue.py','replay_'+P+'.py','replay_aes_command_pool.py','replay_workloop_gate_attachment.py','replay_aes_command_gate.py','replay_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'case_summaries':records,'all_checks_pass':True,'native_target_executed':False,'native_IPC_executed':False,'native_allocation_executed':False,'hardware_PAC_executed':False,'authentic_completion_status_established':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
