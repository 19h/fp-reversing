#!/usr/bin/env python3
"""Fresh original-instruction replay plus independent API/flag/output oracles.
O(visits+effects+image bytes), O(unique PCs+effects+private RAM); no target effects.
"""
import hashlib,json,struct
from collections import Counter
from pathlib import Path
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_kext_constructor_request import sha
from replay_kext_startup_hardware_bridge import Replay
P='kext_startup_hardware_bridge';RAM=0x6500000000;SP=RAM+0xf0000;OUT=RAM+0x81000;OUTSLOT=SP-0x88
PROVIDER=RAM+0xd0700;DESC=RAM+0xd0800;TASK=RAM+0xd0900;BUFFER=RAM+0xb0000;DICT=RAM+0xd0000
READY=0xfffffe000cccea88;WARM=0xfffffe000ccca078;HW=0xfffffe000ccceb00;PG=HW+8;DG=HW+16;BG=0xfffffe000ccc7848;HEAD=0xfffffe000cccca58
def integer(h):return int.from_bytes(bytes.fromhex(h),'little')
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());counts=Counter();totals=Counter();details=[]
 for obj,script in [(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
  for n in ['native_target_executed','idb_mutated','full_goal_complete']:assert obj[n]is False
 assert src['kernel_sha256']==im.k.sha256 and len(src['ranges'])==7 and len(src['slots'])==9 and len(src['views'])==2
 for r in src['ranges']:assert im.k.read(int(r['start'],16),int(r['end'],16)-int(r['start'],16)).hex()==r['bytes_hex']
 for s in src['slots']:
  ptr=s['pointer'];assert im.pointer(int(ptr['slot'],16))==ptr and im.k.symbols([int(ptr['target'],16)])[ptr['target']]==s['exact_symbols']and s['exact_symbols']
 for v in src['views']:assert im.k.read(int(v['address'],16),64).hex()==v['bytes64_hex']and v['name']=='site.FPAESParameters'and v['size_bytes']==104
 assert sha(Path(src['SDK_timespec_reference']['path']))==src['SDK_timespec_reference']['sha256']
 rows=prof['cases'];assert [r['configuration']['variant']for r in rows]==['frontier','absent','descriptor_null','prepare_error','hardware_error'];origin=rows[0]['startup_snapshot'];assert origin['SP']==hex(SP)and int(origin['registers31'][0],16)==0
 ram=bytes.fromhex(origin['RAM_hex']);bss=bytes.fromhex(origin['BSS_hex']);assert len(ram)==0x100000 and len(bss)==0x10000 and hashlib.sha256(ram).hexdigest()==origin['RAM_sha256']and hashlib.sha256(bss).hexdigest()==origin['BSS_sha256']
 assert origin['output_slot4_hex']==ram[OUTSLOT-RAM:OUTSLOT-RAM+4].hex()
 assert bss[READY-0xfffffe000ccc0000]==1 and bss[WARM-0xfffffe000ccc0000]==0 and bss[HW-0xfffffe000ccc0000]==0
 assert struct.unpack_from('<Q',bss,0xda68)[0]==RAM+0x21000 and struct.unpack_from('<I',bss,0xeaf8)[0]==255
 writers=[e for e in rows[0]['bridge_effects']if e['phase']==0 and int(e['address'],16)<=OUTSLOT<int(e['address'],16)+e['size_bytes']];assert writers;last=writers[-1];off=OUTSLOT-int(last['address'],16);assert bytes.fromhex(last['after_hex'])[off:off+4].hex()==origin['output_slot4_hex']
 for j,row in enumerate(rows):
  variant=row['configuration']['variant'];models=row['API_models'];depth={int(a,16):v['depth']for a,v in row['initial_lock_owners'].items()};alive={int(a,16):v['alive']for a,v in row['initial_lock_owners'].items()};cursor=origin['resource_state']['cursor']if j else RAM+0x21000
  if j:
   assert row['source_producer_case']==0 and row['startup_snapshot']is None and row['entry_phase']==1 and row['entry_PC']=='0xfffffe000a66a7e0'
   assert row['initial_private_fixtures']==[{'address':hex(RAM),'bytes_hex':origin['RAM_hex'],'provenance':'Exact original startup-produced RAM; no reset or owner reconstruction'}]
   assert row['initial_image_fixtures'][-1]['address']=='0xfffffe000ccc0000'and row['initial_image_fixtures'][-1]['bytes_hex']==origin['BSS_hex']and row['initial_lock_owners']==origin['resource_state']['locks']and row['initial_model_count']==origin['model_count']and row['initial_Q32']==origin['Q32']and row['initial_FPCR']==origin['FPCR']and row['initial_FPSR']==origin['FPSR'];counts['exact_source_produced_forks_checked']+=1
  else:assert row['entry_phase']==0 and len(row['declared_call_transitions'])==1 and row['declared_call_transitions'][0]['RAM_sha256']==origin['RAM_sha256']and row['declared_call_transitions'][0]['BSS_sha256']==origin['BSS_sha256']
  for mi,m in enumerate(models):
   sym=m['symbol'];args=[int(v,16)for v in m['arguments8']];result=int(m['return_value'],16);effects=m['memory_effects'];ordinal=row['initial_model_count']+mi+1;assert m['model_ordinal']==ordinal and m['native_effects_executed']is False
   expected=[hex(((r+1)*0x123456789abcdef)^ordinal*0x8b3dc651)for r in range(18)];expected[0]=hex(result);assert m['after_registers31'][:18]==expected and int(m['after_NZCV'],16)==(0xf0000000 if ordinal&1 else 0);counts['API_'+sym]+=1
   if sym=='aligned_allocation_model':assert args[:2]==[16384,64]and result==RAM+0x10000 and not effects
   elif sym=='typed_allocation_model':assert args[0]==0xfffffe000847bea0 and result==RAM+0x20000 and not effects
   elif sym in ['data_allocation_model','generic_allocation_model','typed_other_model']:
    size=(struct.unpack('<I',im.k.read(args[0]+44,4))[0]&0xffffff)if sym=='typed_other_model'else args[0];assert result==cursor and not effects;cursor+=(size+4095)&~4095
    if sym=='typed_other_model':assert args[0]==0xfffffe000847b460 and size==104 and result==RAM+0x25000
   elif sym=='lock_allocation_model':assert result and result not in depth and not effects;depth[result]=0;alive[result]=True
   elif sym in ['lock_model','unlock_model','lock_free_model']:
    assert args[0]in depth and alive[args[0]]and result==0 and not effects
    if sym=='lock_model':assert depth[args[0]]==0;depth[args[0]]=1
    elif sym=='unlock_model':assert depth[args[0]]==1;depth[args[0]]=0
    else:assert depth[args[0]]==0;alive[args[0]]=False
   elif sym=='calendar_time_model':assert result==0 and len(effects)==2 and effects[0]['address']==hex(args[0])and effects[0]['after_hex']==struct.pack('<Q',1700000000).hex()and effects[1]['address']==hex(args[1])and effects[1]['after_hex']==struct.pack('<I',123456).hex()
   elif sym=='matching_dictionary_model':assert args[:2]==[0xfffffe000790ba3c,0]and result==DICT and not effects
   elif sym in ['absent_provider_model','nominal_provider_model']:
    assert args[0]==DICT and result==(0 if variant=='absent'else PROVIDER)
    assert effects==[]if variant=='absent'else len(effects)==1 and effects[0]['address']==hex(PROVIDER)and effects[0]['after_hex']==struct.pack('<Q',0xfffffe0008588380).hex()
   elif sym=='retain_no_effect_model':assert args[0]==PROVIDER and result==0 and not effects
   elif sym in ['descriptor_NULL_model','nominal_descriptor_model']:
    assert args[:4]==[TASK,0x13,81920,16384]and result==(0 if variant=='descriptor_null'else DESC)
    assert effects==[]if variant=='descriptor_null'else len(effects)==1 and effects[0]['address']==hex(DESC)and effects[0]['after_hex']==struct.pack('<Q',0xfffffe0007f85d80).hex()
   elif sym=='prepare_model':assert args[:2]==[DESC,0]and result==(4 if variant=='prepare_error'else 0)and not effects
   elif sym=='buffer_address_model':assert args[0]==DESC and result==BUFFER and not effects
   elif sym=='memcpy_model':assert args[2]in [16,32]and RAM<=args[0]<args[0]+args[2]<=RAM+0x100000 and RAM<=args[1]<args[1]+args[2]<=RAM+0x100000 and(args[0]+args[2]<=args[1]or args[1]+args[2]<=args[0])and result==args[0]and len(effects)==1 and effects[0]['address']==hex(args[0])and len(bytes.fromhex(effects[0]['after_hex']))==args[2]
   elif sym=='hardware_nonzero_result_model':assert variant=='hardware_error'and result==4 and not effects and m['pc']=='0xfffffe000abff358'
   elif sym in ['logger_no_effect_model','diagnostic_logger_no_effect_model']:assert result==0 and not effects
   else:
    assert sym=='free_no_effect_model'and result==0 and not effects
    if m['pc']=='0xfffffe000c4ba368':assert args[:2]in [[0xfffffe000847ba60,RAM+0x20000],[0xfffffe000847b3a0,RAM+0x25000]]
  assert row['final_lock_owners']=={hex(a):{'depth':d,'alive':alive[a]}for a,d in depth.items()}
  assert {a:d for a,d in depth.items()if d}==({RAM+0x82200:1}if variant=='frontier'else{});counts['hardware_frontier_or_balanced_return_lock_states_checked']+=1
  expected={READY:1,WARM:0,HW:int(variant in ['frontier','hardware_error']),PG:0 if variant=='absent'else PROVIDER,DG:0 if variant in ['absent','descriptor_null']else DESC,BG:BUFFER if variant in ['frontier','hardware_error']else 0,HEAD:0};assert{int(a,16):integer(h)for a,h in row['final_flags_hex'].items()}==expected
  assert len(row['timeouts'])==1 and row['timeouts'][0]['bytes_hex']=='0000000001000000';counts['one_nanosecond_timeout_cases']+=1
  assert not any(int(r['pc'],16)in [0xfffffe000a5a2064,0xfffffe000a5a22d4]for r in row['original_PC_coverage'])and not any('rpc'in m['symbol'].lower()for m in models)
  slot_writes=[e for e in row['bridge_effects']if e['phase']==1 and int(e['address'],16)<OUTSLOT+4 and OUTSLOT<int(e['address'],16)+e['size_bytes']];assert not slot_writes
  if j:
   assert len(row['returns'])==1 and row['returns'][0]['SP']==hex(SP)and int(row['returns'][0]['registers31'][0],16)==0xffff5bea and row['final_output8_hex']==struct.pack('<Q',integer(origin['output_slot4_hex'])).hex()
   outwrites=[e for e in row['bridge_effects']if e['phase']==1 and e['address']==hex(OUT)];assert len(outwrites)==1 and outwrites[0]['pc']=='0xfffffe000a66ab60'and outwrites[0]['size_bytes']==8 and outwrites[0]['after_hex']==row['final_output8_hex'];assert any(e['pc']=='0xfffffe000a66ab58'and e['address']==hex(OUTSLOT)and e['bytes_hex']==origin['output_slot4_hex']for e in row['bridge_reads']);counts['error_return_and_output_copies_checked']+=1
  else:assert row['boundary']['pc']=='0xfffffe000abff358'and row['final_output8_hex']=='a5'*8 and len(row['returns'])==1
  if variant in ['frontier','hardware_error']:
   assert len(row['AES_boundaries'])==1;aes=row['AES_boundaries'][0];args=[int(v,16)for v in aes['arguments8']];assert args[:4]==[PROVIDER,DESC,DESC,32]and RAM<=args[4]<RAM+0x100000 and args[5]==0 and RAM<=args[6]<RAM+0x100000 and args[7]==0 and aes['stack24_hex']=='00'*24 and aes['IV16_hex']=='00'*16 and aes['buffer32_sha256']==hashlib.sha256(bytes.fromhex([m['memory_effects'][0]['after_hex']for m in models if m['symbol']=='memcpy_model'and m['arguments8'][0]==hex(BUFFER)and int(m['arguments8'][2],16)==32][-1])).hexdigest();counts['actual_global_buffer_AES_frontiers_checked']+=1
  else:assert not row['AES_boundaries']
  totals.update(Replay(im,row).run());details.append({'case':j,'variant':variant,'source_visits':row['fingerprints']['visits']['count'],'API_models':len(models),'logical_data_authentications':len(row['logical_data_authentication']),'bridge_effects':len(row['bridge_effects']),'bridge_reads':len(row['bridge_reads']),'boundary':row['boundary']['pc'],'output8_hex':row['final_output8_hex']});print(json.dumps({**details[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=len(rows),ranges=len(src['ranges']),captured_instructions=sum(len(r['instructions'])for r in src['ranges']),exact_slots=len(src['slots']),views=len(src['views']))
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [P+'_source.json',P+'_profiles.json','replay_'+P+'.py','replay_kext_provider_initialize.py','kernel_vm_mig_tools.py']},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'case_summaries':details,'startup_output_slot_last_writer':last,'startup_output_slot4_hex':origin['output_slot4_hex'],'all_checks_pass':True,'native_target_executed':False,'native_IPC_executed':False,'native_allocator_executed':False,'native_lock_executed':False,'native_clock_executed':False,'native_provider_start_executed':False,'native_hardware_AES_executed':False,'native_constructor_established':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
