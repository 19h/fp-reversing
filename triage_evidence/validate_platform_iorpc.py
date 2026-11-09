#!/usr/bin/env python3
"""Original local IORPC packet/layout, callback, status and output oracles.
O(image+visits+effects+objects), O(image+journals+private RAM); no native effects.
"""
import json,struct,subprocess
from pathlib import Path
from collections import Counter
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from replay_platform_iorpc import Replay
from validate_aes_provider_queue import read,val
P='platform_iorpc';R=0x6500000000;DEV=R+0x2a000;CTRL=R+0x2d000;CONTEXT=R+0x2e000;OUT=R+0x2f000;THREAD=R+0x1b000;CUSTOM=R+0xe2000
METHODS={'clock':(0xfffffe0008cf98e8,0xfffffe0008cb47c0,0x98ae300572af31c2,92,60,128),'power':(0xfffffe0008cf9994,0xfffffe0008cb47f4,0xd33e8303066fa5d3,92,64,132),'psd':(0xfffffe0008cf9b9c,0xfffffe0008cb4890,0x9817bbdfffd2803c,100,60,128)}
FLAGS=['native_target_executed','native_IPC_executed','native_registry_or_platform_effects_executed','native_remote_transport_executed','runtime_metaclass_hierarchy_established','runtime_device_or_controller_identity_established','hardware_PAC_executed','idb_mutated','full_goal_complete']
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());origin=json.loads((ROOT/'aes_platform_gate_profiles.json').read_text())['cases'][0];counts=Counter();totals=Counter();records=[]
 for obj,script in [(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(script,n)
  assert all(obj[k]is False for k in FLAGS)
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==88 and sum(len(r['instructions'])for r in src['functions'])==7533
 for f in src['functions']:
  a=int(f['start'],16);b=im.k.read(a,int(f['end'],16)-a);assert b.hex()==f.get('bytes_hex',f.get('bytes'))and im.k.symbols([a])[f['start']]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(b,a)]==f['instructions']
 for s in src['additional_slots']+src['iorpc_slots']:
  p=s['pointer'];assert im.pointer(int(p['slot'],16))==p and im.k.symbols([int(p['target'],16)])[p['target']]==s['exact_symbols']
 assert len(src['iorpc_slots'])==2 and all(s['pointer']['auth']==1 and s['pointer']['address_diversity']==1 and s['pointer']['key']==0 for s in src['iorpc_slots'])
 for s in src['rpc_stubs']:assert im.k.read(int(s['start'],16),16).hex()==s['bytes_hex']
 c=src['iorpc_constants'];assert im.k.read(int(c['address'],16),len(c['bytes_hex'])//2).hex()==c['bytes_hex']
 for h in [src['SDK_IORPC_reference'],*src['SDK_layout_probe']['message_headers']]:assert sha(Path(h['path']))==h['sha256']
 layout=src['SDK_layout_probe'];assert layout['matched_collection_source_revision_established']is False and len(layout['probes'])==2 and layout['native_target_executed']is False
 for p in layout['probes']:
  assert p['exit_code']==0 and p['command'][0]=='clang++'and '-fsyntax-only'in p['command']and p['command'][-1]=='-'and ('-DKERNEL'in p['command'])==p['kernel'];r=subprocess.run(p['command'],input=layout['source'],capture_output=True,text=True);assert r.returncode==0 and r.stderr==p['stderr'];counts['fresh_SDK_layout_compiles_checked']+=1
 rows=prof['cases'];assert len(rows)==18
 for j,row in enumerate(rows):
  cfg=row['configuration'];method=cfg['method'];invoke,thunk,msgid,send,reply_size,capacity=METHODS[method];models=row['API_models'];assert all(row[k]is False for k in FLAGS)and row['boundary']['kind']=='returned'and row['boundary']['SP']==row['entry_SP']and len(row['final_objects'])==160
  assert row['initial_private_fixtures'][:158]==origin['final_objects']and row['final_source_globals']==origin['final_source_globals'];counts['exact_object_and_global_transfers_checked']+=1
  for e in origin['final_objects']:assert read(row,int(e['address'],16),len(e['bytes_hex'])//2).hex()==e['bytes_hex'];counts['prior_objects_preserved']+=1
  assert val(row,THREAD+0x378)==0x1122334455667788 and read(row,OUT+4,12)==b'\xa5'*12 and val(row,OUT,4)==(0x12345678 if j==4 else 0xa5a5a5a5)
  assert len(row['rpc_frames'])==1;f=row['rpc_frames'][0];a=int(f['message_address'],16);assert f['reply_address']==hex(a)and f['content_address']==hex(a+0x34)and f['send_size']==send and f['reply_capacity']==capacity and f['rpc32_hex']==struct.pack('<QQIIQ',a,a,send,capacity,a+0x34).hex()and f['arguments'][0]==hex(DEV)
  request=bytearray(capacity)
  for off,fmt,v in [(4,'I',send),(0x1c,'I',0x4da2b68c),(0x20,'I',1),(0x34,'Q',msgid),(0x3c,'Q',0x80),(0x44,'Q',1),(0x4c,'Q',DEV),(0x54,'I',1),(0x58,'I',0)]:struct.pack_into('<'+fmt,request,off,v)
  if method=='psd':struct.pack_into('<II',request,0x5c,0xffffffff,0xffffffff)
  assert f['packet_hex']==request.hex();counts['source_request_packet_oracles_checked']+=1
  if j<7:
   assert f['pc']=='0xfffffe000c5957d4'and[e['pc']for e in row['dispatch_frames']]==['0xfffffe0008cf9500','0xfffffe0008cf9530']and len(row['invoke_frames'])==len(row['thunk_frames'])==len(row['thread_frames'])==1
   iv=row['invoke_frames'][0];assert iv['pc']==hex(invoke)and iv['arguments'][1:]==[hex(DEV),hex(thunk)]and iv['rpc32_hex']==f['rpc32_hex'];kernel_request=bytearray(request);struct.pack_into('<Q',kernel_request,0x3c,0x84);assert iv['packet_hex']==kernel_request.hex()
   expected_args=[DEV,1,0]if method=='clock'else[DEV,1,a+0x3c,0]if method=='power'else[DEV,1,0,0xffffffff,0xffffffff];assert[int(x,16)for x in row['thunk_frames'][0]['arguments']]==expected_args
   assert[int(x,16)for x in row['controller_method_frames'][0]['arguments']]==([CTRL,0x123,1]if method=='clock'else[CTRL,0x456,1,a+0x3c]if method=='power'else[CTRL,0x789,0xffffffff,CONTEXT,0xa])
   thread_writes=[e for e in row['source_writes']if e['address']==hex(THREAD+0x378)];assert len(thread_writes)==2 and[e['after_hex']for e in thread_writes]==['00'*8,'8877665544332211']and thread_writes[0]['source_visit_index']<iv['before_source_visit_index']<thread_writes[1]['source_visit_index'];counts['local_Dispatch_Invoke_thunk_backend_chains_checked']+=1;counts['thread_context_clear_restore_pairs_checked']+=1
   if j<3:
    assert not models and int(row['boundary']['registers31'][0],16)==0xe00002c7 and row['final_rpc_buffers'][0]['bytes_hex']==kernel_request.hex();counts['original_unsupported_without_reply_cases_checked']+=1
   else:
    response=bytearray(kernel_request);struct.pack_into('<I',response,4,reply_size);struct.pack_into('<II',response,0x1c,0x4da2b68d,0);struct.pack_into('<QQQ',response,0x24,msgid,8,0)
    if method=='power':struct.pack_into('<I',response,0x3c,0x12345678)
    assert row['final_rpc_buffers'][0]['bytes_hex']==response.hex()and row['boundary']['registers31'][0]=='0x0';counts['original_reply_and_reader_cases_checked']+=1
   assert not any(m['symbol']=='declared_custom_dispatch_model'for m in models)
  else:
   assert f['pc']==hex(CUSTOM)and not any(row[k]for k in ['dispatch_frames','invoke_frames','thunk_frames','thread_frames','controller_method_frames'])
   expected=0xe00002bc if j<10 else 0 if j==13 else 0xe00002bf;assert int(row['boundary']['registers31'][0],16)==expected
   if j<13:assert row['final_rpc_buffers'][0]['bytes_hex']==request.hex();counts['custom_dispatch_without_reply_cases_checked']+=1
   else:
    assert row['source_reply_producer_case']==3;response=bytearray.fromhex(rows[3]['final_rpc_buffers'][0]['bytes_hex']);patch=cfg.get('reply_patch')
    if patch:off,n,v=patch;response[off:off+n]=v.to_bytes(n,'little')
    assert row['final_rpc_buffers'][0]['bytes_hex']==response.hex();counts['source_reply_transfer_and_guard_cases_checked']+=1
  for mi,m in enumerate(models):
   aa=[int(x,16)for x in m['arguments8']];ret=int(m['return_value'],16);expected=[hex(((r+1)*0x123456789abcdef)^(mi+1)*0x8b3dc651)for r in range(18)];expected[0]=hex(ret);assert m['after_registers31'][:18]==expected and int(m['after_NZCV'],16)==(0xf0000000 if(mi+1)&1 else 0)and m['native_effects_executed']is False
   if m['symbol']=='declared_platform_backend_model':
    assert 3<=j<=6 and ret==0
    if method=='power':assert len(m['memory_effects'])==1 and m['memory_effects'][0]['address']==hex(a+0x3c)and m['memory_effects'][0]['before_hex']=='84000000'and m['memory_effects'][0]['after_hex']=='78563412'
    else:assert not m['memory_effects']
   else:
    assert m['symbol']=='declared_custom_dispatch_model'and j>=7 and aa[:2]==[DEV,int(f['rpc_address'],16)]and ret==cfg.get('transport_result',0)
    if j>=13:assert len(m['memory_effects'])==1 and m['memory_effects'][0]['address']==hex(a)and m['memory_effects'][0]['before_hex']==request.hex()and m['memory_effects'][0]['after_hex']==row['final_rpc_buffers'][0]['bytes_hex']
    else:assert not m['memory_effects']
   counts['API_'+m['symbol']]+=1
  assert all(R<=int(e['address'],16)<R+0x100000 for e in row['source_writes'])and not row['trace_frames']and not row['job_allocations']and not row['DMA_allocations'];counts['private_only_write_cases_checked']+=1
  totals.update(Replay(im,row).run());records.append({'case':j,'configuration':cfg,'source_visits':len(row['source_visits']),'API_models':len(models),'raw_X0':row['boundary']['registers31'][0]});print(json.dumps({**records[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=18,functions=88,captured_instructions=7533,iorpc_slots=2,recaptured_bindings=24)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [P+'_source.json',P+'_profiles.json','aes_platform_gate_profiles.json','validate_aes_provider_queue.py','replay_'+P+'.py','replay_aes_platform_gate.py','replay_aes_hardware_job.py','replay_workloop_gate_attachment.py','replay_aes_command_gate.py','replay_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'case_summaries':records,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
