#!/usr/bin/env python3
"""Rebuild original registry and proofs, compile reconstructed layouts, then
independently replay initialized-table, selector, lookup and receiver cases.
O(KC/fixup/source/artifact bytes + visits + solver/compiler resources) time;
O(KC metadata + one CPU map + largest profile + DAGs) space. No native IPC.
"""
import json,struct,subprocess
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from kernel_vm_mig_tools import Image,HASH,SLOTS,MAXPROBE,COUNT,STUB,CONVERT,LEAF,RELEASE,NDR
from recover_kernel_vm_mig import recover
from prove_kernel_vm_mig import obligations
from replay_kernel_vm_mig import Replay
P=0x6500000000;REQ=P+0x1000;REP=P+0x4000;BODY=P+0x5000;TRAILER=P+0x6000;MAP=P+0x3000
def main():
 c=json.loads((ROOT/'kernel_vm_mig_source.json').read_text());assert recover()==c;p=json.loads((ROOT/'kernel_vm_mig_profiles.json').read_text());proof=json.loads((ROOT/'kernel_vm_mig_proofs.json').read_text());assert p['generator_sha256']==sha(ROOT/'probe_kernel_vm_mig.py')
 for n,h in p['dependencies'].items():assert sha(ROOT/n)==h
 qs,counts=obligations();assert counts==proof['source_lift_counts']and len(qs)==len(proof['proofs']);smt=0
 for(name,q),row in zip(qs,proof['proofs'],strict=True):
  assert name==row['name'];s=z3.Solver();s.set(timeout=30000);s.add(q);assert s.check()==z3.unsat
  for f,h in [('file','sha256'),('original_file','original_sha256')]:
   assert sha(ROOT/row[f])==row[h];s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_file(str(ROOT/row[f])));assert s.check()==z3.unsat;smt+=1
 sdk=Path(subprocess.run(['xcrun','--sdk','macosx','--show-sdk-path'],check=True,capture_output=True,text=True).stdout.strip());cmd=['xcrun','--sdk','macosx','clang','-target','arm64e-apple-macos11.0','-isysroot',str(sdk),'-S','-emit-llvm','-O1','-Werror',str(ROOT/'kernel_vm_mig_sdk.c'),'-o',str(ROOT/'kernel_vm_mig_sdk.ll')];cc=subprocess.run(cmd,capture_output=True,text=True);assert cc.returncode==0,(cc.stdout,cc.stderr)
 image=Image();totals=Counter();kinds=Counter();models=Counter();rows=[];good=bad=lookups=selectors=0;init=next(r for r in p['cases']if r['kind']=='init');hashrows={x['id']:x for x in c['hash_model']['insertions']};ndr=image.k.read(NDR,8);assert ndr==bytes.fromhex('0000000001000000')
 expected=bytearray(SLOTS*24)
 for e in hashrows.values():struct.pack_into('<IIQII',expected,e['index']*24,e['id'],0xffffffff,int(e['stub']['target'],16),e['reply_size'],e['reply_descriptors'])
 for j,r in enumerate(p['cases']):
  replay=Replay(image,r);result=replay.run();totals.update(result);kinds[r['kind']]+=1;rows.append({'index':j,'kind':r['kind'],'verified_counts':result});b=r['boundary'];cfg=r['configuration'];assert not r['native_target_executed']and not r['hardware_PAC_executed']
  if r['kind']=='init':assert r['hash_output']['bytes_hex']==expected.hex()and bytes(replay.u.mem_read(HASH,SLOTS*24))==expected and r['hash_output']['maximum_probe']==91 and r['hash_output']['count_word']==390
  elif r['kind']=='selector':
   mid=cfg['id'];stub=c['subsystems'][0]['routines'][mid-4800]['stub']if 4800<=mid<4830 else None;want=int(stub['target'],16)if stub else 0;assert replay.reg(0)==want;selectors+=1
  elif r['kind']=='lookup':
   assert r['initial_image_fixtures'][0]['bytes_hex']==init['hash_output']['bytes_hex'];mid=cfg['id'];z=bool(int(b['NZCV'],16)&(1<<30));assert(not z)==(mid in hashrows)
   if mid in hashrows:assert replay.reg(24)==int(hashrows[mid]['address'],16)and replay.reg(8)==int(hashrows[mid]['stub']['target'],16)
   lookups+=1
  else:
   body=REP+32 if cfg['body_placement']=='joined'else BODY;events=r['API_models'];accepted=cfg['bits']&0x80000000==0 and cfg['request_size']==56;out=bytes(replay.u.mem_read(REP,64));separate=bytes(replay.u.mem_read(BODY,16));assert out.hex()==r['reply_header_storage_hex']and separate.hex()==r['separate_reply_body_hex'];assert not any(int(e['address'],16)<TRAILER+32 and int(e['address'],16)+e['size_bytes']>TRAILER for e in r['source_reads'])
   if not accepted:
    bad+=1;assert not events and out[:32]==bytes([0xa5])*32 and out[32:44]==ndr+struct.pack('<I',0xfffffed0)and separate==bytes([0x5a])*16
   else:
    good+=1;converted=cfg['converted_map']if cfg['port_class']=='normal'else 0;calls=[e['symbol']for e in events];assert calls==(['port_to_map_model']if cfg['port_class']=='normal'else[])+['VM_deallocate_model','map_release_model'];assert out[:32]==bytes([0xa5])*32
    for e in events:
     models[e['symbol']]+=1;args=[int(x,16)for x in e['arguments8']]
     if e['symbol']=='port_to_map_model':assert args[:3]==[P+0x2000,0,0]
     elif e['symbol']=='VM_deallocate_model':assert args[:3]==[converted,cfg['address'],cfg['size']]
     else:assert args[0]==converted
    assert bytes(replay.u.mem_read(body,12))==ndr+struct.pack('<I',cfg['VM_result']&0xffffffff)
    if cfg['body_placement']=='separate':assert out[32:]==bytes([0xa5])*32
   # The received NDR bytes and trailer are not read by this bounded stub.
   assert not any(int(e['address'],16)<REQ+40 and int(e['address'],16)+e['size_bytes']>REQ+32 for e in r['source_reads'])
 assert kinds==Counter({'init':1,'selector':35,'lookup':35,'stub':102})and good==90 and bad==12 and lookups==selectors==35 and totals['source_visits_checked']==35844 and models==Counter({'VM_deallocate_model':90,'map_release_model':90,'port_to_map_model':36})
 deps=['kernel_vm_mig_source.json','kernel_vm_mig_profiles.json','kernel_vm_mig_proofs.json','kernel_vm_mig_tools.py','probe_kernel_vm_mig.py','recover_kernel_vm_mig.py','prove_kernel_vm_mig.py','replay_kernel_vm_mig.py','kernel_vm_mig_sdk.c','kernel_vm_mig_sdk.ll'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':{'source_obligations_rebuilt':len(qs),'SMT_files_checked':smt,'profiles':len(rows),'registered_subsystems':20,'registered_routines':358,'hash_slots':1031,'maximum_probe':91,'message4801_slot':677,'initializer_source_visits':len(init['source_visits']),'selector_cases':selectors,'lookup_cases':lookups,'stub_valid_cases':good,'stub_bad_header_cases':bad,'conversion_models':models['port_to_map_model'],'VM_models':models['VM_deallocate_model'],'release_models':models['map_release_model'],'unique_captured_source_instructions':len(c['unique_source']),'SDK_compile_exit':0},'independent_A64_totals':dict(totals),'kind_counts':dict(kinds),'SDK_layout':{'path':str(sdk),'command':cmd,'exit_code':cc.returncode,'LLVM_sha256':sha(ROOT/'kernel_vm_mig_sdk.ll'),'reconstructed_types_are_not_original_headers':True,'matched_runtime_version_established':False},'fresh_replay_cases':rows,'native_target_executed':False,'native_IPC_executed':False,'native_runtime_table_attested':False,'native_port_or_map_ownership_established':False,'hardware_PAC_executed':False,'idb_mutated':False,'continuous_user_wire_delivery_established':False,'full_goal_complete':False,'all_checks_pass':True};(ROOT/'kernel_vm_mig_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':out['verified_counts'],'A64_totals':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
