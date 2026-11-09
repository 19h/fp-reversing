#!/usr/bin/env python3
"""Original metadata/word recapture and independent allocation/free ABI oracle.
O(image bytes+visits), O(image bytes+largest case). No target operation.
"""
import json,struct
from collections import Counter
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_kext_security_record import sha
from replay_kext_security_record import Replay
P='kext_security_record';REC=0x6500004000;STATS=0x6500010000;ZONE=0x6500006000;ALT=0x6500007000;HEAP=0xfffffe0007f36938
def main():
 im=Image();k=im.k;src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());totals=Counter();counts=Counter()
 for obj,name in [(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
 for v in src['views']:
  a=int(v['address'],16);assert k.read(a,64).hex()==v['bytes64_hex'];assert struct.unpack('<II',k.read(a+0x28,8))==(100,152)and k.read(a,16)==bytes(16)
  for s in v['pointers']:
   assert im.pointer(int(s['pointer']['slot'],16))==s['pointer'];b=bytes.fromhex(s['string_bytes_hex']);assert k.read(int(s['pointer']['target'],16),len(b)+1)==b+b'\0'
 assert src['views'][0]['bytes64_hex']==src['views'][1]['bytes64_hex']and src['fixed_RPC_record_bytes']==136 and src['allocation_metadata_bytes']==152 and 152-136==src['unused_allocation_suffix_bytes']==16
 for f in src['functions']:assert k.function(int(f['start'],16))==f
 for r in src['ranges']:assert k.read(int(r['start'],16),int(r['end'],16)-int(r['start'],16)).hex()==r['bytes_hex']
 for b in src['banks']:
  l=bytes.fromhex(b['left_bytes256_hex']);r=bytes.fromhex(b['right_bytes256_hex']);assert{n^r[l[n]^int(b['key'],16)]for n in range(256)}=={int(b['constant'],16)}and im.pointer(int(b['slot'],16))==b['original_pointer']
 assert len(prof['cases'])==42
 for row in prof['cases']:
  kind=row['kind'];cfg=row['configuration'];route=cfg['route'];value=cfg['record_value'];regs=[int(x,16)for x in row['boundary']['registers31']];counts[kind]+=1
  if kind in ['allocate','caller']:
   assert len(row['API_models'])==1;m=row['API_models'][0];args=[int(x,16)for x in m['arguments8']]
   if route=='heap':assert int(m['pc'],16)==0xfffffe000bcfe5b8 and args[:4]==[HEAP,152,0xd1004,0];counts['heap_alloc_requests']+=1
   elif route=='zone':assert int(m['pc'],16)==0xfffffe000bd75c64 and args[:3]==[ZONE,STATS,0xd1004];counts['zone_alloc_requests']+=1
   else:assert route=='alternate'and int(m['pc'],16)==0xfffffe000bd75c64 and args[:3]==[ALT,STATS,0xd1044];counts['alternate_alloc_requests']+=1
   assert int(m['return_value'],16)==value
  elif kind=='free':
   assert not row['API_models']
   if route=='heap':assert int(row['boundary']['pc'],16)==0xfffffe000bcfec48 and regs[:3]==[HEAP,value,152];counts['heap_free_boundaries']+=1
   else:assert int(row['boundary']['pc'],16)==0xfffffe000bd7a4b8 and regs[:2]==[0xfffffe000847bc60,value];counts['zone_free_boundaries']+=1
  else:
   assert kind=='copy'and not row['API_models'];prev=prof['cases'][cfg['source_caller_case_index']];assert prev['kind']=='caller'and prev['configuration']['record_value']==REC and cfg['record_initial152_hex']==prev['final_record152_hex']and int(row['boundary']['pc'],16)==0xfffffe000a5a2228;counts['allocation_copy_compositions']+=1
  expected_record=bytearray([0xa5]*152);expected_c=bytearray([0x5a]*160)
  if kind=='caller':
   struct.pack_into('<Q',expected_c,0x58,value)
   if value:
    expected_record[0x48:0x50]=bytes(8);expected_record[0x58:0x60]=bytes(8);assert int(row['boundary']['pc'],16)==0xfffffe000a60abb8 and regs[27]==value;counts['caller_nonnull']+=1
   else:assert int(row['boundary']['pc'],16)==0xfffffe000a608958;counts['caller_null']+=1
  elif kind=='allocate':assert int(row['boundary']['pc'],16)==0x65000e0000 and regs[0]==value
  elif kind=='copy':expected_record=bytearray.fromhex(cfg['record_initial152_hex']);expected_record[:136]=bytes.fromhex(cfg['input_record136_hex']);assert expected_record[136:]==bytes([0xa5])*16
  assert row['final_record152_hex']==bytes(expected_record).hex()and row['final_C160_hex']==bytes(expected_c).hex()
  totals.update(Replay(im,row).run())
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [P+'_source.json',P+'_profiles.json','replay_'+P+'.py','kernel_vm_mig_tools.py']},'source_recapture_match':True,'verified_counts':{'cases':42,'functions':len(src['functions']),'ranges':len(src['ranges']),'captured_instructions':sum(len(x['instructions'])for x in src['functions']+src['ranges']),'views':2,'banks256':2,**dict(counts)},'independent_A64_replay':dict(totals),'all_checks_pass':True,'native_target_executed':False,'native_allocation_executed':False,'native_free_executed':False,'native_view_initialization_established':False,'continuous_constructor_close_established':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':out['verified_counts'],'independent_A64_replay':out['independent_A64_replay'],'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
