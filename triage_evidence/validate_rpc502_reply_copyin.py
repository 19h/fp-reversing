#!/usr/bin/env python3
"""Fresh source/replay plus independent descriptor, factory and cleanup oracle.
O(source bytes+visits+effect bytes) time, O(profiles+private RAM) space.
Finite declared cases; no native source removal, IPC, VM or allocator effect.
"""
from collections import Counter
import json,struct
from daemon_receive_tools import ROOT
from kernel_vm_mig_tools import Image
from capture_daemon_record720 import sha
from recover_rpc502_reply_copyin import recover
from replay_rpc502_reply_copyin import Replay
P=0x6500000000;SOURCES=[P+0x50000,P+0x60000];COPIES=[P+0x68000,P+0x69000];BACKS=[P+0x70000,P+0x78000]
def u64(b,o=0):return int.from_bytes(b[o:o+8],'little')
def initial(r,a):return bytes.fromhex(next(x['bytes_hex']for x in r['initial_private_fixtures']if int(x['address'],16)==a))
def main():
 src=json.loads((ROOT/'rpc502_reply_copyin_source.json').read_text());assert src==recover();p=json.loads((ROOT/'rpc502_reply_copyin_profiles.json').read_text());assert p['generator_sha256']==sha(ROOT/'probe_rpc502_reply_copyin.py')
 for n,h in p['dependencies'].items():assert sha(ROOT/n)==h
 ki=Image();counts=Counter();totals=Counter()
 for r in p['cases']:
  q=Replay(ki,r);totals.update(q.run());c=r['configuration'];counts[r['kind']]+=1
  if r['kind']=='normalize':
   raw=initial(r,P+0x10000);addr,flags,n=struct.unpack('<QII',raw);assert flags==0x01000101;assert r['normalized_descriptor_hex']==struct.pack('<QII',addr,flags&0xff0001ff,n).hex()and r['normalization_context_hex']=='00'*88 and r['return_u32']==0;continue
  kind=c['case'];counts[kind]+=1;H=int(r['message_header_address'],16);before=initial(r,H);after=bytes.fromhex(r['message_inline_hex']);assert bytes(q.u.mem_read(H,392))==after and after[:36]==before[:36]and after[68:]==before[68:]
  for j,normal in enumerate(c['normalization_cases']):assert before[36+16*j:52+16*j].hex()==p['cases'][normal]['normalized_descriptor_hex']
  models=r['API_models'];names=[m['symbol']for m in models];counts['source_remove_requests']+=names.count('source_region_remove_request');counts['backing_release_requests']+=names.count('backing_release_request');counts['header_release_requests']+=names.count('copy_header_release_request')
  for j,n in enumerate(c['lengths']):
   prefix=kind.endswith('_failure')and c['failure_descriptor']==1 and j==0;committed=(kind=='success'and n!=0)or prefix;destroyed=prefix;pending=kind=='entry_list_frontier'and j==0;expected=bytearray([0xa5]*48)
   if committed:
    expected=bytearray(48);expected[:8]=struct.pack('<Q',BACKS[j]);expected[32:40]=struct.pack('<Q',n);expected[45]=3;counts['constructed_type3']+=1
    if destroyed:expected=bytearray(48);counts['prefix_discards']+=1
   if pending:
    expected=bytearray(48);expected[16:24]=struct.pack('<Q',SOURCES[j]);expected[32:40]=struct.pack('<Q',n);expected[44]=14;expected[45]=2;counts['pending_type2']+=1
   assert r['copy_headers_hex'][j]==expected.hex()and bytes(q.u.mem_read(COPIES[j],48))==expected
   descriptor=after[36+16*j:52+16*j];wantptr=0 if destroyed or(kind=='success'and n==0)else COPIES[j]if committed else SOURCES[j];assert u64(descriptor)==wantptr and descriptor[8:]==before[44+16*j:52+16*j]
   if committed:
    removes=[m for m in models if m['symbol']=='source_region_remove_request'and int(m['arguments8'][1],16)==(SOURCES[j]&~16383)];publish=[x for x in r['source_writes']if int(x['pc'],16)==0xfffffe000bdd1f38 and x['after_hex']==struct.pack('<Q',COPIES[j]).hex()];assert len(removes)==len(publish)==1 and removes[0]['before_source_visit_index']<publish[0]['source_visit_index'];counts['remove_before_publication']+=1;counts['copied_bytes']+=n
    payload=bytes((j*71+k*37+17)&255 for k in range(n));assert r['backing_bytes_hex'][j][:2*n]==payload.hex()
  if kind=='entry_list_frontier':assert r['boundary']['kind']=='before_entry_list_lookup'and not names.count('source_region_remove_request')
  else:
   assert r['boundary']['kind']=='returned';want=0 if kind=='success'else 0x400 if kind=='allocation_failure'else 0x1000000c;assert r['return_u32']==want,(c,r['return_u32'])
  if kind.endswith('_failure'):
   prefix=c['failure_descriptor'];cleanup=[m for m in models if m['symbol']=='message_pre_cleanup_model'];assert len(cleanup)==1 and names.count('copy_header_release_request')==prefix
 assert counts=={'normalize':10,'body':36,'success':16,'source_remove_requests':32,'backing_release_requests':16,'header_release_requests':8,'constructed_type3':32,'prefix_discards':8,'pending_type2':4,'remove_before_publication':32,'copied_bytes':180388,'allocation_failure':8,'copy_failure':8,'entry_list_frontier':4},dict(counts)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['rpc502_reply_copyin_source.json','rpc502_reply_copyin_profiles.json','recover_rpc502_reply_copyin.py','replay_rpc502_reply_copyin.py','replay_kernel_reply_send.py','replay_kernel_vm_mig.py']},'verified_counts':{'cases':len(p['cases']),'functions':len(src['functions']),'captured_instructions':sum(len(f['instructions'])for f in src['functions']),'exact_instruction_roles':len(src['exact_instruction_roles']),**dict(counts)},'independent_A64_replay':dict(totals),'source_recapture_match':True,'all_checks_pass':True,'native_target_executed':False,'native_VM_effects_executed':False,'native_source_region_removal_executed':False,'native_IPC_executed':False,'native_namespace_conversion_executed':False,'native_application_success_established':False,'hardware_PAC_executed':False,'complete_FairPlay_round_trip_established':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'rpc502_reply_copyin_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':out['verified_counts'],'replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
