#!/usr/bin/env python3
"""Freeze schema caller, shared holder, private lookup packet and error status.
O(B+I+C*W+256R) construction/space; no native execution or IDB changes.
"""
import json
from kext_port_tools import ROOT,IMAGE,CS,TABLE,qword
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_schema_scalar as Parent
P='userclient_schema_registry'
SCOPE='Conditional original-source schema scalar consumer, caller-specific shared global-holder gate, ready-holder token541 lookup record/call request, NULL-holder typed allocation request and caller error-status publication. Native holder coherence/ownership, allocator/helper execution, complete lookup results, application meaning and ADID/daemon/kext transport remain unknown.'
SPANS={'registry_flag_root':(0xfffffe000a635c54,0xfffffe000a635c5c),'registry_payload_root':(0xfffffe000a635e44,0xfffffe000a635e4c),'registry_index_root':(0xfffffe000a635c34,0xfffffe000a635c3c),'registry_packet_roots':(0xfffffe000a635b40,0xfffffe000a635b5c),'registry_default_status':(0xfffffe000a636678,0xfffffe000a636694),'registry_request':(0xfffffe000a63677c,0xfffffe000a6367b4),'registry_holder':(0xfffffe000a65abf8,0xfffffe000a65ac84),'registry_allocate':(0xfffffe000a65ac84,0xfffffe000a65ad54),'registry_resume':(0xfffffe000a65affc,0xfffffe000a65b008),'registry_return':(0xfffffe000a6367b4,0xfffffe000a6367fc),'registry_scalar':(0xfffffe000a6367fc,0xfffffe000a636854),'registry_lookup_entry':(0xfffffe000a65b16c,0xfffffe000a65b1a8),'registry_lookup_header':(0xfffffe000a65b3ac,0xfffffe000a65b408),'registry_lookup_record':(0xfffffe000a65b408,0xfffffe000a65b4dc),'registry_lookup_call':(0xfffffe000a65b4dc,0xfffffe000a65b530),'registry_error_status':(0xfffffe000a641c1c,0xfffffe000a641c60),'registry_lookup_codec':(0xfffffe000a5ae3c8,0xfffffe000a5ae418)}
BRANCHES=Parent.BRANCHES|{0xfffffe000a636794:[0x5b7],0xfffffe000a65ac0c:[0x37],0xfffffe000a65ac78:[0x526,0x539],0xfffffe000a6367e4:[0x7e0,0x80f],0xfffffe000a636840:[0xd89],0xfffffe000a65b170:[0x128],0xfffffe000a65b198:[0x37f],0xfffffe000a65b3bc:[0x160],0xfffffe000a65b3f0:[0x5df,0x602],0xfffffe000a641c50:[0x2b7]}
BANK_PCS={'holder':(0xfffffe000a65ac30,0xfffffe000a65ac3c,0xfffffe000a65ac54),'allocate':(0xfffffe000a65acd8,0xfffffe000a65ace8,0xfffffe000a65acf8),'allocate_descriptor':(0xfffffe000a65ad10,0xfffffe000a65ad20,0xfffffe000a65ad3c),'lookup':(0xfffffe000a65b500,0xfffffe000a65b510,0xfffffe000a65b520)}
RETAGS=Parent.RETAGS;DIRECT=Parent.DIRECT
FALSE=Parent.FALSE+['native_schema_registry_identity_established','native_shared_holder_coherence_established','schema_registry_lookup_result_established']
def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_schema_scalar_checks.json'));assert prior==Parent.build();bootstrap=json.loads(read(ROOT/'userclient_replacement_bootstrap_checks.json'));uid=json.loads(read(ROOT/'userclient_uidlist_replacement_checks.json'));parents=json.loads(read(ROOT/'userclient_early_data_checks.json'));spans=[]
 for label,(a,z)in SPANS.items():
  b=k.read(a,z-a);assert IMAGE.read(a,z-a)==b;ii=list(CS.disasm(b,a));assert len(ii)*4==len(b);spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]})
 rules=[next(r for r in bootstrap['bank_rules']if r['name']==n)for n in ['holder','allocate','allocate_descriptor']]+[next(r for r in uid['bank_rules']if r['name']=='first_lookup')|{'name':'lookup'}]
 banks={}
 for r in rules:
  for side in ['left','right']:
   name=r[side+'_name'];a=int(r[side],16);raw=k.read(a,256);assert raw==IMAGE.read(a,256);banks[name]={'address':hex(a),'bytes_hex':raw.hex()}
  left,right=(bytes.fromhex(banks[r[s+'_name']]['bytes_hex'])for s in ['left','right']);assert all(j^right[left[j]^int(r['key'],16)]==int(r['constant'],16)for j in range(256));assert pointer(k,int(r['slot'],16))==r['original_pointer']and (int(r['original_pointer']['target'],16)+int(r['bias'],16))&((1<<64)-1)==int(r['target'],16)
 pointers=[pointer(k,TABLE+8*j)|{'index':j}for j in sorted({j for js in BRANCHES.values()for j in js})]
 for q in pointers:assert int(q['target'],16)==qword(TABLE+8*q['index'])
 rows=[]
 for p in prior['predecessor_states']:
  r=parents['cases'][p['predecessor_case_index']];g=[int(x,16)for x in p['handoff_state']['registers31']];F=int(p['frame_base_SP'],16);C,S=g[11],g[3];cells=[];record=S+0x968
  wants=[(0xa58,8,0xfffffe000794a0d0),(0xa50,8,0xfffffe0007941f60),(0x658,8,S+0x10),(0x610,8,C+0x440),(0x9ec,4,0xce515bb2),(0x940,8,S+0xa28),(0x998,8,record),(0x6f0,8,record|0xd9d0ab468c12f4cb),(0x9f8,8,0xfffffe0007949ed0),(0x9f0,8,0xfffffe000792fec0)]
  for off,n,want in wants:
   state=[None]*n;touches=[]
   for w in r['source_writes']:
    a=int(w['address'],16);b=bytes.fromhex(w['after_hex']);lo=max(a,F+off);hi=min(a+len(b),F+off+n)
    if lo<hi:
     touches.append(w)
     for addr in range(lo,hi):state[addr-F-off]=b[addr-a]
   assert None not in state and int.from_bytes(bytes(state),'little')==want;cells.append({'root':'F','offset':hex(off),'size_bytes':n,'reconstructed_bytes_hex':bytes(state).hex(),'overlapping_source_stores':touches})
  visit=next(j for j,q in enumerate(r['source_visits'])if q['pc']=='0xfffffe000a635b50');assert int(r['source_frames'][visit]['registers31'][16],16)==record
  rows.append({**p,'registry_additional_source_cells':cells})
 desc=bootstrap['hash_table_descriptors'][0];a=int(desc['address'],16);assert k.read(a,64).hex()==desc['original64_bytes_hex']and IMAGE.read(a,64).hex()==desc['normalized64_bytes_hex'];adapter=k.function(0xfffffe000c4ba154);assert adapter==bootstrap['kernel_adapters']['allocate']
 names=set(prior['dependencies'])|{'recover_userclient_schema_scalar.py','audit_userclient_schema_scalar.py','userclient_schema_scalar_checks.json','userclient_schema_scalar_audit.json','recover_userclient_replacement_bootstrap.py','userclient_replacement_bootstrap_checks.json','userclient_replacement_bootstrap_audit.json','recover_userclient_uidlist_replacement.py','userclient_uidlist_replacement_checks.json','userclient_uidlist_replacement_audit.json','recover_userclient_hash_table_lookup.py','audit_userclient_hash_table_lookup.py','userclient_hash_table_lookup_checks.json','userclient_hash_table_lookup_audit.json'}
 return {**prior,'generator_sha256':sha(__file__),'scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in sorted(names)},'scalar_source':prior['source'],'source':{'container':prior['source']['container'],'spans':spans,'branch_pointers':pointers,'bank_rule':prior['source']['bank_rule'],'banks':prior['source']['banks']},'registry_banks':banks,'registry_bank_rules':rules,'registry_allocation_descriptor':desc,'registry_allocation_adapter':adapter,'predecessor_states':rows,'verified_counts':{'new_source_spans':len(spans),'new_captured_words':sum(len(q['instructions'])for q in spans),'original_table_pointers':len(pointers),'predecessor_states':len(rows),'additional_source_cells_per_state':10,'additional_source_cell_bytes_per_state':76,'new_bank_rules':4,'new_bank_input_cases':1024,'lookup_record_size_bytes':48,'lookup_record_initialized_bytes':40},'conditional_schema_registry_request_established':True,**{n:False for n in FALSE}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
