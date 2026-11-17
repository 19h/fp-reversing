#!/usr/bin/env python3
"""Freeze schema-caller search, protected-tag round trip and callback interfaces.
O(B+I+C*W) construction/space; no native execution or IDB changes.
"""
import json
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,TABLE,qword
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_early_schema as Parent
import recover_userclient_input_reader as Reader
P='userclient_schema_search'
SCOPE='Conditional original-source early-record protected-tag round trip, matching-node or sole-node-miss lookup, schema callback, buffer/extent channels and next header-read request. A source-built synthetic scalar record reproduces the fourteen-byte ADID field and is found by this lookup. Original stopped guest, native admission/PAC/ownership, general whole-list traversal, subsequent field decoding/meaning and matched ADID/daemon/kext transport remain outside the claims.'
SPANS={'buffer_output_root':(0xfffffe000a636104,0xfffffe000a63610c),'node_decode_prepare':(0xfffffe000a662c60,0xfffffe000a662ccc),'word_bridge_read':(0xfffffe000a656ef0,0xfffffe000a656efc),'decode_word':(0xfffffe000a637138,0xfffffe000a637250),'tag_match':(0xfffffe000a63d624,0xfffffe000a63d680),'search_next':(0xfffffe000a63d680,0xfffffe000a63d6a0),'schema_search_return':(0xfffffe000a661c34,0xfffffe000a661c88),'schema_node_fields':(0xfffffe000a661c88,0xfffffe000a661cec),'schema_extent':(0xfffffe000a661cec,0xfffffe000a661da0),'schema_decode_request':(0xfffffe000a661da0,0xfffffe000a661e40),'schema_caller_return':(0xfffffe000a661e40,0xfffffe000a661e50)}
BRANCHES=Parent.BRANCHES|{pc:Reader.BRANCHES[pc]for pc in [0xfffffe000a662c88,0xfffffe000a656ef4,0xfffffe000a63713c,0xfffffe000a63d66c,0xfffffe000a63d694]}
BRANCHES|={0xfffffe000a661c7c:[0x3d8,0xdf7],0xfffffe000a661cd4:[0xf04,0xf06],0xfffffe000a661d8c:[0x3d8,0xc7e],0xfffffe000a661df8:[0x22f]}
RETAGS=Reader.RETAGS|Parent.Parent.P0.RETAGS
FALSE=Parent.FALSE+['whole_schema_reader_established','native_schema_lookup_established','native_schema_result_lifetime_established']
def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_early_schema_checks.json'));parents=json.loads(read(ROOT/'userclient_early_data_checks.json'));raw=k.read(0xfffffe000a635208,0x31728);assert IMAGE.read(0xfffffe000a635208,len(raw))==raw and sha256(raw).hexdigest()==prior['source']['container']['sha256'];spans=[]
 assert k.sha256==prior['kernel_collection_sha256']and sha(SOURCE)==prior['source_sha256']
 for label,(a,z)in SPANS.items():
  b=k.read(a,z-a);assert IMAGE.read(a,len(b))==b;ii=list(CS.disasm(b,a));assert len(ii)*4==len(b);spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]})
 pointers=[pointer(k,TABLE+8*j)|{'index':j}for j in sorted({j for js in BRANCHES.values()for j in js}|{0x1a2})]
 for q in pointers:assert int(q['target'],16)==qword(TABLE+8*q['index'])
 bank=prior['source']['bank_rule'];banks=prior['source']['banks']
 for n in ['FL','FR']:
  row=banks[n];a=int(row['address'],16);assert k.read(a,256)==IMAGE.read(a,256)==bytes.fromhex(row['bytes_hex'])
 left,right=(bytes.fromhex(banks[n]['bytes_hex'])for n in ['FL','FR']);assert all(j^right[left[j]^int(bank['key'],16)]==int(bank['constant'],16)for j in range(256))
 assert pointer(k,int(bank['slot'],16))==bank['original_pointer']and int(bank['original_pointer']['target'],16)-4==int(bank['target'],16)
 assert qword(TABLE+8*0x1a2)==0xfffffe000a638e68
 rows=[]
 for p in prior['predecessor_states']:
  r=parents['cases'][p['predecessor_case_index']];F=int(p['frame_base_SP'],16);C=int(p['handoff_state']['registers31'][11],16);a=F+0x898;state=[None]*8;touches=[]
  for w in r['source_writes']:
   w0=int(w['address'],16);b=bytes.fromhex(w['after_hex']);lo=max(a,w0);hi=min(a+8,w0+len(b))
   if lo<hi:
    touches.append(w)
    for addr in range(lo,hi):state[addr-a]=b[addr-w0]
  assert None not in state and int.from_bytes(bytes(state),'little')==C+0x560
  visit=next(j for j,q in enumerate(r['source_visits'])if q['pc']=='0xfffffe000a636104');assert int(r['source_frames'][visit]['registers31'][2],16)==C
  rows.append({**p,'schema_search_additional_source_cells':[{'root':'F','offset':'0x898','size_bytes':8,'reconstructed_bytes_hex':bytes(state).hex(),'overlapping_source_stores':touches}]})
 names=set(prior['dependencies'])|{'recover_userclient_early_schema.py','audit_userclient_early_schema.py','userclient_early_schema_checks.json','userclient_early_schema_audit.json','recover_userclient_input_reader.py','audit_userclient_input_reader.py','userclient_input_reader_checks.json','userclient_input_reader_audit.json'}
 return {**prior,'generator_sha256':sha(__file__),'scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in sorted(names)},'schema_source':prior['source'],'source':{'container':prior['source']['container'],'spans':spans,'branch_pointers':pointers,'bank_rule':prior['source']['bank_rule'],'banks':prior['source']['banks']},'predecessor_states':rows,'verified_counts':{'new_source_spans':len(spans),'new_captured_words':sum(len(q['instructions'])for q in spans),'original_table_pointers':len(pointers),'predecessor_states':len(rows),'additional_source_cells_per_state':1,'bank_input_cases':256},'conditional_schema_search_step_established':True,**{n:False for n in FALSE}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
