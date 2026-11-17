#!/usr/bin/env python3
"""Freeze original early wire decoding and continuous fixture-input evidence.
O(B+I+256R+C*(B+V+E)) time/space; no native target operation.
"""
import json
from collections import Counter
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,POOL,TABLE,qword,selected
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_userclient_entry_execution import descriptor
import recover_userclient_fpttlv_entry as Parent
import probe_userclient_early_header as B
P='userclient_early_header'
SCOPE='Original core entry through explicitly declared pre-entry input bytes, early raw header/body decoding, typed metadata packing, cursor/publication and selected FPTTLVNode-allocation or FPTTLV-retirement frontiers. Three allocator returns are declared; no model RAM writes. The input bytes are fixtures, not an admitted native request. Node allocation/retirement bodies, whole operation, marker production and matched daemon/kext identity remain unknown.'
DEPS=['recover_userclient_fpttlv_entry.py','probe_userclient_fpttlv_entry.py','replay_userclient_fpttlv_entry.py','recover_userclient_entry_execution.py','probe_userclient_entry_execution.py','replay_userclient_entry_execution.py','audit_userclient_entry_execution.py','lskd_values_symbolic.py','probe_legacy_stack.py','legacy_stack_contracts.json','probe_userclient_early_header.py','replay_userclient_early_header.py','kernel_native_reader.py','kext_port_tools.py','recover_kext_cold_init.py','userclient_fpttlv_entry_checks.json','userclient_fpttlv_entry_audit.json','userclient_record_metadata_checks.json','userclient_record_nodes_checks.json','userclient_container_staging_checks.json']
FALSE=Parent.FALSE+['native_input_byte_provenance_established','earlier_node_allocation_body_executed','early_and_later_node_runtime_identity_established']
RANGES=[(0xfffffe000a660dcc,0xfffffe000a660e84),(0xfffffe000a660e98,0xfffffe000a661004),(0xfffffe000a661084,0xfffffe000a661138),(0xfffffe000a6619bc,0xfffffe000a661b44),(0xfffffe000a6618fc,0xfffffe000a661948),(0xfffffe000a6614b4,0xfffffe000a6614d4),(0xfffffe000a661514,0xfffffe000a661590)]
def source(k,rows):
 parent=json.loads(read(ROOT/'userclient_fpttlv_entry_checks.json'));container=parent['source']['container'];raw=k.read(0xfffffe000a635208,0x31728);assert sha256(raw).hexdigest()==container['sha256']and IMAGE.read(0xfffffe000a635208,len(raw))==raw
 words={int(v['pc'],16)for r in rows for v in r['source_visits'][1464:]};words.update(int(r['boundary']['pc'],16)for r in rows)
 for a,z in RANGES:words.update(range(a,z,4))
 groups=[]
 for a in sorted(words):
  if groups and groups[-1][1]==a:groups[-1][1]=a+4
  else:groups.append([a,a+4])
 spans=[]
 for j,(a,z)in enumerate(groups):
  b=k.read(a,z-a);assert IMAGE.read(a,z-a)==b;ii=list(CS.disasm(b,a));assert len(ii)*4==len(b);spans.append({'label':'source_'+str(j),'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]})
 rules=[]
 for name,l,r,key,add,base,bias in [('node_allocation',0xfffffe000792fdc0,0xfffffe00079392f0,0x93,0xe27,TABLE,0),('node_descriptor',qword(POOL+0xb70),qword(POOL+0xa10),0x32,-0x98,POOL,-8)]:
  x=selected(l,r,key,add,base,bias);x.update(name=name,left256_hex=k.read(l,256).hex(),right256_hex=k.read(r,256).hex(),original_pointer=pointer(k,int(x['slot'],16)));assert x['left256_hex']==IMAGE.read(l,256).hex()and x['right256_hex']==IMAGE.read(r,256).hex();assert(int(x['original_pointer']['target'],16)+bias)&((1<<64)-1)==int(x['target'],16);rules.append(x)
 return {'container':container,'spans':spans,'new_words':len(words),'bank_rules':rules,'descriptors':[descriptor(k,a)for a in [0xfffffe000847b4a0,0xfffffe000847c020]],'branch_pointers':[pointer(k,TABLE+8*j)|{'index':j}for j in [0x7c6,0x82d,0x386,0x5a1,0x63d,0xce0,0x1c2]],'exact_symbols':k.symbols([0xfffffe000c4ba154,0xfffffe000c4ba368])}
def build():
 k=Kernel();rows=[]
 for c in B.cases():
  b=B.Entry(c);rows.append(b.run());del b
 s=source(k,rows);counts={'cases':len(rows),'matched_parent_cases':sum(r['input']['header_parent_case_index']is not None for r in rows),'new_size_cases':sum(r['input']['header_parent_case_index']is None for r in rows),'source_visits':sum(len(r['source_visits'])for r in rows),'source_reads':sum(len(r['source_reads'])for r in rows),'source_writes':sum(len(r['source_writes'])for r in rows),'new_source_spans':len(s['spans']),'new_source_words':s['new_words'],'bank_rules':2,'bank_input_cases':512,'API_models_per_case':3,'initial_input_bytes_declared':sum(r['initial_input_bytes_declared']for r in rows)}
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'dependencies':{n:sha(ROOT/n)for n in DEPS},'scope':SCOPE,'source':s,'cases':rows,'boundary_counts':dict(Counter(r['boundary']['pc']for r in rows)),'verified_counts':counts,'continuous_early_wire_decoding_established':True,**{n:False for n in FALSE}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'counts':e['verified_counts'],'boundaries':e['boundary_counts']}),flush=True)
