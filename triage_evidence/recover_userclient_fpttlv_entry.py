#!/usr/bin/env python3
"""Freeze the earlier FPTTLV return paths and continuous entry evidence.
O(B+I+256R+C*(B+V+E)) time/space; no native target operation.
"""
import json
from collections import Counter
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,POOL,TABLE,qword,selected
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_entry_execution as Parent
import probe_userclient_fpttlv_entry as B
P='userclient_fpttlv_entry'
SCOPE='Continuous original core entry through the earlier 16-byte FPTTLV allocation return, result retention, source zeroing, empty/short/header-read gates, initial-input lineage and typed-retirement or staging-allocation frontiers. Three allocation returns are declared before entry, without model RAM writes. Header contents, completed nonempty parse, native lifetimes/PAC, marker production and daemon transaction identity remain unknown.'
DEPS=['recover_userclient_entry_execution.py','probe_userclient_entry_execution.py','replay_userclient_entry_execution.py','audit_userclient_entry_execution.py','lskd_values_symbolic.py','probe_legacy_stack.py','legacy_stack_contracts.json','probe_userclient_fpttlv_entry.py','replay_userclient_fpttlv_entry.py','kernel_native_reader.py','kext_port_tools.py','recover_kext_cold_init.py','userclient_entry_execution_checks.json','userclient_entry_execution_audit.json','userclient_parser_cleanup_checks.json','userclient_record_metadata_checks.json','userclient_container_staging_checks.json']
FALSE=Parent.FALSE+['complete_earlier_FPTTLV_parse_established','input_header_contents_established']
PROOF_RANGES=[(0xfffffe000a636428,0xfffffe000a636448),(0xfffffe000a6366b0,0xfffffe000a6366cc),(0xfffffe000a660af8,0xfffffe000a660b20),(0xfffffe000a660c84,0xfffffe000a660d58),(0xfffffe000a660d88,0xfffffe000a660dd0),(0xfffffe000a660b68,0xfffffe000a660b74)]
def source(k,rows):
 parent=json.loads(read(ROOT/'userclient_entry_execution_checks.json'));container=parent['source']['container'];raw=k.read(0xfffffe000a635208,0x31728);assert sha256(raw).hexdigest()==container['sha256'] and IMAGE.read(0xfffffe000a635208,len(raw))==raw
 words={int(v['pc'],16) for r in rows for v in r['source_visits'][1162:]};words.update(int(r['boundary']['pc'],16) for r in rows)
 for a,z in PROOF_RANGES:words.update(range(a,z,4))
 groups=[]
 for a in sorted(words):
  if groups and groups[-1][1]==a:groups[-1][1]=a+4
  else:groups.append([a,a+4])
 spans=[]
 for j,(a,z) in enumerate(groups):
  b=k.read(a,z-a);assert IMAGE.read(a,z-a)==b;ii=list(CS.disasm(b,a));assert len(ii)*4==len(b);spans.append({'label':'source_'+str(j),'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 E=(qword(POOL+0xb70),qword(POOL+0xa10));T=(qword(POOL+0x840),qword(POOL+0xbb8));rules=[]
 for name,(l,r),key,add,base,bias in [('container_free',E,0x92,0xe89,TABLE,0),('retirement_descriptor',E,0x92,-0x55,POOL,-4),('staging_allocation',T,0x16,0xe88,TABLE,0)]:
  x=selected(l,r,key,add,base,bias);x.update(name=name,left256_hex=k.read(l,256).hex(),right256_hex=k.read(r,256).hex(),original_pointer=pointer(k,int(x['slot'],16)));assert x['left256_hex']==IMAGE.read(l,256).hex()and x['right256_hex']==IMAGE.read(r,256).hex();assert(int(x['original_pointer']['target'],16)+bias)&((1<<64)-1)==int(x['target'],16);rules.append(x)
 return {'container':container,'spans':spans,'new_words':len(words),'bank_rules':rules,'descriptors':[Parent.descriptor(k,a) for a in [0xfffffe000847bb60,0xfffffe000847bde0]],'branch_pointers':[pointer(k,TABLE+8*j)|{'index':j} for j in [0x68e,0x693,0xc89,0xcd0,0x6a2,0x6bb]],'exact_symbols':k.symbols([0xfffffe000c4ba154,0xfffffe000c4ba368,0xfffffe000c4ba60c])}
def build():
 k=Kernel();rows=[]
 for c in B.cases():
  b=B.Entry(c);rows.append(b.run());del b
 s=source(k,rows);counts={'cases':len(rows),'matched_parent_cases':sum(r['input']['parent_case_index']is not None for r in rows),'new_boundary_cases':sum(r['input']['parent_case_index']is None for r in rows),'source_visits':sum(len(r['source_visits'])for r in rows),'source_reads':sum(len(r['source_reads'])for r in rows),'source_writes':sum(len(r['source_writes'])for r in rows),'new_source_spans':len(s['spans']),'new_source_words':s['new_words'],'bank_rules':3,'bank_input_cases':768,'API_models_per_case':3};boundaries=Counter(r['boundary']['pc'] for r in rows)
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'dependencies':{n:sha(ROOT/n)for n in DEPS},'scope':SCOPE,'source':s,'cases':rows,'boundary_counts':dict(boundaries),'verified_counts':counts,'continuous_earlier_allocation_return_established':True,**{n:False for n in FALSE}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'counts':e['verified_counts'],'boundaries':e['boundary_counts']}),flush=True)
