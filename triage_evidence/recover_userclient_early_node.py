#!/usr/bin/env python3
"""Freeze the early node return, source initialization and lower allocation ABI.
O(B+I+256+C*(B+V+E)) time/retained space. No native target execution.
"""
import json
from collections import Counter
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,TABLE,selected
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_early_header as Parent
import probe_userclient_early_node as B
P='userclient_early_node'
SCOPE='Original compiler entry through declared pre-entry wire bytes and four register-only allocation returns. Early node result retention, source initialization and the next data-buffer request are observed in a private guest. A synthetic NULL result stops before an unbacked load; native NULL reachability or failure behavior is not established. Original allocator wrappers are frozen and symbolically inspected, not executed. Whole-operation completion, native ownership/PAC, marker production and matched daemon/kext identity remain unknown.'
DEPS=Parent.DEPS+['recover_userclient_early_header.py','audit_userclient_early_header.py','userclient_early_header_checks.json','userclient_early_header_audit.json','probe_userclient_early_node.py','replay_userclient_early_node.py']
FALSE=Parent.FALSE+['native_early_node_failure_reachability_established','native_early_node_zeroing_established','data_allocation_body_executed','public_source_matches_target_version']
PUBLIC_CONTEXT={'commit':'f6217f891ac0bb64f3d375211650a4c1ff8ca1ea','commit_date':'2025-10-16T22:36:30Z','matches_target_version':False,'target_version':'Darwin 27.2.0; xnu-13432.41.4~3/RELEASE_ARM64_T6041','sources':[
 {'repository_path':'osfmk/kern/zalloc.h','sha256':'3a7bcfed6b5062574a33ac59e15dd97fc8c8a80cc45b37c67f52f5f112c739d9','size_bytes':76490},
 {'repository_path':'iokit/Kernel/IOLib.cpp','sha256':'22b167a27c504267e80d23e16a9220da16e0480710d981604cfb24fd29b25822','size_bytes':41204},
 {'repository_path':'osfmk/kern/kalloc.c','sha256':'3291bd41a6744d4ebc8fcb5ecf230ef12b5f10bb9cd712b339d271f7551afda8','size_bytes':103269}]}
for s in PUBLIC_CONTEXT['sources']:s['url']='https://raw.githubusercontent.com/apple-oss-distributions/xnu/'+PUBLIC_CONTEXT['commit']+'/'+s['repository_path']
def source(k,rows):
 parent=json.loads(read(ROOT/'userclient_early_header_checks.json'));container=parent['source']['container'];raw=k.read(0xfffffe000a635208,0x31728);assert sha256(raw).hexdigest()==container['sha256']and IMAGE.read(0xfffffe000a635208,len(raw))==raw
 words=set()
 for r in rows:
  n=len(parent['cases'][r['input']['node_parent_case_index']]['source_visits']);words.update(int(v['pc'],16)for v in r['source_visits'][n:]);words.add(int(r['boundary']['pc'],16))
 words.update(range(0xfffffe000a661664,0xfffffe000a66184c,4));words.update(range(0xfffffe000a664074,0xfffffe000a66409c,4))
 groups=[]
 for a in sorted(words):
  if groups and groups[-1][1]==a:groups[-1][1]=a+4
  else:groups.append([a,a+4])
 spans=[]
 for j,(a,z)in enumerate(groups):
  b=k.read(a,z-a);assert IMAGE.read(a,len(b))==b;ii=list(CS.disasm(b,a));assert len(ii)*4==len(b);spans.append({'label':'source_'+str(j),'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]})
 funcs=[k.function(a)for a in [0xfffffe000c4ba154,0xfffffe000bcfeb8c,0xfffffe000c4ba60c]]
 for j,f in enumerate(funcs):spans.append({'label':'allocator_'+str(j),'start':f['start'],'end_exclusive':f['end'],'bytes_hex':f['bytes'],'instructions':[{'pc':i['ea'],'mnemonic':i['mnemonic'],'operands':i['operands']}for i in f['instructions']]})
 rule=selected(0xfffffe0007949dd0,0xfffffe000792fbc0,0x3e,0xebc,TABLE,0);rule.update(left256_hex=k.read(int(rule['left'],16),256).hex(),right256_hex=k.read(int(rule['right'],16),256).hex(),original_pointer=pointer(k,int(rule['slot'],16)))
 for address,payload in [('left','left256_hex'),('right','right256_hex')]:assert IMAGE.read(int(rule[address],16),256).hex()==rule[payload]
 assert rule['original_pointer']['target']==rule['target']
 return {'container':container,'spans':spans,'continuation_words':len(words),'data_allocation_bank':rule,'allocator_functions':funcs,'exact_symbols':k.symbols([0xfffffe000c4ba154,0xfffffe000bcfeb8c,0xfffffe000c4ba60c,0xfffffe000bd75c64,0xfffffe000bcfe5b8]),'branch_pointers':[pointer(k,TABLE+8*j)|{'index':j}for j in [0xaaa,0xb09,0x871]],'node_descriptor':parent['source']['descriptors'][0]}
def build():
 k=Kernel();rows=[]
 for c in B.cases():
  b=B.Entry(c);rows.append(b.run());del b
 s=source(k,rows);counts={'cases':len(rows),'matched_parent_cases':len(rows),'nonnull_node_cases':sum(r['input']['node_result_fixture']!=0 for r in rows),'NULL_node_fixture_cases':sum(r['input']['node_result_fixture']==0 for r in rows),'source_visits':sum(len(r['source_visits'])for r in rows),'source_reads':sum(len(r['source_reads'])for r in rows),'source_writes':sum(len(r['source_writes'])for r in rows),'continuation_words':s['continuation_words'],'continuation_spans':len(s['spans'])-3,'allocator_function_words':sum(len(f['instructions'])for f in s['allocator_functions']),'bank_input_cases':256,'API_models_per_case':4,'initial_input_bytes_declared':sum(r['initial_input_bytes_declared']for r in rows)}
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'dependencies':{n:sha(ROOT/n)for n in DEPS},'scope':SCOPE,'source':s,'public_source_context':PUBLIC_CONTEXT,'cases':rows,'boundary_counts':dict(Counter(r['boundary']['pc']for r in rows)),'verified_counts':counts,'conditional_early_node_prefix_established':True,**{n:False for n in FALSE}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'counts':e['verified_counts'],'boundaries':e['boundary_counts']}),flush=True)
