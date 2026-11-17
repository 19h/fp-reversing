#!/usr/bin/env python3
"""Freeze early data-return and shared-writer input provenance boundaries.
O(B+I+512+C*(B+V+E)) work/retained space; no native target execution.
"""
import json
from collections import Counter
from hashlib import sha256
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_MEM
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,TABLE,POOL,selected
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from recover_userclient_entry_execution import descriptor
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_early_node as Parent
import probe_userclient_early_data as B
P='userclient_early_data'
SCOPE='Original compiler entry through declared wire bytes and five register-only allocation returns. Source retains the data result at early node+0x18. A NULL data fixture reaches typed-node retirement; a non-NULL fixture requests the shared writer but stops before an undefined required-cell load. Five retained-node and seven metadata inputs are inventoried and conditionally lifted, without supplying their missing values. No buffer bytes, native allocation/free body, complete serialization, matched daemon/kext transaction or marker producer is established.'
DEPS=Parent.DEPS+['recover_userclient_early_node.py','audit_userclient_early_node.py','userclient_early_node_checks.json','userclient_early_node_audit.json','probe_userclient_early_data.py','replay_userclient_early_data.py','recover_userclient_record_nodes.py','audit_userclient_record_nodes.py','userclient_record_nodes_checks.json','userclient_record_nodes_audit.json','recover_userclient_record_writer.py','audit_userclient_record_writer.py','userclient_record_writer_checks.json','userclient_record_writer_audit.json']
FALSE=Parent.FALSE+['early_data_buffer_serialized','shared_writer_required_cell_epochs_established','other_node_allocation_returns_executed','typed_node_retirement_body_executed']
RETURN_STORES=[('C_768',0x768,0xfffffe000a6547a4),('C_458',0x458,0xfffffe000a65c46c),('C_140',0x140,0xfffffe000a65ccbc),('C_6b8',0x6b8,0xfffffe000a6425d0),('C_58',0x58,0xfffffe000a661668)]
RANGES=[(0xfffffe000a661848,0xfffffe000a6618ec),(0xfffffe000a664074,0xfffffe000a6640c4),(0xfffffe000a66414c,0xfffffe000a6641e8),(0xfffffe000a654ad4,0xfffffe000a654b98)]+[(a,a+12)for name,off,a in RETURN_STORES]
def source(k,rows):
 parent=json.loads(read(ROOT/'userclient_early_node_checks.json'));container=parent['source']['container'];start=0xfffffe000a635208;raw=k.read(start,0x31728);assert IMAGE.read(start,len(raw))==raw and sha256(raw).hexdigest()==container['sha256'];words=set()
 for r in rows:
  n=len(parent['cases'][r['input']['data_parent_case_index']]['source_visits']);words.update(int(v['pc'],16)for v in r['source_visits'][n:]);words.add(int(r['boundary']['pc'],16))
 for a,z in RANGES:words.update(range(a,z,4))
 groups=[]
 for a in sorted(words):
  if groups and groups[-1][1]==a:groups[-1][1]=a+4
  else:groups.append([a,a+4])
 spans=[]
 for j,(a,z)in enumerate(groups):
  b=k.read(a,z-a);assert IMAGE.read(a,len(b))==b;ii=list(CS.disasm(b,a));assert len(ii)*4==len(b);spans.append({'label':'source_'+str(j),'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]})
 rules=[]
 for name,l,r,key,add,base in [('node_retirement',0xfffffe0007949dd0,0xfffffe000792fbc0,0xb4,0xebd,TABLE),('retirement_descriptor',0xfffffe0007949fd0,0xfffffe000792ffc0,0x37,0xaa,POOL)]:
  q=selected(l,r,key,add,base,0);q.update(name=name,left256_hex=k.read(l,256).hex(),right256_hex=k.read(r,256).hex(),original_pointer=pointer(k,int(q['slot'],16)));assert IMAGE.read(l,256).hex()==q['left256_hex']and IMAGE.read(r,256).hex()==q['right256_hex']and q['original_pointer']['target']==q['target'];rules.append(q)
 dec=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);dec.detail=True;requirements=[]
 for i in dec.disasm(k.read(0xfffffe000a654ad8,0xb4),0xfffffe000a654ad8):
  if i.mnemonic not in ['ldr','ldrh']:continue
  base=i.reg_name(i.operands[1].mem.base)
  if base not in ['x3','x11']:continue
  assert not i.operands[1].mem.index;requirements.append({'source_PC':hex(i.address),'root':'C'if base=='x11'else'S','offset':hex(i.operands[1].mem.disp),'size_bytes':2 if i.mnemonic=='ldrh'else 4 if i.reg_name(i.operands[0].reg).startswith('w')else 8,'destination_register':i.reg_name(i.operands[0].reg)})
 assert len(requirements)==12 and sum(q['size_bytes']for q in requirements)==64
 offsets={int(q['offset'],16)for q in requirements};inventory=[]
 for i in dec.disasm(raw,start):
  if any(o.type==ARM64_OP_MEM and i.reg_name(o.mem.base)!='sp'and o.mem.disp in offsets for o in i.operands):inventory.append({'PC':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
 return {'container':container,'spans':spans,'captured_words':len(words),'bank_rules':rules,'descriptors':[parent['source']['node_descriptor'],descriptor(k,0xfffffe000847bfa0)],'branch_pointers':[pointer(k,TABLE+8*j)|{'index':j}for j in [0x871,0x87c,0x543,0xa71,0xa94]],'writer_requirements':requirements,'call_return_store_sites':[{'root':'C','offset':hex(off),'start':hex(a),'end_exclusive':hex(a+12)}for name,off,a in RETURN_STORES],'syntactic_exact_displacement_inventory':inventory,'inventory_alias_complete':False,'exact_symbols':k.symbols([0xfffffe000c4ba368])}
def build():
 k=Kernel();rows=[]
 for c in B.cases():
  b=B.Entry(c);rows.append(b.run());del b
 s=source(k,rows);counts={'cases':len(rows),'matched_parent_cases':len(rows),'nonnull_data_cases':sum(r['input']['data_result_fixture']!=0 for r in rows),'NULL_data_fixture_cases':sum(r['input']['data_result_fixture']==0 for r in rows),'source_visits':sum(len(r['source_visits'])for r in rows),'source_reads':sum(len(r['source_reads'])for r in rows),'source_writes':sum(len(r['source_writes'])for r in rows),'captured_words':s['captured_words'],'source_spans':len(s['spans']),'bank_input_cases':512,'API_models_per_case':5,'writer_required_cells':12,'writer_required_bytes':64,'call_return_store_sites':5,'syntactic_inventory_sites':len(s['syntactic_exact_displacement_inventory']),'initial_input_bytes_declared':sum(r['initial_input_bytes_declared']for r in rows)}
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'dependencies':{n:sha(ROOT/n)for n in DEPS},'scope':SCOPE,'source':s,'cases':rows,'boundary_counts':dict(Counter(r['boundary']['pc']for r in rows)),'verified_counts':counts,'conditional_early_data_return_established':True,**{n:False for n in FALSE}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'counts':e['verified_counts'],'boundaries':e['boundary_counts']}),flush=True)
