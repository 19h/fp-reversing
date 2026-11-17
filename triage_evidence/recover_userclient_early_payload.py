#!/usr/bin/env python3
"""Freeze all three early payload domains, saved controls and predecessor custody.
O(B+I+C*W) construction/space; no native target operation or IDB mutation.
"""
import json
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,TABLE,qword
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_early_writer as H
P='userclient_early_payload'
SCOPE='Conditional original-source early payload composition for u32/u64 and plaintext spans, with exact scalar widths, protected scalar bytes, zero/nonzero span dispatch and a universal reverse-copy step. All eight unrelated setup cells remain symbolic. Saved controls are source-produced and checked against thirty stopped predecessor prefixes; continuous execution is not repaired or extended. Native storage/PAC/ownership, post-payload publication and matched daemon/kext identity remain unknown.'
SPANS={'fixed_controls':(0xfffffe000a635ad8,0xfffffe000a635af8),'u64_cell':(0xfffffe000a635bac,0xfffffe000a635bb4),'table_cell':(0xfffffe000a6362fc,0xfffffe000a636300),'primary_gate':(0xfffffe000a654dcc,0xfffffe000a654ddc),'u32_gate':(0xfffffe000a654ddc,0xfffffe000a654e34),'u32_request':(0xfffffe000a654e34,0xfffffe000a654e70),'secondary_gate':(0xfffffe000a6551c4,0xfffffe000a6551d0),'span_gate':(0xfffffe000a6551d0,0xfffffe000a6551fc),'span_length':(0xfffffe000a6551fc,0xfffffe000a65538c),'span_request':(0xfffffe000a65538c,0xfffffe000a6553b0),'span_copy':(0xfffffe000a6553b0,0xfffffe000a655434),'u64_gate':(0xfffffe000a655a74,0xfffffe000a655acc),'u64_request':(0xfffffe000a655acc,0xfffffe000a655b14),'u64_writer':(0xfffffe000a655b14,0xfffffe000a655cb4)}
BRANCHES=H.BRANCHES|{0xfffffe000a654c68:[0x13c,0x165,0x129],0xfffffe000a654e18:[0x871,0xc44],0xfffffe000a654e48:[0x2c9],0xfffffe000a655378:[0xdab,0xdac],0xfffffe000a6553a4:[0x922],0xfffffe000a655428:[0x922,0x997],0xfffffe000a655ab0:[0x871,0xc32],0xfffffe000a655af4:[0x684],0xfffffe000a655b30:[0xc5]}
DIRECT={0xfffffe000a654dd8:('b.ne',0xfffffe000a6551c4),0xfffffe000a6551cc:('b.eq',0xfffffe000a655a74),0xfffffe000a6551f8:('b.ne',0xfffffe000a664074)}
RETAGS=H.RETAGS|{0xfffffe000a6553e0:0xfffffe000a6553e4}
FALSE=[n for n in H.FALSE if n!='complete_early_payload_serialization_established']+['unconditional_early_payload_serialization_established','native_span_input_capacity_established','post_payload_publication_established']
def build():
 k=Kernel();h=json.loads(read(ROOT/'userclient_early_writer_checks.json'));p=json.loads(read(ROOT/'userclient_early_data_checks.json'));raw=k.read(0xfffffe000a635208,0x31728);assert sha256(raw).hexdigest()==h['source']['container']['sha256']and IMAGE.read(0xfffffe000a635208,len(raw))==raw
 spans=[]
 for label,(a,z)in SPANS.items():
  b=k.read(a,z-a);assert IMAGE.read(a,len(b))==b;ii=list(CS.disasm(b,a));assert len(ii)*4==len(b);spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]})
 pointers=[pointer(k,TABLE+8*j)|{'index':j}for j in sorted({j for js in BRANCHES.values()for j in js})]
 for q in pointers:assert int(q['target'],16)==qword(TABLE+8*q['index'])
 rows=[]
 for join in h['predecessor_handoffs']:
  ix=join['predecessor_case_index'];r=p['cases'][ix];f=int(r['frame_base_SP'],16);s=int(join['handoff_state']['registers31'][3],16);c=int(join['handoff_state']['registers31'][11],16);cells=[]
  for root,base,off,n in [('F',f,0x104,4),('F',f,0x560,8),('F',f,0xf8,8),('F',f,0xa60,8),('S',s,0xad0,8),('S',s,0xca8,8),('C',c,0x168,8)]:
   writes=[w for w in r['source_writes']if int(w['address'],16)==base+off and w['size_bytes']==n];assert writes;last=writes[-1];state=[None]*n;touches=[]
   for w in r['source_writes']:
    a=int(w['address'],16);b=bytes.fromhex(w['after_hex']);lo=max(a,base+off);hi=min(a+len(b),base+off+n)
    if lo<hi:
     touches.append(w)
     for addr in range(lo,hi):state[addr-base-off]=b[addr-a]
   assert all(x is not None for x in state)and bytes(state)==bytes.fromhex(last['after_hex']);cells.append({'root':root,'offset':hex(off),'size_bytes':n,'last_exact_store':last,'overlapping_source_stores':touches,'reconstructed_bytes_hex':bytes(state).hex()})
  for pc,reg,want in [(0xfffffe000a635bac,4,s),(0xfffffe000a6362fc,7,TABLE)]:
   visit=next(j for j,v in enumerate(r['source_visits'])if int(v['pc'],16)==pc);assert int(r['source_frames'][visit]['registers31'][reg],16)==want
  values=[int.from_bytes(bytes.fromhex(q['reconstructed_bytes_hex']),'little')for q in cells];data=bytes.fromhex(r['input']['input_fixture_hex']);L=r['input']['wire_length32'];profile=r['input']['profile'];Q=int.from_bytes(data[10:18],'big')if profile.startswith('u64')else 0;B=int.from_bytes(data[10:14],'big')if profile.startswith('u32')else 0
  assert values[:4]==[0x802218a3,0x886a1ca0,s+0xad0,TABLE]and values[4]==Q^0x8f98c6acce5848ca and values[5]==L+0x622f763938943e93
  assert values[6]==(r['input']['inputs8'][0]+10 if profile.startswith('blob')else 0)
  rows.append({'predecessor_case_index':ix,'input':r['input'],'frame_base_SP':r['frame_base_SP'],'handoff_state':join['handoff_state'],'stopped_boundary':join['stopped_boundary'],'source_defined_cells':cells,'raw_scalar32':B,'raw_scalar64':Q,'span_source':values[6]})
 deps={n:sha(ROOT/n)for n in H.DEPS+['recover_userclient_early_writer.py','audit_userclient_early_writer.py','userclient_early_writer_checks.json','userclient_early_writer_audit.json']}
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'scope':SCOPE,'dependencies':deps,'source':{'container':h['source']['container'],'spans':spans,'branch_pointers':pointers,'direct_branches':{hex(pc):{'mnemonic':m,'target':hex(t)}for pc,(m,t)in DIRECT.items()},'new_retag_sites':{'0xfffffe000a6553e0':'0xfffffe000a6553e4'}},'header_source':h['source'],'predecessor_states':rows,'verified_counts':{'new_source_spans':len(spans),'new_captured_words':sum(len(s['instructions'])for s in spans),'original_table_pointers':len(pointers),'direct_type_branches':len(DIRECT),'predecessor_states':len(rows),'source_defined_cells_per_state':7,'early_payload_domains':3},'conditional_three_domain_payload_serialization_established':True,**{n:False for n in FALSE}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
