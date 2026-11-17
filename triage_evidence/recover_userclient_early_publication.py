#!/usr/bin/env python3
"""Freeze early lookup/first-publication/cursor ABI and prefix cell custody.
O(B+I+C*W+256) construction/space; no native execution or IDB mutation.
"""
import json
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,TABLE,qword
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_early_payload as P0
import recover_userclient_record_publication as RP
P='userclient_early_publication'
SCOPE='Conditional original-source first-record publication from the early scalar/span serialization frontier: caller-specific lookup output/return ABI, fresh empty container miss, first-node head/tail publication, saved callback and exact parser cursor gate. Thirty predecessor prefixes establish source-defined retained cells, not a continued guest execution. Nonempty lookup/replacement, native storage/PAC/ownership/locking, final operation and matched daemon/kext transaction remain unknown.'
SPANS={'H_zero':(0xfffffe000a6366c8,0xfffffe000a6366cc),'early_output_root':(0xfffffe000a635e64,0xfffffe000a635e6c),'early_publication_request':(0xfffffe000a655cb4,0xfffffe000a655d38),'search_entry':(0xfffffe000a662ab4,0xfffffe000a662b00),'search_nonnull':(0xfffffe000a662be0,0xfffffe000a662c00),'search_node':(0xfffffe000a662c00,0xfffffe000a662c44),'search_result':(0xfffffe000a662c44,0xfffffe000a662c60),'search_callback':(0xfffffe000a662b00,0xfffffe000a662b64),'early_status_success':(0xfffffe000a662b64,0xfffffe000a662b78),'early_status_miss':(0xfffffe000a662b78,0xfffffe000a662b88),'early_append_prepare':(0xfffffe000a662b88,0xfffffe000a662bc4),'early_append_empty':(0xfffffe000a662bc4,0xfffffe000a662be0),'early_saved_callback':(0xfffffe000a664218,0xfffffe000a664230),'early_parser_callback':(0xfffffe000a661ba0,0xfffffe000a661bfc),'early_cursor_gate':(0xfffffe000a660af4,0xfffffe000a660b2c)}
BRANCHES=P0.BRANCHES|{0xfffffe000a655ce4:[0x49a],0xfffffe000a662ac0:[0x6c],0xfffffe000a662ae8:[0x630,0x63e],0xfffffe000a662bf4:[0x52d],0xfffffe000a662c28:[0x50c,0x50d],0xfffffe000a662c50:[0x63e],0xfffffe000a662bb8:[0xd20,0xd6a],0xfffffe000a662bcc:[0x63d],0xfffffe000a661bdc:[0x48c,0x4a2],0xfffffe000a660b20:[0xc89,0xcd0]}
DIRECT=P0.DIRECT|{0xfffffe000a662b74:('b.eq',0xfffffe000a663d28),0xfffffe000a662b84:('b.ne',0xfffffe000a664048)}
FALSE=[n for n in P0.FALSE if n not in ['list_publication_established','post_payload_publication_established']]+['native_list_publication_established','nonempty_early_lookup_replacement_established','whole_early_parser_established','native_locking_established']
def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_early_payload_checks.json'));parents=json.loads(read(ROOT/'userclient_early_data_checks.json'));pub=RP.build();raw=k.read(0xfffffe000a635208,0x31728);assert sha256(raw).hexdigest()==prior['source']['container']['sha256']and IMAGE.read(0xfffffe000a635208,len(raw))==raw
 spans=[]
 for label,(a,z)in SPANS.items():
  b=k.read(a,z-a);assert IMAGE.read(a,len(b))==b;ii=list(CS.disasm(b,a));assert len(ii)*4==len(b);spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]})
 pointers=[pointer(k,TABLE+8*j)|{'index':j}for j in sorted({j for js in BRANCHES.values()for j in js})]
 for q in pointers:assert int(q['target'],16)==qword(TABLE+8*q['index'])
 bank=next(r for r in pub['bank_rules']if r['name']=='search_callback_value');banks={n:pub['banks'][n]for n in ['FL','FR']};l,r=(bytes.fromhex(banks[n]['bytes_hex'])for n in ['FL','FR']);assert all(j^r[l[j]^int(bank['key'],16)]==int(bank['constant'],16)for j in range(256))
 rows=[]
 for p in prior['predecessor_states']:
  source=parents['cases'][p['predecessor_case_index']];g=[int(x,16)for x in p['handoff_state']['registers31']];f=int(p['frame_base_SP'],16);c,s=g[11],g[3];h=source['input']['FPTTLV_result_fixture'];j=source['input']['node_result_fixture'];cells=[];N=source['input']['inputs8'][1]&0xffffffff;L=source['input']['wire_length32'];D=source['input']['wire_tag32']
  specs=[('F',f,o,8,v)for o,v in [(0x348,c+0x50),(0xa30,0xfffffe000ccc30d0),(0xa38,0xfffffe000ccc32f8),(0xa48,0xfffffe0007949dd0),(0xa00,0xfffffe000792fcc0),(0xa20,0xfffffe00079391f0)]]+[('C',c,0x20,8,h),('C',c,0x260,8,0xfffffe000a661ba0),('C',c,0x58,8,j),('S',s,0x1d0,4,D^0x31ae0066),('S',s,0xa10,8,L+10),('S',s,0xb5c,4,N^0x31ae0066),('H',h,0,8,0),('H',h,8,8,0),('J',j,0,8,0),('J',j,8,8,0)]
  for root,base,off,n,want in specs:
   state=[None]*n;touches=[]
   for w in source['source_writes']:
    a=int(w['address'],16);b=bytes.fromhex(w['after_hex']);lo=max(a,base+off);hi=min(a+len(b),base+off+n)
    if lo<hi:
     touches.append(w)
     for addr in range(lo,hi):state[addr-base-off]=b[addr-a]
   assert None not in state and int.from_bytes(bytes(state),'little')==want;cells.append({'root':root,'offset':hex(off),'size_bytes':n,'reconstructed_bytes_hex':bytes(state).hex(),'overlapping_source_stores':touches})
  visit=next(i for i,v in enumerate(source['source_visits'])if v['pc']=='0xfffffe000a635e64');assert int(source['source_frames'][visit]['registers31'][2],16)==c
  rows.append({'predecessor_case_index':p['predecessor_case_index'],'input':p['input'],'frame_base_SP':p['frame_base_SP'],'handoff_state':p['handoff_state'],'stopped_boundary':p['stopped_boundary'],'source_defined_cells':cells,'original_container':hex(h),'outer_size32':N,'cursor64':L+10})
 deps={n:sha(ROOT/n)for n in sorted(set(P0.H.DEPS+RP.DEPS+list(prior['dependencies'])+list(pub['dependencies'])+['recover_userclient_early_payload.py','audit_userclient_early_payload.py','userclient_early_payload_checks.json','userclient_early_payload_audit.json','recover_userclient_record_publication.py','audit_userclient_record_publication.py','userclient_record_publication_checks.json','userclient_record_publication_audit.json']))}
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'scope':SCOPE,'dependencies':deps,'source':{'container':prior['source']['container'],'spans':spans,'branch_pointers':pointers,'direct_branches':{hex(pc):{'mnemonic':m,'target':hex(t)}for pc,(m,t)in DIRECT.items()if pc not in P0.DIRECT},'bank_rule':bank,'banks':banks},'payload_source':prior['source'],'header_source':prior['header_source'],'predecessor_states':rows,'verified_counts':{'new_source_spans':len(spans),'new_captured_words':sum(len(s['instructions'])for s in spans),'original_table_pointers':len(pointers),'new_direct_status_branches':2,'bank_input_cases':256,'predecessor_states':len(rows),'source_defined_cells_per_state':16},'conditional_first_record_publication_established':True,**{n:False for n in FALSE}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
