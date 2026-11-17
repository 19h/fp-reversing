#!/usr/bin/env python3
"""Freeze early protected-header source and predecessor handoff custody.
O(B+I+C*(V+M)) work/space. No target or IDB execution.
"""
import json
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,TABLE,qword
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha
P='userclient_early_writer'
SCOPE='Conditional original-source composition from the early non-NULL data return through shared setup and the exact protected ten-byte early header. The eight previously unknown setup cells remain arbitrary symbols; header/control independence is proved without repairing the stopped continuous private execution. Thirty predecessor-bound partial-state evaluations are distinct from native execution. Native allocation/initialization, retagged alias validity, full payload/list/operation completion and matched daemon/kext identity remain unknown.'
SPANS={'data_return':(0xfffffe000a66184c,0xfffffe000a661884),'early_prepare':(0xfffffe000a661884,0xfffffe000a6618ec),'shared_setup':(0xfffffe000a654ad4,0xfffffe000a654b98),'word_writer':(0xfffffe000a654c64,0xfffffe000a654dcc),'early_type':(0xfffffe000a654fc8,0xfffffe000a655068),'length_bridge':(0xfffffe000a654c44,0xfffffe000a654c64)}
BRANCHES={0xfffffe000a661864:[0x871,0x87c],0xfffffe000a6618b8:[0x543],0xfffffe000a654b8c:[0x439],0xfffffe000a654c68:[0x13c,0x165],0xfffffe000a655044:[0x2c9],0xfffffe000a654c48:[0x439]}
RETAGS={0xfffffe000a654c90:0xfffffe000a654c94,0xfffffe000a654ce0:0xfffffe000a654ce4,0xfffffe000a654d2c:0xfffffe000a654d30,0xfffffe000a654d88:0xfffffe000a654d8c}
DEPS=['kernel_native_reader.py','kext_port_tools.py','recover_kext_cold_init.py','lskd_values_symbolic.py','audit_userclient_entry_execution.py','audit_userclient_early_header.py','audit_userclient_early_node.py','recover_userclient_early_data.py','audit_userclient_early_data.py','replay_userclient_early_data.py','userclient_early_data_checks.json','userclient_early_data_audit.json','userclient_record_writer_checks.json','userclient_record_writer_audit.json','userclient_record_nodes_checks.json','userclient_record_nodes_audit.json','userclient_input_reader_checks.json','userclient_input_reader_audit.json']
FALSE=['native_target_executed','native_PAC_authenticated','continuous_execution_extended_past_undefined_cell','missing_setup_cells_assigned_concrete_values','native_initialization_established','alternate_retag_alias_equivalence_established','complete_early_payload_serialization_established','list_publication_established','native_daemon_kext_identity_established','new_Mach_port_endpoint_established','original_marker_producer_established','IDB_modified','full_goal_complete']
def build():
 k=Kernel();parent=json.loads(read(ROOT/'userclient_early_data_checks.json'));container=parent['source']['container'];raw=k.read(0xfffffe000a635208,0x31728);assert sha256(raw).hexdigest()==container['sha256']and IMAGE.read(0xfffffe000a635208,len(raw))==raw
 spans=[]
 for label,(a,z)in SPANS.items():
  b=k.read(a,z-a);assert IMAGE.read(a,len(b))==b;ii=list(CS.disasm(b,a));assert len(ii)*4==len(b);spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]})
 pointers=[pointer(k,TABLE+8*j)|{'index':j}for j in sorted({j for js in BRANCHES.values()for j in js}|{0x152})]
 for q in pointers:assert int(q['target'],16)==qword(TABLE+8*q['index'])
 joins=[]
 for j,r in enumerate(parent['cases']):
  if not r['input']['data_result_fixture']:continue
  ix=next(n for n,v in enumerate(r['source_visits'])if v['pc']=='0xfffffe000a6618e8');assert r['boundary']['pc']=='0xfffffe000a654ae4'and r['boundary']['kind']=='before_undefined_private_value_load'
  joins.append({'predecessor_case_index':j,'input':r['input'],'frame_base_SP':r['frame_base_SP'],'handoff_PC':'0xfffffe000a6618e8','handoff_state':r['source_frames'][ix],'stopped_boundary':r['boundary'],'node':r['earlier_node'],'writer_input_cells':r['writer_input_cells']})
 assert len(joins)==30
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in DEPS},'source':{'container':container,'spans':spans,'branch_pointers':pointers,'retag_sites':{hex(a):hex(z)for a,z in RETAGS.items()}},'predecessor_handoffs':joins,'verified_counts':{'source_spans':len(spans),'captured_words':sum(len(s['instructions'])for s in spans),'table_lookup_sites':len(BRANCHES),'original_table_pointers':len(pointers),'unique_retag_sites':len(RETAGS),'predecessor_handoffs':len(joins),'header_bytes':10,'arbitrary_missing_cells':8},'conditional_early_header_source_captured':True,**{n:False for n in FALSE}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
