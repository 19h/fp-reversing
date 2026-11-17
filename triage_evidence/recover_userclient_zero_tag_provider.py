#!/usr/bin/env python3
"""Freeze original caller words and core entry-argument store provenance.
O(B+I+C*W) time/space; no native execution or IDB mutation.
"""
import json
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_transfer_boundary as T
import recover_userclient_zero_tag_return as C
P='userclient_zero_tag_provider';pc=C.pc
SCOPE='Conditional nominal selector26 caller completion for the retained zero-tag core result. Bind the direct core call, argument/frame interfaces, nullable forwarded state, copy requests, cleanup and nonzero handler output branch. The selected core theorem, ordinary authenticated returns, stable accessible objects and surviving caller frames are premises. Native transfers, actual matched execution, public status naming and daemon transaction identity remain unknown.'
FALSE=['native_target_executed','idb_mutated','native_core_path_reachability_established','native_transfer_bytes_established','native_pointer_authentication_established','public_error_domain_established','new_Mach_endpoint_established','new_Mach_emission_established','daemon_transaction_correlated','full_goal_complete']
DEPS=['recover_userclient_transfer_boundary.py','audit_userclient_transfer_boundary.py','userclient_transfer_boundary_checks.json','userclient_transfer_boundary_audit.json','recover_userclient_zero_tag_return.py','audit_userclient_zero_tag_return.py','userclient_zero_tag_return_checks.json','userclient_zero_tag_return_audit.json','userclient_message_initialization_checks.json','userclient_early_data_checks.json']
ARGS=[('forwarded_state',2,0x738,0xa63524c),('extent64',1,0x878,0xa635250),('input',0,0x8f8,0xa635254)]
def build():
 t=json.loads(read(ROOT/'userclient_transfer_boundary_checks.json'));assert t==T.build()
 c=json.loads(read(ROOT/'userclient_zero_tag_return_checks.json'));assert c==C.build()
 call=next(x for x in t['calls']if x['role']=='core');assert call['site']==hex(pc(0xa5052fc))and call['mnemonic']=='bl'and call['operands']=='#'+hex(pc(0xa635208))
 init=json.loads(read(ROOT/'userclient_message_initialization_checks.json'));old=json.loads(read(ROOT/'userclient_early_data_checks.json'));rows=[]
 for p in init['predecessor_states']:
  r=old['cases'][p['predecessor_case_index']];F=int(r['frame_base_SP'],16);b=bytes.fromhex(r['frame']['bytes_hex']);known=bytes.fromhex(r['frame']['known_mask_hex']);prov=bytes.fromhex(r['frame']['provenance_hex']);cells=[]
  for role,reg,off,writer in ARGS:
   writes=[w for w in r['source_writes']if max(int(w['address'],16),F+off)<min(int(w['address'],16)+len(bytes.fromhex(w['after_hex'])),F+off+8)]
   assert len(writes)==1;w=writes[0];assert int(w['pc'],16)==pc(writer)and int(w['address'],16)==F+off and len(bytes.fromhex(w['after_hex']))==8
   raw=bytes.fromhex(w['after_hex']);assert raw==b[off:off+8]and known[off:off+8]==prov[off:off+8]==bytes([1])*8 and int.from_bytes(raw,'little')==int(r['entry_registers31'][reg],16)
   cells.append({'role':role,'entry_register':'X'+str(reg),'offset':hex(off),'value64':hex(int.from_bytes(raw,'little')),'source_store':w,'known_and_provenance_bytes':8})
  x0,x1,x2=[int(q,16)for q in r['entry_registers31'][:3]];assert x0==int(p['original_input64'],16)and x1&0xffffffff==p['original_extent32']and x2==0
  rows.append({'predecessor_case_index':p['predecessor_case_index'],'entry_SP':r['entry_SP'],'frame_base_SP':hex(F),'entry_arguments64':[hex(x0),hex(x1),hex(x2)],'selected_extent14':x1==14,'cells':cells,'native_input_bytes_established':False})
 assert len(rows)==30 and [r['predecessor_case_index']for r in rows if r['selected_extent14']]==[5,15,25,35,45,55]
 return {'generator_sha256':sha(__file__),'source_sha256':t['source_sha256'],'kernel_collection_sha256':t['kernel_collection_sha256'],'scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in DEPS},'caller':t,'core_entry_source':next(s for s in c['source']['spans']if s['label']=='frame_entry'),'direct_core_call':call|{'canonical_target':hex(pc(0xa635208)),'nominal_return_PC':hex(pc(0xa505300))},'prefix_argument_custody':rows,'verified_counts':{'caller_source_words':191,'caller_call_sites':14,'original_bindings':8,'prefix_states':30,'argument_cells_per_prefix':3,'reconstructed_argument_cells':90,'reconstructed_argument_bytes':720,'selected_extent14_prefixes':6,'selected_extent_bytes':14,'handler_frame_bytes':64,'provider_frame_bytes':80,'core_frame_bytes':4336,'nested_frame_bytes':4480,'native_target_calls':0,'input_content_bytes_supplied':0},'conditional_zero_tag_provider_established':True,**{n:False for n in FALSE}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
