#!/usr/bin/env python3
"""Freeze actual nonzero-tag construction/writer/first-publication source.
O(B+I+C*W+256R) extraction time/space; original inputs are read-only.
"""
import json
from kext_port_tools import ROOT,IMAGE,TABLE,qword
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_fallback_metadata as Parent
import recover_userclient_record_nodes as N
import recover_userclient_record_writer as W
import recover_userclient_record_publication as L
P='userclient_nonzero_tag_record';pc=Parent.pc
SCOPE='Compose the actual protected 14-byte fallback metadata into nonzero-tag type0x6685 node/data requests, ordinary allocation-return cuts, complete first-record protected header/body writes, empty-container lookup and first-node publication, ending at the original cursor gate. Both retained parent modes and all body lengths0..4 retain byte/field custody. Native allocations, aliases, PAC, complete subsequent parse/outer return, public error semantics and matched daemon transport remain unknown.'
NODE_LABELS=['record_inputs','record_size_gate','node_allocate','node_return','node_null','node_initialize','buffer_allocate','buffer_return','buffer_prepare','writer_request','writer_setup']
WRITER_LABELS=[n for n in W.SPANS if n not in ['phase_token','saved_writer_controls']]
LIST_LABELS=['publication_request','search_entry','search_nonnull','search_node','search_result','search_callback','status_success_gate','status_miss_gate','append_prepare','append_empty','parser_cursor_gate']
BRANCHES={a:sorted({j for group in [Parent.BRANCHES,N.BRANCHES,W.BRANCHES,L.BRANCHES]for j in group.get(a,[])})for a in set(Parent.BRANCHES)|set(N.BRANCHES)|set(W.BRANCHES)|set(L.BRANCHES)}
RETAGS=Parent.RETAGS|W.RETAGS|L.RETAGS
BANK_PCS={n:N.BANK_PCS[n]for n in ['node_allocate','buffer_allocate']}|{'search_callback_value':L.BANK_PCS['search_callback_value']}
PREFIX=[(0x350,8,'context',0x628,0xa635e60),(0x570,8,'literal',0x87b,0xa635b0c),(0x60c,4,'literal',0x3f22ccfb,0xa635b1c)]
FALSE=['native_target_executed','idb_mutated','native_allocation_outcomes_established','native_pointer_authentication_established','native_input_byte_identity_established','native_alias_writer_exclusion_established','whole_message_parse_completed','outer_operation_completed','public_error_domain_established','daemon_transaction_correlated','new_Mach_endpoint_established','new_Mach_emission_established','full_goal_complete']
DEPS=['recover_userclient_fallback_metadata.py','audit_userclient_fallback_metadata.py','userclient_fallback_metadata_checks.json','userclient_fallback_metadata_audit.json','userclient_fallback_parser_checks.json','userclient_fallback_parser_audit.json','recover_userclient_record_nodes.py','audit_userclient_record_nodes.py','userclient_record_nodes_checks.json','userclient_record_nodes_audit.json','recover_userclient_record_writer.py','audit_userclient_record_writer.py','userclient_record_writer_checks.json','userclient_record_writer_audit.json','recover_userclient_record_publication.py','audit_userclient_record_publication.py','userclient_record_publication_checks.json','userclient_record_publication_audit.json','userclient_message_initialization_checks.json','userclient_early_data_checks.json']
def capture(k,label,row,transfer=False):
 a=int(row['start'],16);raw=bytes.fromhex(row['bytes_hex']);z=a+len(raw)
 if transfer:z+=4
 if next(Parent.Parent.CS.disasm(IMAGE.read(a-4,4),a-4)).mnemonic=='bti':a-=4
 return Parent.Parent.capture(k,label,a,z)
def build():
 k=Kernel();parent=json.loads(read(ROOT/'userclient_fallback_metadata_checks.json'));assert parent==Parent.build()
 records=[json.loads(read(ROOT/('userclient_record_'+n+'_checks.json')))for n in ['nodes','writer','publication']];spans=[]
 for e,labels,transfers in [(records[0],NODE_LABELS,N.TRANSFERS),(records[1],WRITER_LABELS,W.TRANSFERS),(records[2],LIST_LABELS,None)]:
  for label in labels:
   row=next(s for s in e['spans']if s['label']==label);end=int(row['start'],16)+len(bytes.fromhex(row['bytes_hex']))
   transfer=label in transfers if transfers is not None else IMAGE.read(end,4).hex() in ['100a1fd7','110a1fd7','300a1fd7','310a1fd7']
   # Decode the following word rather than relying on register-specific encodings.
   if transfers is None:
    i=next(Parent.Parent.CS.disasm(IMAGE.read(end,4),end));transfer=i.mnemonic in ['braa','blraa']
   spans.append(capture(k,'nz_'+label,row,transfer))
 prefix=[Parent.Parent.capture(k,n,pc(a),pc(z))for n,a,z in [('writer_phase_prefix',0xa6355f4,0xa6355fc),('writer_control_prefix',0xa635af8,0xa635b20),('publication_output_prefix',0xa635e5c,0xa635e64)]]
 rules=[];banks={}
 for e,names in [(records[0],['node_allocate','buffer_allocate']),(records[2],['search_callback_value'])]:
  for name in names:
   r=next(r for r in e['bank_rules']if r['name']==name);assert pointer(k,int(r['slot'],16))==r['original_pointer']and int(r['original_pointer']['target'],16)==qword(int(r['slot'],16));rules.append(r)
   for side in ['left','right']:
    a=int(r[side],16);b=IMAGE.read(a,256);assert b==k.read(a,256);banks[hex(a)]=b.hex()
 pointers=[]
 for s in spans:
  for a,indices in BRANCHES.items():
   if int(s['start'],16)<=a<int(s['end_exclusive'],16):
    for j in indices:
     p=pointer(k,TABLE+8*j);assert int(p['target'],16)==qword(TABLE+8*j);pointers.append({'source_PC':hex(a),'slot':hex(TABLE+8*j),'original_pointer':p})
 init=json.loads(read(ROOT/'userclient_message_initialization_checks.json'));old=json.loads(read(ROOT/'userclient_early_data_checks.json'));rows=[]
 for p in init['predecessor_states']:
  r=old['cases'][p['predecessor_case_index']];F=int(r['frame_base_SP'],16);C=int(p['handoff_state']['registers31'][11],16);bs=bytes.fromhex(r['frame']['bytes_hex']);known=bytes.fromhex(r['frame']['known_mask_hex']);prov=bytes.fromhex(r['frame']['provenance_hex']);cells=[]
  for off,n,role,value,writer in PREFIX:
   writes=[w for w in r['source_writes']if max(int(w['address'],16),F+off)<min(int(w['address'],16)+len(bytes.fromhex(w['after_hex'])),F+off+n)];assert len(writes)==1;w=writes[0];raw=bytes.fromhex(w['after_hex']);assert int(w['pc'],16)==pc(writer)and int(w['address'],16)==F+off and len(raw)==n and raw==bs[off:off+n]and known[off:off+n]==prov[off:off+n]==bytes([1])*n;assert int.from_bytes(raw,'little')==(C+value if role=='context'else value);cells.append({'frame_offset':hex(off),'size_bytes':n,'source_store':w,'bytes_hex':raw.hex()})
  rows.append({'predecessor_case_index':p['predecessor_case_index'],'frame_base_SP':hex(F),'cells':cells,'native_values_established':False})
 descriptor=records[0]['allocation_descriptor'];a=int(descriptor['address'],16);assert IMAGE.read(a,64).hex()==descriptor['normalized64_bytes_hex']and k.read(a,64).hex()==descriptor['original64_bytes_hex']
 assert int.from_bytes(k.read(a+40,4),'little')==descriptor['flags_u32']==0x64 and int.from_bytes(k.read(a+44,4),'little')==descriptor['size_bytes']==32
 for off,key,text in [(16,'name_pointer','site.FPTTLVNode'),(32,'signature_pointer','1121')]:
  assert pointer(k,a+off)==descriptor[key];p=int(descriptor[key]['target'],16);assert k.read(p,len(text)+1)==text.encode()+b'\0'
 return {'generator_sha256':sha(__file__),'source_sha256':parent['source_sha256'],'kernel_collection_sha256':k.sha256,'scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in DEPS},'source':{'container':parent['source']['container'],'spans':spans,'original_pointer_observations':pointers},'prefix_source':prefix,'prefix_cells':rows,'bank_rules':rules,'banks':banks,'node_descriptor':descriptor,'verified_counts':{'source_spans':len(spans),'captured_words':sum(len(s['instructions'])for s in spans),'prefix_words':sum(len(s['instructions'])for s in prefix),'bank_rules':len(rules),'bank_inputs_checked':256*len(rules),'original_pointer_observations':len(pointers),'prefix_states':len(rows),'reconstructed_prefix_cells':90,'reconstructed_prefix_bytes':600,'protected_input_extent_bytes':14,'header_bytes':10,'body_lengths_checked':5,'new_node_bytes':32,'container_bytes':16,'native_target_calls':0,'input_content_bytes_supplied':0},'conditional_nonzero_tag_record_established':True,**{n:False for n in FALSE}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
