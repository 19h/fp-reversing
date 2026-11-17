#!/usr/bin/env python3
"""Freeze actual second-parser allocation failure and message/attribute unwind.
O(B+I+256R+C*W) extraction work/space; original inputs are read-only.
"""
import json
from kext_port_tools import ROOT,IMAGE,CS,TABLE,POOL,selected
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from recover_userclient_entry_execution import descriptor
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_message_parser as Parent
P='userclient_message_failure';pc=Parent.pc
SCOPE='Actual source-built message, second-parser allocation NULL, complete selected message and attribute retirement requests/ordinary returns, cleared factory output and preserved raw error through the next original-container cleanup request. No input-content byte, native free/PAC effect, successful parse or completed outer dispatcher is established.'
SPANS={n:(pc(a),pc(z))for n,a,z in [
 ('failure_save',0xa6650a4,0xa665108),('failure_stage',0xa665108,0xa665138),
 ('failure_destroy_entry',0xa6621e4,0xa66222c),('failure_message_children',0xa662264,0xa66229c),
 ('failure_container_bridge',0xa66229c,0xa6622bc),('failure_container_entry',0xa660468,0xa6604a4),
 ('failure_container_object',0xa6604a4,0xa6604fc),('failure_container_return',0xa660614,0xa660630),
 ('failure_second_child',0xa660630,0xa66066c),('failure_message_free',0xa660980,0xa660a24),
 ('failure_message_freed',0xa660a24,0xa660a80),('failure_clear_alias',0xa660a80,0xa660a98),
 ('failure_saved_callback',0xa66222c,0xa66223c),('failure_restore',0xa66223c,0xa662264),
 ('failure_output',0xa665138,0xa665154),('failure_outer',0xa665154,0xa66516c),
 ('failure_outer_status',0xa636d34,0xa636dac),('failure_outer_prepare',0xa641af8,0xa641b3c),
 ('failure_attribute_prepare',0xa641b3c,0xa641b84),('failure_attribute_entry',0xa656a5c,0xa656aa0),
 ('failure_attribute_free',0xa656aa0,0xa656b28),('failure_attribute_freed',0xa656b28,0xa656b68),
 ('failure_attribute_return',0xa656b68,0xa656b74),('failure_final_status',0xa641b84,0xa641bf4),
 ('failure_original_container',0xa641c1c,0xa641c60)]}
ROOTS=[(0x6d0,8,'C',0x1d0),(0x9ac,4,'literal',0xf2b6cffb),(0x688,4,'literal',0x67da8ba5)]
RULES=[(0xa6609b8,0xa6609c8,0x7949ed0,0x792fec0,0x32),(0xa6609ec,0xa6609fc,0x7949dd0,0x792fbc0,0x73),(0xa656ac4,0xa656ad4,0x7949dd0,0x792fbc0,0x5c),(0xa656af0,0xa656b00,0x7941f60,0x794a0d0,0x6d)]
LITERALS={pc(a):pc(b)for a,b in [(0xa6609d8,0x847a878),(0xa660a14,0x8472450),(0xa656ae4,0x847a878),(0xa656b18,0x84722f8)]}
BRANCHES={pc(a):js for a,js in [
 (0xa6650e8,[0x485,0x456]),(0xa665128,[0x41f]),(0xa6621f4,[0x34,0xb0]),(0xa662220,[0x61a,0x621]),
 (0xa662288,[0x2b7]),(0xa6622b0,[0x9a7]),(0xa660470,[0x26,0x4b]),(0xa660498,[0xafc]),
 (0xa6604f0,[0x432]),(0xa660660,[0x9a7]),(0xa660a74,[0xf17]),(0xa660a8c,[0x621]),
 (0xa662258,[0x456]),(0xa665148,[0x477]),(0xa636d70,[0x44d]),(0xa641b2c,[0x41f]),
 (0xa641b5c,[0x270]),(0xa656a78,[0x1c1]),(0xa656a94,[0x3a5]),(0xa656b5c,[0x3f3]),
 (0xa641bd4,[0x656]),(0xa641c50,[0x2b7])]}
FALSE=Parent.FALSE+['native_message_retirement_established','native_attribute_retirement_established','outer_operation_completed']
def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_message_parser_checks.json'));assert prior==Parent.build();init=json.loads(read(ROOT/'userclient_message_initialization_checks.json'));originals=json.loads(read(ROOT/'userclient_early_data_checks.json'));spans=[]
 for name,(a,z)in SPANS.items():
  raw=k.read(a,z-a);assert raw==IMAGE.read(a,z-a);ii=list(CS.disasm(raw,a));assert len(ii)*4==len(raw);spans.append({'label':name,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':raw.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]})
 rules=[];banks={}
 for lp,rp,l,r,key in RULES:
  q=selected(pc(l),pc(r),key,0,POOL,0);rules.append({n:q[n]for n in ['left','right','key','constant','inputs_checked']}|{'left_PC':hex(pc(lp)),'right_PC':hex(pc(rp))})
  for a in [pc(l),pc(r)]:
   raw=k.read(a,256);assert raw==IMAGE.read(a,256);banks[hex(a)]=raw.hex()
 cells=[]
 for p in init['predecessor_states']:
  r=originals['cases'][p['predecessor_case_index']];F=int(p['frame_base_SP'],16);g=[int(x,16)for x in p['handoff_state']['registers31']];C=g[11];rows=[]
  for off,n,root,value in ROOTS:
   want=C+value if root=='C'else value;bs=[None]*n;touch=[]
   for w in r['source_writes']:
    at=int(w['address'],16);b=bytes.fromhex(w['after_hex']);lo,hi=max(at,F+off),min(at+len(b),F+off+n)
    if lo<hi:
     touch.append(w)
     for j in range(lo,hi):bs[j-F-off]=b[j-at]
   assert None not in bs and int.from_bytes(bytes(bs),'little')==want;rows.append({'frame_offset':hex(off),'size_bytes':n,'role':root,'value':hex(value),'reconstructed_bytes_hex':bytes(bs).hex(),'overlapping_original_stores':touch})
  cells.append({'predecessor_case_index':p['predecessor_case_index'],'frame_base_SP':p['frame_base_SP'],'source_defined_cells':rows})
 descriptors=[descriptor(k,pc(a))for a in [0x847b360,0x847b920]]
 attr=json.loads(read(ROOT/'userclient_message_attributes_checks.json'));assert descriptors[0]['normalized64_hex']==init['message_descriptor']['normalized64_bytes_hex']and descriptors[1]['normalized64_hex']==attr['attribute_descriptor']['normalized64_bytes_hex']
 deps=['recover_userclient_message_parser.py','audit_userclient_message_parser.py','userclient_message_parser_checks.json','userclient_message_parser_audit.json','userclient_message_initialization_checks.json','userclient_message_attributes_checks.json','userclient_early_data_checks.json']
 return {'generator_sha256':sha(__file__),'source_sha256':prior['source_sha256'],'kernel_collection_sha256':k.sha256,'scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'source':{'container':prior['source']['container'],'spans':spans,'literal_pointers':[{'source_PC':hex(p),'slot':hex(a),'original_pointer':pointer(k,a)}for p,a in LITERALS.items()],'branch_pointers':[pointer(k,TABLE+8*j)|{'index':j}for j in sorted({j for js in BRANCHES.values()for j in js})]},'bank_rules':rules,'banks':banks,'retirement_descriptors':descriptors,'prefix_cells':cells,'retirement_symbols':k.symbols([pc(0xc4ba368)]),'verified_counts':{'source_spans':len(spans),'captured_words':sum(len(s['instructions'])for s in spans),'bank_rules':4,'certified_bank_inputs':1024,'original_literal_pointers':len(LITERALS),'original_branch_pointers':len({j for js in BRANCHES.values()for j in js}),'prefix_states':len(cells),'additional_cells_per_state':3,'additional_cell_bytes_per_state':16,'retirement_descriptors':2,'message_extent_bytes':128,'attribute_extent_bytes':112,'retirement_calls_per_case':2,'input_content_bytes_supplied':0},'conditional_message_failure_unwind_established':True,**{n:False for n in FALSE}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
