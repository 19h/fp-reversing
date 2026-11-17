#!/usr/bin/env python3
"""Freeze original-container retirement and failure fallback staging interfaces.
O(B+I+256R+C*W) extraction work/space; original inputs remain read-only.
"""
import json
from kext_port_tools import ROOT,IMAGE,CS,qword,selected,POOL
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from recover_userclient_entry_execution import descriptor
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_message_failure as Parent
P='userclient_failure_fallback';pc=Parent.pc
SCOPE='Actual second-parser allocation-NULL unwind through original record/node/container retirement and exact-size fallback allocation; fallback NULL reaches context/workspace retirement requests, and fallback nonnull performs the selected 14-byte protected copy and requests a new staged-parser allocation. Retirement/allocator returns are ordinary-return premises. Native frees, byte custody, complete fallback parsing, compiler-canary/PAC admission and whole outer return remain unknown.'
SPANS={
 'ff_a66229c':(pc(0xa66229c),pc(0xa6622bc)),
 'ff_a660468':(pc(0xa660468),pc(0xa6604a4)),
 'ff_a6604a4':(pc(0xa6604a4),pc(0xa6604fc)),
 'ff_a6604fc':(pc(0xa6604fc),pc(0xa660534)),
 'ff_a660750':(pc(0xa660750),pc(0xa660790)),
 'ff_a660790':(pc(0xa660790),pc(0xa6607ec)),
 'ff_a6607ec':(pc(0xa6607ec),pc(0xa660814)),
 'ff_a66066c':(pc(0xa66066c),pc(0xa66070c)),
 'ff_a66070c':(pc(0xa66070c),pc(0xa660750)),
 'ff_a660534':(pc(0xa660534),pc(0xa6605c8)),
 'ff_a6605c8':(pc(0xa6605c8),pc(0xa660614)),
 'ff_a660614':(pc(0xa660614),pc(0xa660630)),
 'ff_a641c60':(pc(0xa641c60),pc(0xa641cfc)),
 'ff_a641cfc':(pc(0xa641cfc),pc(0xa641d54)),
 'ff_a6661bc':(pc(0xa6661bc),pc(0xa666264)),
 'ff_a666264':(pc(0xa666264),pc(0xa6662b4)),
 'ff_a641d54':(pc(0xa641d54),pc(0xa641dc4)),
 'ff_a641e08':(pc(0xa641e08),pc(0xa641e68)),
 'ff_a641e68':(pc(0xa641e68),pc(0xa641ee0)),
 'ff_a641ee0':(pc(0xa641ee0),pc(0xa641f14)),
 'ff_a641fb4':(pc(0xa641fb4),pc(0xa64209c)),
}
PREFIX_SPANS={'prefix_length_channels':(pc(0xa6356ac),pc(0xa63579c)),'prefix_saved_error':(pc(0xa636678),pc(0xa636694)),'qualified_return_decode':(pc(0xa6662cc),pc(0xa6662d0))}
POINTERS={
 pc(0xa6622b0):[pc(0x8477c58)],
 pc(0xa660470):[pc(0x8473048)],
 pc(0xa660498):[pc(0x8478700)],
 pc(0xa6604f0):[pc(0x8475320)],
 pc(0xa660528):[pc(0x8474fc0)],
 pc(0xa660784):[pc(0x8477c10)],
 pc(0xa6607e0):[pc(0x847a7f0)],
 pc(0xa660808):[pc(0x8477b68)],
 pc(0xa6606c0):[pc(0x847a878)],
 pc(0xa6606f8):[pc(0x8472d20)],
 pc(0xa660740):[pc(0x8475010)],
 pc(0xa660580):[pc(0x847a878)],
 pc(0xa6605b4):[pc(0x8472168)],
 pc(0xa6605ec):[pc(0x8474158)],
 pc(0xa641cd0):[pc(0x847a7a0)],
 pc(0xa641d34):[pc(0x84787a0),pc(0x84787d0)],
 pc(0xa666204):[pc(0x847a878)],
 pc(0xa666240):[pc(0x8472578)],
 pc(0xa6662a0):[pc(0x847a848)],
 pc(0xa641d88):[pc(0x84774d0)],
 pc(0xa641e5c):[pc(0x84774d0),pc(0x8479920)],
 pc(0xa641eb8):[pc(0x84749b8)],
 pc(0xa641ef8):[pc(0x84748a0)],
 pc(0xa641fd0):[pc(0x84734e8)],
 pc(0xa64204c):[pc(0x847a7b8)],
 pc(0xa642090):[pc(0x8472a90)],
}
RULES=[
 (pc(0xa6607bc),pc(0xa6607cc),pc(0x7941f60),pc(0x794a0d0),0x6d),
 (pc(0xa6606a0),pc(0xa6606ac),pc(0x7949fd0),pc(0x792ffc0),0x37),
 (pc(0xa6606d0),pc(0xa6606e0),pc(0x792fcc0),pc(0x79391f0),0x47),
 (pc(0xa660560),pc(0xa660570),pc(0x7949ed0),pc(0x792fec0),0x92),
 (pc(0xa660594),pc(0xa66059c),pc(0x7949ed0),pc(0x792fec0),0x92),
 (pc(0xa641cac),pc(0xa641cbc),pc(0x7949dd0),pc(0x792fbc0),0x16),
 (pc(0xa6661e4),pc(0xa6661f4),pc(0x7941f60),pc(0x794a0d0),0x6d),
 (pc(0xa666218),pc(0xa666228),pc(0x7949dd0),pc(0x792fbc0),0x73),
 (pc(0xa666280),pc(0xa666290),pc(0x792fdc0),pc(0x79392f0),0x93),
 (pc(0xa64202c),pc(0xa64203c),pc(0x7949dd0),pc(0x792fbc0),0xd8),
 (pc(0xa642064),pc(0xa642074),pc(0x7949fd0),pc(0x792ffc0),0xef),
]
CONTROLLERS={pc(p):pc(q)for p,q in [(0xa660794,0xccc30d0),(0xa66079c,0xccc32f8),(0xa660674,0xccc30d0),(0xa66067c,0xccc32f8),(0xa660538,0xccc30d0),(0xa660540,0xccc32f8),(0xa641c88,0xccc30d0),(0xa641c90,0xccc32f8),(0xa6661c8,0xccc30d0),(0xa6661cc,0xccc32f8),(0xa666264,0xccc30d0),(0xa666268,0xccc32f8),(0xa642010,0xccc30d0),(0xa642018,0xccc32f8)]}
ROOTS=[(0x4d8,8,'N_add',0xe33fe5fefaffb7f5),(0x4d0,8,'N_add',0x621745fcc03f95d4),(0x670,8,'C',0x90),(0x8f8,8,'I',0),(0x4b8,8,'N_xor',0xc03f95d4),(0x4b0,8,'N_add',0),(0x888,8,'S',0xbe4),(0x988,8,'C',0x600),(0x930,8,'literal',pc(0x792fdc0)),(0x928,8,'literal',pc(0x79392f0)),(0x9ec,4,'literal',0xce515bb2)]
FALSE=Parent.FALSE+['native_fallback_buffer_identity_established','whole_fallback_parse_completed','native_stack_cookie_check_established','outer_RETAB_executed']
def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_message_failure_checks.json'));assert prior==Parent.build();originals=json.loads(read(ROOT/'userclient_early_data_checks.json'));init=json.loads(read(ROOT/'userclient_message_initialization_checks.json'))
 def capture(mapping):
  out=[]
  for name,(a,z)in mapping.items():
   raw=k.read(a,z-a);assert raw==IMAGE.read(a,z-a);ii=list(CS.disasm(raw,a));assert len(ii)*4==len(raw);out.append({'label':name,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':raw.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]})
  return out
 spans=capture(SPANS);prefix=capture(PREFIX_SPANS);rules=[];banks={}
 for lp,rp,l,r,key in RULES:
  q=selected(l,r,key,0,POOL,0);rules.append({n:q[n]for n in ['left','right','key','constant','inputs_checked']}|{'left_PC':hex(lp),'right_PC':hex(rp)})
  for a in [l,r]:
   raw=k.read(a,256);assert raw==IMAGE.read(a,256);banks[hex(a)]=raw.hex()
 cells=[]
 for p in init['predecessor_states']:
  r=originals['cases'][p['predecessor_case_index']];F=int(p['frame_base_SP'],16);g=[int(v,16)for v in p['handoff_state']['registers31']];C,S=g[11],g[3];N=p['original_extent32'];I=int(p['original_input64'],16);rows=[]
  for off,n,role,value in ROOTS:
   want={'C':C+value,'S':S+value,'I':I,'N_add':(N+value)&((1<<64)-1),'N_xor':N^value,'literal':value}[role];bs=[None]*n;touch=[]
   for w in r['source_writes']:
    at=int(w['address'],16);b=bytes.fromhex(w['after_hex']);lo,hi=max(at,F+off),min(at+len(b),F+off+n)
    if lo<hi:
     touch.append(w)
     for j in range(lo,hi):bs[j-F-off]=b[j-at]
   assert None not in bs and int.from_bytes(bytes(bs),'little')==want;(rows.append({'frame_offset':hex(off),'size_bytes':n,'role':role,'expression_constant':hex(value),'reconstructed_bytes_hex':bytes(bs).hex(),'overlapping_original_stores':touch}))
  cells.append({'predecessor_case_index':p['predecessor_case_index'],'frame_base_SP':p['frame_base_SP'],'source_defined_cells':rows})
 ds=[descriptor(k,pc(a))for a in [0x847be20,0x847bde0,0x847ba60,0x847b620,0x847bea0]];assert ds[2]['normalized64_hex']==ds[4]['normalized64_hex']and ds[1]['normalized64_hex']==ds[3]['normalized64_hex']
 deps=['recover_userclient_message_failure.py','audit_userclient_message_failure.py','userclient_message_failure_checks.json','userclient_message_failure_audit.json','userclient_message_initialization_checks.json','userclient_early_data_checks.json','userclient_parser_cleanup_checks.json','userclient_parser_cleanup_audit.json','userclient_container_staging_checks.json','userclient_container_staging_audit.json']
 return {'generator_sha256':sha(__file__),'source_sha256':prior['source_sha256'],'kernel_collection_sha256':k.sha256,'scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'source':{'container':prior['source']['container'],'spans':spans,'pointer_observations':[{'source_PC':hex(p),'slot':hex(a),'original_pointer':pointer(k,a)}for p,aa in POINTERS.items()for a in aa]},'prefix_source':prefix,'bank_rules':rules,'banks':banks,'typed_descriptors':ds,'prefix_cells':cells,'exact_symbols':k.symbols([pc(a)for a in [0xc4ba368,0xc4ba84c,0xc4ba60c,0xc4b9a24,0xc4ba154]]),'verified_counts':{'source_spans':len(spans),'captured_words':sum(len(s['instructions'])for s in spans),'prefix_and_qualified_cut_words':sum(len(s['instructions'])for s in prefix),'bank_rules':len(rules),'certified_bank_inputs':256*len(rules),'original_pointer_observations':sum(map(len,POINTERS.values())),'original_pointer_slots':len({a for aa in POINTERS.values()for a in aa}),'prefix_states':len(cells),'additional_cells_per_state':len(ROOTS),'additional_cell_bytes_per_state':sum(n for off,n,role,value in ROOTS),'record_extent_bytes':14,'node_extent_bytes':32,'container_extent_bytes':16,'context_extent_bytes':4096,'workspace_extent_bytes':16384,'fallback_extent_bytes':14,'input_content_bytes_supplied':0},'conditional_failure_fallback_established':True,**{n:False for n in FALSE}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
