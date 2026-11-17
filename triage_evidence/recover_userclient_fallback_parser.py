#!/usr/bin/env python3
"""Freeze staged allocation outcomes, restore copy and first header field.
O(B+I+256R+C*W) extraction work/space; original inputs are read-only.
"""
import json
from kext_port_tools import ROOT,IMAGE,CS,POOL,selected
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_failure_fallback as Parent
P='userclient_fallback_parser';pc=Parent.pc
SCOPE='Compose the actual 14-byte protected fallback buffer through staged typed-allocation outcomes. NULL resumes the failure caller, restores all 14 input bytes and requests buffer retirement. Nonnull initializes the new container and decodes/stores the first BE32 tag from original offsets 0..3. Ordinary allocation return and surviving storage are premises; native effects, full header/body parse, lifetime and complete outer return remain unknown.'
SPANS={('fp_'+format(a,'x')):(pc(a),pc(z))for a,z in [(0xa64209c,0xa6420f8),(0xa660ae0,0xa660af4),(0xa656c08,0xa656c44),(0xa65f358,0xa65f3b4),(0xa656f00,0xa656f4c),(0xa665e90,0xa665ee4),(0xa665f8c,0xa665fc8),(0xa665fc8,0xa66609c),(0xa66609c,0xa6660b4),(0xa6660b4,0xa666118),(0xa666118,0xa66618c),(0xa6420f8,0xa642138),(0xa642138,0xa642180),(0xa6421dc,0xa642248),(0xa642248,0xa642330),(0xa642330,0xa6423c0),(0xa656ef0,0xa656f00),(0xa637138,0xa637250),(0xa638db8,0xa638dc8)]}
POINTERS={pc(p):[pc(a)for a in aa]for p,aa in [(0xa6420e0,[0x84765c8,0x8476410]),(0xa656c30,[0x8473260]),(0xa65f3a0,[0x8477120]),(0xa656f3c,[0x8475400]),(0xa665ed0,[0x847a628]),(0xa665fa4,[0x8475c70]),(0xa66607c,[0x8478860]),(0xa6660a4,[0x8479af0]),(0xa66610c,[0x8479af0,0x8479be8]),(0xa666178,[0x847a7f0]),(0xa642104,[0x84773a8]),(0xa642174,[0x8477318]),(0xa642218,[0x8475bb8]),(0xa64231c,[0x8476100]),(0xa642388,[0x8474098]),(0xa656ef4,[0x8479f58]),(0xa63713c,[0x8473af0])]}
CONTROLLERS={pc(0xa666124):pc(0xccc30d0),pc(0xa66612c):pc(0xccc32f8)}
RETAGS={pc(a):pc(a+4)for a in [0xa6660cc,0xa637150,0xa637188,0xa6371cc,0xa63720c]}
FALSE=Parent.FALSE+['whole_fallback_header_completed','native_original_input_writable_established','new_staged_container_identity_established']
def capture(k,name,a,z):
 raw=k.read(a,z-a);assert raw==IMAGE.read(a,z-a);ii=list(CS.disasm(raw,a));assert len(ii)*4==len(raw)
 return {'label':name,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':raw.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]}
def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_failure_fallback_checks.json'));assert prior==Parent.build();init=json.loads(read(ROOT/'userclient_message_initialization_checks.json'));original=json.loads(read(ROOT/'userclient_early_data_checks.json'));cells=[]
 for p in init['predecessor_states']:
  r=original['cases'][p['predecessor_case_index']];F=int(p['frame_base_SP'],16);C=int(p['handoff_state']['registers31'][11],16);bs=[None]*8;touch=[]
  for w in r['source_writes']:
   at=int(w['address'],16);b=bytes.fromhex(w['after_hex']);lo,hi=max(at,F+0x728),min(at+len(b),F+0x730)
   if lo<hi:
    touch.append(w)
    for j in range(lo,hi):bs[j-F-0x728]=b[j-at]
  assert None not in bs and int.from_bytes(bytes(bs),'little')==C+0x3c0
  cells.append({'predecessor_case_index':p['predecessor_case_index'],'frame_base_SP':p['frame_base_SP'],'frame_offset':'0x728','size_bytes':8,'context_offset':'0x3c0','reconstructed_bytes_hex':bytes(bs).hex(),'overlapping_original_stores':touch})
 r=selected(pc(0x7941f60),pc(0x794a0d0),5,0,POOL,0);rule={n:r[n]for n in ['left','right','key','constant','inputs_checked']}|{'left_PC':hex(pc(0xa666144)),'right_PC':hex(pc(0xa666164))};banks={}
 for a in [pc(0x7941f60),pc(0x794a0d0)]:
  raw=k.read(a,256);assert raw==IMAGE.read(a,256);banks[hex(a)]=raw.hex()
 spans=[capture(k,n,a,z)for n,(a,z)in SPANS.items()];prefix=capture(k,'prefix_restore_owner',pc(0xa63612c),pc(0xa636134));deps=['recover_userclient_failure_fallback.py','audit_userclient_failure_fallback.py','userclient_failure_fallback_checks.json','userclient_failure_fallback_audit.json','userclient_message_initialization_checks.json','userclient_early_data_checks.json','userclient_container_staging_audit.json']
 return {'generator_sha256':sha(__file__),'source_sha256':prior['source_sha256'],'kernel_collection_sha256':k.sha256,'scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'source':{'container':prior['source']['container'],'spans':spans,'pointer_observations':[{'source_PC':hex(p),'slot':hex(a),'original_pointer':pointer(k,a)}for p,aa in POINTERS.items()for a in aa]},'prefix_source':prefix,'prefix_cells':cells,'bank_rules':[rule],'banks':banks,'exact_symbols':k.symbols([pc(0xc4ba84c)]),'verified_counts':{'source_spans':len(spans),'captured_words':sum(len(s['instructions'])for s in spans),'prefix_words':2,'original_pointer_observations':sum(map(len,POINTERS.values())),'original_pointer_slots':len({a for aa in POINTERS.values()for a in aa}),'bank_rules':1,'certified_bank_inputs':256,'prefix_states':len(cells),'additional_prefix_bytes':8*len(cells),'fallback_extent_bytes':14,'new_container_extent_bytes':16,'restore_bytes_per_NULL_mode':14,'header_tag_bytes_per_nonnull_mode':4,'input_content_bytes_supplied':0},'conditional_fallback_parser_established':True,**{n:False for n in FALSE}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
