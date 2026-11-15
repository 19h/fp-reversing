#!/usr/bin/env python3
"""Freeze the replacement caller's shared-table constructor and saved continuation.
O(B+I+256R) time/space. Original/normalized reads only; no target or IDB changes.
"""
import json
import struct
from hashlib import sha256
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from kext_port_tools import ROOT,SOURCE,IMAGE,POOL,TABLE,CS,qword,selected
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_uidlist_replacement as PRIOR

P='userclient_replacement_bootstrap'
SCOPE='Conditional replacement-caller null shared-holder typed allocation, token0xabd initializer/header join, exact output gate, global publication, rollback, independent holder reload and saved processing/status continuation. Full incoming reachability, native holder epochs/ownership/locking and daemon transaction correlation remain unknown.'
SPANS={
 'root_call_phase':(0xfffffe000a636328,0xfffffe000a636330),
 'root_call_select':(0xfffffe000a63637c,0xfffffe000a6363c8),
 'allocate_left_root':(0xfffffe000a6363c8,0xfffffe000a6363d4),
 'root_call_descriptor_left':(0xfffffe000a6363d4,0xfffffe000a6363e0),
 'allocate_right_root':(0xfffffe000a6363e0,0xfffffe000a6363e4),
 'root_call_prepare':(0xfffffe000a6363e4,0xfffffe000a636404),
 'allocate_left_save':(0xfffffe000a636528,0xfffffe000a63652c),
 'allocate_right_save':(0xfffffe000a636538,0xfffffe000a63653c),
 'rollback_roots_and_status_default':(0xfffffe000a63665c,0xfffffe000a63669c),
 'resource_entry':PRIOR.SPANS['resource_entry'],
 'holder_gate':PRIOR.SPANS['holder_gate'],
 'allocate_request':(0xfffffe000a65ac88,0xfffffe000a65ad50),
 'allocate_return':(0xfffffe000a65ad54,0xfffffe000a65ad78),
 'initialize_request':(0xfffffe000a65ad80,0xfffffe000a65ae1c),
 'initialize_return':(0xfffffe000a65ae20,0xfffffe000a65ae54),
 'publish':(0xfffffe000a65ae5c,0xfffffe000a65aeac),
 'rollback_request':(0xfffffe000a65af14,0xfffffe000a65af90),
 'rollback_return':(0xfffffe000a65af94,0xfffffe000a65afa4),
 'reload':(0xfffffe000a65afac,0xfffffe000a65aff8),
 'resume':PRIOR.SPANS['holder_resume'],
 'processing_gate':PRIOR.SPANS['processing_gate'],
 'status_gate':PRIOR.SPANS['status_gate'],
 'marker_update':PRIOR.SPANS['marker_update'],
 'initializer_header':(0xfffffe000a62750c,0xfffffe000a627560),
}
BRANCHES={
 0xfffffe000a65eef4:[0x5b7],0xfffffe000a65ac0c:[0xa9],0xfffffe000a65ac78:[0x526,0x539],
 0xfffffe000a65ad70:[0x81b,0x837],0xfffffe000a65ae4c:[0x57a,0x59b],
 0xfffffe000a65ae64:[0x539],0xfffffe000a65af98:[0x4e3],0xfffffe000a65afb4:[0x539],
 0xfffffe000a65b114:[0xac9,0xaf9],0xfffffe000a65e704:[0xf4,0xc0e],0xfffffe000a65e754:[0x746,0xacd],
}
BANK_PCS={
 'root_call_allocate':(0xfffffe000a6363a4,0xfffffe000a6363b0,0xfffffe000a6363c0),
 'root_call_descriptor':(0xfffffe000a6363d8,0xfffffe000a6363e4,0xfffffe000a6363f8),
 'holder':(0xfffffe000a65ac30,0xfffffe000a65ac3c,0xfffffe000a65ac54),
 'allocate':(0xfffffe000a65acd8,0xfffffe000a65ace8,0xfffffe000a65acf8),
 'allocate_descriptor':(0xfffffe000a65ad10,0xfffffe000a65ad20,0xfffffe000a65ad3c),
 'initialize':(0xfffffe000a65ade8,0xfffffe000a65adf8,0xfffffe000a65ae10),
 'rollback':(0xfffffe000a65af34,0xfffffe000a65af44,0xfffffe000a65af54),
 'rollback_descriptor':(0xfffffe000a65af68,0xfffffe000a65af70,0xfffffe000a65af80),
}
TRANSFERS=[z for n,(a,z) in SPANS.items() if n not in ['allocate_left_root','allocate_right_root',
 'allocate_left_save','allocate_right_save','rollback_roots_and_status_default','initializer_header',
 'root_call_phase','root_call_select','root_call_descriptor_left']]
FALSE=['native_target_executed','native_PAC_authenticated','whole_dispatcher_reachability_established',
 'native_allocation_identity_established','native_deallocation_established','native_global_holder_coherence_established',
 'native_ownership_established','native_locking_established','all_holder_writers_established',
 'saved_status_native_domain_established','daemon_kext_transaction_correlated','new_Mach_port_endpoint_established',
 'IDB_modified','full_goal_complete']
DEPS=['kext_port_tools.py','kernel_native_reader.py','recover_kext_cold_init.py','lskd_values_symbolic.py',
 'audit_secure_tunnel_table_insertion.py','recover_userclient_uidlist_replacement.py',
 'userclient_uidlist_replacement_checks.json','userclient_uidlist_replacement_audit.json',
 'userclient_hash_table_bootstrap_checks.json','userclient_hash_table_bootstrap_audit.json',
 'userclient_hash_table_initializer_checks.json','userclient_hash_table_initializer_audit.json']

def build():
 k=Kernel();old=json.loads(read(ROOT/'userclient_uidlist_replacement_checks.json'));container=old['function_container']
 a,z=(int(container[n],16) for n in ['start','end_exclusive']);raw=k.read(a,z-a)
 assert IMAGE.read(a,z-a)==raw and sha256(raw).hexdigest()==container['sha256']
 spans=[]
 for name,(a,z) in SPANS.items():
  raw=k.read(a,z-a);assert IMAGE.read(a,z-a)==raw;ii=list(CS.disasm(raw,a));assert 4*len(ii)==len(raw)
  spans.append({'label':name,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':raw.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 a,z=0xfffffe000a6363c8,0xfffffe000a63669c;raw=k.read(a,z-a);assert IMAGE.read(a,z-a)==raw
 dec=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);dec.detail=True;ii=list(dec.disasm(raw,a));assert len(ii)*4==len(raw)
 rules_preserve=[(0xfffffe000a6363d4,0xfffffe000a636528,['x24','w24']),
  (0xfffffe000a6363e4,0xfffffe000a636538,['x26','w26']),
  (0xfffffe000a6363d0,0xfffffe000a636668,['x28','w28'])]
 calls=[]
 for i in ii:
  if i.mnemonic=='blraa':
   assert i.address==0xfffffe000a636404 and i.op_str=='x11, x17'
   calls.append({'ea':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
  else:assert i.mnemonic!='b' and not i.mnemonic.startswith(('b.','bl','br','ret','cb','tb'))
  _,ww=i.regs_access();written={i.reg_name(r) for r in ww}
  for lo,hi,regs in rules_preserve:
   if lo<=i.address<hi:assert not written&set(regs)
 gap={'start':hex(a),'end_exclusive':hex(z),'bytes_hex':raw.hex(),'sha256':sha256(raw).hexdigest(),
  'instructions':len(ii),'overlaps_selected_root_spans':True,'ordinary_call_cuts':calls,'other_control_transfers':0,
  'callee_save_preservation_required':['X24','X26','X28'],
  'preservation_ranges':[{'start':hex(a),'end_exclusive':hex(z),'register_aliases':rr} for a,z,rr in rules_preserve]}
 roots={'EL':qword(POOL+0xb70),'ER':qword(POOL+0xa10),'VL':qword(POOL+0xc08)-8,'VR':qword(POOL+0x158)-4,
  'TL':qword(POOL+0x840),'TR':qword(POOL+0xbb8),'FL':qword(POOL+0x458)-8,'FR':qword(POOL+0x638)-12}
 rules=[]
 for name,left,right,key,add,base,bias,div in [
  ('holder','VL','VR',0x6d,0x199,POOL,-4,None),
  ('allocate','EL','ER',0x92,0xe71,TABLE,0,0xd0c8),
  ('allocate_descriptor','VL','VR',5,4,POOL,-4,None),
  ('initialize','TL','TR',0xb4,0xf09,TABLE,0,0x2bbe),
  ('rollback','FL','FR',0x87,0xe4c,TABLE,0,0x4d6a),
  ('rollback_descriptor','FL','FR',0x87,-0x90,POOL,-4,None),
  ('root_call_allocate','TL','TR',0x5c,0xe41,TABLE,0,0xd0c8),
  ('root_call_descriptor','EL','ER',0x32,0x107,POOL,0,None)]:
  r=selected(roots[left],roots[right],key,add,base,bias);r.update(name=name,left_name=left,right_name=right)
  r['original_pointer']=pointer(k,int(r['slot'],16));assert (int(r['original_pointer']['target'],16)+bias)&((1<<64)-1)==int(r['target'],16)
  if div is not None:assert r['original_pointer']['authenticated'] and int(r['original_pointer']['diversity'],16)==div
  rules.append(r)
 boot=json.loads(read(ROOT/'userclient_hash_table_bootstrap_checks.json'));init=json.loads(read(ROOT/'userclient_hash_table_initializer_checks.json'))
 descriptors=boot['hash_table_descriptors']
 for d in descriptors:
  a=int(d['address'],16);assert IMAGE.read(a,64).hex()==d['normalized64_bytes_hex'] and k.read(a,64).hex()==d['original64_bytes_hex']
  for name,offset in [('name_pointer',16),('signature_pointer',32)]:assert pointer(k,a+offset)==d[name]
 assert int(rules[2]['target'],16)==int(descriptors[0]['address'],16)
 assert int(next(r for r in rules if r['name']=='rollback_descriptor')['target'],16)==int(descriptors[1]['address'],16)
 assert descriptors[0]['normalized64_bytes_hex']==descriptors[1]['normalized64_bytes_hex']
 a=0xfffffe000847bb60;raw=IMAGE.read(a,64);np,sp=(struct.unpack_from('<Q',raw,o)[0] for o in [16,32])
 name=IMAGE.read(np,64).split(b'\0')[0];sig=IMAGE.read(sp,64).split(b'\0')[0];flags,size=struct.unpack_from('<II',raw,40)
 assert (name,sig,flags,size)==(b'site.FPTTLV',b'11',0xe4,16)
 pn,ps=pointer(k,a+16),pointer(k,a+32);assert (int(pn['target'],16),int(ps['target'],16))==(np,sp)
 assert k.read(a+40,8)==raw[40:48] and k.read(np,len(name)+1)==name+b'\0' and k.read(sp,len(sig)+1)==sig+b'\0'
 root_desc={'address':hex(a),'normalized64_bytes_hex':raw.hex(),'original64_bytes_hex':k.read(a,64).hex(),
  'name':name.decode(),'signature':sig.decode(),'flags_u32':flags,'size_bytes':size,'name_pointer':pn,'signature_pointer':ps}
 f=init['functions']['initializer'];a=int(f['start'],16);raw=bytes.fromhex(f['bytes_hex'])
 assert k.read(a,len(raw))==IMAGE.read(a,len(raw))==raw and f==boot['initializer_function']
 adapters={n:k.function(a) for n,a in [('allocate',0xfffffe000c4ba154),('free',0xfffffe000c4ba368)]}
 assert adapters==boot['kernel_adapters']
 transfers=[]
 for pc in TRANSFERS:
  raw=k.read(pc,4);assert IMAGE.read(pc,4)==raw;i=list(CS.disasm(raw,pc))[0];assert i.mnemonic in ['braa','blraa']
  transfers.append({'ea':hex(pc),'bytes_hex':raw.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'scope':SCOPE,
  'function_container':container,'spans':spans,'transfers':transfers,'bank_root_def_use_envelope':gap,
  'dependencies':{n:sha(ROOT/n) for n in DEPS},'bank_rules':rules,
  'banks':{n:{'address':hex(a),'bytes_hex':IMAGE.read(a,256).hex()} for n,a in roots.items()},
  'pool_pointers':[pointer(k,POOL+o) for o in [0xb70,0xa10,0xc08,0x158,0x840,0xbb8,0x458,0x638]],
  'branch_pointers':[pointer(k,TABLE+8*j)|{'index':j} for j in sorted({j for js in BRANCHES.values() for j in js})],
  'hash_table_descriptors':descriptors,'root_envelope_allocation_descriptor':root_desc,'initializer_function':f,'kernel_adapters':adapters,
  'global_holder':boot['global_holder'],
  'verified_counts':{'source_spans':len(spans),'selected_instructions':sum(len(s['instructions']) for s in spans),
   'terminal_transfers':len(transfers),'bank_rules':len(rules),'bank_input_cases':256*len(rules),
   'bank_root_def_use_envelope_instructions':len(ii),'header_bytes':16,'initializer_record_bytes':16,
   'initializer_captured_instructions':len(f['instructions'])},
  'conditional_replacement_bootstrap_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
