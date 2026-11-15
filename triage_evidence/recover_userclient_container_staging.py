#!/usr/bin/env python3
"""Capture input staging and the shared FPTTLV parser entry/return interface.
O(B+I+256R) extraction time/space. No target execution or IDB mutation.
"""
import json
import struct
from hashlib import sha256
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,POOL,TABLE,qword,selected
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_discriminator_origin as D

P='userclient_container_staging'
SCOPE='Conditional saved-entry pointer/low32-size staging, exact-size allocator request, address-keyed protected reverse copy, shared FPTTLV parser output/continuation ABI, typed 16-byte container initialization, first cursor/input gates and caller handoff to the hash-input reader. Complete parser/node construction, external field identity, termination, native lifetime, full incoming reachability and daemon correlation remain unknown.'
SPANS={
 'saved_entry_arguments':(0xfffffe000a63524c,0xfffffe000a635258),
 'scratch_alias':(0xfffffe000a635538,0xfffffe000a63555c),
 'staging_roots':(0xfffffe000a635568,0xfffffe000a635580),
 'saved_staging_roots':(0xfffffe000a6355b8,0xfffffe000a6355c4),
 'size_channel':(0xfffffe000a6355ec,0xfffffe000a63561c),
 'allocation_size_channel':(0xfffffe000a6356ac,0xfffffe000a6357b4),
 'saved_encoded_size':(0xfffffe000a635958,0xfffffe000a635960),
 'parser_output_root':(0xfffffe000a635e74,0xfffffe000a635e7c),
 'staging_state_root':(0xfffffe000a63603c,0xfffffe000a636044),
 'copy_count_roots':(0xfffffe000a63616c,0xfffffe000a636200),
 'staging_allocate':(0xfffffe000a641c80,0xfffffe000a641cf8),
 'staging_return':(0xfffffe000a641cfc,0xfffffe000a641d50),
 'staging_gate':(0xfffffe000a641d58,0xfffffe000a641dc0),
 'staging_copy':(0xfffffe000a641e0c,0xfffffe000a641e64),
 'staging_done':(0xfffffe000a641dc8,0xfffffe000a641e04),
 'staging_empty':(0xfffffe000a641e6c,0xfffffe000a641edc),
 'parser_request':(0xfffffe000a641ee4,0xfffffe000a641f10),
 'parser_entry':(0xfffffe000a641fb8,0xfffffe000a642098),
 'parser_allocate_return':(0xfffffe000a64209c,0xfffffe000a6420f4),
 'parser_initialize':(0xfffffe000a6420fc,0xfffffe000a642134),
 'parser_cursor_gate':(0xfffffe000a64213c,0xfffffe000a64217c),
 'parser_finish':(0xfffffe000a642184,0xfffffe000a6421ac),
 'parser_success':(0xfffffe000a6421b4,0xfffffe000a6421d8),
 'parser_input_gate':(0xfffffe000a6421e0,0xfffffe000a642244),
 'parser_output':(0xfffffe000a660acc,0xfffffe000a660adc),
 'parser_resume':(0xfffffe000a660ae4,0xfffffe000a660af0),
 'reader_initialize':(0xfffffe000a63dd14,0xfffffe000a63dd7c),
 'reader_key_assignment':(0xfffffe000a636d7c,0xfffffe000a636d9c),
}
TRANSFERS=[n for n in SPANS if n in ['staging_allocate','staging_return','staging_gate','staging_copy',
 'staging_done','staging_empty','parser_request','parser_entry','parser_allocate_return',
 'parser_initialize','parser_cursor_gate','parser_finish','parser_success','parser_input_gate','parser_output','parser_resume','reader_initialize']]
BANK_PCS={'data':(0xfffffe000a641cac,0xfffffe000a641cbc,0xfffffe000a641cd0),
 'container':(0xfffffe000a64202c,0xfffffe000a64203c,0xfffffe000a64204c),
 'descriptor':(0xfffffe000a642064,0xfffffe000a642074,0xfffffe000a642090)}
RETAGS={0xfffffe000a641e20:0xfffffe000a641e24}
BRANCHES={0xfffffe000a63dd60:[0x8c4,0x8ed],0xfffffe000a641d34:[0xb10,0xb16],
 0xfffffe000a641d88:[0x8b6,0x926],0xfffffe000a641dec:[0x353],
 0xfffffe000a641e5c:[0x8b6,0xd40],0xfffffe000a641eb8:[0x353,0x5aa],
 0xfffffe000a641ef8:[0x330],0xfffffe000a641fd0:[0xb9],0xfffffe000a6420e0:[0x69e,0x6d5],
 0xfffffe000a642104:[0x891],0xfffffe000a642174:[0x87f,0x893],0xfffffe000a6421a4:[0x449],
 0xfffffe000a6421c8:[0x970],0xfffffe000a642218:[0x560,0x593],0xfffffe000a660ad4:[0x6d5]}
FALSE=['native_target_executed','native_PAC_authenticated','whole_dispatcher_reachability_established',
 'complete_parser_body_established','native_input_identity_established','NUL_termination_guaranteed',
 'native_ownership_established','native_locking_established','native_allocation_identity_established',
 'original_marker_producer_established','alias_complete_saved_status_writers_established',
 'daemon_kext_transaction_correlated','new_Mach_port_endpoint_established','IDB_modified','full_goal_complete']
DEPS=['kext_port_tools.py','kernel_native_reader.py','recover_kext_cold_init.py','lskd_values_symbolic.py',
 'audit_secure_tunnel_table_insertion.py','recover_userclient_discriminator_origin.py',
 'userclient_input_reader_checks.json','userclient_input_reader_audit.json',
 'userclient_replacement_bootstrap_checks.json','userclient_replacement_bootstrap_audit.json']
CELLS={'container_output_address':('sp',0x988,8),'container':('x2',0x600,8),
 'reader_container':('x2',0x4b0,8),'staged_buffer':('x2',0x90,8),
 'parser_output_address':('x2',0x188,8),'parser_continuation':('x2',0x5c8,8)}

def build():
 k=Kernel();old=json.loads(read(ROOT/'userclient_input_reader_checks.json'));container=old['function_container']
 a,z=(int(container[n],16) for n in ['start','end_exclusive']);raw=k.read(a,z-a)
 assert IMAGE.read(a,z-a)==raw and sha256(raw).hexdigest()==container['sha256'];spans=[]
 for label,(lo,hi) in SPANS.items():
  b=k.read(lo,hi-lo);assert IMAGE.read(lo,hi-lo)==b;ii=list(CS.disasm(b,lo));assert len(ii)*4==len(b)
  spans.append({'label':label,'start':hex(lo),'end_exclusive':hex(hi),'bytes_hex':b.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 roots={'TL':qword(POOL+0x840),'TR':qword(POOL+0xbb8),'BL':qword(POOL+0x4f0)-4,'BR':qword(POOL+0x578)-4};rules=[]
 for name,left,right,key,add,base,div in [('data','TL','TR',0x16,0xe88,TABLE,0xca0c),
  ('container','TL','TR',0xd8,0xef3,TABLE,0xd0c8),('descriptor','BL','BR',0xef,0x111,POOL,None)]:
  r=selected(roots[left],roots[right],key,add,base,0);r.update(name=name,left_name=left,right_name=right)
  r['original_pointer']=pointer(k,int(r['slot'],16))
  if div is not None:assert r['original_pointer']['authenticated'] and int(r['original_pointer']['diversity'],16)==div
  rules.append(r)
 address=int(rules[-1]['target'],16);b=IMAGE.read(address,64);np,sp=(struct.unpack_from('<Q',b,o)[0] for o in [16,32])
 name,sig=(IMAGE.read(p,64).split(b'\0')[0] for p in [np,sp]);flags,size=struct.unpack_from('<II',b,40)
 assert (name,sig,flags,size)==(b'site.FPTTLV',b'11',0xe4,16)
 pn,ps=pointer(k,address+16),pointer(k,address+32);assert int(pn['target'],16)==np and int(ps['target'],16)==sp
 assert k.read(address+40,8)==b[40:48] and k.read(np,len(name)+1)==name+b'\0' and k.read(sp,len(sig)+1)==sig+b'\0'
 descriptor={'address':hex(address),'normalized64_bytes_hex':b.hex(),'original64_bytes_hex':k.read(address,64).hex(),
  'name':name.decode(),'signature':sig.decode(),'flags_u32':flags,'size_bytes':size,'name_pointer':pn,'signature_pointer':ps}
 transfers=[]
 for n in TRANSFERS:
  pc=SPANS[n][1];b=k.read(pc,4);assert IMAGE.read(pc,4)==b;i=next(CS.disasm(b,pc));assert i.mnemonic in ['braa','blraa']
  transfers.append({'ea':hex(pc),'bytes_hex':b.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
 prior_cells=D.CELLS
 try:D.CELLS=CELLS;inv=D.inventory(raw,a)
 finally:D.CELLS=prior_cells
 lo,hi=0xfffffe000a6355ec,0xfffffe000a636200;b=k.read(lo,hi-lo);assert IMAGE.read(lo,hi-lo)==b
 dec=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);dec.detail=True;ii=list(dec.disasm(b,lo));assert len(ii)*4==len(b)
 preservation=[(0xfffffe000a635608,0xfffffe000a6356ac,['x19','w19']),
  (0xfffffe000a6357b0,0xfffffe000a6361f4,['x11','w11']),
  (0xfffffe000a635618,0xfffffe000a635958,['x1','w1'])]
 for i in ii:
  assert not i.mnemonic.startswith(('b','ret','cb','tb'))
  _,ww=i.regs_access();written={i.reg_name(r) for r in ww};assert 'sp' not in written
  for a,z,regs in preservation:
   if a<i.address<z:assert not written&set(regs)
 envelope={'start':hex(lo),'end_exclusive':hex(hi),'bytes_hex':b.hex(),'sha256':sha256(b).hexdigest(),
  'instructions':len(ii),'control_transfers':0,'SP_writes':0,
  'preservation_intervals':[{'definition_ea':hex(a),'use_ea':hex(z),'register_aliases':rr} for a,z,rr in preservation],
  'scope':'Exact byte and register def-use custody between selected codec spans; no native caller or alias-complete memory invariant.'}
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'scope':SCOPE,
  'function_container':container,'dependencies':{n:sha(ROOT/n) for n in DEPS},'spans':spans,'transfers':transfers,
  'bank_rules':rules,'banks':{n:{'address':hex(v),'bytes_hex':IMAGE.read(v,256).hex()} for n,v in roots.items()},
  'allocation_descriptor':descriptor,'literal_base_inventory':inv,'codec_def_use_envelope':envelope,
  'pool_pointers':[pointer(k,POOL+o) for o in [0x840,0xbb8,0x4f0,0x578]],
  'allocator_symbols':k.symbols([int(r['target'],16) for r in rules[:2]]),
  'branch_pointers':[pointer(k,TABLE+8*j)|{'index':j} for j in sorted({j for jj in BRANCHES.values() for j in jj})],
  'verified_counts':{'source_spans':len(spans),'selected_instructions':sum(len(s['instructions']) for s in spans),
   'terminal_transfers':len(transfers),'bank_rules':len(rules),'bank_input_cases':256*len(rules),
   'container_bytes':size,'inventoried_cells':len(CELLS),'container_instructions':inv['container_instructions'],
   'codec_def_use_envelope_instructions':len(ii)},
  'conditional_container_staging_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
