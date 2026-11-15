#!/usr/bin/env python3
"""Freeze caller cleanup, copy-back, outer storage and return interfaces.
O(B+I+256R) extraction time/space; no target execution or IDB mutation.
"""
import json
import struct
from hashlib import sha256
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,POOL,TABLE,qword,selected
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha

P='userclient_caller_return'
SCOPE='Conditional outer allocation requests/result aliases, caller-specific container destructor callback0x1a, optional auxiliary-buffer retirement, original staged-buffer size custody and protected copy-back, staged-buffer/outer-context/workspace retirement requests and guarded decoded status return. Native allocator effects/ownership, all incoming storage/phase paths, auxiliary producer, command semantics, alternate pointer authentication, locking and daemon correlation remain unknown.'
SPANS={
 'outer_workspace_request':(0xfffffe000a635348,0xfffffe000a6353dc),
 'outer_context_request':(0xfffffe000a6353e0,0xfffffe000a635470),
 'outer_context_result':(0xfffffe000a635474,0xfffffe000a635478),
 'primary_alias':(0xfffffe000a635568,0xfffffe000a635570),
 'primary_alias_save':(0xfffffe000a6355c0,0xfffffe000a6355c4),
 'auxiliary_alias':(0xfffffe000a63612c,0xfffffe000a636134),
 'auxiliary_extent_alias':(0xfffffe000a63603c,0xfffffe000a636044),
 'retirement_bank_left':(0xfffffe000a635490,0xfffffe000a63549c),
 'retirement_bank_right':(0xfffffe000a6354ac,0xfffffe000a6354b8),
 'size_channel':(0xfffffe000a6355ec,0xfffffe000a63561c),
 'size_codec':(0xfffffe000a6356ac,0xfffffe000a6357b4),
 'retained_size_store':(0xfffffe000a641c80,0xfffffe000a641c88),
 'staging_result':(0xfffffe000a641cfc,0xfffffe000a641d50),
 'auxiliary_initial_zero':(0xfffffe000a641ddc,0xfffffe000a641dec),
 'cleanup_gate':(0xfffffe000a656f04,0xfffffe000a656f48),
 'cleanup_request':(0xfffffe000a656f50,0xfffffe000a656f88),
 'auxiliary_gate':(0xfffffe000a665e94,0xfffffe000a665ee0),
 'auxiliary_request':(0xfffffe000a665ee8,0xfffffe000a665f58),
 'auxiliary_return':(0xfffffe000a665f5c,0xfffffe000a665f88),
 'primary_load':(0xfffffe000a665f90,0xfffffe000a665fc4),
 'copyback_gate':(0xfffffe000a665fcc,0xfffffe000a666098),
 'copyback_prepare':(0xfffffe000a6660a0,0xfffffe000a6660b0),
 'copyback_step':(0xfffffe000a6660b8,0xfffffe000a666114),
 'primary_request':(0xfffffe000a66611c,0xfffffe000a666188),
 'primary_return':(0xfffffe000a66618c,0xfffffe000a6661b8),
 'context_request':(0xfffffe000a6661c0,0xfffffe000a666260),
 'workspace_request':(0xfffffe000a666264,0xfffffe000a6662b0),
 'guard_save':(0xfffffe000a635258,0xfffffe000a635268),
 'guard_gate':(0xfffffe000a6662b4,0xfffffe000a6662cc),
 'status_return':(0xfffffe000a6662cc,0xfffffe000a6662d0),
 'guard_failure_veneer':(0xfffffe000a69f294,0xfffffe000a69f2a0),
}
REUSED=['failure_bridge','destroy_entry','destroy_object','destroy_head','container_request',
 'container_return','destroy_resume','node_gate','node_data_request','node_data_return','node_type_request','node_type_return']
BRANCHES={
 0xfffffe000a656f3c:[0x49c,0x4a7],0xfffffe000a656f7c:[0x2b7],
 0xfffffe000a665ed0:[0xee1,0xf03],0xfffffe000a665f80:[0xd61],0xfffffe000a665fa4:[0x5aa],
 0xfffffe000a66607c:[0xb1d,0xb28],0xfffffe000a6660a4:[0xd7a],
 0xfffffe000a66610c:[0xd7a,0xd99],0xfffffe000a6661a4:[0x204],
 0xfffffe000a641d34:[0xb10,0xb16],
 0xfffffe000a6622b0:[0x9a7],0xfffffe000a660470:[0x1a],0xfffffe000a660498:[0xafb,0xafc],
 0xfffffe000a6604f0:[0x432,0x480],0xfffffe000a660528:[0x414,0x41e],
 0xfffffe000a6605ec:[0x247],0xfffffe000a660784:[0x989,0x99e],0xfffffe000a660740:[0x414,0x41e],
 0xfffffe000a660808:[0x989],
}
BANK_PCS={
 'workspace_allocate':(0xfffffe000a635360,0xfffffe000a635370,0xfffffe000a6353cc),
 'allocation_table':(0xfffffe000a6353a0,0xfffffe000a6353b4,0xfffffe000a6353c4),
 'context_allocate':(0xfffffe000a635408,0xfffffe000a635420,0xfffffe000a635430),
 'allocation_descriptor':(0xfffffe000a635444,0xfffffe000a635454,0xfffffe000a635464),
 'auxiliary_free':(0xfffffe000a665f14,0xfffffe000a665f3c,0xfffffe000a665f50),
 'primary_free':(0xfffffe000a666144,0xfffffe000a666164,0xfffffe000a666178),
 'context_free':(0xfffffe000a6661e4,0xfffffe000a6661f4,0xfffffe000a666204),
 'context_descriptor':(0xfffffe000a666218,0xfffffe000a666228,0xfffffe000a666240),
 'workspace_free':(0xfffffe000a666280,0xfffffe000a666290,0xfffffe000a6662a0),
 'container_free':(0xfffffe000a660560,0xfffffe000a660570,0xfffffe000a660580),
 'container_descriptor':(0xfffffe000a660594,0xfffffe000a66059c,0xfffffe000a6605b4),
 'node_free':(0xfffffe000a6606a0,0xfffffe000a6606ac,0xfffffe000a6606c0),
 'node_descriptor':(0xfffffe000a6606d0,0xfffffe000a6606e0,0xfffffe000a6606f8),
 'data_free':(0xfffffe000a6607bc,0xfffffe000a6607cc,0xfffffe000a6607e0),
}
RETAGS={0xfffffe000a6660cc:0xfffffe000a6660d0}
NO_TRANSFER={'outer_context_result','primary_alias','primary_alias_save','auxiliary_alias','auxiliary_extent_alias',
 'retirement_bank_left','retirement_bank_right','size_channel','size_codec','retained_size_store',
 'auxiliary_initial_zero','guard_save','guard_gate','status_return'}
FALSE=['native_target_executed','native_PAC_authenticated','whole_dispatcher_reachability_established',
 'native_input_identity_established','native_allocation_identity_established','native_ownership_established',
 'native_locking_established','all_incoming_storage_paths_composed','auxiliary_buffer_producer_established',
 'second_command_body_established','daemon_kext_transaction_correlated','new_Mach_port_endpoint_established',
 'IDB_modified','full_goal_complete']
DEPS=['kext_port_tools.py','kernel_native_reader.py','recover_kext_cold_init.py','lskd_values_symbolic.py',
 'audit_secure_tunnel_table_insertion.py','audit_userclient_input_reader.py','recover_userclient_input_reader.py',
 'userclient_container_staging_checks.json','userclient_container_staging_audit.json',
 'userclient_parser_cleanup_checks.json','userclient_parser_cleanup_audit.json',
 'userclient_command_dispatch_checks.json','userclient_command_dispatch_audit.json']

def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_parser_cleanup_checks.json'));container=prior['function_container']
 a,z=(int(container[n],16) for n in ['start','end_exclusive']);b=k.read(a,z-a)
 assert b==IMAGE.read(a,z-a) and sha256(b).hexdigest()==container['sha256'];ranges=dict(SPANS)
 for label in REUSED:
  row=next(s for s in prior['spans'] if s['label']==label);ranges[label]=(int(row['start'],16),int(row['end_exclusive'],16))
 spans=[];transfers=[]
 for label,(a,z) in ranges.items():
  b=k.read(a,z-a);assert b==IMAGE.read(a,z-a);ii=list(CS.disasm(b,a));assert len(ii)*4==len(b)
  spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
  if label not in NO_TRANSFER:
   b=k.read(z,4);assert b==IMAGE.read(z,4);i=next(CS.disasm(b,z));assert i.mnemonic in ['braa','blraa']
   transfers.append({'ea':hex(z),'bytes_hex':b.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
 pairs={'A':(0xfffffe0007949ed0,0xfffffe000792fec0),'B':(0xfffffe0007949fd0,0xfffffe000792ffc0),
  'F':(0xfffffe000792fcc0,0xfffffe00079391f0),'S':(0xfffffe0007941f60,0xfffffe000794a0d0),
  'T':(0xfffffe0007949dd0,0xfffffe000792fbc0),'U':(0xfffffe000792fdc0,0xfffffe00079392f0)}
 banks={p+s:{'address':hex(a),'bytes_hex':IMAGE.read(a,256).hex()} for p,ab in pairs.items() for s,a in zip(['L','R'],ab)}
 for row in banks.values():assert k.read(int(row['address'],16),256).hex()==row['bytes_hex']
 specs=[('workspace_allocate','T',0x5c,0xe69,TABLE,0,0xca0c),('allocation_table','S',0x6d,0x20,POOL,-12,None),
  ('context_allocate','B',0xef,0xeb2,TABLE,0,0xd0c8),('allocation_descriptor','T',0xd8,0x7b,POOL,-8,None),
  ('auxiliary_free','S',5,0xeed,TABLE,0,0x85d),('primary_free','S',5,0xeed,TABLE,0,0x85d),
  ('context_free','S',0x6d,0xf18,TABLE,0,0x4d6a),('context_descriptor','T',0x73,0x88,POOL,-12,None),
  ('workspace_free','U',0x93,0xe39,TABLE,0,0x84ff)]
 rules=[]
 for name,p,key,add,base,bias,div in specs:
  r=selected(*pairs[p],key,add,base,bias);r.update(name=name,left_name=p+'L',right_name=p+'R',original_pointer=pointer(k,int(r['slot'],16)))
  assert (int(r['original_pointer']['target'],16)+bias)%(2**64)==int(r['target'],16)
  if div is not None:assert r['original_pointer']['authenticated'] and int(r['original_pointer']['diversity'],16)==div
  rules.append(r)
 rules.extend(r for r in prior['bank_rules'] if r['name'] in ['container_free','container_descriptor','node_free','node_descriptor','data_free'])
 assert {r['name'] for r in rules}==BANK_PCS.keys()
 pool_pointers=[pointer(k,POOL+o) for o in [0x840,0xbb8,0x4f0,0x578,0xc08,0x158,0xf50,0xf20]]
 for r in pool_pointers:assert int(r['target'],16)==qword(int(r['slot'],16))
 desc=[]
 for role,a in [('outer_allocation',0xfffffe000847bea0),('outer_retirement',0xfffffe000847ba60)]:
  b=IMAGE.read(a,64);pn,ps=pointer(k,a+16),pointer(k,a+32);np,sp=struct.unpack_from('<Q',b,16)[0],struct.unpack_from('<Q',b,32)[0]
  assert (int(pn['target'],16),int(ps['target'],16))==(np,sp)
  name=b'site.AllocType';sig=b'1'*512
  assert k.read(np,len(name)+1)==IMAGE.read(np,len(name)+1)==name+b'\0'
  assert k.read(sp,len(sig)+1)==IMAGE.read(sp,len(sig)+1)==sig+b'\0'
  assert k.read(a+40,8)==b[40:48] and struct.unpack_from('<II',b,40)==(0xe4,4096)
  desc.append({'role':role,'address':hex(a),'original64_bytes_hex':k.read(a,64).hex(),'normalized64_bytes_hex':b.hex(),
   'name':name.decode(),'signature':sig.decode(),'flags_u32':0xe4,'size_bytes':4096,'name_pointer':pn,'signature_pointer':ps})
 assert desc[0]['normalized64_bytes_hex']==desc[1]['normalized64_bytes_hex']
 desc.extend(r for r in prior['typed_descriptors'] if r['role'] in ['container_retirement','list_node_retirement'])
 guards=[pointer(k,a) for a in [0xfffffe000847c5f8,0xfffffe000847c478]]
 syms=k.symbols([0xfffffe000c4b9a08,0xfffffe000c4ba154,0xfffffe000c4ba368,0xfffffe000c4ba84c,
  0xfffffe000c4b9a24,*[int(r['target'],16) for r in guards]])
 for a,n in [(0xfffffe000c4b9a08,'_IOMallocAligned'),(0xfffffe000c4ba154,'_IOMallocTypeImpl'),
  (0xfffffe000c4ba368,'_IOFreeTypeImpl'),(0xfffffe000c4ba84c,'_IOFreeData'),(0xfffffe000c4b9a24,'_IOFreeAligned'),
  (int(guards[0]['target'],16),'___stack_chk_guard'),(int(guards[1]['target'],16),'___stack_chk_fail')]:assert any(s['name']==n for s in syms[hex(a)])
 bp=[pointer(k,TABLE+8*j)|{'index':j} for j in sorted({j for js in BRANCHES.values() for j in js})]
 for r in bp:assert int(r['target'],16)==qword(TABLE+8*r['index'])
 structural=[];dec=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);dec.detail=True
 for name,a,z in [('allocation_retention',0xfffffe000a635478,0xfffffe000a635538),
  ('frame_prologue',0xfffffe000a635208,0xfffffe000a63524c),('frame_epilogue',0xfffffe000a6662d0,0xfffffe000a6662fc)]:
  b=k.read(a,z-a);assert b==IMAGE.read(a,z-a);ii=list(dec.disasm(b,a));assert len(ii)*4==len(b)
  if name=='allocation_retention':
   for i in ii:
    assert not ({'x23','w23','x24','w24'}&{i.reg_name(r) for r in i.regs_access()[1]})
    assert not i.mnemonic.startswith('b') or i.mnemonic=='blraa'
   assert sum(i.mnemonic=='blraa' for i in ii)==2
  if name=='frame_epilogue':
   assert ii[-1].mnemonic=='retab'
   for i in ii:assert not ({'x0','w0'}&{i.reg_name(r) for r in i.regs_access()[1]})
   assert [(i.mnemonic,i.op_str) for i in ii[:2]]==[('add','sp, sp, #1, lsl #12'),('add','sp, sp, #0x70')]
   assert ii[-2].mnemonic=='ldp' and ii[-2].op_str=='d11, d10, [sp], #0x80'
  structural.append({'label':name,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),'instructions':len(ii)})
 failpc=0xfffffe000a66692c;fb=k.read(failpc,4);assert fb==IMAGE.read(failpc,4);fi=next(CS.disasm(fb,failpc));assert fi.mnemonic=='bl' and fi.op_str=='#0xfffffe000a69f294'
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'scope':SCOPE,'function_container':container,'dependencies':{n:sha(ROOT/n) for n in DEPS},
  'spans':spans,'transfers':transfers,'branch_pointers':bp,'banks':banks,'bank_rules':rules,'pool_pointers':pool_pointers,
  'typed_descriptors':desc,'exact_symbols':syms,'guard_pointers':guards,'structural_ranges':structural,
  'guard_failure_call':{'ea':hex(failpc),'bytes_hex':fb.hex(),'mnemonic':fi.mnemonic,'operands':fi.op_str},
  'verified_counts':{'source_spans':len(spans),'selected_instructions':sum(len(s['instructions']) for s in spans),
   'terminal_transfers':len(transfers),'bank_rules':len(rules),'bank_input_cases':256*len(rules),
   'typed_descriptors':len(desc),'structural_instructions':sum(r['instructions'] for r in structural),
   'alternate_retag_sites':len(RETAGS),'outer_context_bytes':4096,'workspace_bytes':16384,'workspace_alignment_bytes':64},
  'conditional_caller_return_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
