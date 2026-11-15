#!/usr/bin/env python3
"""Capture post-header record dispatch, node construction and buffer ABI.
O(B+I+256R) extraction time/space. No target code executes or IDB changes.
"""
import json
import struct
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,POOL,TABLE,qword,selected
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha

P='userclient_record_nodes'
SCOPE='Conditional post-header metadata ABI, special tag/type success bypass, unsigned payload-plus-ten size gate, original typed 32-byte FPTTLVNode allocation, node initialization, buffer allocation, shared writer setup and first tag-writer selection. Full incoming/nonempty parser reachability, completed serialization/list publication, native identity/lifetime/locking, termination, original marker producer and daemon correlation remain unknown.'
SPANS={
 'descriptor_select':(0xfffffe000a636490,0xfffffe000a6364cc),
 'descriptor_save':(0xfffffe000a6364f4,0xfffffe000a6364fc),
 'header_metadata_return':(0xfffffe000a63dcd4,0xfffffe000a63dd10),
 'metadata_gate':(0xfffffe000a6423c4,0xfffffe000a6423f0),
 'record_kind_gate':(0xfffffe000a6423f8,0xfffffe000a642450),
 'record_inputs':(0xfffffe000a642458,0xfffffe000a6424c4),
 'record_size_gate':(0xfffffe000a6424cc,0xfffffe000a642544),
 'node_allocate':(0xfffffe000a64254c,0xfffffe000a6425cc),
 'node_return':(0xfffffe000a6425d0,0xfffffe000a6425f8),
 'node_null':(0xfffffe000a642600,0xfffffe000a642628),
 'node_initialize':(0xfffffe000a642630,0xfffffe000a642760),
 'buffer_allocate':(0xfffffe000a642760,0xfffffe000a6427c0),
 'buffer_return':(0xfffffe000a6427c4,0xfffffe000a642808),
 'buffer_prepare':(0xfffffe000a642810,0xfffffe000a64283c),
 'writer_request':(0xfffffe000a64283c,0xfffffe000a642860),
 'writer_setup':(0xfffffe000a654ad8,0xfffffe000a654b94),
}
BANK_PCS={'descriptor':(0xfffffe000a6364ac,0xfffffe000a6364b8,0xfffffe000a6364c8),
 'node_allocate':(0xfffffe000a642588,0xfffffe000a642598,0xfffffe000a6425b0),
 'buffer_allocate':(0xfffffe000a642794,0xfffffe000a6427a4,0xfffffe000a6427b4)}
BRANCHES={0xfffffe000a63dcfc:[0x54d],0xfffffe000a6423e8:[0x4a9,0x88c],
 0xfffffe000a642448:[0x449,0x46d],0xfffffe000a6424b0:[0xc88,0xcb2],
 0xfffffe000a64253c:[0x4a9,0x4ba],0xfffffe000a6425f0:[0x238,0x23c],
 0xfffffe000a64260c:[0x7ad],0xfffffe000a6427e0:[0x766,0x7ad],
 0xfffffe000a642848:[0x543],0xfffffe000a654b8c:[0x439]}
TRANSFERS=[n for n in SPANS if n not in ['descriptor_select','descriptor_save','node_initialize','buffer_prepare']]
RETAGS={}
FALSE=['native_target_executed','native_PAC_authenticated','whole_dispatcher_reachability_established',
 'complete_parser_body_established','native_input_identity_established','NUL_termination_guaranteed',
 'native_allocation_identity_established','native_ownership_established','native_locking_established',
 'original_marker_producer_established','daemon_kext_transaction_correlated','new_Mach_port_endpoint_established','IDB_modified','full_goal_complete']
DEPS=['kext_port_tools.py','kernel_native_reader.py','recover_kext_cold_init.py','lskd_values_symbolic.py',
 'audit_secure_tunnel_table_insertion.py','userclient_container_staging_checks.json','userclient_container_staging_audit.json',
 'userclient_input_reader_checks.json','userclient_input_reader_audit.json']

def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_container_staging_checks.json'));container=prior['function_container']
 a,z=(int(container[n],16) for n in ['start','end_exclusive']);raw=k.read(a,z-a)
 assert IMAGE.read(a,z-a)==raw and sha256(raw).hexdigest()==container['sha256'];spans=[]
 for name,(lo,hi) in SPANS.items():
  b=k.read(lo,hi-lo);assert IMAGE.read(lo,hi-lo)==b;ii=list(CS.disasm(b,lo));assert len(ii)*4==len(b)
  spans.append({'label':name,'start':hex(lo),'end_exclusive':hex(hi),'bytes_hex':b.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 roots={'TL':qword(POOL+0x840),'TR':qword(POOL+0xbb8),'SL':qword(POOL+0xc08)-8,'SR':qword(POOL+0x158)-4};rules=[]
 for address in roots.values():assert k.read(address,256)==IMAGE.read(address,256)
 for name,l,r,key,add,base,bias,div in [('descriptor','TL','TR',0x16,0xf1,POOL,-12,None),
  ('node_allocate','TL','TR',0x5c,0xe41,TABLE,0,0xd0c8),('buffer_allocate','SL','SR',5,0xee3,TABLE,0,0xca0c)]:
  row=selected(roots[l],roots[r],key,add,base,bias);row.update(name=name,left_name=l,right_name=r)
  row['original_pointer']=pointer(k,int(row['slot'],16));assert (int(row['original_pointer']['target'],16)+bias)&(2**64-1)==int(row['target'],16)
  if div is not None:assert row['original_pointer']['authenticated'] and int(row['original_pointer']['diversity'],16)==div
  rules.append(row)
 address=int(rules[0]['target'],16);b=IMAGE.read(address,64);np,sp=(struct.unpack_from('<Q',b,o)[0] for o in [16,32])
 name,sig=(IMAGE.read(p,64).split(b'\0')[0] for p in [np,sp]);flags,size=struct.unpack_from('<II',b,40)
 assert (name,sig,flags,size)==(b'site.FPTTLVNode',b'1121',0x64,32)
 pn,ps=pointer(k,address+16),pointer(k,address+32);assert int(pn['target'],16)==np and int(ps['target'],16)==sp
 assert k.read(address+40,8)==b[40:48] and k.read(np,len(name)+1)==name+b'\0' and k.read(sp,len(sig)+1)==sig+b'\0'
 descriptor={'address':hex(address),'normalized64_bytes_hex':b.hex(),'original64_bytes_hex':k.read(address,64).hex(),
  'name':name.decode(),'signature':sig.decode(),'flags_u32':flags,'size_bytes':size,'name_pointer':pn,'signature_pointer':ps}
 transfers=[]
 for name in TRANSFERS:
  pc=SPANS[name][1];b=k.read(pc,4);assert IMAGE.read(pc,4)==b;i=next(CS.disasm(b,pc));assert i.mnemonic in ['braa','blraa']
  transfers.append({'ea':hex(pc),'bytes_hex':b.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
 bp=[pointer(k,TABLE+8*j)|{'index':j} for j in sorted({j for jj in BRANCHES.values() for j in jj})]
 for r in bp:assert int(r['target'],16)==qword(TABLE+8*r['index'])
 lo,hi=0xfffffe000a6364cc,0xfffffe000a6364f4;b=k.read(lo,hi-lo);assert b==IMAGE.read(lo,hi-lo)
 from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
 dec=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);dec.detail=True;gap=list(dec.disasm(b,lo));assert len(gap)==10
 for i in gap:
  assert not i.mnemonic.startswith(('b','ret')) and not {'x1','w1','sp','wsp'}&{i.reg_name(r) for r in i.regs_access()[1]}
 assert [(i.address,i.op_str) for i in gap if i.mnemonic.startswith('st')]==[(0xfffffe000a6364dc,'x14, [sp, #0x828]'),(0xfffffe000a6364f0,'x17, [sp, #0x808]')]
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'scope':SCOPE,
  'function_container':container,'dependencies':{n:sha(ROOT/n) for n in DEPS},'spans':spans,'transfers':transfers,
  'bank_rules':rules,'banks':{n:{'address':hex(v),'bytes_hex':IMAGE.read(v,256).hex()} for n,v in roots.items()},
  'allocation_descriptor':descriptor,'allocator_symbols':k.symbols([int(r['target'],16) for r in rules[1:]]),
  'branch_pointers':bp,'descriptor_retention_envelope':{'start':hex(lo),'end_exclusive':hex(hi),'bytes_hex':b.hex(),
   'instructions':len(gap),'X1_preserved':True,'SP_preserved':True,'stores_only_other_stack_cells':True},
  'pool_pointers':[pointer(k,POOL+o) for o in [0x840,0xbb8,0xc08,0x158]],
  'verified_counts':{'source_spans':len(spans),'selected_instructions':sum(len(s['instructions']) for s in spans),
   'terminal_transfers':len(transfers),'bank_rules':len(rules),'bank_input_cases':256*len(rules),'node_bytes':size,'header_bytes':10},
  'conditional_record_node_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
