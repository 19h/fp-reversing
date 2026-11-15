#!/usr/bin/env python3
"""Capture original discriminator arithmetic, input cell and literal-base inventory.
O(B+I) time/space; original and normalized file reads only.
"""
import json
from hashlib import sha256
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_MEM
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,TABLE
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha

P='userclient_discriminator_origin'
SCOPE='Conditional original-source nullable input-pointer, NUL-byte and status gates, 64-bit 33*h+byte recurrence, final modulo(2^32-1) discriminator and zero-result rejection; complete literal-base operand inventory for six cells. Native input identity, marker producer, alias-complete saved-status writers, full incoming reachability, ownership, serialization and daemon transaction correlation remain unknown.'
SPANS={
 'input_cell_root':(0xfffffe000a635d5c,0xfffffe000a635d64),
 'input_cell_clear':(0xfffffe000a63dd44,0xfffffe000a63dd48),
 'status_gate':(0xfffffe000a6570c8,0xfffffe000a65710c),
 'pointer_gate':(0xfffffe000a657114,0xfffffe000a657160),
 'hash_entry':(0xfffffe000a657168,0xfffffe000a6571e0),
 'empty_default':(0xfffffe000a6571e8,0xfffffe000a657204),
 'hash_step':(0xfffffe000a65720c,0xfffffe000a657258),
 'reduction':(0xfffffe000a657260,0xfffffe000a657290),
 'store_gate':(0xfffffe000a657298,0xfffffe000a6572cc),
 'saved_status_default':(0xfffffe000a636678,0xfffffe000a636694),
 'insertion_inputs':(0xfffffe000a65bb98,0xfffffe000a65bba8),
}
BRANCHES={0xfffffe000a6570fc:[0x2d5,0x9e3],0xfffffe000a657150:[0xa08,0xa2d],
 0xfffffe000a6571a0:[0x580,0x595],0xfffffe000a6571f4:[0x275],
 0xfffffe000a657250:[0x580,0x6b6],0xfffffe000a657280:[0x8b7],0xfffffe000a6572b8:[0x275,0x2d5]}
CELLS={'saved_status':('sp',0x9ec,4),'saved_input_cell_address':('sp',0x478,8),
 'discriminator':('x4',0xc90,4),'insertion_marker':('x4',0x20,4),
 'saved_node_marker':('x4',0xd8c,4),'input_pointer':('x2',0x128,8)}
FALSE=['native_target_executed','native_PAC_authenticated','whole_dispatcher_reachability_established',
 'native_input_identity_established','original_marker_producer_established','alias_complete_saved_status_writers_established',
 'saved_status_native_domain_established','discriminator_business_identity_established','native_ownership_established',
 'native_locking_established','daemon_kext_transaction_correlated','new_Mach_port_endpoint_established','IDB_modified','full_goal_complete']
DEPS=['kext_port_tools.py','kernel_native_reader.py','recover_kext_cold_init.py','lskd_values_symbolic.py',
 'audit_secure_tunnel_table_insertion.py','userclient_uidlist_publication_checks.json','userclient_uidlist_publication_audit.json',
 'secure_tunnel_table_insertion_checks.json','secure_tunnel_table_insertion_audit.json',
 'userclient_replacement_bootstrap_checks.json','userclient_replacement_bootstrap_audit.json']

def inventory(raw,a):
 dec=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);dec.detail=True;rows={n:[] for n in CELLS};indexed={r:0 for r in ['sp','x2','x4']};count=0
 for i in dec.disasm(raw,a):
  count+=1
  for o in i.operands:
   if o.type!=ARM64_OP_MEM:continue
   base=i.reg_name(o.mem.base)
   if base not in indexed:continue
   assert i.mnemonic in ['stp','str','ldr','strb','strh','ldrh','ldp','stur','ldrb']
   if o.mem.index:indexed[base]+=1;continue
   reg=i.reg_name(i.operands[0].reg);reg={'fp':'x29','lr':'x30'}.get(reg,reg);assert reg[0] in 'wxqds'
   n=1 if i.mnemonic.endswith('b') else 2 if i.mnemonic.endswith('h') else {'w':4,'x':8,'q':16,'d':8,'s':4}[reg[0]]
   if i.mnemonic in ['stp','ldp']:n*=2
   for name,(b,t,w) in CELLS.items():
    if base==b and o.mem.disp<t+w and o.mem.disp+n>t:
     rows[name].append({'ea':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,
      'operands':i.op_str,'offset':o.mem.disp,'access_bytes':n,'write':i.mnemonic.startswith('st'),'writeback':i.writeback})
 assert count*4==len(raw)
 return {'scope':'Complete syntactic nonindexed literal-base operand overlap within the pinned container; no alias, call-effect or SP-epoch closure.',
  'cells':{n:{'base_register':b,'offset':t,'extent_bytes':w,'references':rows[n]} for n,(b,t,w) in CELLS.items()},
  'indexed_operand_counts_excluded':indexed,'container_instructions':count}

def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_replacement_bootstrap_checks.json'));container=prior['function_container']
 a,z=(int(container[n],16) for n in ['start','end_exclusive']);raw=k.read(a,z-a)
 assert IMAGE.read(a,z-a)==raw and sha256(raw).hexdigest()==container['sha256']
 spans=[]
 for label,(lo,hi) in SPANS.items():
  b=k.read(lo,hi-lo);assert IMAGE.read(lo,hi-lo)==b;ii=list(CS.disasm(b,lo));assert len(ii)*4==len(b)
  spans.append({'label':label,'start':hex(lo),'end_exclusive':hex(hi),'bytes_hex':b.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 transfers=[]
 for pc in [z for name,(a,z) in SPANS.items() if name in ['status_gate','pointer_gate','hash_entry','empty_default','hash_step','reduction','store_gate']]:
  b=k.read(pc,4);assert IMAGE.read(pc,4)==b;i=list(CS.disasm(b,pc))[0];assert i.mnemonic=='braa'
  transfers.append({'ea':hex(pc),'bytes_hex':b.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
 inv=inventory(raw,int(container['start'],16))
 totals={n:{'reads':sum(not r['write'] for r in x['references']),'writes':sum(r['write'] for r in x['references'])} for n,x in inv['cells'].items()}
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'scope':SCOPE,'function_container':container,'dependencies':{n:sha(ROOT/n) for n in DEPS},
  'spans':spans,'transfers':transfers,'branch_pointers':[pointer(k,TABLE+8*j)|{'index':j} for j in sorted({j for jj in BRANCHES.values() for j in jj})],
  'literal_base_inventory':inv,'inventory_totals':totals,
  'verified_counts':{'source_spans':len(spans),'selected_instructions':sum(len(s['instructions']) for s in spans),
   'terminal_transfers':len(transfers),'container_instructions':inv['container_instructions'],'inventoried_cells':len(CELLS),
   'hash_state_bits':64,'discriminator_bits':32,'modulus':2**32-1,'seed':5381},
  'conditional_discriminator_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'counts':e['verified_counts'],'inventory':e['inventory_totals']}),flush=True)
