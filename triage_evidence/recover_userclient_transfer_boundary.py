#!/usr/bin/env python3
"""Pin selector26 adapter code and original collection bindings.
O(B+I) extraction time/space; no target execution or IDB mutation.
"""
import json
import struct
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,qword
from kernel_native_reader import Kernel
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha

P='userclient_transfer_boundary'
SCOPE='Conditional selector26 handler/provider argument, status, copy request and descriptor lifecycle composition with the previously proved core return. Ordinary returning calls and valid authenticated dispatch are premises. Actual transfers, partial-copy contents, live descriptor ownership, concurrent mutation, native daemon pairing and command business semantics remain unknown.'
FALSE=['native_target_executed','idb_mutated','native_pointer_authentication_proved',
 'complete_byte_transfer_proved','native_ownership_proved','daemon_transaction_correlated','full_goal_complete']
FUNCTIONS={'handler':0xfffffe000a504034,'provider':0xfffffe000a505198}
VENEERS={'task_descriptor':(0xfffffe000a69f1e4,0xfffffe000847c420),
 'buffer_descriptor':(0xfffffe000a69f1f4,0xfffffe000847c428),
 'error_log':(0xfffffe000a69f0d4,0xfffffe000847c398)}
CALLS={
 0xfffffe000a5051d4:('task_descriptor',None),
 0xfffffe000a50520c:('task_prepare',0x218),
 0xfffffe000a505250:('buffer_descriptor',None),
 0xfffffe000a505288:('buffer_prepare',0x218),
 0xfffffe000a5052bc:('buffer_address',0x308),
 0xfffffe000a5052ec:('copy_in',0x208),
 0xfffffe000a5052fc:('core',None),
 0xfffffe000a505344:('copy_out',0x210),
 0xfffffe000a505380:('buffer_complete',0x220),
 0xfffffe000a505398:('buffer_release',0x28),
 0xfffffe000a5053bc:('task_complete',0x220),
 0xfffffe000a5053d4:('task_release',0x28),
 0xfffffe000a50408c:('provider',0xa20),
 0xfffffe000a5040a4:('error_log',None)}
DEPS=['userclient_caller_return_checks.json','userclient_caller_return_audit.json',
 'context_descriptor_task_flow_checks.json','userclient_provider_routes.json',
 'selector26_lifecycle_contract.json',
 'recover_userclient_caller_return.py','audit_userclient_caller_return.py',
 'kext_port_tools.py','kernel_native_reader.py','recover_kext_cold_init.py']

def build():
 assert sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 k=Kernel();entry=next(x for x in k.entries if x['name']=='com.apple.driver.FairPlayIOKit');fs={}
 for name,a in FUNCTIONS.items():
  f=function(k,entry,a);b=bytes.fromhex(f.pop('bytes_hex'));assert b==IMAGE.read(a,len(b))
  f['bytes_hex']=b.hex();fs[name]=f
 assert int(fs['handler']['end'],16)==0xfffffe000a5040d4
 assert int(fs['provider']['end'],16)==0xfffffe000a5053f4
 stubs={};bindings=[]
 for name,(a,slot) in VENEERS.items():
  b=k.read(a,16);assert b==IMAGE.read(a,16);ii=list(CS.disasm(b,a))
  assert [i.mnemonic for i in ii]==['adrp','add','ldr','braa']
  assert ii[0].op_str=='x17, #'+hex(slot&~4095)
  assert ii[1].op_str=='x17, x17, #'+hex(slot&4095)
  assert ii[2].op_str=='x16, [x17]' and ii[3].op_str=='x16, x17'
  r=pointer(k,slot);assert int(r['target'],16)==qword(slot);bindings.append(r|{'role':name})
  stubs[name]={'start':hex(a),'bytes_hex':b.hex(),'slot':hex(slot)}
 for role,slot in [('kernel_task',0xfffffe000847c608),('page_shift',0xfffffe000847c5b0)]:
  r=pointer(k,slot);assert int(r['target'],16)==qword(slot);bindings.append(r|{'role':role})
 for role,slot,target in [('selector_method_record',0xfffffe000846b838,0xfffffe000846b710),
  ('selector_handler',0xfffffe000846b718,FUNCTIONS['handler']),('nominal_provider_method',0xfffffe000846c2f0,FUNCTIONS['provider'])]:
  r=pointer(k,slot);assert int(r['target'],16)==qword(slot)==target;bindings.append(r|{'role':role})
 assert int(bindings[-1]['diversity'],16)==0x3499
 route=json.loads(read(ROOT/'selector26_lifecycle_contract.json'));record=IMAGE.read(0xfffffe000846b710,48)
 assert record.hex()==route['selector26']['record_bytes']
 assert struct.unpack_from('<3Q',record,24)==(3,16,16)
 assert k.read(0xfffffe000846b728,24)==record[24:]
 syms=k.symbols([int(r['target'],16) for r in bindings]+list(FUNCTIONS.values())+[0xfffffe000a635208])
 for r in bindings:r['exact_symbols']=syms[r['target']]
 assert any(x['name']=='_kernel_task' for x in bindings[3]['exact_symbols'])
 assert any(x['name']=='_PAGE_SHIFT_CONST' for x in bindings[4]['exact_symbols'])
 calls=[]
 for f in fs.values():
  for i in CS.disasm(bytes.fromhex(f['bytes_hex']),int(f['start'],16)):
   if i.mnemonic not in ['bl','blraa']:continue
   name,slot=CALLS[i.address];calls.append({'site':hex(i.address),'role':name,'virtual_offset':slot,'mnemonic':i.mnemonic,'operands':i.op_str})
 assert len(calls)==len(CALLS)==14
 prior=json.loads(read(ROOT/'userclient_caller_return_checks.json'))
 assert prior['conditional_caller_return_contract_established']
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'scope':SCOPE,'functions':fs,'veneers':stubs,'bindings':bindings,'exact_symbols':syms,'calls':calls,
  'selector26':route['selector26'],'provider_vtable_symbol':route['provider_vtable_symbol'],
  'dependencies':{n:sha(ROOT/n) for n in DEPS},
  'verified_counts':{'source_functions':2,'selected_instructions':sum(len(f['instructions']) for f in fs.values()),
   'call_sites':14,'original_bindings':8,'import_veneer_instructions':12,'provider_failure_classes':4},
  'conditional_transfer_boundary_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
