#!/usr/bin/env python3
"""Capture auxiliary publication, extent gate and reverse byte transcode.
O(B+I) time/space; static original/normalized image comparison only.
"""
import json
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,TABLE,qword
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha

P='userclient_auxiliary_copy'
SCOPE='Source-derived initial mode/counter, conditional auxiliary publication, exact length/success gate, saved-mode dispatch and reverse byte transcode with conditional N-step composition. Complete serializer-to-callback reachability, native memory effects and daemon transaction pairing remain unknown.'
SPANS={'argument_basis':(0xfffffe000a635604,0xfffffe000a63560c),
 'mode_basis':(0xfffffe000a63596c,0xfffffe000a635990),'saved_counter':(0xfffffe000a63621c,0xfffffe000a636228),
 'publish':(0xfffffe000a65fe70,0xfffffe000a65fe94),
 'return':(0xfffffe000a65fe9c,0xfffffe000a65fea4),
 'callback':(0xfffffe000a65feac,0xfffffe000a65ff34),
 'copy_gate':(0xfffffe000a65ff3c,0xfffffe000a65ff80),
 'step':(0xfffffe000a65ff88,0xfffffe000a660058)}
BRANCHES={0xfffffe000a65fe80:[0x217,0x614,0xd5f,0xe2f],0xfffffe000a65fef8:[0xb6b,0xbd0],
 0xfffffe000a65ff74:[0xb6b,0xbbb],0xfffffe000a660050:[0xb6b,0xbbb]}
RETAGS={0xfffffe000a65ffb8:0xfffffe000a65ffbc,0xfffffe000a65ffd0:0xfffffe000a65ffd4}
NO_TRANSFER={'argument_basis','mode_basis','saved_counter'}
FALSE=['native_target_executed','IDB_modified','native_PAC_authenticated','complete_serializer_established',
 'complete_serializer_to_callback_reachability_established','native_loop_execution_established','native_memory_effects_established',
 'daemon_kext_transaction_correlated','new_Mach_port_endpoint_established','full_goal_complete']
DEPS=['userclient_query_records_checks.json','userclient_query_records_audit.json',
 'userclient_caller_return_checks.json','userclient_container_staging_audit.json',
 'audit_userclient_record_metadata.py','audit_secure_tunnel_table_insertion.py','kext_port_tools.py','kernel_native_reader.py']

def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_query_records_checks.json'));c=prior['function_container']
 a,z=(int(c[n],16) for n in ['start','end_exclusive']);b=k.read(a,z-a)
 assert b==IMAGE.read(a,z-a) and sha256(b).hexdigest()==c['sha256']
 spans=[];transfers=[]
 for label,(a,z) in SPANS.items():
  b=k.read(a,z-a);assert b==IMAGE.read(a,z-a);ii=list(CS.disasm(b,a));assert len(ii)*4==len(b)
  spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
  if label not in NO_TRANSFER:
   b=k.read(z,4);assert b==IMAGE.read(z,4);i=next(CS.disasm(b,z));assert i.mnemonic=='braa'
   transfers.append({'label':label,'ea':hex(z),'bytes_hex':b.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
 from audit_userclient_input_reader import DEC
 structural=[]
 for label,a,z,regs in [('argument_basis_retention',0xfffffe000a63560c,0xfffffe000a63596c,{'x0','w0','x19','w19'}),
  ('mode_basis_retention',0xfffffe000a635990,0xfffffe000a63621c,{'x13','w13','x14','w14'})]:
  b=k.read(a,z-a);assert b==IMAGE.read(a,z-a);ii=list(DEC.disasm(b,a));assert len(ii)*4==len(b)
  for i in ii:
   assert not i.mnemonic.startswith(('b','cb','tb')) and i.mnemonic not in ['ret','retab','retaa','eret','svc','hvc','smc']
   assert not (regs&{i.reg_name(r) for r in i.regs_access()[1]})
  structural.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),
   'instructions':len(ii),'preserved_register_aliases':sorted(regs)})
 ps=[pointer(k,TABLE+8*j)|{'index':j} for j in [0x161,0x217,0x614,0xb6b,0xbbb,0xbd0,0xd5f,0xe2f]]
 for p in ps:assert int(p['target'],16)==qword(TABLE+8*p['index'])
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'scope':SCOPE,'function_container':c,'dependencies':{n:sha(ROOT/n) for n in DEPS},'spans':spans,
  'transfers':transfers,'branch_pointers':ps,'structural_ranges':structural,'verified_counts':{'source_spans':len(spans),
   'selected_instructions':sum(len(s['instructions']) for s in spans),'terminal_transfers':len(transfers),
   'original_branch_pointers':len(ps),'nominal_pointer_guards':len(RETAGS),
   'structural_instruction_instances':sum(r['instructions'] for r in structural)},
  'initial_counter_mode_derivation_established':True,'conditional_N_step_loop_established':True,
  'conditional_auxiliary_copy_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
