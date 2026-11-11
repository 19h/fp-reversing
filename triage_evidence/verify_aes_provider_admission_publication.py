#!/usr/bin/env python3
"""Audit nominal AES provider guards/ABI and exact publication delta.

Read-only; complete key policy, native extents and completion remain unproved.
O(source/index bytes + owned bytes + retained expressions) time/space;
SMT solver cost separate.
"""
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess

from compression import zstd
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_MEM
import z3

from kernel_native_reader import Kernel
from recover_kext_aes_handoff import starts
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene

ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent
PREVIOUS='110ca23b19729f82f1baef4300a01929131fc399'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={
 'kext_aes_handoff_report.md','lskd_hardware_staging_report.md','sample_state_report.md',
 'sample_transfer_report.md','obfuscated_routines_report.md','foundational_triage_report.md',
 'interface_abi_report.md','interface_investigation_status.md','lskd_operation_preflight_report.md',
 'triage_evidence/validate_rpc502_sidecar_delivery.py',
}
ADDED={
 'aes_provider_admission_report.md','triage_evidence/recover_aes_provider_admission.py',
 'triage_evidence/aes_provider_admission_checks.json','triage_evidence/verify_aes_provider_admission_publication.py',
}
ARCHIVES={MANIFEST,'triage_evidence/aes_provider_admission_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'queries_unsat':29,'source_pieces':27,'source_lifted_instances':91,
 'spans':7,'instructions':568,'code_B':2272,'original_slots':16}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def check(query,expected):
 solver=z3.Solver();solver.set(timeout=15000);solver.from_string(query)
 assert solver.check()==expected


def main():
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
 assert sha256(raw).hexdigest()=='c84895fec77a0042073aa3abaa65da383c20f69a513e3ac0efba1a7798e29747'
 previous=json.loads(raw);current=json.loads(read(BASE/MANIFEST))
 old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
 assert len(old)==len(previous['files'])==8078 and len(new)==len(current['files'])==8082
 assert not old.keys()-new.keys() and new.keys()-old.keys()==ADDED
 assert {p for p in old if old[p]!=new[p]}==CHANGED
 assert current['inputs_preserved']==previous['inputs_preserved']
 for row in current['inputs_preserved']:
  assert sha(BASE/row['path'])==row['sha256'] and size(BASE/row['path'])==row['size_bytes']
 for p in CHANGED|ADDED:
  assert sha(BASE/p)==new[p]['sha256'] and size(BASE/p)==new[p]['size_bytes']
 report=read(BASE/'aes_provider_admission_report.md')
 assert all(f'| PA{i} |' in report for i in range(1,9)) and all(f'**QG{i}**' in report for i in range(1,8))
 e=json.loads(read(ROOT/'aes_provider_admission_checks.json'))
 assert e['generator_sha256']==sha(ROOT/'recover_aes_provider_admission.py')
 for p,digest in e['dependencies'].items():assert sha(ROOT/p)==digest
 assert e['verified_counts']==COUNTS and len(e['proofs'])==29
 assert {'length_range','key_control_strip','key_entry_selection','physical_alignment',
  'command_first_fields','operation_one_quantum','scheduler_quantum','queue_return_status'}<=e['proofs'].keys()
 for proof in e['proofs'].values():assert proof['result']=='unsat';check(proof['query'],z3.unsat)
 prior=json.loads(read(ROOT/'lskd_hardware_staging_checks.json'));assert len(prior['proofs'])==36
 for proof in prior['proofs'].values():assert proof['result']=='unsat';check(proof['query'],z3.unsat)
 assert len(prior['negative_controls'])==1
 for control in prior['negative_controls'].values():assert control['result']=='sat';check(control['query'],z3.sat)
 k=Kernel();assert e['kernel_collection_sha256']==k.sha256
 cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
 spans={r['label']:r for r in e['spans']};assert len(spans)==7
 ranges=sorted((int(r['start'],16),int(r['end'],16)) for r in spans.values())
 assert all(z<=a for (_,z),(a,_) in zip(ranges,ranges[1:]))
 frozen=json.loads(read(ROOT/'kext_aes_handoff_contracts.json'))
 for row in spans.values():
  data=bytes.fromhex(row['bytes_hex']);a,z=int(row['start'],16),int(row['end'],16)
  assert len(data)==z-a==4*len(row['instructions']) and data==k.read(a,len(data))
  assert row['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in cs.disasm(data,a)]
  if row['label'] in ['provider','base_options','queue','start','hardware_options']:
   entry=next(x for x in k.entries if x['name']==row['entry']);catalog=starts(k,entry)
   assert a in catalog and catalog[catalog.index(a)+1]==z
  if row['label'] in ['provider','base_options','queue','start']:
   old_row=next(r for r in frozen['functions'] if r['start']==row['start'])
   assert old_row['bytes_hex']==row['bytes_hex'] and old_row['end']==row['end']
 assert sum(len(r['instructions']) for r in spans.values())==568
 assert len(e['source_pieces'])==27 and sum(e['source_lift_counts'].values())==91
 for name,piece in e['source_pieces'].items():
  a,z=int(piece['start'],16),int(piece['end'],16)
  assert piece['instructions']==(z-a)//4==e['source_lift_counts'][name]
  assert any(left<=a<z<=right for left,right in ranges)
  assert not any(i.mnemonic.startswith('bl') for i in cs.disasm(k.read(a,z-a),a))
 assert len(e['slots'])==16
 for a,row in e['slots'].items():assert row==pointer(k,int(a,16)) and row['authenticated']
 assert e['exact_symbols']==k.symbols([int(r['target'],16) for r in e['slots'].values()])
 assert [r['name'] for r in e['exact_symbols']['0xfffffe000c53c2c4']]==['__ZN18IOMemoryDescriptor18getPhysicalAddressEv']
 assert [r['name'] for r in e['exact_symbols']['0xfffffe000c536304']]==['__ZN25IOGeneralMemoryDescriptor18getPhysicalSegmentEyPyj']
 assert [r['name'] for r in e['exact_symbols']['0xfffffe0009d50a28']]==['__ZN24AppleS8000AESAccelerator17performAESQuantumEP23IOAESAcceleratorCommand']
 table=e['operation_offset_table'];assert table['address']=='0xfffffe0007abf4f8'
 assert bytes.fromhex(table['bytes_hex'])==k.read(int(table['address'],16),40)
 assert table['values_u64']==[0xe0,0xe8,0xe0,0xe8,0xe0]
 # Independent decode/access checks qualify the joins between lifted cuts.
 code={r['ea']:(r['mnemonic'],r['operands']) for row in spans.values() for r in row['instructions']}
 for a,op in [('0xfffffe000abff3cc','x22'),('0xfffffe000abff3d0','x20'),('0xfffffe000abff3d4','x26')]:
  assert code[a]==('cbz',op+', #0xfffffe000abff640')
 assert code['0xfffffe000abff3dc']==('b.ne','#0xfffffe000abff640')
 assert code['0xfffffe000abff3ec']==('b.lo','#0xfffffe000abff640')
 assert code['0xfffffe000abff400']==('str','w9, [x23]')
 assert code['0xfffffe000abff66c']==('ldr','w11, [x26]')
 for a,value in [('0xfffffe000abff670','0x80'),('0xfffffe000abff678','0x100'),('0xfffffe000abff688','0xc0')]:
  assert code[a]==('cmp','w11, #'+value)
 for a in [0xfffffe000abff710,0xfffffe000abff728]:
  assert code[hex(a)]==('ldr','w8, [x19, #0xb0]')
  assert code[hex(a+4)]==('sub','w8, w8, #1')
  assert code[hex(a+8)]==('tst','x0, x8')
 for a,value in [('0xfffffe000abfd2fc',('tbnz','w8, #0, #0xfffffe000abfd354')),
  ('0xfffffe000abfd30c',('b.hi','#0xfffffe000abfd354')),
  ('0xfffffe000abfd314',('cbnz','x8, #0xfffffe000abfd354')),
  ('0xfffffe000abfd350',('b.ne','#0xfffffe000abfd440')),
  ('0xfffffe000abfd3bc',('cbz','x8, #0xfffffe000abfd3c8')),
  ('0xfffffe000abfd3f8',('cbnz','w0, #0xfffffe000abfd4b8'))]:assert code[a]==value
 def writes(ins):
  # These aliases write flags only; operand access metadata can overreport.
  if ins.mnemonic in ['cmp','cmn','tst']:
   word=int.from_bytes(ins.bytes,'little');assert word&31==31 and word&(1<<29)
   return {'nzcv'}
  return {re.sub(r'^w(?=\d)','x',{'fp':'x29','lr':'x30'}.get(ins.reg_name(r),ins.reg_name(r))) for r in ins.regs_access()[1]}
 # Exclude exit-only epilogues and the failed-alignment cleanup branch.
 for a,z in [(0xfffffe000abff3cc,0xfffffe000abff640),(0xfffffe000abff66c,0xfffffe000abff738),
  (0xfffffe000abff7b8,0xfffffe000abff7f4)]:
  for ins in cs.disasm(k.read(a,z-a),a):assert not writes(ins)&{'x20','x21','x22','x24','x25','x28'}
 # Immediate-SP stores overlapping the saved IV have exactly one writer.
 iv_writes=[]
 for ins in cs.disasm(bytes.fromhex(spans['provider']['bytes_hex']),int(spans['provider']['start'],16)):
  if ins.mnemonic not in ['str','stp','stur']:continue
  mem=[o for o in ins.operands if o.type==ARM64_OP_MEM];assert len(mem)==1
  if ins.reg_name(mem[0].mem.base)!='sp':continue
  width=(4 if ins.reg_name(ins.operands[0].reg).startswith('w') else 8)*(2 if ins.mnemonic=='stp' else 1)
  if mem[0].mem.disp<0x30 and mem[0].mem.disp+width>0x28:iv_writes.append(ins.address)
 assert iv_writes==[0xfffffe000abff38c]
 state=json.loads(read(ROOT/'sample_state_contracts.json'))['state_contract']
 roles=json.loads(read(ROOT/'sample_transfer_contracts.json'))['carrier_roles']
 assert state['header_word0']==128 and state['mode_code_offset']==36
 assert roles['key_data_argument']=='state object base'
 c=e['selected_contract'];assert c['provider_length_full64'] and c['key_selector_high_bit_cleared']
 assert [c[n] for n in ['provider_maximum_length_B','provider_length_alignment_B','operation_one_quantum_provider_offset_B',
  'key_selector_field_offset_B','provider_key_entry_stride_B','matched_key_data_entry_offset_B','scheduler_quantum_command_offset_B']]==[8388608,16,0xe8,0x24,52,8,0x70]
 assert not any(c[n] for n in ['full_key_policy_proven','native_descriptor_extent_matched','native_provider_class_matched',
  'native_completion_proven','daemon_request_lineage_proven'])
 assert not any(e[n] for n in ['new_IDA_access','new_native_execution','new_IDB_mutations','full_goal_complete'])
 assert current['validation']['aes_provider_admission_increment_checks']==COUNTS
 assert current['validation']['aes_provider_admission_static_scope']==e['scope']
 assert current['validation']['reports']==previous['validation']['reports']+1==394
 assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
 assert current['goal_status']=='active' and len(OWNED)==15
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:path_hygiene((BASE/p).read_bytes())
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
  'original_inputs_preserved':3,'new_UNSAT_queries_rechecked':29,'prior_UNSAT_queries_rechecked':36,
  'prior_SAT_controls_rechecked':1,'source_instructions_retained':568,'original_fixup_addresses':16,
  'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
