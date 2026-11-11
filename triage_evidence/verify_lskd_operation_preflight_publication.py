#!/usr/bin/env python3
"""Audit operation preflight source certificates and the exact publication delta.

Read-only; call effects, native epochs and complete operation semantics remain
premises. O(source/index bytes + owned bytes + lifted cuts + 256R) time/space;
SMT solver cost is separate.
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
from kext_port_tools import IMAGE,SOURCE
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene

ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent
PREVIOUS='6340f3ee92b0616df850aeb9d99450cde3956733'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={
 'lskd_context_return_report.md','lskd_reader_lineage_report.md','kext_cold_init_report.md',
 'kext_buffer_report.md','sample_transfer_report.md','obfuscated_routines_report.md',
 'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md',
 'triage_evidence/validate_rpc502_sidecar_delivery.py',
}
ADDED={
 'lskd_operation_preflight_report.md','triage_evidence/recover_lskd_operation_preflight.py',
 'triage_evidence/lskd_operation_preflight_checks.json','triage_evidence/verify_lskd_operation_preflight_publication.py',
}
ARCHIVES={MANIFEST,'triage_evidence/lskd_operation_preflight_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def check(query,expected):
 s=z3.Solver();s.set(timeout=10000);s.from_string(query);assert s.check()==expected


def main():
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
 assert sha256(raw).hexdigest()=='9ccb4ff8af1e48b3ea3872b50f66f616f7b307c9f1a08746350339ab50174703'
 previous=json.loads(raw);current=json.loads(read(BASE/MANIFEST))
 old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
 assert len(old)==len(previous['files'])==8066 and len(new)==len(current['files'])==8070
 assert not old.keys()-new.keys() and new.keys()-old.keys()==ADDED
 assert {p for p in old if old[p]!=new[p]}==CHANGED
 assert current['inputs_preserved']==previous['inputs_preserved']
 for row in current['inputs_preserved']:
  assert sha(BASE/row['path'])==row['sha256'] and size(BASE/row['path'])==row['size_bytes']
 for p in CHANGED|ADDED:
  assert sha(BASE/p)==new[p]['sha256'] and size(BASE/p)==new[p]['size_bytes']
 report=read(BASE/'lskd_operation_preflight_report.md')
 assert all(f'| PF{i} |' in report for i in range(1,9)) and all(f'**QG{i}**' in report for i in range(1,8))
 e=json.loads(read(ROOT/'lskd_operation_preflight_checks.json'))
 assert e['generator_sha256']==sha(ROOT/'recover_lskd_operation_preflight.py')
 for p,digest in e['dependencies'].items():assert sha(ROOT/p)==digest
 assert len(e['proofs'])==28
 assert {'hook_record_key_and_fields','wrapper_status_projection','caller_status_gate',
  'nonzero_initializer_result_forwarding','post_selector_and_count','cached_bytes_cell_root','count_gate'}<=e['proofs'].keys()
 for proof in e['proofs'].values():assert proof['result']=='unsat';check(proof['query'],z3.unsat)
 assert set(e['negative_controls'])=={'ready_bit_does_not_itself_validate_cached_bytes'}
 for control in e['negative_controls'].values():
  assert control['result']=='sat' and control['model'] and not control['native_state_reachability_proven']
  check(control['query'],z3.sat)
 prior_unsat=prior_sat=0
 for name,count in [('lskd_context_return_checks.json',39),('lskd_reader_lineage_checks.json',26)]:
  prior=json.loads(read(ROOT/name));assert len(prior['proofs'])==count
  for proof in prior['proofs'].values():
   assert proof['result']=='unsat';check(proof['query'],z3.unsat);prior_unsat+=1
  for control in prior.get('negative_controls',{}).values():
   assert control['result']=='sat';check(control['query'],z3.sat);prior_sat+=1
 assert (prior_unsat,prior_sat)==(65,4)
 counts=e['verified_counts'];assert counts=={'queries_unsat':28,'negative_controls_sat':1,
  'source_pieces':27,'source_lifted_instances':19867,'bank_source_lifted_instances':19712,
  'bank_rules':7,'bank_byte_inputs':1792,'spans':10,'instructions':430,'code_B':1720,
  'original_continuation_slots':10,'original_pool_slots':6}
 assert sum(e['source_lift_counts'].values())==19867 and len(e['source_pieces'])==27
 k=Kernel();assert e['kernel_collection_sha256']==k.sha256 and e['normalized_image_sha256']==sha(SOURCE)
 cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
 for row in e['spans']:
  data=bytes.fromhex(row['bytes_hex']);a=int(row['start'],16)
  assert len(data)==int(row['end'],16)-a==4*len(row['instructions'])
  assert data==k.read(a,len(data))==IMAGE.read(a,len(data))
  decoded=[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in cs.disasm(data,a)]
  assert row['instructions']==decoded
  if row['label']=='noop':assert [(r['mnemonic'],r['operands']) for r in decoded]==[('bti','c'),('ret','')]
  if row['label']=='initializer':
   frozen=json.loads(read(ROOT/'aes_cleanup_epoch_source.json'))['functions']['init']
   assert data.hex()==frozen['bytes_hex'] and row['start']==frozen['start'] and row['end']==frozen['end']
 for name,piece in e['source_pieces'].items():
  a,z=int(piece['start'],16),int(piece['end'],16)
  assert piece['instructions']==(z-a)//4 and piece['instructions']*piece['instances']==e['source_lift_counts'][name]
  assert piece['instances']==(256 if name.startswith('bank_') else 1)
  assert any(int(s['start'],16)<=a<z<=int(s['end'],16) for s in e['spans'])
  assert not any(i.mnemonic.startswith('bl') for i in cs.disasm(k.read(a,z-a),a))
 table=0xfffffe000846c420;pool=0xfffffe00084716e0;fixup_addresses=set()
 for name,rule in e['rules'].items():
  left,right=[bytes.fromhex(b) for b in rule['banks_hex']]
  for field,data in [('left',left),('right',right)]:
   a=int(rule[field],16);assert len(data)==256 and data==k.read(a,256)==IMAGE.read(a,256)
  key=int(rule['key'],16);constant=int(rule['constant'],16);add=int(rule['additive'],16)
  assert {x^right[left[x]^key] for x in range(256)}=={constant} and rule['inputs_checked']==256
  index=add+constant;assert index==int(rule['index'],16)
  base=table if name in ['noop','wrapper','initializer'] else pool
  a=base+8*index;row=rule['original_fixup'];assert row==pointer(k,a) and a==int(rule['slot'],16)
  assert (int(row['target'],16)+int(rule['bias'],16))%(1<<64)==int(rule['target'],16)
  cut=e['bank_source_cuts'][name];assert len(cut['rows'])==256 and cut['arbitrary_upper_input_bits']==24
  assert cut['source_lifted_instances']==256*(int(cut['end'],16)-int(cut['start'],16))//4
  for byte,row in enumerate(cut['rows']):
   assert row['input_byte']==byte and int(row['index'],16)==index and len(row['reads'])==2
   first,second=row['reads']
   assert int(first['address'],16)==int(rule['left'],16)+byte and first['value']==left[byte]
   assert int(second['address'],16)==int(rule['right'],16)+(left[byte]^key) and second['value']==right[left[byte]^key]
  fixup_addresses.add(a)
 for a,row in e['pool_slots'].items():
  assert row==pointer(k,int(a,16)) and not row['authenticated']
  assert e['pool_reads'][a]==IMAGE.read(int(a,16),8).hex()
  assert int.from_bytes(bytes.fromhex(e['pool_reads'][a]),'little')==int(row['target'],16)
  fixup_addresses.add(int(a,16))
 targets={0x17:0xa527b24,0x979:0xa59b718,0x849:0xa52a990,0x659:0xa520554,0x628:0xa536798,
  0x2f6:0xa535ad8,0x302:0xa534758,0x928:0xa5238f8,0x996:0xa57f8e8,0x988:0xa51a934}
 assert set(e['continuations'])=={hex(i) for i in targets}
 for i,target in targets.items():
  row=e['continuations'][hex(i)];a=table+8*i;assert row==pointer(k,a) and row['authenticated']
  assert int(row['target'],16)==0xfffffe0000000000+target;fixup_addresses.add(a)
 assert len(fixup_addresses)==21
 # Independent access/register checks qualify the record/call composition.
 def writes(ins):
  return {re.sub(r'^w(?=\d)','x',{'fp':'x29','lr':'x30'}.get(ins.reg_name(r),ins.reg_name(r))) for r in ins.regs_access()[1]}
 record_accesses=[]
 for ins in cs.disasm(k.read(0xfffffe000a5607e4,0x1b8),0xfffffe000a5607e4):
  for op in ins.operands:
   if op.type==ARM64_OP_MEM and ins.reg_name(op.mem.base)=='x19':record_accesses.append((ins.address,ins.mnemonic,op.mem.disp))
 assert record_accesses==[(0xfffffe000a560988,'str',4)]
 for ins in cs.disasm(k.read(0xfffffe000a56086c,0x38),0xfffffe000a56086c):
  assert not writes(ins)&{'x14','x15','x10','x11','sp','x19'} and not ins.mnemonic.startswith('bl')
 for ins in cs.disasm(k.read(0xfffffe000a560960,0x3c),0xfffffe000a560960):assert 'x0' not in writes(ins)
 for ins in cs.disasm(k.read(0xfffffe000a52a7d8,0x1b8),0xfffffe000a52a7d8):assert not writes(ins)&{'x20','x22'}
 source=e['supplied_reference'];assert sha(BASE/source['path'])==source['sha256']
 lines=read(BASE/source['path']).splitlines(keepends=True)
 for row in source['excerpts']:assert row['text']==''.join(lines[row['first_line']-1:row['last_line']])
 contract=e['selected_contract'];assert contract['phase32']=='0x6e3' and contract['original_operations']==[1,2,4,5]
 assert contract['initializer_result_test_width_bits']==32 and contract['cached_root_is_address_of_cell']
 assert (contract['operation_1_minimum_original_X4_low32'],contract['operation_5_minimum_original_X4_low32'])==(32,16)
 assert not any(contract[n] for n in ['X4_units_proven','complete_operation_semantics_proven','native_epoch_matched','daemon_request_lineage_proven'])
 assert not any(e[n] for n in ['new_IDA_access','new_native_execution','new_IDB_mutations','full_goal_complete'])
 assert current['validation']['lskd_operation_preflight_increment_checks']==counts
 assert current['validation']['lskd_operation_preflight_static_scope']==e['scope']
 assert current['validation']['reports']==previous['validation']['reports']+1==391
 assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
 assert current['goal_status']=='active' and len(OWNED)==15
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:path_hygiene((BASE/p).read_bytes())
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
  'original_inputs_preserved':3,'new_UNSAT_queries_rechecked':28,'new_SAT_controls_rechecked':1,
  'prior_UNSAT_queries_rechecked':prior_unsat,'prior_SAT_controls_rechecked':prior_sat,
  'source_bank_byte_cases':1792,'original_fixup_addresses':21,
  'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
