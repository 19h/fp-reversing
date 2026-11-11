#!/usr/bin/env python3
"""Audit byte-span source certificates, copy cases and exact publication delta.

Read-only; native validity and full-operation semantics remain premises.
O(source/index bytes + owned bytes + retained proof expressions) time/space;
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
PREVIOUS='588b7930071887f1bd3fbc5a3e2e9a7d629111f8'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={
 'lskd_operation_preflight_report.md','lskd_context_return_report.md',
 'lskd_reader_lineage_report.md','lskd_context_codec_report.md',
 'sample_transfer_report.md','obfuscated_routines_report.md',
 'foundational_triage_report.md','interface_abi_report.md',
 'interface_investigation_status.md','kext_buffer_report.md','kext_cold_init_report.md',
 'triage_evidence/validate_rpc502_sidecar_delivery.py',
}
ADDED={
 'lskd_byte_spans_report.md','triage_evidence/recover_lskd_byte_spans.py',
 'triage_evidence/lskd_byte_spans_checks.json','triage_evidence/verify_lskd_byte_spans_publication.py',
}
ARCHIVES={MANIFEST,'triage_evidence/lskd_byte_spans_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'queries_unsat':156,'negative_controls_sat':1,'source_pieces':32,
 'source_lifted_instances':11351,'byte_copy_cases':64,'byte_copy_loads':992,
 'byte_copy_stores':992,'spans':24,'instructions':545,'code_B':2180,
 'original_loaded_slots':25,'original_slots':30}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def check(query,expected):
 solver=z3.Solver();solver.set(timeout=10000);solver.from_string(query)
 assert solver.check()==expected


def main():
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
 assert sha256(raw).hexdigest()=='1feb0451bbbd190bd33dcaa99c2536c394a292041c7de57bd828323c72de1724'
 previous=json.loads(raw);current=json.loads(read(BASE/MANIFEST))
 old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
 assert len(old)==len(previous['files'])==8070 and len(new)==len(current['files'])==8074
 assert not old.keys()-new.keys() and new.keys()-old.keys()==ADDED
 assert {p for p in old if old[p]!=new[p]}==CHANGED
 assert current['inputs_preserved']==previous['inputs_preserved']
 for row in current['inputs_preserved']:
  assert sha(BASE/row['path'])==row['sha256'] and size(BASE/row['path'])==row['size_bytes']
 for p in CHANGED|ADDED:
  assert sha(BASE/p)==new[p]['sha256'] and size(BASE/p)==new[p]['size_bytes']
 report=read(BASE/'lskd_byte_spans_report.md')
 assert all(f'| BS{i} |' in report for i in range(1,9)) and all(f'**QG{i}**' in report for i in range(1,8))
 e=json.loads(read(ROOT/'lskd_byte_spans_checks.json'))
 assert e['generator_sha256']==sha(ROOT/'recover_lskd_byte_spans.py')
 for p,digest in e['dependencies'].items():assert sha(ROOT/p)==digest
 assert e['verified_counts']==COUNTS and len(e['proofs'])==156
 assert {'array_read_over_write_equal','array_read_over_write_unequal',
  'short_arm_reencoding_continuation','short_copy_conditional_outer_zero',
  'builder_full_arm_status','suffix_pointer_direction_and_offsets','bulk_frontier'}<=e['proofs'].keys()
 for proof in e['proofs'].values():assert proof['result']=='unsat';check(proof['query'],z3.unsat)
 assert set(e['negative_controls'])=={'wrong_direction_can_change_snapshot_copy'}
 for control in e['negative_controls'].values():
  assert control['result']=='sat' and control['length_B']==2 and not control['native_target_state']
  check(control['query'],z3.sat)
 prior_unsat=prior_sat=0
 for name,count in [('lskd_operation_preflight_checks.json',28),('lskd_context_return_checks.json',39)]:
  prior=json.loads(read(ROOT/name));assert len(prior['proofs'])==count
  for proof in prior['proofs'].values():
   assert proof['result']=='unsat';check(proof['query'],z3.unsat);prior_unsat+=1
  for control in prior.get('negative_controls',{}).values():
   assert control['result']=='sat';check(control['query'],z3.sat);prior_sat+=1
 assert (prior_unsat,prior_sat)==(67,3)
 assert len(e['source_pieces'])==32 and sum(e['source_lift_counts'].values())==11351
 k=Kernel();assert e['kernel_collection_sha256']==k.sha256 and e['normalized_image_sha256']==sha(SOURCE)
 cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
 spans={r['label']:r for r in e['spans']}
 assert len(spans)==24
 ranges=sorted((int(r['start'],16),int(r['end'],16)) for r in spans.values())
 assert all(z<=a for (_,z),(a,_) in zip(ranges,ranges[1:]))
 for row in spans.values():
  data=bytes.fromhex(row['bytes_hex']);a=int(row['start'],16)
  assert len(data)==int(row['end'],16)-a==4*len(row['instructions'])
  assert data==k.read(a,len(data))==IMAGE.read(a,len(data))
  decoded=[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in cs.disasm(data,a)]
  assert row['instructions']==decoded and not any(r['mnemonic'].startswith('bl') for r in decoded)
 assert sum(len(r['instructions']) for r in spans.values())==545
 for name,piece in e['source_pieces'].items():
  a,z=int(piece['start'],16),int(piece['end'],16)
  assert piece['instructions']==(z-a)//4 and piece['instructions']*piece['instances']==e['source_lift_counts'][name]
  assert any(left<=a<z<=right for left,right in ranges)
 table=0xfffffe000846c420
 assert len(e['slots'])==30 and len(e['table_loads'])==25
 for a,row in e['slots'].items():
  at=int(a,16);assert at>=table and (at-table)%8==0 and row==pointer(k,at)
  assert row['authenticated']
 for a,target in e['table_loads'].items():
  assert a in e['slots'] and int(target,16)==int(e['slots'][a]['target'],16)
  assert int.from_bytes(IMAGE.read(int(a,16),8),'little')==int(target,16)
 cases=e['byte_copy_cases'];assert len(cases)==64
 assert {(c['direction'],c['length_B']) for c in cases}=={(d,n) for d in ['backward','forward'] for n in range(32)}
 copy_labels={'backward_gate','forward_gate','backward_setup','backward_tail',
  'backward_bulk_gate','backward_bulk_setup','backward_bulk','forward_setup',
  'forward_pair_setup','forward_pairs','forward_odd_gate','forward_odd'}
 copy_starts={spans[n]['start'] for n in copy_labels}
 for case in cases:
  n=case['length_B'];d=case['direction'];order=list(range(n-1,-1,-1)) if d=='backward' else list(range(n))
  assert case['source_offsets_B']==case['destination_offsets_B']==order
  assert case['arbitrary_common_offset64'] and case['read_over_write_premises_proven']
  assert case['exit']=='0xfffffe000a545d44' and set(case['visits'])<=copy_starts
  assert 'copy_order_'+d+'_'+str(n) in e['proofs'] and 'copy_'+d+'_'+str(n) in e['proofs']
  for row in case['table_loads']:assert e['table_loads'][row['slot']]==row['target']
 assert sum(len(c['source_offsets_B']) for c in cases)==sum(len(c['destination_offsets_B']) for c in cases)==992
 # Independent clobber checks join source cuts across omitted dispatch tails.
 def writes(ins):
  return {re.sub(r'^w(?=\d)','x',{'fp':'x29','lr':'x30'}.get(ins.reg_name(r),ins.reg_name(r))) for r in ins.regs_access()[1]}
 def preserved(a,z,regs):
  for ins in cs.disasm(k.read(a,z-a),a):assert not writes(ins)&regs,(hex(ins.address),ins.op_str)
 preserved(0xfffffe000a55b628,0xfffffe000a55b858,{'x8','x9','x10','x12'})
 preserved(0xfffffe000a52e534,0xfffffe000a52e54c,{'x8','x9','x10','x12'})
 preserved(0xfffffe000a5237dc,0xfffffe000a5237f0,{'x8','x9','x10','x12'})
 preserved(0xfffffe000a52dfc8,0xfffffe000a52e028,{'x9','x14','x15'})
 preserved(0xfffffe000a52dfd0,0xfffffe000a52e028,{'x11'})
 for name in copy_labels:
  row=spans[name];preserved(int(row['start'],16),int(row['end'],16),{'x11','x14','x15','x21','x22','x30'})
 preserved(0xfffffe000a545d48,0xfffffe000a545d74,{'x11'})
 # Every retained store is a frame write or the recovered byte destination.
 for row in spans.values():
  for ins in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if ins.mnemonic.startswith('st'):
    mem=[o for o in ins.operands if o.type==ARM64_OP_MEM];assert len(mem)==1
    base=ins.reg_name(mem[0].mem.base)
    assert base=='sp' or (row['label'] in copy_labels and ins.mnemonic=='strb' and base=='x15'),(row['label'],hex(ins.address),ins.op_str)
 source=e['supplied_reference'];assert sha(BASE/source['path'])==source['sha256']
 lines=read(BASE/source['path']).splitlines(keepends=True)
 for row in source['excerpts']:assert row['text']==''.join(lines[row['first_line']-1:row['last_line']])
 contract=e['selected_contract'];assert contract['original_operations']==[1,5]
 assert contract['full_split_minimum_N']=={'1':32,'5':16} and contract['bounded_copy_lengths_B']==list(range(32))
 assert all(contract[n] for n in ['N_is_low32_original_X4','source_is_original_X2','destination_is_original_X3',
  'arbitrary_common_offset64','relational_read_normalization_uses_proven_array_lemmas','per_pass_snapshot_only'])
 assert not any(contract[n] for n in ['threshold_is_complete_rejection_test','whole_operation_overlap_contract_proven',
  'short_arm_scratch_origins_proven','native_epoch_matched','daemon_request_lineage_proven'])
 assert not any(e[n] for n in ['new_IDA_access','new_native_execution','new_IDB_mutations','full_goal_complete'])
 assert current['validation']['lskd_byte_spans_increment_checks']==COUNTS
 assert current['validation']['lskd_byte_spans_static_scope']==e['scope']
 assert current['validation']['reports']==previous['validation']['reports']+1==392
 assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
 assert current['goal_status']=='active' and len(OWNED)==17
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:path_hygiene((BASE/p).read_bytes())
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
  'original_inputs_preserved':3,'new_UNSAT_queries_rechecked':156,'new_SAT_controls_rechecked':1,
  'prior_UNSAT_queries_rechecked':prior_unsat,'prior_SAT_controls_rechecked':prior_sat,
  'byte_copy_cases':64,'original_fixup_addresses':30,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
