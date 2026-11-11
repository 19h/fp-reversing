#!/usr/bin/env python3
"""Audit source-backed context re-encoding, selectors and record-return publication.

Read-only checks; native object, call, guard/PAC and cursor epochs remain premises.
Time/space O(source input/index bytes + owned bytes + code + queries + 256R);
SMT solving has separate input-dependent cost.
"""
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess

from compression import zstd
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
import z3

from kernel_native_reader import Kernel
from kext_port_tools import IMAGE,SOURCE
from recover_kext_cold_init import pointer as original_pointer
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene

ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent
PREVIOUS='f03b67185de06f98f82adaa9308464978019bb6d'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={
 'lskd_context_codec_report.md','lskd_context_compare_report.md','lskd_reader_lineage_report.md',
 'legacy_stack_report.md','lskd_continuations_report.md','obfuscated_routines_report.md',
 'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md',
 'triage_evidence/validate_rpc502_sidecar_delivery.py',
}
ADDED={
 'lskd_context_return_report.md','triage_evidence/recover_lskd_context_return.py',
 'triage_evidence/lskd_context_return_checks.json','triage_evidence/verify_lskd_context_return_publication.py',
}
ARCHIVES={MANIFEST,'triage_evidence/lskd_context_return_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def check(query,expected):
 s=z3.Solver();s.set(timeout=10000);s.from_string(query);assert s.check()==expected


def main():
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
 assert sha256(raw).hexdigest()=='5b7317aaafba7f57ffefae3bcdc73475913ec7181492703d9f0b5a8fad7402df'
 previous=json.loads(raw);current=json.loads(read(BASE/MANIFEST))
 old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
 assert len(old)==len(previous['files'])==8062 and len(new)==len(current['files'])==8066
 assert not old.keys()-new.keys() and new.keys()-old.keys()==ADDED
 assert {p for p in old if old[p]!=new[p]}==CHANGED
 assert current['inputs_preserved']==previous['inputs_preserved']
 for row in current['inputs_preserved']:
  assert sha(BASE/row['path'])==row['sha256'] and size(BASE/row['path'])==row['size_bytes']
 for p in CHANGED|ADDED:
  assert sha(BASE/p)==new[p]['sha256'] and size(BASE/p)==new[p]['size_bytes']
 report=read(BASE/'lskd_context_return_report.md')
 assert all(f'| RT{i} |' in report for i in range(1,9)) and all(f'**QG{i}**' in report for i in range(1,8))
 e=json.loads(read(ROOT/'lskd_context_return_checks.json'))
 assert e['generator_sha256']==sha(ROOT/'recover_lskd_context_return.py')
 for p,digest in e['dependencies'].items():assert sha(ROOT/p)==digest
 assert len(e['proofs'])==39
 assert {'complete_signed_selector_partition','rewrap_SIMD_body','rewrap_saved_word','release_record',
  'result_store','outer_result_zero_displacement'}<=e['proofs'].keys()
 for proof in e['proofs'].values():assert proof['result']=='unsat';check(proof['query'],z3.unsat)
 assert set(e['negative_controls'])=={'unsigned_selector_partition_is_different','clock_predicate_does_not_establish_zero_return'}
 for control in e['negative_controls'].values():
  assert control['result']=='sat' and control['model'];check(control['query'],z3.sat)
 prior_unsat=prior_sat=0
 for name,count in [('lskd_context_codec_checks.json',48),('lskd_reader_lineage_checks.json',26),('lskd_context_compare_checks.json',22)]:
  prior=json.loads(read(ROOT/name));assert len(prior['proofs'])==count
  for proof in prior['proofs'].values():
   assert proof['result']=='unsat';check(proof['query'],z3.unsat);prior_unsat+=1
  for control in prior.get('negative_controls',{}).values():
   assert control['result']=='sat';check(control['query'],z3.sat);prior_sat+=1
 assert (prior_unsat,prior_sat)==(96,6)
 counts=e['verified_counts'];assert counts=={'queries_unsat':39,'negative_controls_sat':2,
  'source_lifted_instances':399,'source_pieces':35,'spans':16,'instructions':543,'code_B':2172,
  'original_slots':18,'bank_rules':1,'bank_byte_inputs':256,'preservation_audit_rows':187}
 assert sum(e['source_lift_counts'].values())==399 and len(e['source_pieces'])==35
 k=Kernel();assert e['kernel_collection_sha256']==k.sha256 and e['normalized_image_sha256']==sha(SOURCE)
 cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
 for row in e['spans']:
  data=bytes.fromhex(row['bytes_hex']);a=int(row['start'],16)
  assert len(data)==int(row['end'],16)-a==4*len(row['instructions'])
  assert data==k.read(a,len(data))==IMAGE.read(a,len(data))
  decoded=[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in cs.disasm(data,a)]
  assert row['instructions']==decoded
  if row['label']=='rewrap':
   assert not any(i['mnemonic'].startswith('bl') for i in decoded)
   for ins in cs.disasm(data,a):
    writes={ins.reg_name(r) for r in ins.regs_access()[1]}
    assert not writes&{'w21','x21','sp','fp','x29'}
 for name,piece in e['source_pieces'].items():
  a,z=int(piece['start'],16),int(piece['end'],16)
  assert piece['instructions']==(z-a)//4==e['source_lift_counts'][name]
  assert any(int(s['start'],16)<=a<z<=int(s['end'],16) for s in e['spans'])
 constant=e['constants'];a=int(constant['start'],16);data=bytes.fromhex(constant['bytes_hex'])
 assert len(data)==192 and data==k.read(a,192)==IMAGE.read(a,192)
 for audit in e['register_preservation_audits'].values():
  a,z=int(audit['start'],16),int(audit['end'],16);rows=[]
  for ins in cs.disasm(k.read(a,z-a),a):
   writes=[]
   for reg in ins.regs_access()[1]:
    name=ins.reg_name(reg);name={'fp':'x29','lr':'x30'}.get(name,name)
    name=re.sub(r'^w(?=\d)','x',name);writes.append(re.sub(r'^[bhsdq](?=\d)','v',name))
   assert not set(writes)&set(audit['protected_registers']) and not ins.mnemonic.startswith('bl')
   rows.append({'pc':hex(ins.address),'writes':writes})
  assert rows==audit['rows'] and len(rows)==(z-a)//4
  assert audit['indirect_object_writes_disjoint_from_frame_is_premise']
 table=0xfffffe000846c420
 targets={0x17:0xa527b24,0x418:0xa522538,0x498:0xa5323f0,0x1ab:0xa533a60,0x1c7:0xa532820,
  0x69e:0xa55c0d0,0x68f:0xa55267c,0x58f:0xa5184d4,0x580:0xa595bb4,0x999:0xa527b24,
  0x9ab:0xa52a7d8,0x220:0xa526c7c,0x980:0xa52a7d8,0x34e:0xa5536a8,0x325:0xa52a7d8,
  0x30a:0xa5144f0,0x4d1:0xa52a508,0x106:0xa50ef94}
 assert set(e['slots'])=={hex(i) for i in targets}
 for i,target in targets.items():
  row=e['slots'][hex(i)];assert row==original_pointer(k,table+8*i)
  assert int(row['target'],16)==0xfffffe0000000000+target and row['authenticated']
 for slot,target in [(0xfffffe00084719e8,0xfffffe00079174c0),(0xfffffe0008471b00,0xfffffe0007919db0)]:
  row=e['bank_root_slots'][hex(slot)];assert row==original_pointer(k,slot)
  assert int(row['target'],16)==target and not row['authenticated'] and row['pointer_format']==8
 bank=e['release_bank'];assert (bank['key'],bank['constant'],bank['additive'],bank['index'])==('0x18','0xdf','0x930','0xa0f')
 left,right=[bytes.fromhex(bank[n+'256_hex']) for n in ['left','right']]
 for name,data in [('left',left),('right',right)]:
  a=int(bank[name],16);assert len(data)==256 and data==k.read(a,256)==IMAGE.read(a,256)
 assert {x^right[left[x]^0x18] for x in range(256)}=={0xdf} and bank['inputs_checked']==256
 row=bank['original_fixup'];assert row==original_pointer(k,table+8*0xa0f)
 assert row['target']==bank['target']=='0xfffffe000a551f38' and row['authenticated'] and row['diversity']=='0x84cc'
 assert e['conditional_status32_map']=={'0x6371ecc':'0x0','0x6371ecb':'0xffffffff','0x636782c':'0xffff5960','0x6367832':'0xffff5966'}
 source=e['supplied_reference'];assert sha(BASE/source['path'])==source['sha256']
 lines=read(BASE/source['path']).splitlines(keepends=True)
 for row in source['excerpts']:assert row['text']==''.join(lines[row['first_line']-1:row['last_line']])
 contract=e['selected_contract'];assert contract['phase32']=='0x6e3' and contract['signed_selector32']
 assert contract['common_operation_inputs']==[1,2,4,5] and contract['object_extent_B']==512
 assert contract['outer_result_requires_zero_displacement'] and contract['selector_source']=='original outer W1'
 assert not any(contract[n] for n in ['cached_release_ownership_proven','full_named_operation_completed','native_epoch_matched','daemon_request_lineage_proven'])
 assert not any(e[n] for n in ['new_IDA_access','new_native_execution','new_IDB_mutations','full_goal_complete'])
 assert current['validation']['lskd_context_return_increment_checks']==counts
 assert current['validation']['lskd_context_return_static_scope']==e['scope']
 assert current['validation']['reports']==previous['validation']['reports']+1
 assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
 assert current['goal_status']=='active' and len(OWNED)==15
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:path_hygiene((BASE/p).read_bytes())
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
  'original_inputs_preserved':3,'new_UNSAT_queries_rechecked':39,'new_SAT_controls_rechecked':2,
  'prior_UNSAT_queries_rechecked':prior_unsat,'prior_SAT_controls_rechecked':prior_sat,
  'preservation_audit_rows':187,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
