#!/usr/bin/env python3
"""Verify full dispatcher scope, symbolic boundaries and exact publication delta.

O(owned decoded bytes+receipt+source+manifest) time/space, plus 30 s/query.
No native call, IPC, new guest replay, IDA operation or history rewrite.
"""
import json,struct,subprocess
from pathlib import Path
from hashlib import sha256
from compression import zstd
import z3
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
import verify_corefp_late_preparation_publication as H
import recover_versioned_dispatcher_frame as R
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='8622450c15cef092e34953864093da082197b0cf'
BASELINE_SHA='63a898faf45c4efbaeae7c08da2afa9d63c85dd879034a51b8c49a25090ee199'
CHECKS_SHA='f33cd61a5e74dc26f8f62af789a24d0d431b3ec50e23c364373e269efb1e0c80'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','versioned_core_preparation_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'versioned_dispatcher_frame_report.md','triage_evidence/recover_versioned_dispatcher_frame.py','triage_evidence/verify_versioned_dispatcher_frame_publication.py','triage_evidence/versioned_dispatcher_frame_checks.json'}
ARCHIVES={MANIFEST,'triage_evidence/versioned_dispatcher_frame_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'retained_mode2_cases':12,'compiler_function_instruction_words':4013,'slot130_direct_store_sites':3,'source_queries_unsat':6,'source_lift_instructions':28,'symbolic_slice_queries_unsat':12,'symbolic_slice_instruction_visits':828,'symbolic_slice_read_bytes':960,'original_transfer_pointers_checked':36,'exhaustive_bank_inputs':512,'source_instruction_visits':103764,'write_bytes_checked':31104,'read_bytes_checked':95088}

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)

def reject(action,fragment):
 try:action()
 except AssertionError as e:assert fragment in str(e),str(e);return
 raise AssertionError('negative control unexpectedly accepted')

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));fresh=R.build()
 # Solver printer names may differ; frozen queries are checked independently.
 assert fresh.keys()==e.keys()
 for k in e:
  if k not in ['source_proofs','cases']:assert fresh[k]==e[k],k
 assert [(q['label'],q['result'])for q in fresh['source_proofs']]==[(q['label'],q['result'])for q in e['source_proofs']]
 assert len(e['cases'])==len(fresh['cases'])==12
 for a,b in zip(e['cases'],fresh['cases']):
  assert a.keys()==b.keys()
  for k in a:
   if k!='observable_independence':assert a[k]==b[k],k
  assert a['observable_independence']['observables']==b['observable_independence']['observables']and a['observable_independence']['result']=='unsat'
 for q in e['source_proofs']+[r['observable_independence']for r in e['cases']]:
  s=z3.Solver();s.set(timeout=30000);s.from_string(q['query']);assert s.check()==z3.unsat
 assert e['verified_counts']==COUNTS and e['generator_sha256']==sha(R.__file__)
 raw=bytes.fromhex(e['source_function']['bytes_hex']);assert len(raw)==16052 and sha256(raw).hexdigest()==e['source_function']['sha256']
 # Independent A64 STR Wt,[SP,#imm12*4] encoding scan; no Capstone dependency.
 stores=[hex(R.START+off)for off in range(0,len(raw),4)if (struct.unpack_from('<I',raw,off)[0]&0xffc003e0)==0xb90003e0 and((struct.unpack_from('<I',raw,off)[0]>>10)&0xfff)*4==0x130]
 assert stores==['0xfffffe000a5a76f0','0xfffffe000a5a8150','0xfffffe000a5a8d58']
 assert all(int(a,16)>=0xfffffe000a5a72bc for a in stores)and len(e['frame_census']['slot_accesses'])==19
 assert len([a for a in e['frame_census']['slot_accesses']if a['write']and a['body_SP_offset']=='0x134'])==7
 prior=json.loads(read(ROOT/'versioned_core_preparation_checks.json'));parents=[r for r in prior['cases']if r['configuration']['mode32']==2]
 for row,out in zip(parents,e['cases']):
  assert not set(stores)&{v['pc']for v in row['source_visits']}
  assert row['boundary']['pc']==hex(R.FRONTIER)and row['boundary']['known_bytes']==0 and not row['boundary']['instruction_executed']
  assert len(out['source_trace'])==69 and len(out['source_reads'])==15 and out['W24_still_symbolic']and not out['guest_continued']
  assert out['pending_call']=={'pc':'0xfffffe000a5a6f74','bytes_hex':'51093fd7','target':'0xfffffe000c4ba154','modifier':'0xd0c8','X0':'0xfffffe000847b320','executed':False}
  assert all('w24'not in i['operands']and 'x24'not in i['operands']for i in out['source_trace'])
 k=R.Kernel();v=R.Slice(k,parents[0]);v.pc=R.FRONTIER
 reject(lambda:v.load(v.read('sp')+0x148,4),'unspecified private read')
 v=R.Slice(k,parents[0]);v.seed('x23',z3.ZeroExt(32,v.opaque))
 reject(v.run_slice,'unknown observable')
 assert not e['new_guest_execution']and not e['native_target_executed']and not e['new_model_memory_writes']and not e['full_goal_complete']
 report=read(BASE/'versioned_dispatcher_frame_report.md');assert all(f'| DF{k} |'in report for k in range(1,7))and all(f'**QG{k}**'in report for k in range(1,8))
 assert all(t in report for t in ['4,013','1,922','32 B','site.FPByteArrayStreamInternal','unknown','103,764','0xfffffe000a5a9324'])
 return e

def main():
 e=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
 assert len(before)==len(old['files'])==8599 and len(after)==len(new['files'])==8603
 assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 assert new['validation']['versioned_dispatcher_frame_increment_checks']==COUNTS and new['validation']['versioned_dispatcher_frame_static_scope']==e['scope']
 assert new['validation']['reports']==old['validation']['reports']+1==478 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
 path_hygiene(json.dumps(H.paths_in_typed_payloads(e)).encode());fields,extent=H.hex_hygiene(e);path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
 print(json.dumps({'unchanged_manifest_entries':8591,'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':478,'source_equations_unsat':6,'symbolic_independence_checks':12,'negative_controls_rejected':2,'complete_function_words':4013,'decoded_hex_fields_path_checked':fields,'decoded_hex_bytes_path_checked':extent,'new_guest_executed':False,'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
