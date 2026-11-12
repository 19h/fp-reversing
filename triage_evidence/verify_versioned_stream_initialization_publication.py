#!/usr/bin/env python3
"""Fresh symbolic cases, independent byte epochs and exact publication delta.

O(owned decoded bytes+receipt+source+manifest) time/space plus 30 s/query.
No native call, new guest execution, IDA operation or history rewrite.
"""
import json,subprocess
from pathlib import Path
from hashlib import sha256
from collections import Counter
from copy import deepcopy
from compression import zstd
import z3
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
import verify_corefp_late_preparation_publication as H
import recover_versioned_stream_initialization as R
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='96896b74832a0e8e122d092ddaed4c00815d92f5'
BASELINE_SHA='fe9f115c3e4fdcfbae17df3079b5f6c7993f03204f686b676b44e01c8b391c52'
CHECKS_SHA='be35ea79704879200c95fb057b0d7a8cb4809c55405238b5affa4fde6fc9efff'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','versioned_dispatcher_frame_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'versioned_stream_initialization_report.md','triage_evidence/recover_versioned_stream_initialization.py','triage_evidence/verify_versioned_stream_initialization_publication.py','triage_evidence/versioned_stream_initialization_checks.json'}
ARCHIVES={MANIFEST,'triage_evidence/versioned_stream_initialization_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'cases':24,'source_queries_unsat':11,'source_lift_instructions':95,'kernel_function_instruction_words':66,'cleanup_bank_inputs':512,'control_pointer_records':9,'pending_cleanup_pointers_checked':4,'symbolic_instruction_visits':2124,'source_read_bytes':1556,'source_write_bytes':816,'authenticated_transfers':76,'symbolic_frame_writes':8,'before_unspecified_frame_or_heap_read':8,'before_dispatcher_epilogue':12,'before_pending_cleanup_call':4}

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)

def no_queries(o):
 if isinstance(o,dict):return{k:no_queries(v)for k,v in o.items()if k!='query'}
 if isinstance(o,list):return[no_queries(v)for v in o]
 return o

def byte_epochs(row,parent,k):
 state={};known=set();counts=Counter();events={};P=R.Parent.Parent.Parent.P
 for a,h in parent['initial_cells'].items():
  for j,b in enumerate(bytes.fromhex(h),int(a,16)):state[j]=b;known.add(j)
 for e in parent['source_writes']:
  for j,b in enumerate(bytes.fromhex(e['after_hex']),int(e['address'],16)):state[j]=b;known.add(j)
 for field,kind in [('source_reads','read'),('source_writes','write')]:
  for e in row[field]:events.setdefault(e['visit'],[]).append((kind,e))
 for visit,i in enumerate(row['source_trace']):
  pc=int(i['pc'],16);assert k.read(pc,4).hex()==i['bytes_hex']==R.IMAGE.read(pc,4).hex();counts['source_words_checked']+=1
  for kind,e in events.get(visit,[]):
   assert e['pc']==i['pc'];a=int(e['address'],16);n=e['size_bytes']
   if kind=='read':
    assert 'bytes_hex'in e
    if P<=a<P+0x20000:assert all(j in known for j in range(a,a+n))
    actual=bytes(state[j]if j in state else R.IMAGE.read(j,1)[0]for j in range(a,a+n));assert actual.hex()==e['bytes_hex'];counts['read_bytes_checked']+=n
   else:
    if 'bytes_hex'in e:
     bs=list(bytes.fromhex(e['bytes_hex']));assert len(bs)==n;counts['concrete_write_bytes_checked']+=n
    else:
     assert e['expression']=='unresolved_frame_word32'and n==4 and e['pc']=='0xfffffe000a5a7318';bs=[('opaque_frame_word',j)for j in range(n)];counts['symbolic_write_bytes_checked']+=n
    for j,b in enumerate(bs,a):state[j]=b;known.add(j)
 for key in ['heap_at_boundary','dispatcher_result_at_boundary']:
  s=row[key];a=int(s['address'],16);n=s['size_bytes'];assert bytes(int(j in known)for j in range(a,a+n)).hex()==s['known_mask_hex']
  for j,t in enumerate(s['terms'],a):
   if j in known:assert t=={'bytes_hex':bytes([state[j]]).hex()}
   else:assert t=={'origin':'unspecified byte; no source definition in retained epoch'}
  counts['snapshot_bytes_checked']+=n
 return counts

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));fresh=R.build();assert no_queries(fresh)==no_queries(e)
 assert e['verified_counts']==COUNTS and e['generator_sha256']==sha(R.__file__)and e['dependencies']=={n:sha(ROOT/n)for n in e['dependencies']}
 for q in e['source_proofs']+[r['source_preallocation_slice']['observable_independence']for r in e['cases']]:
  s=z3.Solver();s.set(timeout=30000);s.from_string(q['query']);assert s.check()==z3.unsat
 prior=json.loads(read(ROOT/'versioned_core_preparation_checks.json'));k=R.Kernel();counts=Counter()
 for row in e['cases']:
  parent=prior['cases'][row['parent_case_index']];counts.update(byte_epochs(row,parent,k));b=row['boundary'];fresh=row['allocation_return_fixture']=='fresh_distinct_object';heap=int(row['heap_at_boundary']['address'],16)
  assert row['allocator_clobbers_declared']==list(range(1,19))and row['carried_word_still_symbolic']and not row['new_guest_executed']and not row['native_target_executed']and row['model_memory_writes']==0
  if not fresh:
   assert b['kind']=='before_dispatcher_epilogue'and not row['scan']and not any(heap<=int(w['address'],16)<heap+32 for w in row['source_writes'])
   assert bytes.fromhex(''.join(t['bytes_hex']for t in row['dispatcher_result_at_boundary']['terms']))==bytes.fromhex('b25b51ce')
  elif row['operand_profile']=='block_bit0':
   assert b['kind']=='before_pending_cleanup_call'and b['pc']=='0xfffffe000a5a7274'and b['target']=='0xfffffe000c4ba368'and b['modifier']=='0x4d6a'and b['X0']=='0xfffffe000847b720'and b['X1']==hex(heap)
   assert [s['byte']for s in row['scan']]==[0xda]and row['heap_at_boundary']['known_mask_hex']=='00'*32
  else:
   assert b['kind']=='before_unspecified_frame_or_heap_read'and b['pc']=='0xfffffe000a5a731c'and b['known_bytes']==0 and int(b['address'],16)==int(parent['boundary']['SP'],16)+0x168
   assert [s['byte']for s in row['scan']]==[0xcd,0xcd,0xcd,0x4d]and [int(s['address'],16)-P for s in row['scan']for P in [R.Parent.Parent.Parent.P+0x1200]]==[15,14,13,12]
   assert row['heap_at_boundary']['known_mask_hex']=='01'*28+'00'*4 and row['symbolic_frame_writes']==1
 assert counts=={'source_words_checked':2124,'read_bytes_checked':1556,'concrete_write_bytes_checked':784,'symbolic_write_bytes_checked':32,'snapshot_bytes_checked':864}
 parent=next(r for r in prior['cases']if r['configuration']['mode32']==2);v=R.Stream(k,parent,'fresh_distinct_object');v.pc=R.Parent.CALL+4
 try:v.load(v.read('x0'),1)
 except R.Frontier:assert v.boundary['kind']=='before_unspecified_frame_or_heap_read'
 else:raise AssertionError('fresh heap was implicitly initialized')
 broken=deepcopy(parent);broken['source_writes']=[w for w in broken['source_writes']if w['pc']!='0xfffffe000a5a6134'];out=R.Stream(k,broken,'fresh_distinct_object').run_stream();assert out['boundary']['pc']=='0xfffffe000a5a6fd0'and out['boundary']['known_bytes']==0
 v=R.Stream(k,parent,'fresh_distinct_object');v.seed('x23',z3.ZeroExt(32,v.opaque));out=v.run_stream();assert out['boundary']['kind']=='before_unknown_dependent_observable'and out['boundary']['pc']=='0xfffffe000a5a7034'
 assert not e['model_memory_writes']and not e['new_guest_executed']and not e['native_target_executed']and not e['full_goal_complete']
 report=read(BASE/'versioned_stream_initialization_report.md');assert all(f'| SI{k} |'in report for k in range(1,8))and all(f'**QG{k}**'in report for k in range(1,8))
 assert all(t in report for t in ['2,124','28 B','0xfffffe000a5a731c','0x472d6e07','0xffff5bd4','0xffff5bd9','unknown'])
 return e,counts

def main():
 e,counts=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
 assert len(before)==len(old['files'])==8603 and len(after)==len(new['files'])==8607
 assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 assert new['validation']['versioned_stream_initialization_increment_checks']==COUNTS and new['validation']['versioned_stream_initialization_static_scope']==e['scope']
 assert new['validation']['reports']==old['validation']['reports']+1==479 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
 path_hygiene(json.dumps(H.paths_in_typed_payloads(e)).encode());fields,extent=H.hex_hygiene(e);path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
 print(json.dumps({'unchanged_manifest_entries':8595,'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':479,'source_equations_unsat':11,'cases':24,'negative_controls_rejected':3,'independent_byte_epochs':dict(counts),'decoded_hex_fields_path_checked':fields,'decoded_hex_bytes_path_checked':extent,'new_guest_executed':False,'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
