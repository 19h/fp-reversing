#!/usr/bin/env python3
"""Fresh source equations, independent byte epochs and exact publication audit.

O(receipt+source+owned decoded bytes+manifest) time/space plus 30 s/query.
No native operation, IDA mutation, guest execution or history rewrite.
"""
import json,subprocess
from pathlib import Path
from hashlib import sha256
from collections import Counter
from compression import zstd
import z3
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
import verify_corefp_late_preparation_publication as H
from verify_versioned_stream_initialization_publication import no_queries
from verify_versioned_stream_words_publication import tokens
import recover_versioned_output_stream as R
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='e16166be8eec3fdc7ef89b5023b77c18d69470af'
BASELINE_SHA='b3fea960b498c12ff4197e8290af06a0369c11bb1994c24e41b59f84265728af'
CHECKS_SHA='be9917579a29d521f1608f69db5ee89823d24bab35006af9e80bcb4f4754ec54'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','versioned_stream_words_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'versioned_output_stream_report.md','triage_evidence/recover_versioned_output_stream.py','triage_evidence/verify_versioned_output_stream_publication.py','triage_evidence/versioned_output_stream_checks.json'}
ARCHIVES={MANIFEST,'triage_evidence/versioned_output_stream_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'cases':16,'source_queries_unsat':27,'source_lift_instructions':198,'adapter_instruction_words':139,'inner_prefix_instruction_words':90,'adapter_bank_inputs':1280,'new_source_visits':10064,'source_read_bytes':6688,'source_write_bytes':3424,'authenticated_transfers':296,'before_private_stack_adapter':8,'before_input_stream_free_after_null_second_allocation':8}

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)

def byte_epochs(row,parent,reader,k):
 state={};known=set();events={};count=Counter();orig={int(o['address'],16):o['symbol']for o in reader['frame_byte_origins']}
 def publish(e,old=False):
  a=int(e['address'],16);n=e.get('size_bytes',len(e.get('after_hex',''))//2)
  bs=list(bytes.fromhex(e.get('bytes_hex',e.get('after_hex',''))))if 'expression'not in e else tokens(e['expression'],n)
  assert len(bs)==n
  for j,b in enumerate(bs,a):state[j]=b;known.add(j)
  return bs
 for a,h in parent['initial_cells'].items():
  for j,b in enumerate(bytes.fromhex(h),int(a,16)):state[j]=b;known.add(j)
 for e in parent['source_writes']:publish(e)
 for e in reader['source_writes']:publish(e)
 for key,kind in [('source_reads','read'),('source_writes','write')]:
  for e in row[key]:events.setdefault(e['visit'],[]).append((kind,e))
 for ix,i in enumerate(row['source_trace']):
  pc=int(i['pc'],16);assert k.read(pc,4).hex()==i['bytes_hex']==R.IMAGE.read(pc,4).hex();count['source_words_checked']+=1
  for kind,e in events.get(ix,[]):
   assert e['pc']==i['pc'];a=int(e['address'],16);n=e['size_bytes']
   if kind=='read':
    bs=[]
    for j in range(a,a+n):
     if R.GUEST<=j<R.GUEST+0x20000:assert j in known,('new unspecified read',i['pc'],hex(j))
     bs.append(state[j]if j in state else R.IMAGE.read(j,1)[0])
    expected=list(bytes.fromhex(e['bytes_hex']))if 'bytes_hex'in e else tokens(e['expression'],n);assert expected==bs
    count['read_bytes_checked']+=n;count['symbolic_read_bytes_checked']+=sum(isinstance(b,str)for b in bs)
   else:
    bs=publish(e);count['write_bytes_checked']+=n;count['symbolic_write_bytes_checked']+=sum(isinstance(b,str)for b in bs)
 for key in ['input_stream_at_boundary','output_stream_at_boundary','reused_record_at_boundary']:
  s=row[key];a=int(s['address'],16);n=s['size_bytes'];assert bytes(int(j in known)for j in range(a,a+n)).hex()==s['known_mask_hex']
  for j,t in enumerate(s['terms'],a):
   if j in known:
    if isinstance(state[j],int):assert t=={'bytes_hex':bytes([state[j]]).hex()}
    else:assert t=={'expression':state[j]}
   else:assert t=={'origin':'unspecified byte; no source definition in retained epoch'}
  count['snapshot_bytes_checked']+=n
 return count

def receipts(fresh=True):
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA;e=json.loads(read(ROOT/(R.P+'_checks.json')))
 if fresh:assert no_queries(R.build())==no_queries(e)
 assert e['verified_counts']==COUNTS and e['generator_sha256']==sha(R.__file__)and e['dependencies']=={n:sha(ROOT/n)for n in e['dependencies']}
 for q in e['source_proofs']:
  s=z3.Solver();s.set(timeout=30000);s.from_string(q['query']);assert s.check()==z3.unsat
 parent=json.loads(read(ROOT/'versioned_core_preparation_checks.json'));old=json.loads(read(ROOT/'versioned_stream_words_checks.json'));k=R.Kernel();counts=Counter()
 for row in e['cases']:
  reader=next(r for r in old['cases']if r['parent_case_index']==row['parent_case_index']);counts.update(byte_epochs(row,parent['cases'][row['parent_case_index']],reader,k));success=row['allocation_return_fixture']=='fresh_distinct_object'
  assert len(row['source_trace'])==(187 if success else 1071)and not row['new_origin_bytes']and row['all_selected_observables_concrete']
  assert row['boundary']['pc']==hex(R.CALL if success else R.PENDING_FREE)and not row['boundary']['instruction_executed']
  H2=int(row['declared_distinct_object'],16);H1=H2-0x200
  stores=[s for s in row['source_writes']if H1<=int(s['address'],16)<H1+32]
  if success:
   assert not stores
   s=row['output_stream_at_boundary'];assert s['known_mask_hex']=='01'*28+'00'*4
   b=bytes.fromhex(''.join(t['bytes_hex']for t in s['terms'][:28]));assert b==((R.GUEST+0x1600).to_bytes(8,'little')+bytes.fromhex('622b92e61164491347aa690c344c90bd6600ae31'))
   assert row['boundary']['target']==hex(R.ADAPTER)and row['boundary']['modifier']=='0x2bbe'
  else:
   assert len(stores)==32 and all(s['size_bytes']==1 and s['pc']=='0xfffffe000a5a921c'for s in stores)
   assert [int(s['address'],16)-H1 for s in stores]==list(range(31,-1,-1))
   assert row['input_stream_at_boundary']['known_mask_hex']=='01'*32 and row['output_stream_at_boundary']['known_mask_hex']=='00'*32
   assert row['boundary']['target']=='0xfffffe000c4ba368'
  assert not row['output_B_bytes_written']and not row['model_memory_writes']and not row['new_guest_executed']and not row['native_target_executed']
 assert e['last_function_boundary']=={'last_LC_FUNCTION_STARTS_entry':hex(R.ADAPTER),'text_end':hex(R.END),'auth_stubs_start':hex(R.END)}
 assert len(e['adapter_source']['instructions'])==139 and len(bytes.fromhex(e['adapter_source']['bytes_hex']))==556
 assert e['inner_call_pointer']['target']==hex(R.INNER)and e['inner_call_pointer']['diversity']=='0x4d6a'
 assert [r['target']for r in e['adapter_bank_rules']]==['0xfffffe000ccc30dc','0xfffffe000ccc32fc','0xfffffe000ccc32f4',hex(R.INNER),'0xfffffe0008472f2c']
 assert(e['null_cleanup_type_view']['name'],e['null_cleanup_type_view']['size_bytes'])==('site.FPByteArrayStreamInternal',32)
 assert not any(e[n]for n in ['full_inner_header_preservation_proved','actual_adapter_delta_proved_zero','output_B_bytes_written','model_memory_writes','new_guest_executed','native_target_executed','full_goal_complete'])
 assert dict(counts)=={'source_words_checked':10064,'read_bytes_checked':6688,'write_bytes_checked':3424,'snapshot_bytes_checked':2304,'symbolic_read_bytes_checked':64,'symbolic_write_bytes_checked':32}
 report=read(BASE/'versioned_output_stream_report.md');assert all(f'| OS{k} |'in report for k in range(1,8))and all(f'**QG{k}**'in report for k in range(1,8))
 return e,counts

def main():
 e,count=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
 assert len(before)==8611 and len(after)==8615 and not before.keys()-after.keys()and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 assert new['validation']['versioned_output_stream_increment_checks']==COUNTS and new['validation']['versioned_output_stream_static_scope']==e['scope']
 assert new['validation']['reports']==old['validation']['reports']+1==481 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
 path_hygiene(json.dumps(H.paths_in_typed_payloads(e)).encode());fields,extent=H.hex_hygiene(e);path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
 print(json.dumps({'unchanged_manifest_entries':8603,'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':481,'source_queries_unsat':len(e['source_proofs']),'cases':16,'independent_byte_epochs':dict(count),'decoded_hex_fields_path_checked':fields,'decoded_hex_bytes_path_checked':extent,'native_API_executed':False,'new_guest_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
