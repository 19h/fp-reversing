#!/usr/bin/env python3
"""Audit forked byte epochs, nonvacuous source predicates and publication delta.

O(receipt+owned decoded bytes+manifest) time/space plus 30 s/query. No target,
native lock, API, IDA mutation or Git-history rewrite executes.
"""
import json,subprocess
from pathlib import Path
from hashlib import sha256
from collections import Counter
from compression import zstd
import z3
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_versioned_stream_initialization_publication import no_queries
import verify_corefp_late_preparation_publication as H
import verify_versioned_aes_parameters_publication as A
import recover_versioned_lock_handoff as R
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='6d0e4c18e462df37574b4cfdc3b48db2258330ef'
BASELINE_SHA='151bced669bdcef7f5bd454d2903918ed6ced59f70b494e13499962c90e0ea82'
CHECKS_SHA='98802a68b25b7e78a3f39bd34328f22a1b9c569a09812d04ee2462e181c0eeeb'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','versioned_aes_parameters_report.md','sample_lock_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'versioned_lock_handoff_report.md','triage_evidence/recover_versioned_lock_handoff.py','triage_evidence/verify_versioned_lock_handoff_publication.py','triage_evidence/versioned_lock_handoff_checks.json'}
ARCHIVES={MANIFEST,'triage_evidence/versioned_lock_handoff_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'parent_cases':8,'retained_branches':88,'source_queries_unsat':8,'source_lift_instructions':103,'primitive_bindings':2,'selected_original_routes':8,'source_visits':10584,'source_read_bytes':12416,'source_write_bytes':7584,'authenticated_transfers':200,'source_returns':48,'unique_observables_proved':64}
GUEST=R.Parent.Parent.GUEST
SNAPSHOTS=['input_stream_at_boundary','output_stream_at_boundary','record_at_boundary','caller_delta_cell','private_header','parameters_at_boundary','lock_record_at_boundary','job_delta_cell','job_private_header']

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)
def tokens(expr,n):
 if expr=='cached_rw_lock_cell64':assert n==8;return[f'((_ extract {8*j+7} {8*j}) cached_rw_lock_cell64)'for j in range(8)]
 return A.tokens(expr,n)
def predicates(expressions):
 return z3.parse_smt2_string('\n'.join('(assert '+p+')'for p in expressions),decls={'startup_lock_cell64':R.L,'cached_rw_lock_cell64':R.G})
def epochs(row,state,known,k):
 state=dict(state);known=set(known);events={};counts=Counter()
 ps=predicates(row['predicate_expressions']);s=z3.Solver();s.set(timeout=30000);s.add(*ps);assert s.check()==z3.sat
 for q in row['unique_observable_proofs']:
  assert q['predicate_expressions']==row['predicate_expressions']and q['width_bits']==64 and q['result']=='unsat'
  t=z3.Solver();t.set(timeout=30000);t.from_string(q['query']);assert t.check()==z3.unsat
  literal='#x'+format(int(q['value'],16),'016x');term=z3.parse_smt2_string('(assert (= '+q['expression']+' '+literal+'))',decls={'startup_lock_cell64':R.L,'cached_rw_lock_cell64':R.G})[0]
  t=z3.Solver();t.set(timeout=30000);t.add(*ps,z3.Not(term));assert t.check()==z3.unsat;counts['unique_observables_rebuilt']+=1
 for key,kind in [('source_reads','read'),('source_writes','write')]:
  for e in row[key]:assert 0<=e['visit']<len(row['source_trace']);events.setdefault(e['visit'],[]).append((kind,e))
 for ix,i in enumerate(row['source_trace']):
  pc=int(i['pc'],16);assert k.read(pc,4).hex()==i['bytes_hex']==R.Parent.Parent.Parent.IMAGE.read(pc,4).hex();counts['source_words_checked']+=1
  for p in row['discarded_probe_reads']:
   if p['visit']==ix:assert p['pc']==i['pc']=='0xfffffe000a5a1cf0'and p['source_defined']==(int(p['address'],16)in known)and p['architectural_destination']=='WZR'and p['readability_assumed'];counts['discarded_probe_bytes_checked']+=1
  for kind,e in events.get(ix,[]):
   assert e['pc']==i['pc'];a=int(e['address'],16);n=e['size_bytes'];expected=list(bytes.fromhex(e['bytes_hex']))if 'bytes_hex'in e else tokens(e['expression'],n)
   if kind=='write':
    assert not(a<GUEST+0x1800 and a+n>GUEST+0x1600)
    for j,b in enumerate(expected,a):state[j]=b;known.add(j)
    counts['write_bytes_checked']+=n;counts['symbolic_write_bytes_checked']+=sum(isinstance(b,str)for b in expected);continue
   if a==R.Parent.Parent.GUARD:assert n==8;bs=tokens('kernel_stack_guard64',8)
   elif a==R.CACHED:assert e['pc']==hex(R.CACHED_READ)and n==8;bs=tokens('cached_rw_lock_cell64',8)
   else:
    bs=[]
    for j in range(a,a+n):
     if GUEST<=j<GUEST+0x20000:assert j in known,('unspecified private read',i['pc'],hex(j))
     bs.append(state[j]if j in state else R.Parent.Parent.Parent.IMAGE.read(j,1)[0])
   assert bs==expected,(i['pc'],hex(a));p=e.get('original_pointer_fixup')
   if p is not None:assert p==R.Parent.Parent.Parent.pointer(k,a)
   counts['read_bytes_checked']+=n;counts['symbolic_read_bytes_checked']+=sum(isinstance(b,str)for b in bs)
 for edge in row['source_transfers']:
  assert edge['original_pointer']==R.Parent.Parent.Parent.pointer(k,int(edge['original_pointer']['slot'],16));assert edge['original_pointer']['target']==edge['target'];counts['authenticated_edges_checked']+=1
 for key in SNAPSHOTS:
  if key not in row:continue
  snap=row[key];a=int(snap['address'],16);n=snap['size_bytes'];assert snap['known_mask_hex']==bytes(int(j in known)for j in range(a,a+n)).hex()
  for j,t in enumerate(snap['terms'],a):
   if j not in known:assert t=={'origin':'unspecified byte; no source definition in retained epoch'}
   elif isinstance(state[j],int):assert t=={'bytes_hex':bytes([state[j]]).hex()}
   else:assert t=={'expression':state[j]}
  counts['snapshot_bytes_checked']+=n
 for ret in row['source_returns']:assert ret['SP']==ret['entry_SP']
 assert row['all_selected_observables_concrete']and not row['boundary']['instruction_executed']
 assert not any(row[n]for n in ['native_lock_executed','new_guest_executed','native_target_executed','allocator_model_memory_writes','output_B_bytes_written'])
 return state,known,counts

def receipts(fresh=True):
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA;e=json.loads(read(ROOT/(R.P+'_checks.json')))
 if fresh:assert no_queries(R.build())==no_queries(e)
 assert e['verified_counts']==COUNTS and e['generator_sha256']==sha(R.__file__)and e['dependencies']=={n:sha(ROOT/n)for n in e['dependencies']};assert e['prior_context_sha256']=={n:sha(ROOT/n)for n in e['prior_context_sha256']}
 for q in e['source_proofs']:
  s=z3.Solver();s.set(timeout=30000);s.from_string(q['query']);assert s.check()==z3.unsat
 old=json.loads(read(ROOT/'versioned_inner_entry_checks.json'));param=json.loads(read(ROOT/'versioned_aes_parameters_checks.json'));prep=json.loads(read(ROOT/'versioned_core_preparation_checks.json'));words=json.loads(read(ROOT/'versioned_stream_words_checks.json'));out=json.loads(read(ROOT/'versioned_output_stream_checks.json'));k=R.Parent.Parent.Parent.Kernel();count=Counter()
 for case in e['cases']:
  ix=case['parent_case_index'];previous=next(c for c in old['cases']if c['parent_case_index']==ix);p=prep['cases'][ix];w=next(c for c in words['cases']if c['parent_case_index']==ix);o=next(c for c in out['cases']if c['parent_case_index']==ix and c['allocation_return_fixture']=='fresh_distinct_object');ap=next(c for c in param['cases']if c['parent_case_index']==ix and c['allocation_return_fixture']=='fresh_distinct_object');state={};known=set()
  for a,h in p['initial_cells'].items():
   for j,b in enumerate(bytes.fromhex(h),int(a,16)):state[j]=b;known.add(j)
  for b in [p,w,o]:
   for x in b['source_writes']:A.V.write(state,known,x)
  state,known,_=A.V.epochs(previous['strict_prefix'],state,known,k);state,known,_=A.V.epochs(previous['continuations'][0],state,known,k,0);state,known,_=A.epochs(ap,state,known,k);state,known,_=A.epochs(ap['lock_origin_continuation'],state,known,k)
  branches=case['branches'];states={'base':(state,known)};parents={'strict_wrapper_prefix':'base','explicit_nonnull':'strict_wrapper_prefix','mutex_void_return':'explicit_nonnull','mutex_job_prefix':'mutex_void_return','explicit_null':'strict_wrapper_prefix','strict_cached_origin_prefix':'explicit_null','cached_nonnull':'strict_cached_origin_prefix','rw_void_return':'cached_nonnull','rw_job_prefix':'rw_void_return','cached_null':'strict_cached_origin_prefix','no_primitive_job_prefix':'cached_null'}
  expected_visits=[97,23,55,327,26,8,23,55,327,55,327];assert list(branches)==list(parents)
  for (name,parent),visits in zip(parents.items(),expected_visits):
   row=branches[name];assert len(row['source_trace'])==visits;ss,kk,c=epochs(row,*states[parent],k);states[name]=(ss,kk);count.update(c);assert row['parameters_at_boundary']==ap['parameters_at_boundary']
  assert branches['strict_wrapper_prefix']['boundary']['pc']==hex(R.GATE)and not branches['strict_wrapper_prefix']['predicate_expressions']
  for name,target in [('explicit_nonnull',0xfffffe000a508dd4),('cached_nonnull',0xfffffe000a508d94)]:
   row=branches[name];assert row['boundary']['target']==hex(target)and row['boundary']['X0']=={'expression':'startup_lock_cell64'if name=='explicit_nonnull'else 'cached_rw_lock_cell64'}
  for name in ['mutex_void_return','rw_void_return']:
   premise=branches[name]['void_primitive_return_premise'];assert premise['registers_clobbered']==list(range(19))and premise['model_memory_effects']==0 and not premise['native_acquisition_established']
  for name in ['mutex_void_return','rw_void_return','cached_null']:assert branches[name]['boundary']['pc']==hex(R.JOB_CALL)and branches[name]['boundary']['target']==hex(R.JOB_ADAPTER)
  for name in ['mutex_job_prefix','rw_job_prefix','no_primitive_job_prefix']:
   row=branches[name];assert row['boundary']['pc']=='0xfffffe000a6881dc'and row['boundary']['target']=='0xfffffe000a508030'and len(row['discarded_probe_reads'])==1
   a=int(ap['declared_distinct_object'],16);reads=[r for r in row['source_reads']if a<=int(r['address'],16)<a+104];assert[(int(r['address'],16)-a,r['size_bytes'],r['bytes_hex'])for r in reads]==[(0x28,4,'00100000'),(0x24,4,'00000000')]
   assert row['job_private_header']['terms']==[{'bytes_hex':f'{b:02x}'}for b in bytes.fromhex('f1ca777cde8895e3')]
   assert row['lock_record_at_boundary']['terms'][8:12]==ap['lock_origin_continuation']['lock_record_at_boundary']['terms'][8:12]
  for key in ['source_trace','source_reads','source_writes','boundary','job_private_header','job_delta_cell']:
   assert branches['mutex_job_prefix'][key]==branches['rw_job_prefix'][key]==branches['no_primitive_job_prefix'][key]
 assert count['source_words_checked']==COUNTS['source_visits']and count['read_bytes_checked']==COUNTS['source_read_bytes']and count['write_bytes_checked']==COUNTS['source_write_bytes']and count['authenticated_edges_checked']==COUNTS['authenticated_transfers']and count['unique_observables_rebuilt']==64
 report=read(BASE/'versioned_lock_handoff_report.md');assert all(f'| LH{j} |'in report for j in range(1,8))and all(f'**QG{j}**'in report for j in range(1,8))
 return e,count

def main():
 e,count=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
 assert len(before)==8623 and len(after)==8627 and not before.keys()-after.keys()and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 assert new['validation']['versioned_lock_handoff_increment_checks']==COUNTS and new['validation']['versioned_lock_handoff_static_scope']==e['scope']
 assert new['validation']['reports']==old['validation']['reports']+1==484 and new['goal_status']=='active'and new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
 path_hygiene(json.dumps(H.paths_in_typed_payloads(e)).encode());fields,extent=H.hex_hygiene(e);path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
 print(json.dumps({'unchanged_manifest_entries':8614,'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':484,'source_queries_unsat':8,'independent_byte_epochs':dict(count),'decoded_hex_fields_path_checked':fields,'decoded_hex_bytes_path_checked':extent,'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
