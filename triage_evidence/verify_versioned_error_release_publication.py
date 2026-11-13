#!/usr/bin/env python3
"""Independent release/retirement byte epochs and exact publication audit.

O(receipt+owned decoded bytes+manifest) time/space plus 30 s/query. No native
unlock/free/IPC, guest, IDA mutation or Git-history rewrite executes.
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
import verify_versioned_hardware_admission_publication as A
import recover_versioned_error_release as R
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='b9adb2e325461bd6b583ca1e62c489c6f43896c4'
BASELINE_SHA='7faf76a16e6b029fa048f56e26a8913f1650aeca3bd3198392421519e9b78314'
CHECKS_SHA='f1776efe92cb22fe7f829ea4764407864bfc0fb779e4a7b2b1e1b6e64f3bcedd';MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','versioned_hardware_admission_report.md','sample_lock_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'versioned_error_release_report.md','triage_evidence/recover_versioned_error_release.py','triage_evidence/verify_versioned_error_release_publication.py','triage_evidence/versioned_error_release_checks.json'}
ARCHIVES={MANIFEST,'triage_evidence/versioned_error_release_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES};COUNTS={'parent_cases': 8, 'retained_intervals': 96, 'source_queries_unsat': 6, 'source_lift_instructions': 65, 'source_visits': 20856, 'authenticated_transfers': 672, 'source_returns': 40, 'unique_observables_proved': 96, 'source_read_bytes': 17496, 'source_write_bytes': 5408}
GUEST=A.GUEST;DECLS={**A.DECLS,'post_operation_lock64':R.E,'post_operation_cached_lock64':R.G}
SNAPSHOTS=A.SNAPSHOTS+['local_constant_at_boundary','auxiliary_parameter_cell','dispatcher_result_at_boundary']
def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)
def predicates(expressions):return z3.parse_smt2_string('\n'.join('(assert '+p+')'for p in expressions),decls=DECLS)
def tokens(expr,n):
 if expr in ['post_operation_lock64','post_operation_cached_lock64']:assert n==8;return[f'((_ extract {8*j+7} {8*j}) {expr})'for j in range(8)]
 return A.tokens(expr,n)
def epochs(row,state,known,k,retired):
 state=dict(state);known=set(known);events={};counts=Counter();ps=predicates(row['predicate_expressions']);s=z3.Solver();s.set(timeout=30000);s.add(*ps);assert s.check()==z3.sat
 for q in row['unique_observable_proofs']:
  assert q['predicate_expressions']==row['predicate_expressions']and q['result']=='unsat';width=q['width_bits'];assert width==64
  t=z3.Solver();t.set(timeout=30000);t.from_string(q['query']);assert t.check()==z3.unsat
  literal='#x'+format(int(q['value'],16),'016x');term=z3.parse_smt2_string('(assert (= '+q['expression']+' '+literal+'))',decls=DECLS)[0];t=z3.Solver();t.set(timeout=30000);t.add(*ps,z3.Not(term));assert t.check()==z3.unsat;counts['unique_observables_rebuilt']+=1
 for key,kind in [('source_reads','read'),('source_writes','write')]:
  for e in row[key]:assert 0<=e['visit']<len(row['source_trace']);events.setdefault(e['visit'],[]).append((kind,e))
 for ix,i in enumerate(row['source_trace']):
  pc=int(i['pc'],16);assert k.read(pc,4).hex()==i['bytes_hex']==R.Parent.Parent.Parent.Parent.Parent.IMAGE.read(pc,4).hex();counts['source_words_checked']+=1
  for kind,e in events.get(ix,[]):
   assert e['pc']==i['pc'];a=int(e['address'],16);n=e['size_bytes'];assert not any(a<z and a+n>b for b,z in retired);expected=list(bytes.fromhex(e['bytes_hex']))if 'bytes_hex'in e else tokens(e['expression'],n)
   if kind=='write':
    assert not(a<GUEST+0x1800 and a+n>GUEST+0x1600)
    for j,b in enumerate(expected,a):state[j]=b;known.add(j)
    counts['write_bytes_checked']+=n;counts['symbolic_write_bytes_checked']+=sum(isinstance(b,str)for b in expected);continue
   if e['pc']in [hex(R.READ),hex(R.CACHE_READ)]:assert(a,n)==(R.LOCK if e['pc']==hex(R.READ)else R.CACHED,8);bs=tokens('post_operation_lock64'if e['pc']==hex(R.READ)else 'post_operation_cached_lock64',8)
   elif a==R.Parent.Parent.Parent.Parent.GUARD:assert n==8;bs=tokens('kernel_stack_guard64',8)
   else:
    bs=[]
    for j in range(a,a+n):
     if GUEST<=j<GUEST+0x20000:assert j in known,('unspecified private read',i['pc'],hex(j))
     bs.append(state[j]if j in state else R.Parent.Parent.Parent.Parent.Parent.IMAGE.read(j,1)[0])
   assert bs==expected,(i['pc'],hex(a));p=e.get('original_pointer_fixup')
   if p is not None:assert p==R.Parent.Parent.Parent.Parent.Parent.pointer(k,a)
   counts['read_bytes_checked']+=n;counts['symbolic_read_bytes_checked']+=sum(isinstance(b,str)for b in bs)
 for edge in row['source_transfers']:
  assert edge['original_pointer']==R.Parent.Parent.Parent.Parent.Parent.pointer(k,int(edge['original_pointer']['slot'],16));assert edge['original_pointer']['target']==edge['target'];counts['authenticated_edges_checked']+=1
 for key in SNAPSHOTS:
  snap=row[key];a=int(snap['address'],16);n=snap['size_bytes'];assert snap['known_mask_hex']==bytes(int(j in known)for j in range(a,a+n)).hex()
  for j,t in enumerate(snap['terms'],a):
   if j not in known:assert t=={'origin':'unspecified byte; no source definition in retained epoch'}
   elif isinstance(state[j],int):assert t=={'bytes_hex':bytes([state[j]]).hex()}
   else:assert t=={'expression':state[j]}
  counts['snapshot_bytes_checked']+=n
 for ret in row['source_returns']:assert ret['SP']==ret['entry_SP']
 assert row['all_selected_observables_concrete']and not row['boundary']['instruction_executed']and not row['discarded_probe_reads']
 assert not any(row[n]for n in ['native_lock_executed','new_guest_executed','native_target_executed','allocator_model_memory_writes','output_B_bytes_written'])
 return state,known,counts

def receipts(fresh=True):
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA;e=json.loads(read(ROOT/(R.P+'_checks.json')))
 if fresh:assert no_queries(R.build())==no_queries(e)
 assert e['verified_counts']==COUNTS and e['generator_sha256']==sha(R.__file__)and e['dependencies']=={n:sha(ROOT/n)for n in e['dependencies']}
 for q in e['source_proofs']:
  s=z3.Solver();s.set(timeout=30000);s.from_string(q['query']);assert s.check()==z3.unsat
 old=json.loads(read(ROOT/'versioned_hardware_admission_checks.json'));hand=json.loads(read(ROOT/'versioned_lock_handoff_checks.json'));k=R.Parent.Parent.Parent.Parent.Parent.Kernel();count=Counter()
 parents={'fresh_release_origin':'base','release_wrapper_prefix':'fresh_release_origin','explicit_nonnull':'release_wrapper_prefix','mutex_void_return':'explicit_nonnull','explicit_null':'release_wrapper_prefix','fresh_cached_origin':'explicit_null','cached_nonnull':'fresh_cached_origin','rw_void_return':'cached_nonnull','cached_null':'fresh_cached_origin','parameter_retirement_return':'cached_null','output_retirement_return':'parameter_retirement_return','input_retirement_return':'output_retirement_return'}
 for case in e['cases']:
  ix=case['parent_case_index'];state,known,ap,_=A.base_state(ix,hand,k);ha=next(c for c in old['cases']if c['parent_case_index']==ix)
  for name in ['strict_initializer_prefix','arbitrary_readiness_origin','cold_matching_request','matching_return','wait_return','provider_absent']:state,known,_=A.epochs(ha['branches'][name],state,known,k)
  states={'base':(state,known)};b=case['branches'];assert list(b)==list(parents);h1=int(ap['input_stream_at_boundary']['address'],16);h2=h1+0x200;h3=int(ap['declared_distinct_object'],16)
  retired=[]
  for(name,up),visits in zip(parents.items(),[45,111,24,43,28,8,19,43,43,1164,1061,18]):
   if name=='parameter_retirement_return':retired=[(h3,h3+104)]
   if name=='output_retirement_return':retired.append((h2,h2+32))
   if name=='input_retirement_return':retired.append((h1,h1+32))
   row=b[name];assert len(row['source_trace'])==visits and row['logical_retired_spans']==[{'start':hex(a),'end':hex(z)}for a,z in retired];ss,kk,c=epochs(row,*states[up],k,retired);states[name]=(ss,kk);count.update(c);assert row['parameters_at_boundary']==ap['parameters_at_boundary']
  assert b['fresh_release_origin']['boundary']['pc']==hex(R.CALL)and b['fresh_release_origin']['boundary']['target']==hex(R.RELEASE)and b['release_wrapper_prefix']['boundary']['pc']==hex(R.GATE)
  for name,target,origin in [('explicit_nonnull',0xfffffe000a508de4,'post_operation_lock64'),('cached_nonnull',0xfffffe000a508d9c,'post_operation_cached_lock64')]:assert b[name]['boundary']['target']==hex(target)and b[name]['boundary']['X0']=={'expression':origin}
  assert b['explicit_null']['boundary']['pc']==hex(R.CACHE_READ)and b['fresh_cached_origin']['boundary']['pc']==hex(R.CACHE_GATE)
  for name in ['mutex_void_return','rw_void_return','cached_null']:
   event=b[name]['boundary'];assert event['pc']==hex(R.PARAM_FREE)and event['target']=='0xfffffe000c4ba368'and event['X0']=={'bytes_hex':'a0b3470800feffff'}and event['X1']=={'bytes_hex':h3.to_bytes(8,'little').hex()}
  for name,ptr in [('parameter_retirement_return',h2),('output_retirement_return',h1)]:
   event=b[name]['boundary'];assert event['pc']=='0xfffffe000a5a92e4'and event['target']=='0xfffffe000c4ba368'and event['X0']=={'bytes_hex':'a0bb470800feffff'}and event['X1']=={'bytes_hex':ptr.to_bytes(8,'little').hex()}
   writes=[w for w in b[name]['source_writes']if ptr<=int(w['address'],16)<ptr+32];assert [int(w['address'],16)for w in writes]==list(reversed(range(ptr,ptr+32)))and all(w['size_bytes']==1 for w in writes);count['stream_overwrite_bytes_checked']+=32
  for name in ['mutex_void_return','rw_void_return','parameter_retirement_return','output_retirement_return','input_retirement_return']:
   premise=b[name]['ordinary_void_return_premise'];assert premise['registers_clobbered']==list(range(19))and premise['model_memory_effects']==0 and not premise['native_API_executed']
  status=[{'bytes_hex':f'{x:02x}'}for x in bytes.fromhex('385a51ce')]
  for name in ['parameter_retirement_return','output_retirement_return','input_retirement_return']:assert b[name]['record_at_boundary']['terms'][32:36]==status and b[name]['auxiliary_parameter_cell']['terms']==[{'bytes_hex':f'{x:02x}'}for x in h3.to_bytes(8,'little')]
  assert b['input_retirement_return']['dispatcher_result_at_boundary']['terms']==status and b['input_retirement_return']['boundary']=={'kind':'before_dispatcher_epilogue','pc':'0xfffffe000a5a729c','instruction_executed':False}
  pub=[w for w in b['parameter_retirement_return']['source_writes']if w['pc']=='0xfffffe000a69b228'];assert len(pub)==1 and pub[0]['address']==hex(GUEST+0xc270)and pub[0]['bytes_hex']==h3.to_bytes(8,'little').hex()
  for name,prior in [('output_retirement_return','parameter_retirement_return'),('input_retirement_return','output_retirement_return')]:
   historical=b[name]['historical_pointer_origins'];assert len(historical)==1;v=historical[0];o=v['origin'];assert v['pc']=='0xfffffe000a5a9320'and o['read_pc']=='0xfffffe000a5a90fc'
   assert any(r['pc']==o['read_pc']and r['address']==o['read_address']and r['original_pointer_fixup']==o['original_pointer']for r in b[prior]['source_reads']);assert o['original_pointer']['target']==v['target'];count['historical_pointer_origins_checked']+=1
 for ck,tk in [('source_words_checked','source_visits'),('read_bytes_checked','source_read_bytes'),('write_bytes_checked','source_write_bytes'),('authenticated_edges_checked','authenticated_transfers'),('unique_observables_rebuilt','unique_observables_proved')]:assert count[ck]==COUNTS[tk]
 report=read(BASE/'versioned_error_release_report.md');assert all(f'| ER{j} |'in report for j in range(1,8))and all(f'**QG{j}**'in report for j in range(1,8))
 return e,count

def main():
 e,count=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA;old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
 assert len(before)==8631 and len(after)==8635 and not before.keys()-after.keys()and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 assert new['validation']['versioned_error_release_increment_checks']==COUNTS and new['validation']['versioned_error_release_static_scope']==e['scope'];assert new['validation']['reports']==old['validation']['reports']+1==486 and new['goal_status']=='active'and new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
 path_hygiene(json.dumps(H.paths_in_typed_payloads(e)).encode());fields,extent=H.hex_hygiene(e);path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
 print(json.dumps({'unchanged_manifest_entries':8622,'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':486,'source_queries_unsat':6,'independent_byte_epochs':dict(count),'decoded_hex_fields_path_checked':fields,'decoded_hex_bytes_path_checked':extent,'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
