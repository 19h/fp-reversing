#!/usr/bin/env python3
"""Independent byte-epoch, solver, source identity and publication audit.

O(receipt+owned decoded bytes+manifest) time/space plus 30 s/query. Original
files are read only; no native APIs, guest, IDA or history rewrite executes.
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
import verify_versioned_lock_handoff_publication as A
import recover_versioned_hardware_admission as R
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='fa5a5d0aacfb51835b99b10f09363a94f359731c'
BASELINE_SHA='3f4c5f5ebb46db19d60e1ccf6ee4c2ed0b8bc33e761d6aa34d93ae900284b1d7'
CHECKS_SHA='bc9265d25e394e365d782d7cbbab9520eb8852b3298bf26dc0486659f347e81e'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','versioned_lock_handoff_report.md','kext_cold_init_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'versioned_hardware_admission_report.md','triage_evidence/recover_versioned_hardware_admission.py','triage_evidence/verify_versioned_hardware_admission_publication.py','triage_evidence/versioned_hardware_admission_checks.json'}
ARCHIVES={MANIFEST,'triage_evidence/versioned_hardware_admission_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'parent_cases': 8, 'retained_intervals': 72, 'source_queries_unsat': 3, 'source_lift_instructions': 18, 'source_visits': 1936, 'authenticated_transfers': 48, 'source_returns': 40, 'unique_observables_proved': 32, 'source_read_bytes': 3184, 'source_write_bytes': 2080}
GUEST=A.GUEST
DECLS={'startup_lock_cell64':R.Parent.L,'cached_rw_lock_cell64':R.Parent.G,'aes_readiness_byte8':R.F,'matching_result64':R.M,'wait_service_result64':R.S}
SNAPSHOTS=A.SNAPSHOTS+['provider_cell','initializer_timeout']
def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)
def predicates(expressions):return z3.parse_smt2_string('\n'.join('(assert '+p+')'for p in expressions),decls=DECLS)
def tokens(expr,n):
 if expr=='aes_readiness_byte8':assert n==1;return[expr]
 if expr=='wait_service_result64':assert n==8;return[f'((_ extract {8*j+7} {8*j}) wait_service_result64)'for j in range(8)]
 return A.tokens(expr,n)
def epochs(row,state,known,k):
 state=dict(state);known=set(known);events={};counts=Counter();ps=predicates(row['predicate_expressions']);s=z3.Solver();s.set(timeout=30000);s.add(*ps);assert s.check()==z3.sat
 for q in row['unique_observable_proofs']:
  assert q['predicate_expressions']==row['predicate_expressions']and q['result']=='unsat';width=q['width_bits'];assert width in [8,64]
  t=z3.Solver();t.set(timeout=30000);t.from_string(q['query']);assert t.check()==z3.unsat
  literal='#x'+format(int(q['value'],16),'0'+str(width//4)+'x');term=z3.parse_smt2_string('(assert (= '+q['expression']+' '+literal+'))',decls=DECLS)[0]
  t=z3.Solver();t.set(timeout=30000);t.add(*ps,z3.Not(term));assert t.check()==z3.unsat;counts['unique_observables_rebuilt']+=1
 for key,kind in [('source_reads','read'),('source_writes','write')]:
  for e in row[key]:assert 0<=e['visit']<len(row['source_trace']);events.setdefault(e['visit'],[]).append((kind,e))
 for ix,i in enumerate(row['source_trace']):
  pc=int(i['pc'],16);assert k.read(pc,4).hex()==i['bytes_hex']==R.Parent.Parent.Parent.Parent.IMAGE.read(pc,4).hex();counts['source_words_checked']+=1
  for kind,e in events.get(ix,[]):
   assert e['pc']==i['pc'];a=int(e['address'],16);n=e['size_bytes'];expected=list(bytes.fromhex(e['bytes_hex']))if 'bytes_hex'in e else tokens(e['expression'],n)
   if kind=='write':
    assert not(a<GUEST+0x1800 and a+n>GUEST+0x1600)
    for j,b in enumerate(expected,a):state[j]=b;known.add(j)
    counts['write_bytes_checked']+=n;counts['symbolic_write_bytes_checked']+=sum(isinstance(b,str)for b in expected);continue
   if a==R.FLAG:assert e['pc']==hex(R.FLAG_READ)and n==1;bs=tokens('aes_readiness_byte8',1)
   elif a==R.Parent.Parent.Parent.GUARD:assert n==8;bs=tokens('kernel_stack_guard64',8)
   else:
    bs=[]
    for j in range(a,a+n):
     if GUEST<=j<GUEST+0x20000:assert j in known,('unspecified private read',i['pc'],hex(j))
     bs.append(state[j]if j in state else R.Parent.Parent.Parent.Parent.IMAGE.read(j,1)[0])
   assert bs==expected,(i['pc'],hex(a));p=e.get('original_pointer_fixup')
   if p is not None:assert p==R.Parent.Parent.Parent.Parent.pointer(k,a)
   counts['read_bytes_checked']+=n;counts['symbolic_read_bytes_checked']+=sum(isinstance(b,str)for b in bs)
 for edge in row['source_transfers']:
  assert edge['original_pointer']==R.Parent.Parent.Parent.Parent.pointer(k,int(edge['original_pointer']['slot'],16));assert edge['original_pointer']['target']==edge['target'];counts['authenticated_edges_checked']+=1
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
def base_state(ix,old,k):
 B=A.A;inn=json.loads(read(ROOT/'versioned_inner_entry_checks.json'));param=json.loads(read(ROOT/'versioned_aes_parameters_checks.json'));prep=json.loads(read(ROOT/'versioned_core_preparation_checks.json'));words=json.loads(read(ROOT/'versioned_stream_words_checks.json'));out=json.loads(read(ROOT/'versioned_output_stream_checks.json'))
 previous=next(c for c in inn['cases']if c['parent_case_index']==ix);p=prep['cases'][ix];w=next(c for c in words['cases']if c['parent_case_index']==ix);o=next(c for c in out['cases']if c['parent_case_index']==ix and c['allocation_return_fixture']=='fresh_distinct_object');ap=next(c for c in param['cases']if c['parent_case_index']==ix and c['allocation_return_fixture']=='fresh_distinct_object');state={};known=set()
 for a,h in p['initial_cells'].items():
  for j,b in enumerate(bytes.fromhex(h),int(a,16)):state[j]=b;known.add(j)
 for b in [p,w,o]:
  for x in b['source_writes']:B.V.write(state,known,x)
 state,known,_=B.V.epochs(previous['strict_prefix'],state,known,k);state,known,_=B.V.epochs(previous['continuations'][0],state,known,k,0);state,known,_=B.epochs(ap,state,known,k);state,known,_=B.epochs(ap['lock_origin_continuation'],state,known,k)
 parent=next(c for c in old['cases']if c['parent_case_index']==ix)
 for name in ['strict_wrapper_prefix','explicit_null','strict_cached_origin_prefix','cached_null','no_primitive_job_prefix']:state,known,_=A.epochs(parent['branches'][name],state,known,k)
 return state,known,ap,parent
def receipts(fresh=True):
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA;e=json.loads(read(ROOT/(R.P+'_checks.json')))
 if fresh:assert no_queries(R.build())==no_queries(e)
 assert e['verified_counts']==COUNTS and e['generator_sha256']==sha(R.__file__)and e['dependencies']=={n:sha(ROOT/n)for n in e['dependencies']};assert e['prior_context_sha256']=={n:sha(ROOT/n)for n in e['prior_context_sha256']}
 for q in e['source_proofs']:
  s=z3.Solver();s.set(timeout=30000);s.from_string(q['query']);assert s.check()==z3.unsat
 old=json.loads(read(ROOT/'versioned_lock_handoff_checks.json'));k=R.Parent.Parent.Parent.Parent.Kernel();count=Counter()
 parents={'strict_initializer_prefix':'base','arbitrary_readiness_origin':'strict_initializer_prefix','warm_return':'arbitrary_readiness_origin','warm_scratch_fill':'warm_return','cold_matching_request':'arbitrary_readiness_origin','matching_return':'cold_matching_request','wait_return':'matching_return','provider_absent':'wait_return','provider_present':'wait_return'}
 for case in e['cases']:
  ix=case['parent_case_index'];state,known,ap,parent=base_state(ix,old,k);branches=case['branches'];states={'base':(state,known)};assert list(branches)==list(parents)
  for(name,up),visits in zip(parents.items(),[8,1,43,113,6,1,0,67,3]):
   row=branches[name];assert len(row['source_trace'])==visits;ss,kk,c=epochs(row,*states[up],k);states[name]=(ss,kk);count.update(c);assert row['parameters_at_boundary']==ap['parameters_at_boundary']
  assert branches['strict_initializer_prefix']['boundary']['pc']==hex(R.FLAG_READ)and branches['arbitrary_readiness_origin']['boundary']['pc']==hex(R.FLAG_BRANCH)
  warm=branches['warm_return'];fill=branches['warm_scratch_fill'];assert warm['boundary']['pc']==hex(R.FILL_CALL)and warm['boundary']['X2']=={'bytes_hex':'a800000000000000'}
  assert fill['boundary']['pc']=='0xfffffe000a68858c'and fill['boundary']['target']=='0xfffffe000a508cf4'and fill['boundary']['X2']=={'bytes_hex':'1000000000000000'}
  h3=int(ap['declared_distinct_object'],16);assert int.from_bytes(bytes.fromhex(fill['boundary']['X1']['bytes_hex']),'little')==h3+0x12
  src=states['warm_scratch_fill'][0];assert bytes(src[h3+j]for j in range(0x12,0x22))==bytes(16)
  sp=int(fill['boundary']['SP'],16);dst=int.from_bytes(bytes.fromhex(fill['boundary']['X0']['bytes_hex']),'little');assert dst==sp+0x140
  fill_start=int.from_bytes(bytes.fromhex(warm['boundary']['X0']['bytes_hex']),'little');assert fill_start==sp+0x98 and fill_start+168==dst
  private_writes=[x for x in fill['source_writes']if R.Parent.Parent.FILL<=int(x['pc'],16)<0xfffffe000a687ecc];assert sum(x['size_bytes']for x in private_writes)==168
  assert {j for w in private_writes for j in range(int(w['address'],16),int(w['address'],16)+w['size_bytes'])}==set(range(fill_start,dst))and all(bytes.fromhex(w['bytes_hex'])==bytes(w['size_bytes'])for w in private_writes)
  for name in ['matching_return','wait_return']:
   premise=branches[name]['external_return_premise'];assert premise['registers_clobbered']==list(range(1,19))and premise['model_memory_effects']==0 and not premise['native_API_executed']
  timeout=bytes.fromhex('0000000001000000')
  for name in ['cold_matching_request','matching_return','wait_return']:assert branches[name]['initializer_timeout']['terms']==[{'bytes_hex':f'{b:02x}'}for b in timeout]
  assert branches['matching_return']['boundary']['X0']=={'expression':'matching_result64'}and branches['matching_return']['boundary']['pc']==hex(R.WAIT)
  assert branches['wait_return']['boundary']['pc']==hex(R.SERVICE_BRANCH)
  absent=branches['provider_absent'];present=branches['provider_present'];assert absent['boundary']['pc']=='0xfffffe000a69dcd0'and absent['boundary']['address']=='0xfffffe000cccda78';assert present['boundary']['pc']=='0xfffffe000a508088'and present['boundary']['expression']=='wait_service_result64'
  assert absent['lock_record_at_boundary']['terms'][8:12]==[{'bytes_hex':f'{b:02x}'}for b in bytes.fromhex('beff51ce')]
  assert absent['job_delta_cell']['terms']==[{'bytes_hex':'00'}]*8
  assert [(w['size_bytes'],w['bytes_hex'])for w in absent['source_writes']if w['pc']=='0xfffffe000a6887e4']==[(4,'beff51ce')]
  assert present['provider_cell']['known_mask_hex']=='01'*8 and present['provider_cell']['terms']==[{'expression':t}for t in tokens('wait_service_result64',8)]
  for row in branches.values():assert row['job_private_header']==parent['branches']['no_primitive_job_prefix']['job_private_header']
 for count_key,total_key in [('source_words_checked','source_visits'),('read_bytes_checked','source_read_bytes'),('write_bytes_checked','source_write_bytes'),('authenticated_edges_checked','authenticated_transfers'),('unique_observables_rebuilt','unique_observables_proved')]:assert count[count_key]==COUNTS[total_key]
 report=read(BASE/'versioned_hardware_admission_report.md');assert all(f'| HA{j} |'in report for j in range(1,8))and all(f'**QG{j}**'in report for j in range(1,8))
 return e,count
def main():
 e,count=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA;old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
 assert len(before)==8627 and len(after)==8631 and not before.keys()-after.keys()and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 assert new['validation']['versioned_hardware_admission_increment_checks']==COUNTS and new['validation']['versioned_hardware_admission_static_scope']==e['scope'];assert new['validation']['reports']==old['validation']['reports']+1==485 and new['goal_status']=='active'and new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
 path_hygiene(json.dumps(H.paths_in_typed_payloads(e)).encode());fields,extent=H.hex_hygiene(e);path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
 print(json.dumps({'unchanged_manifest_entries':8618,'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':485,'source_queries_unsat':3,'independent_byte_epochs':dict(count),'decoded_hex_fields_path_checked':fields,'decoded_hex_bytes_path_checked':extent,'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
