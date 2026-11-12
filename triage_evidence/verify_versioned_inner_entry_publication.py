#!/usr/bin/env python3
"""Independent byte epochs, source proofs and exact publication delta.

O(receipt+source+owned decoded bytes+manifest) time/space; 30 s/source query.
No native API, guest, IDA mutation or Git-history rewrite.
"""
import json,subprocess
from pathlib import Path
from hashlib import sha256
from collections import Counter
from compression import zstd
import z3
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_versioned_stream_words_publication import tokens as parent_tokens
from verify_versioned_stream_initialization_publication import no_queries
import verify_corefp_late_preparation_publication as H
import recover_versioned_inner_entry as R
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='d7c5ba4af1a662ff8a9c261fd8bdf8ad255eee1e'
BASELINE_SHA='05f8c7339f9f99e43d06b01d9aedc3064b983f81cd07f401be181c4ca1f77e47'
CHECKS_SHA='9337520390e93eb413f513e495bd85b65fc9601656abb495304ddaf4fa4aae4c'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','versioned_output_stream_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'versioned_inner_entry_report.md','triage_evidence/recover_versioned_inner_entry.py','triage_evidence/verify_versioned_inner_entry_publication.py','triage_evidence/versioned_inner_entry_checks.json'}
ARCHIVES={MANIFEST,'triage_evidence/versioned_inner_entry_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'parent_cases':8,'strict_prefixes':8,'symbolic_continuations':16,'source_queries_unsat':10,'source_lift_instructions':68,'bank_inputs':1280,'relative_table_entries':16,'inner_instruction_words':22279,'source_visits':18160,'source_read_bytes':16288,'source_write_bytes':14304,'authenticated_transfers':496,'returns':40,'relative_table_transfers':8,'discarded_probe_reads':8}

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)
def tokens(expr,n):
 if expr in ['kernel_stack_guard64','aux270_word64']:assert n==8;return[expr+'_byte'+str(j)for j in range(8)]
 return parent_tokens(expr,n)
def write(state,known,e):
 a=int(e['address'],16);n=e.get('size_bytes',len(e.get('after_hex',''))//2);bs=list(bytes.fromhex(e.get('bytes_hex',e.get('after_hex',''))))if 'expression'not in e else tokens(e['expression'],n);assert len(bs)==n
 for j,b in enumerate(bs,a):state[j]=b;known.add(j)
 return bs
def epochs(row,state,known,k,environment=None):
 state=dict(state);known=set(known);events={};counts=Counter()
 for key,kind in [('source_reads','read'),('source_writes','write')]:
  for e in row[key]:events.setdefault(e['visit'],[]).append((kind,e))
 for ix,i in enumerate(row['source_trace']):
  pc=int(i['pc'],16);assert k.read(pc,4).hex()==i['bytes_hex']==R.Parent.IMAGE.read(pc,4).hex();counts['source_words_checked']+=1
  for p in row['discarded_probe_reads']:
   if p['visit']==ix:
    assert p['pc']==i['pc']=='0xfffffe000a5a1cf0'and p['size_bytes']==1 and p['architectural_destination']=='WZR'and p['readability_assumed'];assert p['source_defined']==(int(p['address'],16)in known);counts['discarded_probe_bytes_checked']+=1
  for kind,e in events.get(ix,[]):
   assert e['pc']==i['pc'];a=int(e['address'],16);n=e['size_bytes']
   if kind=='write':
    bs=write(state,known,e);counts['write_bytes_checked']+=n;counts['symbolic_write_bytes_checked']+=sum(isinstance(b,str)for b in bs);continue
   if a==R.GUARD:assert n==8;bs=tokens('kernel_stack_guard64',8)
   elif a==R.FLAG:assert n==1 and environment in [0,1];bs=[environment]
   elif a==R.AUX+0x270 and not all(j in known for j in range(a,a+n)):assert n==8 and environment in [0,1];bs=tokens('aux270_word64',8)
   else:
    bs=[]
    for j in range(a,a+n):
     if R.GUEST<=j<R.GUEST+0x20000:assert j in known,('unspecified private read',i['pc'],hex(j))
     bs.append(state[j]if j in state else R.Parent.IMAGE.read(j,1)[0])
   expected=list(bytes.fromhex(e['bytes_hex']))if 'bytes_hex'in e else tokens(e['expression'],n);assert bs==expected,(i['pc'],a)
   counts['read_bytes_checked']+=n;counts['symbolic_read_bytes_checked']+=sum(isinstance(b,str)for b in bs)
 for key in ['input_stream_at_boundary','output_stream_at_boundary','record_at_boundary','caller_delta_cell','private_header']:
  s=row[key];a=int(s['address'],16);n=s['size_bytes'];assert s['known_mask_hex']==bytes(int(j in known)for j in range(a,a+n)).hex()
  for j,t in enumerate(s['terms'],a):
   if j not in known:assert t=={'origin':'unspecified byte; no source definition in retained epoch'}
   elif isinstance(state[j],int):assert t=={'bytes_hex':bytes([state[j]]).hex()}
   else:assert t=={'expression':state[j]}
  counts['snapshot_bytes_checked']+=n
 return state,known,counts

def receipts(fresh=True):
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA;e=json.loads(read(ROOT/(R.P+'_checks.json')))
 if fresh:assert no_queries(R.build())==no_queries(e)
 assert e['verified_counts']==COUNTS and e['generator_sha256']==sha(R.__file__)and e['dependencies']=={n:sha(ROOT/n)for n in e['dependencies']}
 for q in e['source_proofs']:
  s=z3.Solver();s.set(timeout=30000);s.from_string(q['query']);assert s.check()==z3.unsat
 prep=json.loads(read(ROOT/'versioned_core_preparation_checks.json'));words=json.loads(read(ROOT/'versioned_stream_words_checks.json'));out=json.loads(read(ROOT/'versioned_output_stream_checks.json'));k=R.Parent.Kernel();count=Counter()
 for case in e['cases']:
  ix=case['parent_case_index'];p=prep['cases'][ix];w=next(r for r in words['cases']if r['parent_case_index']==ix);o=next(r for r in out['cases']if r['parent_case_index']==ix and r['allocation_return_fixture']=='fresh_distinct_object');state={};known=set()
  for a,h in p['initial_cells'].items():
   for j,b in enumerate(bytes.fromhex(h),int(a,16)):state[j]=b;known.add(j)
  for row in [p,w,o]:
   for x in row['source_writes']:write(state,known,x)
  strict=case['strict_prefix'];state,known,c=epochs(strict,state,known,k);count.update(c);assert len(strict['source_trace'])==678 and strict['boundary']['pc']==hex(R.SLOT)and strict['boundary']['known_bytes']==0
  assert len(strict['discarded_probe_reads'])==1 and len(strict['source_returns'])==3
  for b in case['continuations']:
   env=b['environment_byte'];_,_,c=epochs(b,state,known,k,env);count.update(c);assert len(b['source_trace'])==(65 if env==0 else 1527)
   assert b['boundary']['pc']==hex(R.ALLOC if env==0 else R.FREE)and not b['boundary']['instruction_executed']
   assert b['source_trace'][0]['pc']==hex(R.SLOT)and b['all_selected_observables_concrete']and not b['new_allocator_return_supplied']
   if env==0:assert not b['source_returns']and b['boundary']['X0']=={'bytes_hex':'60b4470800feffff'}
   else:
    assert b['caller_delta_cell']['terms']==[{'bytes_hex':'00'}]*8 and b['private_header']==strict['private_header']
    assert len(b['source_returns'])==2 and all(r['SP']==r['entry_SP']for r in b['source_returns'])
    visit=next(j for j,i in enumerate(b['source_trace'])if i['pc']=='0xfffffe000a69ded8');assert b['relative_table_transfers']==[{'address':'0xfffffe000a69ecf8','index':0,'target':'0xfffffe000a69b1e4','base':'0xfffffe000a69ded0','branch_pc':'0xfffffe000a69ded8','visit':visit}]
    assert b['boundary']['X1']=={'bytes_hex':(int(o['declared_distinct_object'],16)).to_bytes(8,'little').hex()}
    stores=[s for s in b['source_writes']if s['pc']=='0xfffffe000a69d834'];assert len(stores)==1 and stores[0]['address']==hex(R.GUEST+0x4080)and stores[0]['bytes_hex']=='535b51ce'
   for row in [strict,b]:assert row['all_selected_observables_concrete']and not any(row[n]for n in ['output_B_bytes_written','allocator_model_memory_writes','new_guest_executed','native_target_executed'])
 tv=e['next_allocation_type_view'];assert(tv['name'],tv['flags'],tv['size_bytes'])==('site.FPAESParameters','0x64',104)
 assert e['guard_import_pointer']['target']==hex(R.GUARD)and e['guard_symbols'][hex(R.GUARD)][0]['name']=='___stack_chk_guard'
 assert e['flag_pointer']['target']==hex(R.FLAG)and e['flag_original_byte_hex']=='00'
 assert not any(e[n]for n in ['all_actual_native_deltas_proved_zero','full_inner_semantics_proved','output_B_bytes_written','allocator_model_memory_writes','new_guest_executed','native_target_executed','full_goal_complete'])
 assert dict(count)=={'source_words_checked':18160,'write_bytes_checked':14304,'symbolic_write_bytes_checked':128,'read_bytes_checked':16288,'symbolic_read_bytes_checked':352,'discarded_probe_bytes_checked':8,'snapshot_bytes_checked':3840}
 report=read(BASE/'versioned_inner_entry_report.md');assert all(f'| IE{k} |'in report for k in range(1,8))and all(f'**QG{k}**'in report for k in range(1,8))
 return e,count

def main():
 e,count=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
 assert len(before)==8615 and len(after)==8619 and not before.keys()-after.keys()and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 assert new['validation']['versioned_inner_entry_increment_checks']==COUNTS and new['validation']['versioned_inner_entry_static_scope']==e['scope']
 assert new['validation']['reports']==old['validation']['reports']+1==482 and new['goal_status']=='active'and new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
 path_hygiene(json.dumps(H.paths_in_typed_payloads(e)).encode());fields,extent=H.hex_hygiene(e);path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
 print(json.dumps({'unchanged_manifest_entries':8607,'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':482,'source_queries_unsat':10,'independent_byte_epochs':dict(count),'decoded_hex_fields_path_checked':fields,'decoded_hex_bytes_path_checked':extent,'native_API_executed':False,'new_guest_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
