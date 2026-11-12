#!/usr/bin/env python3
"""Independent source-byte epochs, partial initialization and publication audit.

O(receipt+owned decoded bytes+manifest) time/space; 30 s/source query.
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
from verify_versioned_stream_initialization_publication import no_queries
import verify_corefp_late_preparation_publication as H
import verify_versioned_inner_entry_publication as V
import recover_versioned_aes_parameters as R
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='efd8251f2748b75de59db9cc0b17c2a9354b6205'
BASELINE_SHA='e52396326c475a96a8a105578e98a2cc37cc033fe2cd398133326f8eea6b423a'
CHECKS_SHA='4f38b356c30c213c0040f9c536c4bfa19115090c932726f351e015fe38d99968'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','versioned_inner_entry_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'versioned_aes_parameters_report.md','triage_evidence/recover_versioned_aes_parameters.py','triage_evidence/verify_versioned_aes_parameters_publication.py','triage_evidence/versioned_aes_parameters_checks.json'}
ARCHIVES={MANIFEST,'triage_evidence/versioned_aes_parameters_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'parent_cases':8,'allocation_continuations':16,'separate_lock_origin_continuations':8,'source_queries_unsat':7,'source_lift_instructions':61,'constant_bank_inputs':256,'source_visits':18384,'authenticated_transfers':584,'source_returns':24,'source_read_bytes':15304,'source_write_bytes':3128}

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)
def tokens(expr,n):
 if expr=='startup_lock_cell64':assert n==8;return[f'((_ extract {8*j+7} {8*j}) startup_lock_cell64)'for j in range(8)]
 return V.tokens(expr,n)
def epochs(row,state,known,k):
 state=dict(state);known=set(known);events={};counts=Counter()
 for key,kind in [('source_reads','read'),('source_writes','write')]:
  for e in row[key]:assert 0<=e['visit']<len(row['source_trace']);events.setdefault(e['visit'],[]).append((kind,e))
 for ix,i in enumerate(row['source_trace']):
  pc=int(i['pc'],16);assert k.read(pc,4).hex()==i['bytes_hex']==R.Parent.Parent.IMAGE.read(pc,4).hex();counts['source_words_checked']+=1
  for kind,e in events.get(ix,[]):
   assert e['pc']==i['pc'];a=int(e['address'],16);n=e['size_bytes'];expected=list(bytes.fromhex(e['bytes_hex']))if 'bytes_hex'in e else tokens(e['expression'],n)
   if kind=='write':
    for j,b in enumerate(expected,a):state[j]=b;known.add(j)
    counts['write_bytes_checked']+=n;counts['symbolic_write_bytes_checked']+=sum(isinstance(b,str)for b in expected);continue
   if a==R.Parent.GUARD:assert n==8;bs=tokens('kernel_stack_guard64',8)
   elif a==R.Parent.FLAG:assert n==1;bs=[0]
   elif a==R.LOCK_CELL:assert e['pc']==hex(R.LOCK_READ)and n==8 and e['expression']=='startup_lock_cell64';bs=tokens('startup_lock_cell64',8)
   else:
    bs=[]
    for j in range(a,a+n):
     if R.Parent.GUEST<=j<R.Parent.GUEST+0x20000:assert j in known,('unspecified private read',i['pc'],hex(j))
     bs.append(state[j]if j in state else R.Parent.Parent.IMAGE.read(j,1)[0])
   assert bs==expected,(i['pc'],hex(a));p=e.get('original_pointer_fixup')
   if p is not None:assert p==R.Parent.Parent.pointer(k,a)
   counts['read_bytes_checked']+=n;counts['symbolic_read_bytes_checked']+=sum(isinstance(b,str)for b in bs)
 for edge in row['source_transfers']:
  assert edge['original_pointer']==R.Parent.Parent.pointer(k,int(edge['original_pointer']['slot'],16));assert edge['original_pointer']['target']==edge['target'];counts['authenticated_edges_checked']+=1
 for key in ['input_stream_at_boundary','output_stream_at_boundary','record_at_boundary','caller_delta_cell','private_header','parameters_at_boundary','local_constant_at_boundary','lock_record_at_boundary']:
  if key not in row:continue
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
 context=e['startup_context'];assert context['references']=={n:sha(ROOT/n)for n in context['references']}and not context['native_epoch_join_established'];assert context['lock_cell_section']['section']=='__common'and context['lock_cell_section']['flags']==1 and context['lock_cell_section']['file_offset']==0
 for source in [e['fill_source'],e['lock_decoder_source'],context['startup_store_source']]:
  a,z=int(source['start'],16),int(source['end'],16);assert bytes.fromhex(source['bytes_hex'])==kread(a,z-a)
 old=json.loads(read(ROOT/'versioned_inner_entry_checks.json'));prep=json.loads(read(ROOT/'versioned_core_preparation_checks.json'));words=json.loads(read(ROOT/'versioned_stream_words_checks.json'));out=json.loads(read(ROOT/'versioned_output_stream_checks.json'));k=R.Parent.Parent.Kernel();count=Counter()
 for row in e['cases']:
  ix=row['parent_case_index'];previous=next(c for c in old['cases']if c['parent_case_index']==ix);p=prep['cases'][ix];w=next(c for c in words['cases']if c['parent_case_index']==ix);o=next(c for c in out['cases']if c['parent_case_index']==ix and c['allocation_return_fixture']=='fresh_distinct_object');state={};known=set()
  for a,h in p['initial_cells'].items():
   for j,b in enumerate(bytes.fromhex(h),int(a,16)):state[j]=b;known.add(j)
  for b in [p,w,o]:
   for x in b['source_writes']:V.write(state,known,x)
  state,known,_=V.epochs(previous['strict_prefix'],state,known,k);state,known,_=V.epochs(previous['continuations'][0],state,known,k,0)
  assert row['allocation_gate_phase']=={'w19':{'bytes_hex':'4e030000'},'w22':{'bytes_hex':'710d0000'}}and row['allocator_clobbers_declared']==list(range(1,19));a=int(row['declared_distinct_object'],16);assert a==int(o['declared_distinct_object'],16)+0x200
  state,known,c=epochs(row,state,known,k);count.update(c);success=row['allocation_return_fixture']=='fresh_distinct_object';assert row['allocation_result']==(hex(a)if success else '0x0')and len(row['source_trace'])==(1082 if success else 1169)
  mask=bytes.fromhex(row['parameters_at_boundary']['known_mask_hex']);defined=set(range(2))|set(range(18,34))|set(range(36,48))|{56}
  assert {j for j,b in enumerate(mask)if b}==(defined if success else set())
  if success:
   assert len(defined)==31 and row['boundary']['pc']==hex(R.LOCK_READ)and row['boundary']['address']==hex(R.LOCK_CELL)and row['retained_parameter_register']=={'bytes_hex':a.to_bytes(8,'little').hex()}
   fill=next(x for x in row['source_transfers']if x['pc']==hex(R.FILL_CALL));assert fill['target']==hex(R.FILL)and fill['X0']=={'bytes_hex':(a+18).to_bytes(8,'little').hex()}and fill['X1']=={'bytes_hex':'00'*8}and fill['X2']=={'bytes_hex':'1000000000000000'}
   writes=[x for x in row['source_writes']if R.FILL<=int(x['pc'],16)<0xfffffe000a687ecc];assert sum(x['size_bytes']for x in writes)==16 and {j for x in writes for j in range(int(x['address'],16),int(x['address'],16)+x['size_bytes'])}==set(range(a+18,a+34))
   raw=bytes.fromhex(e['constant_source']['bytes_hex']);constant=bytes(b^((-19*j)&255)^0x95 for j,b in enumerate(raw));assert bytes.fromhex(''.join(t['bytes_hex']for t in row['local_constant_at_boundary']['terms']))==constant
   b=row['lock_origin_continuation'];state,known,c=epochs(b,state,known,k);count.update(c);assert len(b['source_trace'])==47 and b['boundary']['pc']=='0xfffffe000a69db54'and b['boundary']['target']=='0xfffffe000a5b403c'and b['retained_parameter_register']==row['retained_parameter_register']and b['parameters_at_boundary']==row['parameters_at_boundary']
   record=b['lock_record_at_boundary'];C=int(record['address'],16);encoded=int.from_bytes(bytes.fromhex(''.join(t['bytes_hex']for t in record['terms'][8:12])),'little');assert(encoded+((C^0x6133a0c8)*0x84d77373))&0xffffffff==0x729 and b['lock_pack_phase']=={'bytes_hex':'8c070000'};assert not b['boundary']['instruction_executed']
   assert b['all_selected_observables_concrete']and not any(b[n]for n in ['output_B_bytes_written','allocator_model_memory_writes','new_guest_executed','native_target_executed'])
  else:
   assert row['boundary']['pc']=='0xfffffe000a5a92e4'and row['boundary']['X1']=={'bytes_hex':int(o['declared_distinct_object'],16).to_bytes(8,'little').hex()}
   assert row['caller_delta_cell']['terms']==[{'bytes_hex':'00'}]*8 and row['private_header']==previous['strict_prefix']['private_header'];assert len(row['source_returns'])==2 and all(x['SP']==x['entry_SP']for x in row['source_returns'])
   assert [x['bytes_hex']for x in row['source_writes']if x['pc']=='0xfffffe000a69d834']==['385a51ce'];assert [x['bytes_hex']for x in row['source_writes']if x['pc']=='0xfffffe000a69b228']==['00'*8]
  assert row['all_selected_observables_concrete']and not row['boundary']['instruction_executed']and not any(row[n]for n in ['output_B_bytes_written','allocator_model_memory_writes','new_guest_executed','native_target_executed'])
  assert not any(R.Parent.GUEST+0x1200<=int(x['address'],16)<R.Parent.GUEST+0x1210 or a<=int(x['address'],16)<a+104 for x in row['source_reads'])
 assert count['source_words_checked']==COUNTS['source_visits']and count['read_bytes_checked']==COUNTS['source_read_bytes']and count['write_bytes_checked']==COUNTS['source_write_bytes']and count['authenticated_edges_checked']==COUNTS['authenticated_transfers']
 assert not any(e[n]for n in ['allocator_model_memory_writes','output_B_bytes_written','new_guest_executed','native_target_executed','full_goal_complete'])
 report=read(BASE/'versioned_aes_parameters_report.md');assert all(f'| AP{j} |'in report for j in range(1,8))and all(f'**QG{j}**'in report for j in range(1,8))
 return e,count

def kread(a,n):
 from kernel_native_reader import Kernel
 return Kernel().read(a,n)

def main():
 e,count=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
 assert len(before)==8619 and len(after)==8623 and not before.keys()-after.keys()and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 assert new['validation']['versioned_aes_parameters_increment_checks']==COUNTS and new['validation']['versioned_aes_parameters_static_scope']==e['scope']
 assert new['validation']['reports']==old['validation']['reports']+1==483 and new['goal_status']=='active'and new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
 path_hygiene(json.dumps(H.paths_in_typed_payloads(e)).encode());fields,extent=H.hex_hygiene(e);path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
 print(json.dumps({'unchanged_manifest_entries':8611,'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':483,'source_queries_unsat':7,'independent_byte_epochs':dict(count),'decoded_hex_fields_path_checked':fields,'decoded_hex_bytes_path_checked':extent,'native_API_executed':False,'new_guest_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
