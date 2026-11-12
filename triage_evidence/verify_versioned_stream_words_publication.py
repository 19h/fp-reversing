#!/usr/bin/env python3
"""Fresh reader proofs, independent origin epochs and publication checks.

O(owned bytes+receipt+source+manifest) time/space plus 30 s/query. No native
operation, new guest execution, database mutation or history rewrite.
"""
import json,re,subprocess
from pathlib import Path
from hashlib import sha256
from collections import Counter
from compression import zstd
import z3
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
import verify_corefp_late_preparation_publication as H
from verify_versioned_stream_initialization_publication import no_queries
import recover_versioned_stream_words as R
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='a20b540da93d69ea767313315fbea70c0886bb9d'
BASELINE_SHA='4a04505200a305db2d681aad3ba4017d011bb65bae5d16941c0cc46cfe642ec4'
CHECKS_SHA='6d716dcc1ffc8a2d2d19f078a433f130b3e387198894c5fce291ae825c46b9ed'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','versioned_stream_initialization_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'versioned_stream_words_report.md','triage_evidence/recover_versioned_stream_words.py','triage_evidence/verify_versioned_stream_words_publication.py','triage_evidence/versioned_stream_words_checks.json'}
ARCHIVES={MANIFEST,'triage_evidence/versioned_stream_words_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'cases':8,'source_queries_unsat':6,'source_lift_instructions':89,'bank_inputs':512,'header_control_pointer_records':4,'pending_allocator_pointers_checked':8,'strict_prefix_visits':1552,'new_reader_visits':5088,'source_read_bytes':4992,'source_write_bytes':1696,'authenticated_transfers':272,'origin_bytes':192,'decoded_words':24}

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)

def tokens(expr,n):
 if expr=='unresolved_frame_word32':assert n==4;return['original_W24_byte'+str(j)for j in range(4)]
 names=re.findall(r'frame_[0-9a-f]+_byte',expr);assert len(names)==n and expr=='(concat '+' '.join(names)+')';return list(reversed(names))

def epochs(row,parent,k):
 state={};known=set();events={};count=Counter();P=R.Parent.Parent.Parent.Parent.P;G=int(parent['boundary']['SP'],16);orig={int(o['address'],16):o['symbol']for o in row['frame_byte_origins']}
 for a,h in parent['initial_cells'].items():
  for j,b in enumerate(bytes.fromhex(h),int(a,16)):state[j]=b;known.add(j)
 for e in parent['source_writes']:
  for j,b in enumerate(bytes.fromhex(e['after_hex']),int(e['address'],16)):state[j]=b;known.add(j)
 for field,kind in [('source_reads','read'),('source_writes','write')]:
  for e in row[field]:events.setdefault(e['visit'],[]).append((kind,e))
 for ix,i in enumerate(row['source_trace']):
  pc=int(i['pc'],16);assert k.read(pc,4).hex()==i['bytes_hex']==R.IMAGE.read(pc,4).hex();count['source_words_checked']+=1
  for kind,e in events.get(ix,[]):
   assert e['pc']==i['pc'];a=int(e['address'],16);n=e['size_bytes']
   if kind=='read':
    bs=[]
    for j in range(a,a+n):
     if P<=j<P+0x20000 and j not in known:assert G<=j<G+0x200 and j in orig
     bs.append(state[j]if j in state else orig[j]if j in orig else R.IMAGE.read(j,1)[0])
    expected=list(bytes.fromhex(e['bytes_hex']))if 'bytes_hex'in e else tokens(e['expression'],n);assert expected==bs
    if 'source_defined_mask_hex'in e:assert bytes(int(j in known)for j in range(a,a+n)).hex()==e['source_defined_mask_hex']
    count['read_bytes_checked']+=n;count['symbolic_read_bytes_checked']+=sum(isinstance(b,str)for b in bs)
   else:
    if 'bytes_hex'in e:bs=list(bytes.fromhex(e['bytes_hex']));assert len(bs)==n;count['concrete_write_bytes_checked']+=n
    else:assert G<=a<a+n<=G+0x200;bs=tokens(e['expression'],n);count['symbolic_write_bytes_checked']+=n
    for j,b in enumerate(bs,a):state[j]=b;known.add(j)
 s=row['input_stream_at_boundary'];a=int(s['address'],16);n=s['size_bytes'];assert bytes(int(j in known)for j in range(a,a+n)).hex()==s['known_mask_hex']
 for j,t in enumerate(s['terms'],a):
  if j in known:assert t=={'bytes_hex':bytes([state[j]]).hex()}
  else:assert t=={'origin':'unspecified byte; no source definition in retained epoch'}
 count['snapshot_bytes_checked']+=n;return count

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA;e=json.loads(read(ROOT/(R.P+'_checks.json')));assert no_queries(R.build())==no_queries(e)
 assert e['verified_counts']==COUNTS and e['generator_sha256']==sha(R.__file__)and e['dependencies']=={n:sha(ROOT/n)for n in e['dependencies']}
 for q in e['source_proofs']:
  s=z3.Solver();s.set(timeout=30000);s.from_string(q['query']);assert s.check()==z3.unsat
 prior=json.loads(read(ROOT/'versioned_core_preparation_checks.json'));k=R.Kernel();count=Counter()
 for row in e['cases']:
  parent=prior['cases'][row['parent_case_index']];count.update(epochs(row,parent,k));assert row['strict_parent_prefix_visits']==194 and row['new_reader_visits']==636 and len(row['source_trace'])==830
  assert len(row['frame_byte_origins'])==24 and {int(o['body_SP_offset'],16)&~3 for o in row['frame_byte_origins']}=={0x9c,0x10c,0x120,0x124,0x148,0x168}
  assert row['unconstrained_origin_bits']==224 and row['all_selected_observables_concrete']and not row['frame_initialization_claimed']
  for j,w in enumerate(row['decoded_words']):
   reads=[row['source_reads'][i]for i in w['source_read_indices']];assert len(reads)==4 and w['index']==[0,4,0][j]
   assert [int(r['address'],16)-int(w['pointer'],16)for r in reads]==list(range(w['index'],w['index']+4))
   assert [int(r['address'],16)-(R.Parent.Parent.Parent.Parent.P+0x1200)for r in reads]==list(range(j*4,j*4+4))
   raw=bytes.fromhex(''.join(r['bytes_hex']for r in reads));normalized=int.from_bytes(bytes(b^0xcd for b in raw),'big');assert hex(normalized)==w['canonical_word32']and hex(normalized^0x31ae0066)==w['encoded_word32']
   assert {r:int.from_bytes(bytes.fromhex(v['bytes_hex']),'little')for r,v in w['registers'].items()}=={'w5':0xcd,'w6':0x9c6d3bf2,'w7':0x6392c400,'w26':0x85905ec3,'w30':0xadc33b59}
  assert row['output_B_view']['capacity_bytes']==512 and row['boundary']['pc']==hex(R.CALL)and row['boundary']['X0']=='0xfffffe000847b8e0'and not row['boundary']['instruction_executed']
  assert not row['model_memory_writes']and not row['new_guest_executed']and not row['native_target_executed']
 assert {k:v for k,v in count.items()if k!='symbolic_read_bytes_checked'}=={'source_words_checked':6640,'read_bytes_checked':4992,'concrete_write_bytes_checked':1344,'symbolic_write_bytes_checked':352,'snapshot_bytes_checked':256}
 tv=e['second_allocation_type_view'];assert(tv['name'],tv['flags'],tv['size_bytes'])==('site.FPByteArrayStreamInternal','0x64',32)
 parent=prior['cases'][e['cases'][0]['parent_case_index']];v=R.Reader(k,parent);v.run_stream();v.allow_origins=True;v.pc=0xfffffe000a5a731c;G=z3.simplify(v.read('sp')).as_long();before=set(v.known);a=v.load(z3.BitVecVal(G+0x168,64),4);b=v.load(z3.BitVecVal(G+0x168,64),4);assert z3.eq(a,b)and set(v.known)==before and len(v.origins)==4
 try:v.load(z3.BitVecVal(v.heap+28,64),4)
 except R.Parent.Frontier:assert v.boundary['kind']=='before_unspecified_frame_or_heap_read'
 else:raise AssertionError('unknown heap read accepted as frame')
 v=R.Reader(k,parent);v.run_stream();v.allow_origins=True;v.state[v.heap]=z3.BitVec('missing_input_pointer_byte',8);pc=0xfffffe000a5a731c;v.boundary=None
 try:
  for _ in range(1000):pc=v.step(pc)
 except R.Parent.Frontier:assert v.boundary['kind']=='before_unknown_dependent_observable'
 else:raise AssertionError('unknown input address accepted')
 assert not e['native_frame_initialization_established']and not e['new_guest_executed']and not e['model_memory_writes']and not e['native_target_executed']and not e['full_goal_complete']
 report=read(BASE/'versioned_stream_words_report.md');assert all(f'| SW{k} |'in report for k in range(1,8))and all(f'**QG{k}**'in report for k in range(1,8))
 assert all(t in report for t in ['5,088','224','0x00fb1958','0xfffffffb','0xfffffe000a5a8218','512 B','unknown'])
 return e,count

def main():
 e,count=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
 assert len(before)==len(old['files'])==8607 and len(after)==len(new['files'])==8611
 assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 assert new['validation']['versioned_stream_words_increment_checks']==COUNTS and new['validation']['versioned_stream_words_static_scope']==e['scope']
 assert new['validation']['reports']==old['validation']['reports']+1==480 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
 path_hygiene(json.dumps(H.paths_in_typed_payloads(e)).encode());fields,extent=H.hex_hygiene(e);path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
 print(json.dumps({'unchanged_manifest_entries':8599,'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':480,'source_equations_unsat':6,'cases':8,'negative_controls_rejected':2,'repeated_origin_coherence_passed':True,'independent_byte_epochs':dict(count),'decoded_hex_fields_path_checked':fields,'decoded_hex_bytes_path_checked':extent,'new_guest_executed':False,'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
