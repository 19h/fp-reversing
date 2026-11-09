#!/usr/bin/env python3
"""Independent original-byte, opaque-memory, gate, array and replay checks.
O(snapshot+cases*source effects+SMT+fresh A64) time, O(largest trace+RAM) space.
Conditional API contracts only; native operations and IDB mutation never run.
"""
import json,hashlib,zlib,base64,struct
from pathlib import Path
from collections import Counter
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,qword
from recover_daemon_callback_revisit import snapshot_read,verify_fixups
from recover_daemon_context_lock import ida_output
from replay_daemon_context_lock import ContextReplay,unpack,APIS,HEAP

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def checked(n,g):
 q=json.loads((ROOT/n).read_text());assert q['generator_sha256']==sha(ROOT/g)and not q['full_goal_complete']
 for name,h in q.get('dependencies',{}).items():assert sha(ROOT/name)==h,(n,name)
 if 'source_sha256'in q:assert sha(SOURCE)==q['source_sha256']
 return q
def terms(s):return list(bytes.fromhex(s['hex']))if'hex'in s else s['terms']
def number(s):return int.from_bytes(bytes.fromhex(s['hex']),'little')
def main():
 snap=checked('daemon_context_lock_snapshot.json','capture_daemon_context_lock.py');profiles=checked('daemon_context_lock_profiles.json','probe_daemon_context_lock.py');success=checked('daemon_context_lock_success.json','probe_daemon_context_lock_success.py');c=checked('daemon_context_lock_contracts.json','recover_daemon_context_lock.py');proofs=checked('daemon_context_lock_proofs.json','prove_daemon_context_lock.py');replays=checked('daemon_context_lock_replays.json','replay_daemon_context_lock.py');cases=profiles['cases']+[success['case']];assert len(cases)==13 and success['preceding_prefix_identical'];counts=Counter();F=int(snap['frame_SP'],16);R=F+0xaf8;H=int(snap['arena_owner'],16);G=0x1010c8218;traces=[unpack(r)for r in cases];prior=next(t for r,t in zip(cases,traces)if r['configuration']['name']=='both_locks_success_buffer_1');assert traces[-1]['steps'][:len(prior['steps'])]==prior['steps'];counts['preserved_success_prefix_visits']=len(prior['steps'])
 for r in snap['regions']:
  b=zlib.decompress(base64.b64decode(r['bytes_zlib_base64']));assert len(b)==r['size_bytes']and hashlib.sha256(b).hexdigest()==r['sha256'];counts['snapshot_regions_checked']+=1;counts['snapshot_bytes_checked']+=len(b)
 assert snap['sealed_source_visits_replayed']==160048 and snap['snapshot_before_creator_call']and snap['unknown_backing_is_not_source_definition']
 for span in c['spans']:
  b=bytes.fromhex(span['bytes_hex']);assert IMAGE.read(int(span['start'],16),len(b))==b and hashlib.sha256(b).hexdigest()==span['sha256'];counts['source_spans_checked']+=1
 assert verify_fixups([int(r['address'],16)for r in c['source_fixups']['records']])==c['source_fixups'];counts['original_fixups_checked']=len(c['source_fixups']['records'])
 for p in proofs['proofs']:
  for fk,hk in [('original_file','original_sha256'),('file','sha256')]:
   path=ROOT/p[fk];assert sha(path)==p[hk];s=z3.Solver();s.set(timeout=30000);s.from_file(str(path));assert str(s.check())=='unsat',p['name'];counts['SMT_queries_unsat']+=1
 counts['source_proof_pairs_unsat']=len(proofs['proofs']);assert counts['source_proof_pairs_unsat']==18;assert len(proofs['nonempty_premise_witnesses'])==4;counts['nonempty_premise_witnesses']=4
 live=ida_output(json.loads((ROOT/'daemon_context_lock_ida_bytes.json').read_text()))
 for row in live['results']:
  a=int(row['address'],16);b=bytes.fromhex(row['bytes']);assert IMAGE.read(a,len(b))==b;counts['live_IDB_raw_ranges']+=1;counts['live_IDB_raw_bytes']+=len(b)
  for i in row['instructions']:
   b2=bytes.fromhex(i['bytes']);assert IMAGE.read(int(i['address'],16),len(b2))==b2 and len(b2)<=i['size'];counts['live_IDB_display_rows']+=1;counts['live_IDB_macro_rows_partial_display_bytes']+=len(b2)<i['size']
 assert counts['live_IDB_raw_ranges']==4 and counts['live_IDB_raw_bytes']==640 and counts['live_IDB_display_rows']==139 and counts['live_IDB_macro_rows_partial_display_bytes']==3
 slot=c['conditional_pool_resolution'];assert qword(int(slot['slot'],16))==int(slot['original_decoded_rebase'],16)and(qword(int(slot['slot'],16))+int(slot['bias'],16))&((1<<64)-1)==G
 assert len(c['saved_annotation_candidates']['records'])==2 and sha(Path(c['saved_annotation_candidates']['path']))==c['saved_annotation_candidates']['sha256'];counts['conditional_reader_candidates']=2
 summaries=[];pool={};APItotal=Counter();boundaries=Counter()
 for case,t in zip(cases,traces):
  assert not t['definitions']and not t['origins']and case['unknown_input_bytes_used']==0;pool.update(t['source_pool']);regs=t['initial_registers'].copy();ram={};defined={};owners={int(o['address'],16):o['size_bytes']for o in t['allocated_owners']};api_origins={r['offset']:r for r in t['API_origins']};assert len(api_origins)==len(t['API_origins'])==case['arbitrary_API_bytes'];calls=[];returns=[];records=[];descriptor=[];buffer_writes=[];publications=[];array_entries=[];before_source_api=0
  def read(a,n):
   if all(a+j in ram for j in range(n)):return [ram[a+j]for j in range(n)]
   initial=list(snapshot_read(snap,a,n));return [ram.get(a+j,initial[j])for j in range(n)]
  def num(a,n=8):
   b=read(a,n);assert all(isinstance(x,int)for x in b);return int.from_bytes(bytes(b),'little')
  def store(a,values,known):
   for j,v in enumerate(values):ram[a+j]=v;defined[a+j]=isinstance(v,int)if known else False
  for idx,step in enumerate(t['steps']):
   pc=int(step['pc'],16);assert IMAGE.read(pc,4).hex()==step['bytes_hex'];counts['source_visits_checked']+=1
   if pc==0x100407458:array_entries.append(number(regs['x9']))
   if step['mnemonic']=='blraa'and step.get('target')=='0x10043a240':
    dest=num(R+8);raw=num(R,4);key=(R^0xdc40790b)&0xffffffff;assert(raw+key*0x5973a279)&0xffffffff==0xaed7;records.append({'pc':step['pc'],'destination':hex(dest),'source_visit_index':idx})
   if pc in [0x100492658,0x1003ae60c]:returns.append({'pc':step['pc'],'raw_result32':hex(num(R+16,4))})
   if 'api_model'in step:
    model=step['api_model'];name,slot,div=APIS[pc];assert model['name']==name and model['binding']==c['API_bindings'][hex(slot)]and step['target']=='0x7c100000'and int(step['modifier16'],16)==div
    assert model['arguments8']==[regs['x'+str(j)]for j in range(8)]and not step['events'];index=model['allocation_index'];ptr=HEAP+index*4096;assert int(model['allocation_address'],16)==ptr
    if name=='malloc':
     extent=960 if pc==0x10038eb5c else 200;assert number(regs['x0'])==extent;out=model['configuration']['malloc_nonnull'];assert number(step['registers_after']['x0'])==(ptr if out else 0);assert len(model['memory_effects'])==int(out)
    else:
     assert number(regs['x0'])==ptr and number(regs['x1'])==0 and num(ptr,8)==0 and all(defined[ptr+j]for j in range(8));out=terms(step['registers_after']['x0']);assert int.from_bytes(bytes(out[:4]),'little')==model['configuration']['init_status']and all(isinstance(x,dict)for x in out[4:]);counts['source_cleared_headers_before_initializer']+=1
    for j in range(1,18):assert all(isinstance(x,dict)and api_origins[x['origin']]['kind']=='caller_GPR_clobber'for x in terms(step['registers_after']['x'+str(j)]))
    for j in range(32):
     n='q'+str(j);vals=terms(step['registers_after'][n]);old=terms(regs[n])
     if 8<=j<16:assert vals[:8]==old[:8]and all(isinstance(x,dict)for x in vals[8:])
     else:assert all(isinstance(x,dict)for x in vals)
    assert model['preserved']=={n:regs[n]for n in ['sp']+['x'+str(j)for j in range(18,30)]}
    for e in model['memory_effects']:
     a=int(e['address'],16);vals=terms(e['value']);assert a==ptr and len(vals)==e['size_bytes']==owners[ptr]and all(isinstance(x,dict)and x['origin']in api_origins for x in vals);store(a,vals,False);counts['opaque_API_memory_bytes_checked']+=len(vals)
    APItotal[name]+=1;calls.append({'pc':step['pc'],'name':name,'allocation_index':index,'source_visit_index':idx})
   for e in step['events']:
    assert 'hex'in e['value'];a=int(e['address'],16);vals=terms(e['value']);assert len(vals)==e['size_bytes']
    if e['kind']=='read':
     if all(a+j in ram for j in range(len(vals))):assert read(a,len(vals))==vals
    else:
     store(a,vals,True)
     if G<=a<G+24:descriptor.append({'pc':step['pc'],'address':hex(a),'value_hex':bytes(vals).hex(),'source_visit_index':idx})
     if pc==0x1002097dc and a in [H+0x15b28,G,0x1010c8240,0x1010c5748]and len(vals)==8:publications.append((step['pc'],hex(a),hex(int.from_bytes(bytes(vals),'little'))))
     if HEAP+8192<=a<HEAP+8192+960:buffer_writes.append((a,bytes(vals)))
   regs.update(step['registers_after'])
  for ptr,size in owners.items():
   if size==200:assert all(not defined[ptr+j]for j in range(200))
  name=case['configuration']['name'];boundary=t['boundary'];boundaries[boundary['kind']]+=1
  if name.startswith('first_')and not name.startswith('first_success'):
   assert boundary['pc']=='0x1003868d8'and num(0x1010c9298)==0xe5f6a0000600f0c1 and num(F+0x358)==0xe5f6a0000600f0c1 and not publications;counts['outside_owner_failure_paths']+=1
  if name=='all_success_extended':
   assert [r['destination']for r in records]==[hex(H+0x15b28),hex(G),'0x1010c8240','0x1010c5748'];assert [p[1]for p in publications]==[hex(H+0x15b28),hex(G),'0x1010c8240','0x1010c5748'];assert len(owners)==5 and [s for p,s in sorted(owners.items())]==[200,200,960,200,200];assert boundary['pc']=='0x10030631c'and boundary['target']=='0x10046faf8'
   rec=struct.pack('<QQQQIIII',0,0,0,0xe3b88695c0d52dbc,0x9008b011,0x95bddb,0x95bddb,0x95bddb);assert len(rec)==48 and bytes(read(HEAP+8192,960))==rec*20 and all(defined[HEAP+8192+j]for j in range(960));assert array_entries==list(range(0x7a3a710c,0x7a3a7120));assert len(buffer_writes)==160 and sum(len(b)for a,b in buffer_writes)==960 and num(G+8,4)==20 and num(G+16)==HEAP+8192;counts.update(array_records_initialized=20,array_stride_bytes=48,array_source_bytes_defined=960,array_source_stores=160,rejoined_known_lock_creator_calls=2)
   order=[e['pc']for e in descriptor];assert order==['0x1002097dc','0x10038eb08','0x10038eb60','0x100393d34'];assert descriptor[-1]['source_visit_index']<next(j for j,s in enumerate(t['steps'])if s['pc']=='0x100407464')
  if boundary['kind']=='return_outside_source_image':assert boundary['pc']=='0x1002db86c'and boundary['target']=='0x22222222220a'and int(boundary['SP'],16)==F+0xbe0;counts['callback_epilogue_paths']+=1
  summaries.append({'name':name,'source_visits':len(t['steps']),'creator_records':records,'creator_results':returns,'API_calls':calls,'publications':publications,'descriptor_publication_order':descriptor,'boundary':boundary,'final_descriptor_hex':bytes(read(G,24)).hex(),'global_status32':hex(num(0x1010b6360,4))})

 seal=checked('daemon_context_seal_contracts.json','recover_daemon_context_seal.py');sealchecks=checked('daemon_context_seal_checks.json','validate_daemon_context_seal.py');assert sealchecks['all_checks_pass'];counts.update(sealchecks['verified_counts']);from validate_daemon_context_seal import encode,decode,source
 for row in seal['cases']:
  b=bytes.fromhex(row['before_hex']);after=bytes.fromhex(row['after_hex']);seed=int(row['seed32'],16);assert len(b)==len(after)==552 and encode(b,seed)==after and decode(after,seed)==b;inputs=row['seed_inputs'];assert int(inputs['coefficient32'],16)==0xeb36c1ca and seed==((int(inputs['address'],16)*int(inputs['coefficient32'],16))^int(inputs['code_fold32'],16))&0xffffffff
  perm=list(range(69))
  for i in range(68,0,-1):j=((((seed+i)&0xffffffff)^seed)*0x01000193&0xffffffff)%i;perm[i],perm[j]=perm[j],perm[i]
  offset=perm.index(1)*8;expected=bytes(((x^((seed^((i+seed)*(i-seed)))&255))*0x93)&255 for i,x in enumerate(b[8:16],8));assert offset==row['encoded_lock_field_offset_bytes']==248 and after[offset:offset+8]==expected and after[offset:offset+8].hex()==row['encoded_lock_word_hex']
  counts['raw_lock_token_field_offset_bytes']=8;counts['encoded_lock_token_field_offset_bytes']=248
  assert int.from_bytes(b[8:16],'little')==int(row['raw_lock_value_before_seal'],16);fold=int(row['initial_code_fold32'],16);base=0x100822058
  for e in row['code_reads']:
   a=int(e['address'],16);assert a==base+(fold&32767)and IMAGE.read(a,4).hex()==e['value']['hex'];fold^=number(e['value']);counts['header_self_text_u32_reads_checked']+=1
  assert fold==int(inputs['code_fold32'],16)and len(row['code_reads'])==8;counts['retained_header_codec_contracts_checked']+=1
 for row in [seal['cases'][0],seal['cases'][-1]]:assert source(bytes.fromhex(row['before_hex']),int(row['seed32'],16),row).hex()==row['after_hex'];counts['fresh_isolated_header_codec_cases']+=1
 counts['conditional_paths_checked']=len(cases);counts['source_pool_opcodes_checked']=len(pool);counts['source_unknown_byte_reads']=sum(r['unknown_input_bytes_used']for r in cases);counts['arbitrary_API_bytes_retained']=sum(r['arbitrary_API_bytes']for r in cases);counts['modeled_API_calls_checked']=sum(APItotal.values());counts['modeled_malloc_calls']=APItotal['malloc'];counts['modeled_initializer_calls']=APItotal['pthread_rwlock_init'];counts['source_lift_visits']=sum(proofs['source_lift_counts'].values());cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
 for pc,row in pool.items():
  i=next(cs.disasm(IMAGE.read(int(pc,16),4),int(pc,16)));rr,ww=i.regs_access();assert not any(i.reg_name(r)in ['x18','w18']for r in list(rr)+list(ww));assert i.mnemonic not in ['svc','hvc','smc'];counts['X18_free_source_opcodes_checked']+=1
 for gate in proofs['gate_targets']:
  assert [hex(qword(int(a,16)))for a in gate['slots']]==gate['targets']
 assert proofs['gate_targets'][-1]['targets']==['0x100407458','0x1002dab28'];counts['source_gate_targets_checked']=sum(len(g['targets'])for g in proofs['gate_targets'])
 assert replays['all_checks_pass']and len(replays['cases'])==52;totals=Counter()
 for r in replays['cases']:assert r['all_checks_pass'];totals.update(r['verified_counts'])
 assert totals['source_visits']==175372 and totals['modeled_API_calls_checked']==188;counts['independent_A64_cases']=52
 for i in [0,len(traces)-1]:
  fresh=ContextReplay(snap,traces[i],3).run();assert fresh['all_checks_pass'];counts['fresh_A64_source_visits']+=fresh['verified_counts']['source_visits'];counts['fresh_A64_cases']+=1
 assert counts['source_visits_checked']==43843 and counts['source_pool_opcodes_checked']==1182 and counts['outside_owner_failure_paths']==5 and counts['callback_epilogue_paths']==6 and counts['source_unknown_byte_reads']==0
 deps=['daemon_context_lock_snapshot.json','daemon_context_lock_profiles.json','daemon_context_lock_success.json','daemon_context_lock_contracts.json','daemon_context_lock_proofs.json','daemon_context_lock_replays.json','daemon_context_seal_contracts.json','daemon_context_seal_checks.json','daemon_context_lock_ida_bytes.json','replay_daemon_context_lock.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'verified_counts':dict(counts),'independent_A64_totals':dict(totals),'case_summaries':summaries,'boundary_classes':dict(boundaries),'all_checks_pass':True,'live_IDB_raw_bytes_verified':True,'live_IDB_automatic_analysis_complete':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_context_lock_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'independent_A64_totals':dict(totals)}),flush=True)
if __name__=='__main__':main()
