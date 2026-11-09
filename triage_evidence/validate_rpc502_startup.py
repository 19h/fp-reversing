#!/usr/bin/env python3
"""Independent source/state/arena/DER checks and all eight fresh phase replays.

Original opcode/fixup/compiler checks;every retained ordered source visit;
source-store reconstruction of private arena and both embedded certificates;
independent DER/OpenSSL/RSA/hash,ABI compile and local solver obligations.
Two isolated replay processes are analysis scheduling,not target concurrency.
O(C*(B+V+E+S)) bounded time/space plus integer pow and bounded solver work.
"""
import hashlib,json,multiprocessing,struct,subprocess
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
from daemon_receive_tools import IMAGE,SOURCE,ROOT,CS,POOL,TABLE,qword,verify_original_fixups
from daemon_import_bindings import binding
from recover_rpc502_parser_ownership import starts
from rpc502_startup_tools import unpack,journals,visits,certificate_view,rsa_sha1_relation
from probe_rpc502_startup_cases import run_case

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def fresh(c):return json.loads(json.dumps(run_case(c)[0]))

def main():
 assertions=0;counts={k:0 for k in ['retained_source_visits','fresh_source_visits','fresh_runs','startup_source_visits','worker_source_visits','startup_source_stack_stores','source_owner_stores','source_arena_store_checks','startup_API_models','readiness_reads','opaque_lock_initializations','timeval_actual_reads','outer_parameter28_reads','complete_worker_returns','completed_original_startup_callbacks','source_built_certificate_bytes','source_certificate_shift_bytes']};summaries=[];bank={};results={}
 def check(v,label):
  nonlocal assertions
  assert v,label;assertions+=1
 p=json.loads((ROOT/'rpc502_startup_profiles.json').read_text());c=json.loads((ROOT/'rpc502_startup_contracts.json').read_text());source_sha=sha(SOURCE)
 for obj,producer in [(p,'probe_rpc502_startup_cases.py'),(c,'recover_rpc502_startup.py')]:
  check(obj['generator_sha256']==sha(ROOT/producer),'producer pin');check(obj['source_sha256']==source_sha=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e','source pin')
  for n,h in obj['dependencies'].items():check(sha(ROOT/n)==h,'dependency '+n)
 for e in p['original_instruction_pool']:
  a=int(e['ea'],16);b=IMAGE.read(a,4);i=next(CS.disasm(b,a));check(b.hex()==e['bytes']and i.mnemonic==e['mnemonic']and i.op_str==e['operands'],'original instruction');bank[a]=struct.pack('<Q',a)+b
 for e in c['source_ranges']:
  a=int(e['start'],16);z=int(e['end'],16);b=IMAGE.read(a,z-a);check(b.hex()==e['bytes']and hashlib.sha256(b).hexdigest()==e['sha256'],'original bounded bytes');check(e['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a)],'source decode')
 f,meta=starts();check(meta==c['LC_FUNCTION_STARTS'],'original function metadata')
 for e in c['compiler_ranges']:
  a=int(e['start'],16);j=f.index(a);check(f[j+1]==int(e['end'],16)and hashlib.sha256(IMAGE.read(a,f[j+1]-a)).hexdigest()==e['sha256'],'physical compiler range')
 for e in c['consumed_pointer_import_records']:
  v=binding(int(e['slot'],16))if'slot'in e else verify_original_fixups([int(e['address'],16)])['records'][0];check(v==e,'independent pointer/import decode')
 b=c['ready_pointer_bank'];l=IMAGE.read(int(b['left'],16),256);r=IMAGE.read(int(b['right'],16),256);check(l.hex()==b['left256_hex']and r.hex()==b['right256_hex'],'pointer bank bytes')
 for e in b['inputs']:check(0xf53+(e['input']^r[l[e['input']]^0xbb])==e['index']==0x100e,'all256 readiness selector inputs')
 check((qword(POOL+8*0x100e)-0x29e8ab0e)&((1<<64)-1)==0x1010c5798,'readiness selected pointer+bias')
 check(verify_original_fixups([int(b['slot'],16)])==b['pointer_fixup'],'ready pointer source word')
 for e in c['local_dispatch_slots']:check(qword(TABLE+int(e['index'],16)*8)==int(e['target'],16)and verify_original_fixups([int(e['pointer']['address'],16)])['records'][0]==e['pointer'],'actual dispatch slot')
 for e in c['proofs']:
  path=ROOT/e['path'];check(sha(path)==e['sha256'],'proof pin');r=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);check(r.stdout.strip()=='unsat'and not r.stderr,'fresh local proof')
 sdk=c['sdk_compile'];check(sha(ROOT/'rpc502_startup_layouts.c')==sdk['source_sha256']and sha(ROOT/'rpc502_startup_layouts.s')==sdk['assembly_sha256'],'SDK artifact pin');cmd=list(sdk['command']);cmd[-1]='/tmp/rpc502-startup-verified-layout.s';r=subprocess.run(cmd,capture_output=True,text=True);check(r.returncode==0 and not r.stderr and sha(Path(cmd[-1]))==sdk['assembly_sha256'],'fresh compile-only SDK ABI')
 certs={}
 for e in c['embedded_certificates']:
  off=int(e['source_file_offset'],16);n=e['source_size_bytes'];enc=SOURCE.read_bytes()[off:off+n];decoded=bytes(x^0x98 for x in enc);der=decoded[4:];check(enc.hex()==e['source_encoded_hex']and IMAGE.read(int(e['source_VA'],16),n)==enc,'original encoded certificate bytes');check((ROOT/e['DER_path']).read_bytes()==der and sha(ROOT/e['DER_path'])==e['DER_sha256'],'decoded certificate artifact');view=certificate_view(der);check(view==e['certificate_view'],'independent DER byte layout');r=subprocess.run(e['independent_OpenSSL_command'],capture_output=True,text=True,check=True);check(r.stdout==e['independent_OpenSSL_output']and not r.stderr,'fresh independent OpenSSL parser');certs[e['label']]=e
 for rel in c['independent_RSA_SHA1_relations']:
  got=rsa_sha1_relation(certs[rel['child']]['certificate_view'],certs[rel['issuer']]['certificate_view']);check(all(got[k]==v for k,v in rel.items()if k in got)and got['exact_equality']and got['padding_ff_bytes']>=8,'independent integer RSA/digest byte relationship')
 with ProcessPoolExecutor(max_workers=2,mp_context=multiprocessing.get_context('spawn'))as ex:
  rows=ex.map(fresh,[w['case']for w in p['cases']],buffersize=2)
  for w in p['cases']:
   case=w['case'];label=case['label'];r=unpack(w);results[label]=r;js=list(journals(r));allstores=[];allwrites=[];allrecords=[];allseq=[]
   check(r['generator_sha256']==sha(ROOT/'probe_rpc502_startup.py'),'phase observer pin');check(not r['native_target_executed']and not r['target_host_ipc_files_or_system_calls_executed']and not r['idb_mutated']and not r['full_goal_complete'],'native/IDB boundary')
   for d in js:
    seq=visits(d);h=hashlib.sha256();check(len(seq)==d['source_visit_count'],'journal visit extent');allseq.extend(seq)
    for a in seq:check(a in bank,'attested original instruction visit');h.update(bank[a])
    check(h.hexdigest()==d['ordered_source_bytes_sha256'],'ordered source bytes digest');counts['retained_source_visits']+=len(seq);counts['startup_source_visits'if d['phase']=='startup'else'worker_source_visits']+=len(seq)
    for e in d['owner_stores']:check(int(e['pc'],16)in bank and len(bytes.fromhex(e['actual_after_hex']))==e['size_bytes'],'source-owned store byte epoch');counts['source_owner_stores']+=1
    if d['phase']=='startup':
     for e in d['stack_stores']:check(int(e['pc'],16)in bank and len(bytes.fromhex(e['actual_after_hex']))==e['size_bytes'],'startup source stack-store byte epoch');counts['startup_source_stack_stores']+=1
    allstores.extend(d['owner_stores']);allwrites.extend(d['image_writes']);allrecords.extend(d['records'])
    for e in d['records']:
     if e['kind']!='startup_declared_API_model':continue
     counts['startup_API_models']+=1;check(not e['native_API_executed'],'declared API only')
     if e['name']=='libSystem/_pthread_rwlock_init':
      mask=bytes.fromhex(e['before_known_mask_hex']);b=bytes.fromhex(e['before_bytes_hex']);startup=e['phase']=='startup';check(e['owner_extent_bytes']==e['object_extent_bytes']==len(b)==len(mask)==200 and mask==(b'\1'*8+b'\0'*192 if startup else b'\1'*200)and b==(bytes(8)+b'\xa5'*192 if startup else bytes(200))and e['opaque_native_bytes_not_synthesized'],'opaque200 lock;startup8 known versus worker200 known');counts['opaque_lock_initializations']+=1
   # Independently rebuild every big-arena byte and source-knownness bit.
   for o in r['final_owned_regions']:
    if o['size_bytes']!=90000:continue
    data=bytearray([0xa5])*90000;known=bytearray(90000)
    for d in js:
     for e in d['owner_stores']:
      if e['owner']!=o['address']:continue
      off=e['offset_bytes'];raw=bytes.fromhex(e['actual_after_hex']);check(0<=off and off+len(raw)<=90000,'arena source extent');data[off:off+len(raw)]=raw;known[off:off+len(raw)]=b'\1'*len(raw);counts['source_arena_store_checks']+=1
     if d['phase']=='startup'and d.get('stop_reason')=='original_startup_callback_returned':
      s=next(v for v in r['startup_snapshot']['heap_owners']if v['address']==o['address']);check(data.hex()==s['bytes_hex']and known.hex()==s['known_mask_hex'],'complete startup arena byte/mask reconstruction')
    check(data.hex()==o['bytes_hex']and known.hex()==o['known_mask_hex'],'complete final arena byte/mask reconstruction')
   if r['startup_returned']:
    check(any(e['kind']=='original_callback_return'for e in r['startup_events'])and r['startup_snapshot']['SP']=='0x70078000','actual original callback returned with restored SP');counts['completed_original_startup_callbacks']+=1
   for e in r['readiness_reads']:check(e['address']=='0x1010c5798'and e['size_bytes']==1 and e['bytes_hex']in ['00','01'],'actual byte gate read');counts['readiness_reads']+=1
   for e in r['timeval_observations']:
    for q in e['reads']:
     check(q['pc']in ['0x1002dc30c','0x1002dc334']and q['size_bytes']==4 and int(q['address'],16)-int(e['pointer'],16)in[0,8],'actual low32 seconds/usec reads;no native padding');counts['timeval_actual_reads']+=1
   for e in r['core_argument_reads']:
    if e['offset_bytes']<32 and e['offset_bytes']+e['size_bytes']>28:counts['outer_parameter28_reads']+=1
   check(counts['outer_parameter28_reads']==0,'outer parameter28 remains unconsumed')
   if r['stop_reason']=='returned_to_fixture':counts['complete_worker_returns']+=1
   if label=='initialized_worker':
    check(r['records'][-1]['result']=='0xffff5bdb'and r['startup_returned'],'complete initialized source worker result')
    for labelcert,e in certs.items():
     own=next(o for o in r['final_owned_regions']if o['allocation_pc']=='0x100346714'and o['size_bytes']==e['source_size_bytes']);prefix=bytes(x^0x98 for x in bytes.fromhex(e['source_encoded_hex']));first=[s for s in allstores if s['owner']==own['address']and s['pc']=='0x1003f0e5c'];shift=[s for s in allstores if s['owner']==own['address']and s['pc']=='0x10030980c'];check([s['offset_bytes']for s in first]==list(range(len(prefix)-1,-1,-1)),'whole descending source XOR-copy epoch');check([s['offset_bytes']for s in shift]==list(range(len(prefix)-4)),'whole ascending source shift epoch')
     for s in first:check(s['actual_after_hex']==prefix[s['offset_bytes']:s['offset_bytes']+1].hex(),'every source-built certificate byte');counts['source_built_certificate_bytes']+=1
     for s in shift:check(s['actual_after_hex']==prefix[s['offset_bytes']+4:s['offset_bytes']+5].hex(),'every source-shifted DER byte');counts['source_certificate_shift_bytes']+=1
     expected=prefix[4:]+prefix[-4:];check(own['bytes_hex']==expected.hex()and own['known_mask_hex']=='01'*len(prefix),'complete output epoch including residual tail');roots=[q for q in r['schema_callbacks']if q['entry']=='0x10040f7a4'and int.from_bytes(bytes.fromhex(q['x1_view']['prefix64_hex'])[24:32],'little')==int(own['address'],16)];check(len(roots)==1,'original root callback parsed each embedded output')
    gate=[q for q in r['readiness_points']if q['pc']=='0x100a03450'];check(len(gate)==2 and all(q['registers'][8]=='0x1006521d4'for q in gate),'two actual ready continuations');ps=[int(q['registers'][25],16)for q in r['readiness_points']if q['pc']=='0x1009757d0'];check(ps==[0x5000014bec,0x5000014564]and all(0x5000000000<=a<0x5000000000+90000 for a in ps),'actual original arena result carriers')
   elif label=='cold_worker':check(r['records'][-1]['result']=='0xffff5bd4'and not r['startup_returned']and r['final_readiness_hex']=='00','cold readiness failure')
   elif label=='arena_malloc_NULL':check(r['stop_reason']=='unicorn_error'and any(e.get('pc')=='0x10032a55c'for e in allrecords if e['kind']=='engine_error'),'source NULL-write boundary')
   elif label=='time_failure':check(r['stop_reason']=='unknown_timeval_output_read'and not r['startup_returned']and r['final_readiness_hex']=='01','unknown failed-API output blocked')
   elif label=='lock_init_failure':check(r['stop_reason']=='unicorn_error'and any(e.get('pc')=='0x1003868d8'for e in allrecords if e['kind']=='engine_error'),'bounded original lock-failure continuation')
   elif label=='startup_budget':check(r['stop_reason']=='startup_instruction_budget'and not r['startup_returned']and r['final_readiness_hex']=='01'and not any(e['kind']=='worker_ABI_fixture_entry'for e in r['startup_events']),'incomplete startup never enters worker')
   else:check(r['stop_reason']=='instruction_budget'and r['startup_returned'],'declared worker prefix bound')
   fr=next(rows);check(fr==r,'fresh canonical JSON full source replay '+label);counts['fresh_runs']+=1;counts['fresh_source_visits']+=sum(len(visits(d))for d in journals(fr));summaries.append({'case':label,'steps':r['steps'],'source_visits':len(allseq),'stop':r['stop_reason'],'startup_returned':r['startup_returned'],'ready_hex':r['final_readiness_hex'],'startup_status_hex':r['final_startup_status_hex'],'last_worker_result':r['records'][-1].get('result')if r['records']else None});print('VERIFIED',label,assertions,flush=True)
 a=results['initialized_worker'];b=results['quantum250k_prefix'];seq=lambda r:[a for d in journals(r)for a in visits(d)];x=seq(a);y=seq(b);check(x[:len(y)]==y,'all original source visits invariant under quantum subdivision');check(a['startup_snapshot']==b['startup_snapshot']and a['readiness_points']==b['readiness_points']and a['startup_events']==b['startup_events'],'identical startup and ready result state under quantum subdivision');check(results['entropy_time_prefix']['startup_snapshot']['heap_owners']!=a['startup_snapshot']['heap_owners'],'declared entropy/time variation changes actual source state')
 counts.update(assertions=assertions,cases=len(p['cases']),original_instructions=len(bank),source_ranges=len(c['source_ranges']),compiler_ranges=len(c['compiler_ranges']),pointer_records=len(c['consumed_pointer_import_records']),local_proofs_unsat=len(c['proofs']),pointer_selector_inputs=256,embedded_certificates=2,independent_RSA_SHA1_relations=2)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':source_sha,'dependencies':{n:sha(ROOT/n)for n in ['rpc502_startup_profiles.json','rpc502_startup_contracts.json','probe_rpc502_startup.py','probe_rpc502_startup_cases.py','rpc502_startup_tools.py']},'verified_counts':counts,'case_summaries':summaries,'quantum_subdivision_source_prefix_equal':True,'native_target_executed':False,'all_checks_pass':True,'full_goal_complete':False};(ROOT/'rpc502_startup_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)

if __name__=='__main__':main()
