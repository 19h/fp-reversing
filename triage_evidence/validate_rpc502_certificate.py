#!/usr/bin/env python3
"""Independent certificate/TLV/digest/schema/atomic and full worker checks.

Original source opcodes/fixups/compiler metadata,local proofs,record byte epochs,
finite TLV oracle,standard digests and all fresh worker sequences. Four isolated
processes have bounded ordered results. O(C*(B+V+E+S)) time/space plus bounded
solver cost;no native target/API or IDB operations. Parsed is not authenticated.
"""
import base64,hashlib,json,multiprocessing,struct,subprocess,zlib
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
from daemon_receive_tools import IMAGE,SOURCE,ROOT,CS,FIXUPS,verify_original_fixups
from daemon_import_bindings import binding
from recover_rpc502_parser_ownership import starts
from probe_rpc502_certificate_cases import run_case
from rpc502_certificate_oracles import tlv_at,item_argument,callback_item,digest_oracles,BASE,K,MASK

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def unpack(w):return json.loads(zlib.decompress(base64.b64decode(w['payload_zlib_base64'])))
def visits(r):
 b=zlib.decompress(base64.b64decode(r['original_visits_zlib_base64']));return struct.unpack('<'+'Q'*(len(b)//8),b)
def fresh(case):return json.loads(json.dumps(run_case(case)[0]))

def main():
 assertions=0;counts={k:0 for k in ['retained_source_visits','fresh_source_visits','fresh_worker_runs','item_calls','successful_item_headers','rejected_item_headers','item_span_reads','schema_reads','schema_callbacks','parsed_item_records','source_stack_stores','digest_oracles','SHA1_outputs','MD5_outputs','zero_size_algorithm_contexts','digest_source_stores','complete_worker_returns','CPU_boundaries','CASAL_executions']}
 def check(v,label):
  nonlocal assertions
  assert v,label
  assertions+=1
 p=json.loads((ROOT/'rpc502_certificate_profiles.json').read_text());c=json.loads((ROOT/'rpc502_certificate_contracts.json').read_text());source_sha=sha(SOURCE);bank={};results={};summaries=[];hashes=[]
 for obj,generator in [(p,'probe_rpc502_certificate_cases.py'),(c,'recover_rpc502_certificate.py')]:
  check(obj['source_sha256']==source_sha=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e','original identity');check(obj['generator_sha256']==sha(ROOT/generator),'producer pin')
  for n,h in obj['dependencies'].items():check(sha(ROOT/n)==h,'dependency '+n)
 for e in p['original_instruction_pool']:
  a=int(e['ea'],16);raw=IMAGE.read(a,4);i=next(CS.disasm(raw,a));check(e['bytes']==raw.hex()and e['mnemonic']==i.mnemonic and e['operands']==i.op_str,'original opcode');bank[a]=raw
 for e in c['original_ranges']:
  a=int(e['start'],16);z=int(e['end'],16);raw=IMAGE.read(a,z-a);check(raw.hex()==e['bytes']and hashlib.sha256(raw).hexdigest()==e['sha256'],'bounded source bytes');check(e['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)],'original decoder')
 f,m=starts();check(m==c['LC_FUNCTION_STARTS'],'original compiler metadata')
 for e in c['compiler_ranges']:
  a=int(e['start'],16);j=f.index(a);check(f[j+1]==int(e['end'],16)and hashlib.sha256(IMAGE.read(a,f[j+1]-a)).hexdigest()==e['sha256'],'whole physical compiler range')
 for e in c['all_observed_pointer_fixups']:
  got=binding(int(e['slot'],16))if'slot'in e else verify_original_fixups([int(e['address'],16)])['records'][0];check(got==e,'independent consumed pointer/import decode')
 for e in c['schema_pointer_fixups']['records']:check(verify_original_fixups([int(e['address'],16)])['records'][0]==e,'schema authenticated source pointer')
 T=int(c['schema_base'],16);rows=c['schema_rows'];check(len(rows)==26 and c['schema_stride_bytes']==48,'closed root schema26')
 for row in rows:
  a=T+row['index']*48;b=IMAGE.read(a,48);w=struct.unpack('<12I',b);check(b.hex()==row['raw_hex']and(w[0]-0x5cbf4ba3)&MASK==int(row['decoded_tag'],16),'schema raw tag');check([(w[j]-0x3fcc2052)&MASK for j in[8,9]]==[0xffffffff if x is None else x for x in[row['child'],row['sibling']]],'schema child/sibling values');check((w[10]-0x2f9615c4)&MASK==int(row['decoded_flags'],16),'schema flag codec')
 for e in c['proofs']:
  path=ROOT/e['path'];check(sha(path)==e['sha256'],'proof bytes');r=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);check(r.stdout.strip()=='unsat'and not r.stderr,'fresh local proof '+e['path'])
 encoded=[int(x,16)for x in c['digest_initialization']['encoded_words']];check([x^0xf4f92df7 for x in encoded]==[int(x,16)for x in c['digest_initialization']['SHA1_IV']],'standard SHA1 IV match')
 sdk=c['sdk_compile'];check(sha(ROOT/'rpc502_certificate_layouts.c')==sdk['source_sha256']and sha(ROOT/'rpc502_certificate_layouts.s')==sdk['assembly_sha256'],'SDK artifacts');cmd=list(sdk['command']);cmd[-1]='/tmp/rpc502-certificate-verified-layout.s';rr=subprocess.run(cmd,capture_output=True,text=True);check(rr.returncode==0 and not rr.stderr and sha(Path(cmd[-1]))==sdk['assembly_sha256'],'fresh compile-only layout')
 with ProcessPoolExecutor(max_workers=4,mp_context=multiprocessing.get_context('spawn'))as executor:
  fresh_rows=executor.map(fresh,[w['case']for w in p['cases']],buffersize=4)
  for w in p['cases']:
   case=w['case'];label=case['label'];r=unpack(w);raw=bytes.fromhex(case['file_hex']);seq=visits(r);seqset=set(seq);d=hashlib.sha256();check(r['guest_source_opcodes_checked_each_visit']and len(seq)==r['original_visit_count'],'per-visit guest/source byte attestation')
   for a in seq:check(a in bank,'original instruction visit');d.update(struct.pack('<Q',a));d.update(bank[a])
   check(d.hexdigest()==r['original_ordered_bytes_sha256'],'ordered source digest');counts['retained_source_visits']+=len(seq);check(not r['native_target_executed']and not r['target_host_ipc_files_or_system_calls_executed']and not r['idb_mutated']and not r['full_goal_complete'],'native/IDB boundary');check(r['declared_second_file_bytes_hex']==case['file_hex']and r['fixture']==case['fixture'],'input and fixture pins');check(r['body_probe_generator_sha256']==sha(ROOT/'probe_rpc502_body.py'),'body observer pin')
   for call in r['body_helper_calls']:
    if call['helper']!='item_parser':continue
    counts['item_calls']+=1;arg=item_argument(call);check(int(call['argument_pointer'],16)&7==0 and arg['mode']==0x80d1,'observed aligned caller/mode');check('returned_view'in call,'actual item helper return');before=bytes.fromhex(call['entry_view']['prefix64_hex']);after=bytes.fromhex(call['returned_view']['prefix64_hex']);status=struct.unpack_from('<I',after,16)[0]^K;start=arg['input']-BASE+arg['cursor'];view=tlv_at(raw,start,max(0,arg['available']-arg['cursor']));check((status==0)==(view is not None),'independent finite header classification');out={e['slot_offset']:bytes.fromhex(e['bytes_hex'])for e in call['returned_view']['pointed_views']}
    if view is not None:
     check(int.from_bytes(out[24][:4],'little')^K==view['length'],'parsed length');check(int.from_bytes(out[32][:8],'little')==BASE+view['content'],'parsed content pointer');check(int.from_bytes(out[48][:4],'little')^0x21e8ae22==view['tag'],'parsed tag');check((int.from_bytes(out[56][:4],'little')-0x50af9a6f)&MASK==arg['cursor']+view['total'],'updated cumulative cursor');counts['successful_item_headers']+=1
    else:check(status==0xffff5bde,'tested helper error');counts['rejected_item_headers']+=1
   for e in r['item_span_reads']:check(e['within_span']and 0<=e['offset_bytes']and e['offset_bytes']+e['size_bytes']<=e['declared_span_bytes'],'actual bounded item read');counts['item_span_reads']+=1
   for e in r['schema_reads']:
    check(0<=e['row']<26 and int(e['pc'],16)in seqset,'original schema access');a=T+48*e['row']+e['offset_bytes'];n=e['size_bytes'];value=bytes.fromhex(e['bytes_hex'])
    if n==8 and a in FIXUPS:check(int.from_bytes(value,'little')==FIXUPS[a]['target'],'normalized callback target')
    else:check(IMAGE.read(a,n)==value,'exact table data read')
    counts['schema_reads']+=1
   for call in r['schema_callbacks']:
    check(call['entry']in{row['callback']for row in rows}and'return_step'in call,'source table callback and return');item=callback_item(call);ref=tlv_at(raw,item['start'],len(raw)-item['start']);check(ref is not None and all(item[k]==ref[k]for k in['tag','length','content','total']),'source-built parsed item32 ABI');counts['schema_callbacks']+=1;counts['parsed_item_records']+=1
   for e in r['core_stack_stores']:
    check(int(e['pc'],16)in seqset and len(bytes.fromhex(e['actual_after_hex']))==e['size_bytes'],'source stack byte epoch');counts['source_stack_stores']+=1
   for e in r['digest_context_writes']:
    check(int(e['pc'],16)in seqset and len(bytes.fromhex(e['actual_after_hex']))==e['size_bytes'],'source live digest store');counts['digest_source_stores']+=1
   for call in r['body_helper_calls']:
    if call['helper']!='container_helper':continue
    ptr=int(call['argument_pointer'],16);key=((ptr^0xf9d49974)*0xda51a827)&MASK;b0=bytes.fromhex(call['entry_view']['prefix64_hex']);b1=bytes.fromhex(call['returned_view']['prefix64_hex']);algorithm=(((struct.unpack_from('<I',b0,8)[0]^key)&511)^30);ctx=bytes.fromhex(next(v['bytes_hex']for v in call['returned_view']['pointed_views']if v['slot_offset']==16));check(struct.unpack_from('<I',ctx,96)[0]==algorithm and struct.unpack_from('<I',b1,4)[0]==0x8519bd23,'source initializer selector/result marker')
    if algorithm in[1,2]:check(list(struct.unpack_from('<'+str(4 if algorithm==1 else 5)+'I',ctx,72))==encoded[:4 if algorithm==1 else 5]and struct.unpack_from('<I',ctx,92)[0]==(16 if algorithm==1 else 20),'actual initial state and output-size context')
    else:check(algorithm==3 and struct.unpack_from('<I',ctx,92)[0]==0,'observed selector3 zero-size context;state words not assumed')
   oracle=digest_oracles(r,raw)
   for e in oracle:
    if e['output_size']==0:counts['zero_size_algorithm_contexts']+=1;continue
    check(len(e['hits'])==1,'independent standard digest sink');schema=next(x for x in r['schema_callbacks']if x['entry']==e['schema_entry']);check(all(schema['step']<=step<schema['return_step']for step in e['hits'][0]['last_store_steps']),'digest sink source epoch');counts['digest_oracles']+=1;counts['SHA1_outputs'if e['algorithm']==2 else'MD5_outputs']+=1
   hashes.append({'case':label,'oracles':oracle})
   for e in r['atomic_points']:
    check(e['pc']in['0x100a04c58','0x100a04c5c']and int(e['address'],16)==0x1010b5de0,'source CASAL word')
   if len(r['atomic_points'])==2:
    a,b=r['atomic_points'];old=int.from_bytes(bytes.fromhex(a['memory32_hex']),'little');new=int.from_bytes(bytes.fromhex(b['memory32_hex']),'little');expect=int(a['registers'][11],16)&MASK;desired=int(a['registers'][0],16)&MASK;check(int(b['registers'][11],16)&MASK==old and new==(desired if old==expect else old),'original CASAL private single-thread effect');counts['CASAL_executions']+=1
   if r['stop_reason']=='unicorn_error':check(label=='certificate_A72'and r['records'][-1]['pc']=='0x100a04c58','bounded unsupported CPU instruction');counts['CPU_boundaries']+=1
   else:check(r['stop_reason']=='returned_to_fixture','whole source worker return');counts['complete_worker_returns']+=1
   check(set(e['offset_bytes']for e in r['core_argument_reads'])<={0,4,16,24,36},'no parameter28 consumer on retained paths');freshr=next(fresh_rows);check(freshr==r,'full canonical-JSON fresh worker replay '+label);counts['fresh_worker_runs']+=1;counts['fresh_source_visits']+=freshr['original_visit_count'];results[label]=r;summaries.append({'case':label,'steps':r['steps'],'stop':r['stop_reason'],'result':r['records'][-1].get('result'),'item_calls':sum(e['helper']=='item_parser'for e in r['body_helper_calls']),'schema_callbacks':len(r['schema_callbacks']),'digest_oracles':sum(e['output_size']>0 for e in oracle)});print('VERIFIED',label,assertions,flush=True)
 a=results['certificate_A72'];b=results['certificate_empty_names'];x=visits(a);y=visits(b);check(x==y[:len(x)]and x[-1]==0x100a04c58,'complete A72/MAX original instruction prefix equality');check(a['atomic_points'][0]==b['atomic_points'][0],'identical pre-CASAL register/memory state')
 counts.update(cases=len(p['cases']),original_instructions=len(bank),original_ranges=len(c['original_ranges']),compiler_ranges=len(c['compiler_ranges']),original_pointer_records=len(c['all_observed_pointer_fixups']),schema_rows=26,local_proofs_unsat=len(c['proofs']),assertions=assertions)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':source_sha,'dependencies':{n:sha(ROOT/n)for n in ['rpc502_certificate_profiles.json','rpc502_certificate_contracts.json','probe_rpc502_body.py','probe_rpc502_certificate_cases.py','rpc502_body_fixtures.py','rpc502_certificate_oracles.py']},'verified_counts':counts,'case_summaries':summaries,'standard_digest_oracles':hashes,'CPU_prefix_equal_through_CASAL':True,'all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_certificate_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)

if __name__=='__main__':main()
