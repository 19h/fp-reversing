#!/usr/bin/env python3
"""Independent late prefix/hash/signature/pointer/packet and fresh source checks.

Six complete fresh original callback/worker sequences. All retained source
visits,selected byte epochs,raw file reads,SHA256 prefix outputs,width gates,
source-built public-operation pointers/status/extent/export and cleanups.
O(C*(B+V+E+S)) work/space plus bounded hashing/public-key arithmetic.
Two isolated analysis processes,not agents;no native target/API/IDB action.
"""
import base64,hashlib,json,multiprocessing,struct,subprocess,zlib
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
from daemon_receive_tools import IMAGE,SOURCE,ROOT,CS,verify_original_fixups
from daemon_import_bindings import binding
from recover_rpc502_parser_ownership import starts
from rpc502_startup_tools import unpack,journals,visits,certificate_view
from rpc502_rsa_models import integer_at
from probe_rpc502_late_cases import cases as control_cases,run_case
from probe_rpc502_late_spans import cases as span_cases
K=0x8b3dc651;BIAS=0x693be708;M=0xffffffff

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def fresh(c):return zlib.compress(json.dumps(run_case(c)[0],separators=(',',':')).encode())
def main():
 assertions=0;counts={n:0 for n in ['retained_source_visits','fresh_source_visits','fresh_runs','complete_worker_returns','prefix_source_bytes','signature_source_bytes','SHA256_prefix_outputs','matched_width_acceptances','matched_width_rejections','pointer_derivations','public_operation_calls','public_operation_successes','exported_public_output_bytes','observed_Montgomery_squares','observed_Montgomery_products','source_stack_bytes','source_heap_bytes','observed_late_calls','observed_call_returns','prefix_digest_frees']};summaries=[];pool={}
 def check(v,label):
  nonlocal assertions
  assert v,label;assertions+=1
 profiles=[json.loads((ROOT/n).read_text())for n in['rpc502_late_profiles.json','rpc502_late_span_profiles.json']];c=json.loads((ROOT/'rpc502_late_contracts.json').read_text());source_sha=sha(SOURCE)
 for obj,producer in zip(profiles+[c],['probe_rpc502_late_cases.py','probe_rpc502_late_spans.py','recover_rpc502_late.py']):
  check(obj['generator_sha256']==sha(ROOT/producer),'producer pin');check(obj['source_sha256']==source_sha=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e','source identity')
  for n,h in obj['dependencies'].items():check(sha(ROOT/n)==h,'dependency '+n)
 for obj in profiles:
  for e in obj['original_instruction_pool']:
   a=int(e['ea'],16);b=IMAGE.read(a,4);i=next(CS.disasm(b,a));check(b.hex()==e['bytes']and i.mnemonic==e['mnemonic']and i.op_str==e['operands'],'original opcode');check(a not in pool or pool[a]==struct.pack('<Q',a)+b,'consistent source pool');pool[a]=struct.pack('<Q',a)+b
 wrappers=[w for p in profiles for w in p['cases']];check([w['case']for w in wrappers]==control_cases()+span_cases(),'fresh external input definitions')
 for e in c['source_ranges']:
  a=int(e['start'],16);z=int(e['end'],16);b=IMAGE.read(a,z-a);check(b.hex()==e['bytes']and hashlib.sha256(b).hexdigest()==e['sha256'],'source span');check(e['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a)],'source disassembly')
 f,meta=starts();check(meta==c['LC_FUNCTION_STARTS'],'compiler starts')
 for e in c['compiler_ranges']:
  a=int(e['start'],16);j=f.index(a);check(f[j+1]==int(e['end'],16)and hashlib.sha256(IMAGE.read(a,f[j+1]-a)).hexdigest()==e['sha256'],'physical compiler interval')
 for e in c['consumed_pointer_import_records']:check((binding(int(e['slot'],16))if'slot'in e else verify_original_fixups([int(e['address'],16)])['records'][0])==e,'original fixup/import')
 for e in c['proofs']:
  path=ROOT/e['path'];check(sha(path)==e['sha256'],'proof pin');q=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);check(q.stdout.strip()=='unsat'and not q.stderr,'fresh local scalar proof')
 counter=c['width_modular_counterexample'];check(((int(counter['stored_count32'],16)-BIAS)*4)&M==counter['C32']==0,'independent modular scalar alias;not a worker fixture')
 sdk=c['sdk_compile'];check(sha(ROOT/'rpc502_late_layouts.c')==sdk['source_sha256']and sha(ROOT/'rpc502_late_layouts.s')==sdk['assembly_sha256'],'SDK pins');cmd=list(sdk['command']);cmd[-1]='/tmp/rpc502-late-verified-layout.s';q=subprocess.run(cmd,capture_output=True,text=True);check(q.returncode==0 and not q.stderr and sha(Path(cmd[-1]))==sdk['assembly_sha256'],'fresh SDK compile')
 with ProcessPoolExecutor(max_workers=2,mp_context=multiprocessing.get_context('spawn'))as ex:
  replays=ex.map(fresh,[w['case']for w in wrappers],buffersize=2)
  for w in wrappers:
   case=w['case'];r=unpack(w);events=[];total=0;check(r['late_generator_sha256']==sha(ROOT/'probe_rpc502_late.py'),'late observer pin');check(r['startup_returned']and r['stop_reason']=='returned_to_fixture'and r['records'][-1]['result']=='0xffff5bd9','complete original callback/worker return');counts['complete_worker_returns']+=1;check(not r['native_target_executed']and not r['target_host_ipc_files_or_system_calls_executed']and not r['idb_mutated']and not r['full_goal_complete'],'native boundary');check(r['declared_first_input_hex']==case['first_hex']and r['declared_second_file_bytes_hex']==case['second_hex'],'two original input declarations');check(not r['incomplete_late_call_indices'],'all captured calls return')
   for d in journals(r):
    seq=visits(d);check(len(seq)==d['source_visit_count'],'journal extent');h=hashlib.sha256()
    for a in seq:check(a in pool,'source visit');h.update(pool[a])
    check(h.hexdigest()==d['ordered_source_bytes_sha256'],'ordered original source bytes');total+=len(seq)
   counts['retained_source_visits']+=total;points={p['pc']:p for p in r['late_points']};start=r['late_points'][0]['step'];frame=int(r['late_frame'],16);raw=bytes.fromhex(case['second_hex']);A=case.get('A',0);extent=8+A;body=bytes.fromhex(case['body_hex']);D=12+A;signature_offset=D+len(body)+4;check(raw[D:D+len(body)]==body and struct.unpack_from('>I',raw,D+len(body))[0]==case['C'],'independent body/C wire layout');C=case['C'];accepted=C==128
   # Original carrier fields and local pointer equation.
   core=r['core_argument_calls'][0];P=int(core['pointer'],16);record=bytes.fromhex(core['prefix128_hex']);key=((P^0xc6d66014)*0x6b86592f)&M;u32=lambda off:struct.unpack_from('<I',record,off)[0];check((((u32(28)+key)&M)^K)==C and(((u32(8)^key)+0xd51c85f8)&M)==extent,'actual carrier C/prefix extent codec');aux=(u32(40)-key)&M
   p0=points['0x100a8b838'];regs=[int(v,16)for v in p0['registers31']];seed=regs[11]&M;fb=bytes.fromhex(p0['frame700_hex']);saved=struct.unpack_from('<I',fb,0x110)[0];expected=((((seed+0x83b4)&M)^0x8b3d25e5)+seed)&M;offset=(aux+seed+0xd59ecc1e-(saved==expected))&M;mapbase=struct.unpack_from('<Q',fb,0x138)[0];check(offset==signature_offset and mapbase==0x5300000000,'independent trailer pointer offset equation');p1=points['0x100a8b880'];check(int(p1['registers31'][8],16)==offset and int(p1['registers31'][9],16)==mapbase,'actual zero-extended pointer operands');p2=points['0x100a8b8b0'];signature_pointer=int(p2['registers31'][8],16);check(signature_pointer==mapbase+signature_offset,'actual constructed signature pointer');counts['pointer_derivations']+=1
   for p in [p0,points['0x100747f90']]:
    f0=bytes.fromhex(p['frame700_hex']);sp=int(p['sp'],16)
    for off,n in[(0x68,4),(0xec,4),(0x110,4),(0x138,8),(0x178,4)]:events.append((p['step'],sp+off,f0[off:off+n]))
   # Width comparison is checked independently of the obfuscated expression.
   a=points['0x100a21aac'];regs=[int(v,16)for v in a['registers31']];used=((regs[13]&M)-BIAS)&M;check(regs[12]&M==0x1daa and used==32,'actual source count and constrained dispatch seed');cmp=points['0x100a21ac0'];cr=[int(v,16)&M for v in cmp['registers31']];check((cr[13]==cr[14])==(C==((4*used)&M))==accepted,'actual width comparison versus independent4*n oracle');counts['matched_width_acceptances'if accepted else'matched_width_rejections']+=1
   # Exact file bytes consumed after late entry:prefix and conditional signature.
   reads=[e for e in r['body_mapping_reads']if e['step']>=start];prefix_reads=[e for e in reads if e['pc']=='0x100647ad8'];sig_reads=[e for e in reads if e['pc']=='0x10008eaf4'];check(len(reads)==len(prefix_reads)+len(sig_reads),'complete late mapping read classification');check([e['offset_bytes']for e in prefix_reads]==list(range(extent-1,-1,-1)),'exact signed-prefix input extent/order');check([e['offset_bytes']for e in sig_reads]==(list(range(signature_offset+127,signature_offset-1,-1))if accepted else[]),'signature extent/read gate/order')
   for e in reads:
    off=e['offset_bytes'];n=e['size_bytes'];check(n==1 and 0<=off and off+n<=len(raw)and e['bytes_hex']==raw[off:off+n].hex(),'actual source-mapping byte versus declared input')
   counts['prefix_source_bytes']+=len(prefix_reads);counts['signature_source_bytes']+=len(sig_reads)
   # Original allocation and source-write ledger;digest has independent SHA256 oracle.
   mallocs=[e for e in r['late_calls']if e['import_name']=='libSystem/_malloc'];check([int(e['registers31'][0],16)for e in mallocs]==[extent,32],'original prefix and digest allocation extents');owners={e['address']:e for e in r['final_owned_regions']};selected={e['returned_registers31'][0]:owners[e['returned_registers31'][0]]for e in mallocs};ledger={a:bytearray(v['size_bytes'])for a,v in selected.items()};known={a:bytearray(v['size_bytes'])for a,v in selected.items()}
   for d in journals(r):
    for e in d['owner_stores']:
     owner=e.get('owner')
     if owner not in ledger:continue
     off=e['offset_bytes'];b=bytes.fromhex(e['actual_after_hex']);check(0<=off and off+len(b)<=len(ledger[owner])and int(e['pc'],16)in pool,'selected source owner store');ledger[owner][off:off+len(b)]=b;known[owner][off:off+len(b)]=b'\1'*len(b)
   for owner,v in selected.items():check(all(known[owner])and ledger[owner].hex()==v['bytes_hex']and bytes.fromhex(v['known_mask_hex'])==bytes(known[owner]),'complete selected source-owned bytes');counts['source_heap_bytes']+=len(ledger[owner])
   digest_owner=mallocs[1]['returned_registers31'][0];digest=bytes(x^0x98 for x in ledger[digest_owner]);check(digest==hashlib.sha256(raw[:extent]).digest(),'independent SHA256 of exact raw prefix');counts['SHA256_prefix_outputs']+=1
   for owner in selected:check(sum(e['import_name']=='libSystem/_free'and e['registers31'][0]==owner for e in r['late_calls'])==1,'single source-requested retirement of prefix/digest');counts['prefix_digest_frees']+=1
   # Source-built80-byte partial public-operation view and actual source export.
   operations=[e for e in r['late_calls']if e['pc']=='0x100657488'];check(len(operations)==int(accepted),'width gates actual public-operation call');monts=[e for e in r['late_calls']if e['target']=='0x100539ea0'];montp=[e for e in r['late_calls']if e['target']=='0x10094593c'];check(len(monts)==(27 if accepted else 0)and len(montp)==(4 if accepted else 0),'observed zero-signature Montgomery call targets');counts['observed_Montgomery_squares']+=len(monts);counts['observed_Montgomery_products']+=len(montp)
   for op in operations:
    counts['public_operation_calls']+=1;check(op['target']=='0x100abebe4','actual public-operation wrapper');arg=int(op['registers31'][0],16);b=bytes.fromhex(op['pointed_views']['0']['bytes_hex']);certptr=int(p2['registers31'][11],16);v=p2['pointed_views']['11'];pseudo={'pointed_views':{'0':{'prefix':v,'nested_views':{}}}};modulus=integer_at(pseudo,certptr+0x210);exponent=integer_at(pseudo,certptr+0x320);cv=certificate_view(body);check(modulus['value']==int(cv['modulus_hex'],16)and exponent['value']==cv['exponent']==65537,'actual leaf public key');check(struct.unpack_from('<Q',b,8)[0]==certptr+0x320 and struct.unpack_from('<Q',b,32)[0]==certptr+0x210 and struct.unpack_from('<Q',b,64)[0]==signature_pointer,'actual input exponent/modulus/signature pointers');output=struct.unpack_from('<Q',b,56)[0];lengthptr=struct.unpack_from('<Q',b,40)[0]
    for off in[8,32,40,56,64]:events.append((op['step'],arg+off,b[off:off+8]))
    for value in[modulus,exponent]:
     for address,n in[(int(value['address'],16),16),(int(value['limb_pointer'],16),4*abs(value['signed_count']))]:
      off=address-certptr;events.append((p2['step'],address,bytes.fromhex(v['bytes_hex'])[off:off+n]))
    mem={}
    regions=[(arg+16,4),(output,128),(lengthptr,4)]
    for e in r['core_stack_stores']:
     if e['step_index']>op['return_step']:break
     address=int(e['address'],16)
     for j,value in enumerate(bytes.fromhex(e['actual_after_hex'])):
      if any(q<=address+j<q+n for q,n in regions):mem[address+j]=value
    status=bytes(mem.get(arg+16+j,0xcc)for j in range(4));encoded=bytes(mem.get(output+j,0xcc)for j in range(128));outn=bytes(mem.get(lengthptr+j,0xcc)for j in range(4));check(int.from_bytes(status,'little')==K and int.from_bytes(outn,'little')==128,'original status success and raw export extent');counts['public_operation_successes']+=1;decoded=bytes(x^0x98 for x in encoded);S=int.from_bytes(raw[signature_offset:signature_offset+128],'big');check(S==0 and int.from_bytes(decoded,'big')==pow(S,65537,modulus['value'])==0,'source export versus independent RSA public output');counts['exported_public_output_bytes']+=len(encoded)
    first=points['0x100950fd8'];sp=int(first['sp'],16);fb=bytes.fromhex(first['frame700_hex']);off=output-sp;check(0<=off and off+128<=len(fb)and fb[off:off+128]==encoded,'independent actual export snapshot versus source stores');events.append((first['step'],output,encoded));check(points['0x10095103c']['registers31'][14]=='0x74c29d8a','later padding/status reduction fails after math success');edges=[e for e in r['parser_edges']if e['pc']=='0x1006574cc'];check(int(edges[-1]['registers_x0_x28'][14],16)==K,'actual caller loaded success word')
   mem={};cursor=0;stores=r['core_stack_stores']
   for step,address,b in sorted(events):
    while cursor<len(stores)and stores[cursor]['step_index']<=step:
     e=stores[cursor];q=int(e['address'],16)
     for j,value in enumerate(bytes.fromhex(e['actual_after_hex'])):mem[q+j]=value
     cursor+=1
    for j,value in enumerate(b):check(mem.get(address+j)==value,'original source stack-byte epoch');counts['source_stack_bytes']+=1
   for call in r['late_calls']:check('return_step'in call and call['return_step']>call['step'],'actual observed call/return');counts['observed_late_calls']+=1;counts['observed_call_returns']+=1
   fr=json.loads(zlib.decompress(next(replays)));check(fr==r,'fresh complete canonical execution '+case['label']);counts['fresh_runs']+=1;counts['fresh_source_visits']+=sum(len(visits(d))for d in journals(fr));summaries.append({'case':case['label'],'A':A,'C':C,'selector':case['selector'],'steps':r['steps'],'source_visits':total,'hashed_prefix_extent_bytes':extent,'SHA256_hex':digest.hex(),'signature_offset_bytes':signature_offset,'signature_extent_bytes':128 if accepted else 0,'width_admitted':accepted,'public_operation_status':hex(K)if accepted else None,'public_output_zero':accepted,'worker_result':'0xffff5bd9'});print('VERIFIED',case['label'],assertions,flush=True)
 counts.update(assertions=assertions,cases=len(wrappers),original_instructions=len(pool),source_ranges=len(c['source_ranges']),compiler_ranges=len(c['compiler_ranges']),pointer_records=len(c['consumed_pointer_import_records']),proofs_unsat=len(c['proofs']))
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':source_sha,'dependencies':{n:sha(ROOT/n)for n in['rpc502_late_profiles.json','rpc502_late_span_profiles.json','rpc502_late_contracts.json','probe_rpc502_late.py','probe_rpc502_late_cases.py','probe_rpc502_late_spans.py','rpc502_rsa_models.py','rpc502_startup_tools.py']},'verified_counts':counts,'case_summaries':summaries,'native_target_executed':False,'all_checks_pass':True,'full_goal_complete':False};(ROOT/'rpc502_late_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
