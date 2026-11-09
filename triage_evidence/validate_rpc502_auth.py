#!/usr/bin/env python3
"""Independent issuer/extent/status/tail/DER checks and six fresh source runs.

Every retained original instruction visit;source store epochs for stack reads;
original fixed DN,DER-based issuer oracle,signature bytes and SHA1 TBS digest;
all41 classified certificates/fresh scan/OpenSSL and47 RSA/hash relationships.
O(C*(B+V+E+S)+inventory) bounded time/space plus solvers and integer pow.
Two analysis processes;no native target/API/IDB execution.
"""
import hashlib,json,multiprocessing,struct,subprocess
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
from daemon_receive_tools import IMAGE,SOURCE,ROOT,CS,verify_original_fixups
from daemon_import_bindings import binding
from recover_rpc502_parser_ownership import starts
from rpc502_startup_tools import unpack,journals,visits,certificate_view
from rpc502_auth_models import K,E,D,status_oracle,name_text,tail_view
from probe_rpc502_auth_cases import run_case
from scan_rpc502_auth_certificates import build

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def fresh(c):return json.loads(json.dumps(run_case(c)[0]))

def main():
 assertions=0;counts={n:0 for n in ['retained_source_visits','fresh_source_visits','fresh_runs','complete_worker_returns','comparison_bytes','comparison_next_index_guards','source_stack_read_bytes','source_tail_bytes','verification_tail_records','successful_local_combiners','failed_local_combiners','first_status_checks','outer_parameter28_reads','multiplier_loop_visits']};summaries=[];pool={}
 def check(v,label):
  nonlocal assertions
  assert v,label;assertions+=1
 p=json.loads((ROOT/'rpc502_auth_profiles.json').read_text());c=json.loads((ROOT/'rpc502_auth_contracts.json').read_text());inventory=json.loads((ROOT/'rpc502_auth_certificate_inventory.json').read_text());source_sha=sha(SOURCE)
 for obj,producer in [(p,'probe_rpc502_auth_cases.py'),(c,'recover_rpc502_auth.py'),(inventory,'scan_rpc502_auth_certificates.py')]:
  check(obj['generator_sha256']==sha(ROOT/producer),'producer pin');check(obj['source_sha256']==source_sha=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e','source identity')
  for n,h in obj['dependencies'].items():check(sha(ROOT/n)==h,'dependency '+n)
 for e in p['original_instruction_pool']:
  a=int(e['ea'],16);b=IMAGE.read(a,4);i=next(CS.disasm(b,a));check(b.hex()==e['bytes']and i.mnemonic==e['mnemonic']and i.op_str==e['operands'],'original opcode');pool[a]=struct.pack('<Q',a)+b
 for e in c['source_ranges']:
  a=int(e['start'],16);z=int(e['end'],16);b=IMAGE.read(a,z-a);check(b.hex()==e['bytes']and hashlib.sha256(b).hexdigest()==e['sha256'],'bounded source bytes');check(e['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a)],'source disassembly')
 f,m=starts();check(m==c['LC_FUNCTION_STARTS'],'compiler metadata')
 for e in c['compiler_ranges']:
  a=int(e['start'],16);j=f.index(a);check(f[j+1]==int(e['end'],16)and hashlib.sha256(IMAGE.read(a,f[j+1]-a)).hexdigest()==e['sha256'],'physical compiler interval')
 for e in c['consumed_pointer_import_records']:check((binding(int(e['slot'],16))if'slot'in e else verify_original_fixups([int(e['address'],16)])['records'][0])==e,'independent original fixup/import')
 for e in c['proofs']:
  path=ROOT/e['path'];check(sha(path)==e['sha256'],'proof bytes');r=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);check(r.stdout.strip()=='unsat'and not r.stderr,'fresh local scalar proof')
 counter=c['status_full_word_counterexample'];check(status_oracle(int(counter['saved32'],16),int(counter['prior32'],16))==int(counter['result32'],16)==K and int(counter['saved32'],16)!=0,'independent full-word counterexample;not a target fixture')
 sdk=c['sdk_compile'];check(sha(ROOT/'rpc502_auth_layouts.c')==sdk['source_sha256']and sha(ROOT/'rpc502_auth_layouts.s')==sdk['assembly_sha256'],'SDK artifacts');cmd=list(sdk['command']);cmd[-1]='/tmp/rpc502-auth-verified-layout.s';r=subprocess.run(cmd,capture_output=True,text=True);check(r.returncode==0 and not r.stderr and sha(Path(cmd[-1]))==sdk['assembly_sha256'],'fresh compile-only ABI')
 fixed=c['fixed_issuer_DN'];encoded=IMAGE.read(int(fixed['source_address'],16),fixed['size_bytes']);expected=bytes(x^0x81 for x in encoded);check(encoded.hex()==fixed['original_encoded_hex']and expected.decode('ascii')==fixed['decoded_ascii_including_NUL'],'source fixed DN bytes');expected=expected[:-1];keyview=certificate_view((ROOT/'rpc502_startup_key_services.der').read_bytes());check(name_text(keyview,'subject')==expected,'original Key Services subject/name relation')
 check(build()==inventory,'fresh complete classifier scan and public RSA/hash relationships')
 for entry in inventory['records']:
  off=int(entry['file_offset'],16);n=entry['size_bytes'];xor=int(entry['XOR_byte'],16);raw=bytes(x^xor for x in SOURCE.read_bytes()[off:off+n]);check(hashlib.sha256(raw).hexdigest()==entry['DER_sha256'],'inventory source decode');tmp=Path('/tmp/rpc502-auth-inventory-check.der');tmp.write_bytes(raw);r=subprocess.run(['/usr/bin/openssl','x509','-inform','DER','-in',str(tmp),'-noout','-subject','-issuer'],capture_output=True,text=True,check=True);lines=r.stdout.splitlines();check(lines==['subject= '+name_text(entry['certificate'],'subject').decode(),'issuer= '+name_text(entry['certificate'],'issuer').decode()]and not r.stderr,'independent OpenSSL Name parse')
 with ProcessPoolExecutor(max_workers=2,mp_context=multiprocessing.get_context('spawn'))as ex:
  fresh_rows=ex.map(fresh,[w['case']for w in p['cases']],buffersize=2)
  for w in p['cases']:
   case=w['case'];label=case['label'];r=unpack(w);body=bytes.fromhex(case['body_hex']);v=certificate_view(body);issuer=name_text(v,'issuer');accepted=not issuer or expected.startswith(issuer);js=list(journals(r));events=[]
   check(r['auth_generator_sha256']==sha(ROOT/'probe_rpc502_auth.py')and r['generator_sha256']==sha(ROOT/'probe_rpc502_startup.py'),'observer/engine pins');check(r['startup_returned']and r['stop_reason']=='returned_to_fixture'and r['records'][-1]['result']=='0xffff5bdb','actual callback and worker return');counts['complete_worker_returns']+=1
   check(not r['native_target_executed']and not r['target_host_ipc_files_or_system_calls_executed']and not r['idb_mutated']and not r['full_goal_complete'],'native/IDB boundary')
   total=0
   for d in js:
    seq=visits(d);check(len(seq)==d['source_visit_count'],'source visit extent');h=hashlib.sha256()
    for a in seq:check(a in pool,'original source visit');h.update(pool[a])
    check(h.hexdigest()==d['ordered_source_bytes_sha256'],'ordered original source byte digest');counts['retained_source_visits']+=len(seq);total+=len(seq)
   points=r['auth_points'];guards=[a for a in points if a['pc']=='0x10064b420'];reads=[a for a in r['auth_reads']if a['pc']in['0x100a46fc0','0x100a46fc8']];check(len(reads)%2==0,'paired original byte loads');pairs=[reads[j:j+2]for j in range(0,len(reads),2)];nread=len(issuer)if accepted else next(i+1 for i,(a,b)in enumerate(zip(issuer,expected))if a!=b);check(len(pairs)==nread,'independent exact prefix comparison extent')
   for i,(a,b)in enumerate(pairs):
    check(a['pc']=='0x100a46fc0'and b['pc']=='0x100a46fc8'and a['size_bytes']==b['size_bytes']==1 and a['bytes_hex']==issuer[i:i+1].hex()and b['bytes_hex']==encoded[i:i+1].hex(),'actual rendered issuer versus original encoded literal byte');check((int(a['bytes_hex'],16)^int(b['bytes_hex'],16)==0x81)==(issuer[i]==expected[i]),'signed/unsigned byte equality oracle');counts['comparison_bytes']+=1
   for a in guards:
    regs=[int(x,16)for x in a['registers']];i=(regs[9]+1)&((1<<64)-1);L=(regs[10]-D)&((1<<64)-1);check(L==len(issuer)and 1<=i<=len(issuer),'actual biased extent/index ABI;first byte entered separately');counts['comparison_next_index_guards']+=1
   errors=[a for a in points if a['pc']=='0x10076d170'];check(len(errors)==(0 if accepted else 1),'issuer rejection source producer')
   tails=[a for a in points if a['pc']=='0x10097531c'];check(len(tails)==(2 if accepted else 0),'issuer selection gates later record comparisons')
   for j,a in enumerate(tails):
    t=tail_view(a);ref=keyview if j==0 else v;check(t['signature_size_bytes']==len(bytes.fromhex(ref['signature_hex']))and t['signature_raw_hex']==ref['signature_hex'],'source raw signature bytes/encoded extent');check(t['digest_size_bytes']==20 and t['digest_decoded_hex']==hashlib.sha1(bytes.fromhex(ref['tbs_hex'])).hexdigest(),'source digest bytes versus independent TBS SHA1');check((j!=0 or(t['child_record']=='0x5000014564'and t['issuer_record']=='0x5000014bec'))and(j!=1 or t['issuer_record']=='0x5000014564'),'actual record-carrier sequence');counts['verification_tail_records']+=1;counts['source_tail_bytes']+=t['signature_size_bytes']+28
    raw=bytes.fromhex(t['raw_view']['bytes_hex']);p0=int(t['raw_view']['address'],16)
    for off,n in [(0,t['signature_size_bytes']),(256,28)]:
     if t['raw_view']['role']=='private_stack':events.append((a['step'],p0+off,raw[off:off+n]))
     else:check(bytes.fromhex(t['raw_view']['known_mask_hex'])[off:off+n]==b'\1'*n,'heap tail knownness')
   status_points=[a for a in points if a['pc']=='0x100896930'];outputs=[a for a in points if a['pc']=='0x1008969a8'];check(len(status_points)==len(outputs)==len(tails),'local status input/output pairing')
   for a,b in zip(status_points,outputs):
    saved=struct.unpack_from('<I',bytes.fromhex(a['frame_prefix500_hex']),0x2e4)[0];prior=int(a['registers'][14],16)&0xffffffff;want=status_oracle(saved,prior);check(int(b['registers'][1],16)==want,'actual low-byte status conjunction');counts['successful_local_combiners'if want==K else'failed_local_combiners']+=1
   first=[a for a in points if a['pc']=='0x100950fd8'];firstout=[a for a in points if a['pc']=='0x10095103c'];check(len(first)==len(firstout)==(1 if accepted else 0),'first status stage source pairing')
   for a,b in zip(first,firstout):
    regs=[int(x,16)for x in a['registers']];check(regs[9]==regs[10]==1 and int(b['registers'][14],16)==(K if regs[8]&255==0xa2 else E),'actual raw-byte status reduction with observed seed1/1');counts['first_status_checks']+=1
   for q in r['auth_reads']:
    if q['owner_view']and q['owner_view']['role']=='private_stack':events.append((q['step'],int(q['address'],16),bytes.fromhex(q['bytes_hex'])))
   # Actual stack bytes must have an original source-store epoch before use.
   mem={};cursor=0;stores=r['core_stack_stores']
   for step,address,raw in sorted(events):
    while cursor<len(stores)and stores[cursor]['step_index']<step:
     s=stores[cursor];p0=int(s['address'],16)
     for j,value in enumerate(bytes.fromhex(s['actual_after_hex'])):mem[p0+j]=value
     cursor+=1
    for j,value in enumerate(raw):check(mem.get(address+j)==value,'source-defined stack byte at actual read/record epoch');counts['source_stack_read_bytes']+=1
   for q in r['core_argument_reads']:
    if q['offset_bytes']<32 and q['offset_bytes']+q['size_bytes']>28:counts['outer_parameter28_reads']+=1
   check(counts['outer_parameter28_reads']==0,'outer28 still unconsumed');counts['multiplier_loop_visits']+=r['multiply_visits'];check((r['multiply_visits']>0)==accepted,'later multiply/accumulate reachability')
   fr=next(fresh_rows);check(fr==r,'fresh canonical JSON whole callback/worker replay '+label);counts['fresh_runs']+=1;counts['fresh_source_visits']+=sum(len(visits(d))for d in journals(fr));summaries.append({'case':label,'issuer_ascii':issuer.decode(),'prefix_or_empty_admitted':accepted,'steps':r['steps'],'source_visits':total,'comparison_bytes':len(pairs),'verification_records':len(tails),'multiplier_visits':r['multiply_visits'],'worker_result':'0xffff5bdb'});print('VERIFIED',label,assertions,flush=True)
 counts.update(assertions=assertions,cases=len(p['cases']),original_instructions=len(pool),source_ranges=len(c['source_ranges']),compiler_ranges=len(c['compiler_ranges']),pointer_records=len(c['consumed_pointer_import_records']),proofs_unsat=len(c['proofs']),classifier_candidates=inventory['classified_candidates'],classified_certificates=len(inventory['records']),unique_DER=inventory['unique_DER_count'],unique_RSA_keys=inventory['unique_RSA_key_count'],inventory_signature_relations=len(inventory['same_Name_signature_relations']),matching_inventory_relations=inventory['matching_relations'])
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':source_sha,'dependencies':{n:sha(ROOT/n)for n in ['rpc502_auth_profiles.json','rpc502_auth_contracts.json','rpc502_auth_certificate_inventory.json','probe_rpc502_auth.py','probe_rpc502_auth_cases.py','rpc502_auth_fixtures.py','rpc502_auth_models.py','scan_rpc502_auth_certificates.py']},'verified_counts':counts,'case_summaries':summaries,'native_target_executed':False,'all_checks_pass':True,'full_goal_complete':False};(ROOT/'rpc502_auth_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)

if __name__=='__main__':main()
