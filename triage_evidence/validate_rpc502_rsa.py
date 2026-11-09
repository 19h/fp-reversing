#!/usr/bin/env python3
"""Independent modular arithmetic,row/carry,source epochs and fresh executions.

Checks every retained source visit;every selected full-call output and inner
row;RSA public output against Python pow;four complete fresh case replays.
O(C*(B+V+E+S)+rows) work/space,plus bounded key-size integer arithmetic.
No native target,trust,IOKit,Mach or IDB execution.
"""
import base64,hashlib,json,multiprocessing,struct,subprocess,zlib
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
from daemon_receive_tools import IMAGE,SOURCE,ROOT,CS,verify_original_fixups
from daemon_import_bindings import binding
from recover_rpc502_parser_ownership import starts
from rpc502_startup_tools import unpack,journals,visits,certificate_view,rsa_sha1_relation
from probe_rpc502_rsa_cases import run_case,cases
from rpc502_rsa_models import integer_arg,integer_at,memory,signed32,K,M

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def fresh(c):return zlib.compress(json.dumps(run_case(c)[0],separators=(',',':')).encode())
def main():
 assertions=0;counts={n:0 for n in ['retained_source_visits','fresh_source_visits','fresh_runs','complete_worker_returns','square_calls','product_calls','square_rows','product_rows','full_modular_products','certificate_key_records','source_stack_bytes','source_heap_bytes','RSA_public_outputs','matching_SHA1_encoded_messages']};summaries=[];pool={}
 def check(v,label):
  nonlocal assertions
  assert v,label;assertions+=1
 p=json.loads((ROOT/'rpc502_rsa_profiles.json').read_text());c=json.loads((ROOT/'rpc502_rsa_contracts.json').read_text());source_sha=sha(SOURCE)
 for obj,producer in [(p,'probe_rpc502_rsa_cases.py'),(c,'recover_rpc502_rsa.py')]:
  check(obj['generator_sha256']==sha(ROOT/producer),'producer pin');check(obj['source_sha256']==source_sha=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e','source identity')
  for n,h in obj['dependencies'].items():check(sha(ROOT/n)==h,'dependency '+n)
 check([w['case']for w in p['cases']]==cases(),'fresh fixture definitions')
 for e in p['original_instruction_pool']:
  a=int(e['ea'],16);b=IMAGE.read(a,4);i=next(CS.disasm(b,a));check(b.hex()==e['bytes']and i.mnemonic==e['mnemonic']and i.op_str==e['operands'],'source opcode');pool[a]=struct.pack('<Q',a)+b
 for e in c['source_ranges']:
  a=int(e['start'],16);z=int(e['end'],16);b=IMAGE.read(a,z-a);check(b.hex()==e['bytes']and hashlib.sha256(b).hexdigest()==e['sha256'],'source span');check(e['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a)],'source disassembly')
 f,meta=starts();check(meta==c['LC_FUNCTION_STARTS'],'compiler starts')
 for e in c['compiler_ranges']:
  a=int(e['start'],16);j=f.index(a);check(f[j+1]==int(e['end'],16)and hashlib.sha256(IMAGE.read(a,f[j+1]-a)).hexdigest()==e['sha256'],'physical compiler interval')
 for e in c['consumed_pointer_import_records']:check((binding(int(e['slot'],16))if'slot'in e else verify_original_fixups([int(e['address'],16)])['records'][0])==e,'original fixup/import')
 for e in c['proofs']:
  path=ROOT/e['path'];check(sha(path)==e['sha256'],'proof identity');q=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);check(q.stdout.strip()=='unsat'and not q.stderr,'fresh scalar proof')
 sdk=c['sdk_compile'];check(sha(ROOT/'rpc502_rsa_layouts.c')==sdk['source_sha256']and sha(ROOT/'rpc502_rsa_layouts.s')==sdk['assembly_sha256'],'SDK pins');cmd=list(sdk['command']);cmd[-1]='/tmp/rpc502-rsa-verified-layout.s';q=subprocess.run(cmd,capture_output=True,text=True);check(q.returncode==0 and not q.stderr and sha(Path(cmd[-1]))==sdk['assembly_sha256'],'fresh SDK compile')
 root=certificate_view((ROOT/'rpc502_startup_root.der').read_bytes());key=certificate_view((ROOT/'rpc502_startup_key_services.der').read_bytes());keys={int(v['modulus_hex'],16):v for v in [root,key]};valid_relation=rsa_sha1_relation(key,root);check(valid_relation['exact_equality'],'independent embedded certificate relation')
 with ProcessPoolExecutor(max_workers=2,mp_context=multiprocessing.get_context('spawn'))as ex:
  replays=ex.map(fresh,[w['case']for w in p['cases']],buffersize=2)
  for w in p['cases']:
   case=w['case'];r=unpack(w);events=[];calls=r['montgomery_calls'];call_summaries=[];check(r['rsa_generator_sha256']==sha(ROOT/'probe_rpc502_rsa.py'),'RSA observer pin');check(r['startup_returned']and r['stop_reason']=='returned_to_fixture'and r['records'][-1]['result']=='0xffff5bdb','original callback and worker return');counts['complete_worker_returns']+=1;check(r['pending_kernel_at_stop']is None,'no truncated kernel row');check(not r['native_target_executed']and not r['target_host_ipc_files_or_system_calls_executed']and not r['idb_mutated']and not r['full_goal_complete'],'execution boundary')
   def epoch(rec,step,address,n):
    if not n:return
    for q0 in rec['pointed_views'].values():
     for v in [q0['prefix'],*q0['nested_views'].values()]:
      a=int(v['address'],16);raw=bytes.fromhex(v['bytes_hex'])
      if a<=address and address+n<=a+len(raw):
       off=address-a;b=raw[off:off+n]
       if v['role']=='private_heap':check(bytes.fromhex(v['known_mask_hex'])[off:off+n]==b'\1'*n,'heap source-known bytes');counts['source_heap_bytes']+=n
       elif v['role']=='private_stack':events.append((step,address,b))
       else:raise AssertionError(('unexpected owner',v['role']))
       return
    raise AssertionError(('uncaptured epoch',hex(address),n))
   def checked_integer(rec,step,off):
    v=integer_arg(rec,off);epoch(rec,step,int(v['address'],16),16);epoch(rec,step,int(v['limb_pointer'],16),4*abs(v['signed_count']));return v
   total=0
   for d in journals(r):
    seq=visits(d);check(len(seq)==d['source_visit_count'],'journal extent');h=hashlib.sha256()
    for a in seq:check(a in pool,'source visit');h.update(pool[a])
    check(h.hexdigest()==d['ordered_source_bytes_sha256'],'ordered original source bytes');total+=len(seq)
   counts['retained_source_visits']+=total
   for j,call in enumerate(calls):
    kind=call['kind'];check(call['complete_return']and call['return_SP']==call['entry_SP'],'actual function return and restored SP');check(call['return_pc']==('0x10053dcb0'if kind=='square'else'0x100948024'),'actual adapter return address');check(int.from_bytes(bytes.fromhex(call['seed_after_hex']),'little')==(int.from_bytes(bytes.fromhex(call['seed_before_hex']),'little')+(0x70 if kind=='square'else 0xe0))&((1<<64)-1),'actual seed update')
    before=call['entry_record'];after=call['returned_record'];step=call['step'];ret=call['return_step'];a=checked_integer(before,step,24);n=checked_integer(before,step,32 if kind=='square'else 8);b=a if kind=='square'else checked_integer(before,step,40);out=checked_integer(after,ret,16);N=n['value'];R=1<<(32*abs(n['signed_count']));check(N in keys and N>1 and N&1,'exact decoded issuer modulus');check(out['value']==(a['value']*b['value']*pow(R,-1,N))%N,'independent complete Montgomery product');counts['full_modular_products']+=1
    arg=bytes.fromhex(before['prefix96_hex']);P=int(call['argument'],16);stored=struct.unpack_from('<I',arg,8 if kind=='square'else 32)[0];key0=((P^(0x7a9247f6 if kind=='square'else 0x966e5812))*(0x31b6b333 if kind=='square'else 0x592e2f77))&M;mode=(stored+key0)&M if kind=='square'else stored^key0;check(mode==(0x9d3a if kind=='square'else 0x973e),'decoded actual Montgomery mode');ctx=struct.unpack_from('<Q',arg)[0];ctxbytes=memory(before,ctx,20);epoch(before,step,ctx,20);n0=struct.unpack_from('<I',ctxbytes,16)[0];check(n0==(-pow(N&M,-1,1<<32))&M,'n0prime versus independent modular inverse');rp=struct.unpack_from('<Q',ctxbytes)[0];rv=integer_at(before,rp);check(rv['value']==R%N,'context radix integer');epoch(before,step,rp,16);epoch(before,step,int(rv['limb_pointer'],16),4*abs(rv['signed_count']))
    cols=len(call['row_columns']);raw=zlib.decompress(base64.b64decode(call['rows_zlib_base64']));check(len(raw)==8*cols*call['kernel_rows'],'row extent');const={int(k):int(v,16)for k,v in call.get('kernel_constants',{}).items()}
    if call['kernel_rows']:check(const[7 if kind=='square'else 14]==K and const[27 if kind=='square'else 21]==(2*K)&M,'source limb codec constants')
    for row in struct.iter_unpack('<'+'Q'*cols,raw):
     if kind=='square':
      x,y,w6,w3,w19,w30,t,av,nv,postx,posty,enc=row;ka=(((const[20]-0xf1d)&M)|w30)^const[12];wantx=(t^K)+(x>>32)+w6*(av^ka);wanty=(y>>32)+w3*(nv^K)+(wantx&M);src=(w19+const[22])&M;dst=(w19+const[28])&M
     else:
      x,y,w13,w10,w19,w6,w27,t,av,nv,w5,w15,x0,postx,posty,enc=row;mask=((((w5-0xdc7)&M)|w15)^x0);wantx=(t^K)+(x>>32)+w13*(av^K);wanty=(y>>32)+w10*(nv^K)+(wantx&mask);check(mask==M,'actual product low-word mask');src=(w19+w6)&M;dst=(w19+w27)&M
     check(1<=src<=63 and dst==src-1,'actual signed source/output limb indices');check(wantx==postx and wanty==posty and enc==(posty&M)^K,'independent exact multiply/carry/store row');counts[kind+'_rows']+=1
    counts[kind+'_calls']+=1;call_summaries.append({'kind':kind,'entry':call['entry'],'step':step,'return_step':ret,'N_sha256':hashlib.sha256(N.to_bytes(256,'big')).hexdigest(),'left_hex':hex(a['value']),'right_hex':hex(b['value']),'output_hex':hex(out['value']),'kernel_rows':call['kernel_rows'],'mode':hex(mode),'n0prime':hex(n0),'output_alias_left':out['address']==a['address']})
   # Selected parent public-key fields;active extents only,not whole unknown record.
   for point in r['rsa_points']:
    if point['pc']!='0x10097531c':continue
    v=point['X11_record600'];raw=bytes.fromhex(v['bytes_hex']);P=int(v['address'],16);pseudo={'pointed_views':{'0':{'prefix':v,'nested_views':{}}}}
    n=integer_at(pseudo,P+0x210);e=integer_at(pseudo,P+0x320);check(n['value']in keys and e['value']==keys[n['value']]['exponent']==65537,'actual parent public key versus DER');counts['certificate_key_records']+=1
    for value in [n,e]:epoch(pseudo,point['step'],int(value['address'],16),16);epoch(pseudo,point['step'],int(value['limb_pointer'],16),4*abs(value['signed_count']))
   # Groups separated by actual modulus;last product converts out with1.
   groups=[]
   for call,cs in zip(calls,call_summaries):
    if not groups or groups[-1][0]['N_sha256']!=cs['N_sha256']:groups.append([])
    groups[-1].append(cs)
   for gi,group in enumerate(groups):
    child=key if gi==0 else certificate_view(bytes.fromhex(case['body_hex']));issuer=root if gi==0 else key;N=int(issuer['modulus_hex'],16);S=int(child['signature_hex'],16);last=group[-1];check(last['kind']=='product'and int(last['right_hex'],16)==1,'source conversion out with1');em=int(last['output_hex'],16).to_bytes(256,'big');check(int.from_bytes(em,'big')==pow(S,65537,N),'full RSA public exponent output');counts['RSA_public_outputs']+=1
    digest=hashlib.sha1(bytes.fromhex(child['tbs_hex'])).digest();tail=bytes.fromhex('3021300906052b0e03021a05000414')+digest;expected=b'\0\1'+b'\xff'*(256-len(tail)-3)+b'\0'+tail
    if em==expected:counts['matching_SHA1_encoded_messages']+=1
    check((em==expected)==(gi==0),'valid embedded signature versus unsigned external signature')
   mem={};cursor=0;stores=r['core_stack_stores']
   for step,address,raw in sorted(events):
    while cursor<len(stores)and stores[cursor]['step_index']<step:
     s=stores[cursor];a=int(s['address'],16)
     for k,v in enumerate(bytes.fromhex(s['actual_after_hex'])):mem[a+k]=v
     cursor+=1
    for k,v in enumerate(raw):check(mem.get(address+k)==v,'last original stack-store epoch');counts['source_stack_bytes']+=1
   fr=json.loads(zlib.decompress(next(replays)));check(fr==r,'fresh canonical complete execution '+case['label']);counts['fresh_runs']+=1;counts['fresh_source_visits']+=sum(len(visits(d))for d in journals(fr));summaries.append({'case':case['label'],'steps':r['steps'],'source_visits':total,'calls':call_summaries,'RSA_groups':len(groups),'outer28_reads':sum(q['offset_bytes']==28 for q in r['core_argument_reads']),'worker_result':r['records'][-1]['result']});print('VERIFIED',case['label'],assertions,flush=True)
 counts.update(assertions=assertions,cases=len(p['cases']),original_instructions=len(pool),source_ranges=len(c['source_ranges']),compiler_ranges=len(c['compiler_ranges']),pointer_records=len(c['consumed_pointer_import_records']),proofs_unsat=len(c['proofs']))
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':source_sha,'dependencies':{n:sha(ROOT/n)for n in ['rpc502_rsa_profiles.json','rpc502_rsa_contracts.json','probe_rpc502_rsa.py','probe_rpc502_rsa_cases.py','rpc502_rsa_models.py','rpc502_rsa_fixtures.py','rpc502_startup_tools.py']},'verified_counts':counts,'case_summaries':summaries,'native_target_executed':False,'all_checks_pass':True,'full_goal_complete':False};(ROOT/'rpc502_rsa_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
