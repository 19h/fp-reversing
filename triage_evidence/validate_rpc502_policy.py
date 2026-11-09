#!/usr/bin/env python3
"""Independent late-field,public-key/status,source-byte and fresh-case checks.

Three complete original callback/worker replays;all source visits and selected
stack byte epochs. File inputs precede every guest instruction. Complexity
O(C*(B+V+E+S)) plus bounded modular exponentiation. No native target/API/IDB.
"""
import base64,hashlib,json,multiprocessing,struct,subprocess,zlib
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
from daemon_receive_tools import IMAGE,SOURCE,ROOT,CS,verify_original_fixups
from daemon_import_bindings import binding
from recover_rpc502_parser_ownership import starts
from rpc502_startup_tools import unpack,journals,visits,certificate_view,rsa_sha1_relation
from rpc502_auth_models import tail_view,K
from rpc502_rsa_models import integer_at
from probe_rpc502_policy_cases import cases,run_case
M=0xffffffff

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def fresh(c):return zlib.compress(json.dumps(run_case(c)[0],separators=(',',':')).encode())
def main():
 assertions=0;counts={n:0 for n in ['retained_source_visits','fresh_source_visits','fresh_runs','complete_worker_returns','valid_certificate_relations','actual_parent_key_records','actual_child_key_records','successful_local_statuses','failed_later_first_statuses','outer28_reads','outer40_reads','outer8_reads','observed_common_allocation_calls','source_stack_bytes','source_heap_bytes']};summaries=[];pool={}
 def check(v,label):
  nonlocal assertions
  assert v,label;assertions+=1
 p=json.loads((ROOT/'rpc502_policy_profiles.json').read_text());c=json.loads((ROOT/'rpc502_policy_contracts.json').read_text());source_sha=sha(SOURCE)
 for obj,producer in [(p,'probe_rpc502_policy_cases.py'),(c,'recover_rpc502_policy.py')]:
  check(obj['generator_sha256']==sha(ROOT/producer),'producer pin');check(obj['source_sha256']==source_sha=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e','source identity')
  for n,h in obj['dependencies'].items():check(sha(ROOT/n)==h,'dependency '+n)
 check([w['case']for w in p['cases']]==cases(),'fresh complete external fixtures')
 for e in p['original_instruction_pool']:
  a=int(e['ea'],16);b=IMAGE.read(a,4);i=next(CS.disasm(b,a));check(b.hex()==e['bytes']and i.mnemonic==e['mnemonic']and i.op_str==e['operands'],'source opcode');pool[a]=struct.pack('<Q',a)+b
 for e in c['source_ranges']:
  a=int(e['start'],16);z=int(e['end'],16);b=IMAGE.read(a,z-a);check(b.hex()==e['bytes']and hashlib.sha256(b).hexdigest()==e['sha256'],'source span');check(e['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a)],'source disassembly')
 f,meta=starts();check(meta==c['LC_FUNCTION_STARTS'],'compiler starts')
 for e in c['compiler_ranges']:
  a=int(e['start'],16);j=f.index(a);check(f[j+1]==int(e['end'],16)and hashlib.sha256(IMAGE.read(a,f[j+1]-a)).hexdigest()==e['sha256'],'physical compiler interval')
 for e in c['consumed_pointer_import_records']:check((binding(int(e['slot'],16))if'slot'in e else verify_original_fixups([int(e['address'],16)])['records'][0])==e,'original fixup/import')
 sdk=c['sdk_compile'];check(sha(ROOT/'rpc502_policy_layouts.c')==sdk['source_sha256']and sha(ROOT/'rpc502_policy_layouts.s')==sdk['assembly_sha256'],'SDK artifact pins');cmd=list(sdk['command']);cmd[-1]='/tmp/rpc502-policy-verified-layout.s';q=subprocess.run(cmd,capture_output=True,text=True);check(q.returncode==0 and not q.stderr and sha(Path(cmd[-1]))==sdk['assembly_sha256'],'fresh SDK compile')
 certs={}
 for e in c['original_certificates']:
  a=int(e['file_offset'],16);raw=bytes(x^int(e['XOR_byte'],16)for x in SOURCE.read_bytes()[a:a+e['size_bytes']]);v=certificate_view(raw);check(raw.hex()==e['DER_hex']and v==e['certificate'],'original DER re-decode');certs[a]=v
 root=certificate_view((ROOT/'rpc502_startup_root.der').read_bytes());aaa=certs[0xff63a4];leaf=certs[0xee87f4];check(rsa_sha1_relation(aaa,root)['exact_equality']and rsa_sha1_relation(leaf,aaa)['exact_equality'],'independent complete Root-AAA-leaf RSA/hash chain')
 with ProcessPoolExecutor(max_workers=2,mp_context=multiprocessing.get_context('spawn'))as ex:
  replays=ex.map(fresh,[w['case']for w in p['cases']],buffersize=2)
  for w in p['cases']:
   case=w['case'];r=unpack(w);events=[];total=0;check(r['policy_cases_generator_sha256']==sha(ROOT/'probe_rpc502_policy_cases.py')and r['policy_generator_sha256']==sha(ROOT/'probe_rpc502_policy_transition.py'),'observer pins');check(r['declared_first_input_hex']==case['first_hex']and r['declared_second_file_bytes_hex']==case['second_hex'],'both original input declarations');check(r['startup_returned']and r['stop_reason']=='returned_to_fixture'and r['records'][-1]['result']=='0xffff5bd9','complete source returns');counts['complete_worker_returns']+=1;check(not r['native_target_executed']and not r['target_host_ipc_files_or_system_calls_executed']and not r['idb_mutated']and not r['full_goal_complete'],'execution boundary')
   for d in journals(r):
    seq=visits(d);check(len(seq)==d['source_visit_count'],'journal extent');h=hashlib.sha256()
    for a in seq:check(a in pool,'source visit');h.update(pool[a])
    check(h.hexdigest()==d['ordered_source_bytes_sha256'],'ordered original source bytes');total+=len(seq)
   counts['retained_source_visits']+=total;check(len(r['core_argument_calls'])==1,'single original carrier');call=r['core_argument_calls'][0];P=int(call['pointer'],16);prefix=bytes.fromhex(call['prefix128_hex']);key=((P^0xc6d66014)*0x6b86592f)&M;u32=lambda off:struct.unpack_from('<I',prefix,off)[0];parameter=((u32(28)+key)&M)^K;aux=(u32(40)-key)&M;extent=((u32(8)^key)+0xd51c85f8)&M;tag=u32(0)^key;check(parameter==128 and extent==8,'independent late parameter/extent codec');check(tag==(0x38411d06 if case['version']==2 else 0x38411d07),'original kind partition')
   rebuilt=bytearray(44);known=bytearray(44)
   for e in call['predecessor_source_stores']:
    a=int(e['address'],16);raw=bytes.fromhex(e['actual_after_hex']);check(e['step_index']<call['entry_step'],'prior original store epoch')
    for j,b in enumerate(raw):
     off=a+j-P
     if 0<=off<44:rebuilt[off]=b;known[off]=1
   for off,n in [(0,12),(16,28)]:check(all(known[off:off+n])and rebuilt[off:off+n]==prefix[off:off+n],'source-created selected carrier bytes')
   for e in r['core_argument_reads']:
    off=e['offset_bytes'];n=e['size_bytes'];check(e['bytes_hex']==prefix[off:off+n].hex(),'actual original carrier read');
    if off in [28,40,8]:counts['outer'+str(off)+'_reads']+=1;check(e['pc']=={28:'0x100747f70',40:'0x100747f7c',8:'0x100747f84'}[off],'late field emission/consumer site')
   points={a['pc']:a for a in r['policy_points']if a['pc']!='0x10097531c'};a=points['0x100747f90'];regs=[int(v,16)for v in a['registers']];frame=bytes.fromhex(a['frame_prefix500_hex']);check(regs[11]&M==key and regs[13]&M==aux and regs[9]&M==u32(8)^key,'actual field-key/intermediate register ABI');check(struct.unpack_from('<I',frame,0x68)[0]==(parameter^K)and struct.unpack_from('<I',frame,0x178)[0]==u32(8)^key,'actual saved selected fields');sp=int(a['sp'],16);events.extend([(a['step'],sp+0x68,frame[0x68:0x6c]),(a['step'],sp+0x178,frame[0x178:0x17c])]);branch=points['0x100747fcc'];check(int(branch['registers'][10],16)==(0x10098e144 if case['version']==2 else 0x100a7b00c),'actual kind-selected branch');cmp=points['0x100747fa8'];check(int(cmp['registers'][12],16)==tag and int(cmp['registers'][10],16)==0x38411d07,'actual signed kind comparison')
   allocs=[a for a in r['policy_points']if a['pc']=='0x100919330'];check(len(allocs)==(0 if case['version']==2 else 1),'observed common allocation caller partition')
   for a in allocs:check(int(a['registers'][0],16)==extent==8 and a['registers'][8]=='0x6000000060','declared allocator boundary and size');counts['observed_common_allocation_calls']+=1
   tails=[a for a in r['auth_points']if a['pc']=='0x10097531c'];records=[a for a in r['policy_points']if a['pc']=='0x10097531c'];check(len(tails)==len(records)==2,'two original verification records')
   for j,(t,rec)in enumerate(zip(tails,records)):
    child=aaa if j==0 else leaf;parent=root if j==0 else aaa;tv=tail_view(t);check(tv['signature_raw_hex']==child['signature_hex']and tv['digest_decoded_hex']==hashlib.sha1(bytes.fromhex(child['tbs_hex'])).hexdigest(),'actual child signature/digest versus original DER');check(rsa_sha1_relation(child,parent)['exact_equality'],'independent mathematical signature relation');counts['valid_certificate_relations']+=1
    def epoch(v,address,n):
     a=int(v['address'],16);off=address-a;raw=bytes.fromhex(v['bytes_hex']);check(0<=off and off+n<=len(raw),'selected record extent');b=raw[off:off+n]
     if v['role']=='private_heap':check(bytes.fromhex(v['known_mask_hex'])[off:off+n]==b'\1'*n,'source-known heap bytes');counts['source_heap_bytes']+=n
     elif v['role']=='private_stack':events.append((rec['step'],address,b))
     else:raise AssertionError(v['role'])
    for field,expected,countname in [('X9_record600',child,'actual_child_key_records'),('X11_record600',parent,'actual_parent_key_records')]:
     v=rec[field];ptr=int(v['address'],16);pseudo={'pointed_views':{'0':{'prefix':v,'nested_views':{}}}};n=integer_at(pseudo,ptr+0x210);e=integer_at(pseudo,ptr+0x320);check(n['value']==int(expected['modulus_hex'],16)and e['value']==expected['exponent'],'source child/parent active public keys');counts[countname]+=1
     for b in [n,e]:epoch(v,int(b['address'],16),16);epoch(v,int(b['limb_pointer'],16),4*abs(b['signed_count']))
    v=rec['X9_record600'];ptr=int(v['address'],16);epoch(v,ptr+0x490,len(bytes.fromhex(child['signature_hex'])));epoch(v,ptr+0x590,28)
   status=[a for a in r['auth_points']if a['pc']=='0x1008969a8'];check(len(status)==2 and all(int(a['registers'][1],16)==K for a in status),'two actual successful local conjunctions');counts['successful_local_statuses']+=2;first=[a for a in r['auth_points']if a['pc']=='0x10095103c'];check([int(a['registers'][14],16)for a in first]==[K,K,0x74c29d8a],'later distinct local verification fails');counts['failed_later_first_statuses']+=1
   writes=r['core_argument_writes'];check(len(writes)==1 and writes[0]['offset_bytes']==32 and writes[0]['pc']=='0x10065f11c'and int.from_bytes(bytes.fromhex(writes[0]['actual_after_hex']),'little')^K==0xffff5bd9,'actual encoded outer result publication')
   mem={};cursor=0;stores=r['core_stack_stores']
   for step,address,raw in sorted(events):
    # Points run before the inherited hook increments;the immediately
    # preceding executed store may share the point's numeric step count.
    while cursor<len(stores)and stores[cursor]['step_index']<=step:
     s=stores[cursor];a=int(s['address'],16)
     for k,v in enumerate(bytes.fromhex(s['actual_after_hex'])):mem[a+k]=v
     cursor+=1
    for k,v in enumerate(raw):check(mem.get(address+k)==v,'last original stack-store epoch');counts['source_stack_bytes']+=1
   fr=json.loads(zlib.decompress(next(replays)));check(fr==r,'fresh canonical complete execution '+case['label']);counts['fresh_runs']+=1;counts['fresh_source_visits']+=sum(len(visits(d))for d in journals(fr));summaries.append({'case':case['label'],'steps':r['steps'],'source_visits':total,'kind':hex(tag),'parameter28':parameter,'field40_intermediate':hex(aux),'extent8_derived_call_argument':extent,'common_allocation_calls':len(allocs),'worker_result':'0xffff5bd9'});print('VERIFIED',case['label'],assertions,flush=True)
 counts.update(assertions=assertions,cases=len(p['cases']),original_instructions=len(pool),source_ranges=len(c['source_ranges']),compiler_ranges=len(c['compiler_ranges']),pointer_records=len(c['consumed_pointer_import_records']))
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':source_sha,'dependencies':{n:sha(ROOT/n)for n in ['rpc502_policy_profiles.json','rpc502_policy_contracts.json','probe_rpc502_policy_cases.py','probe_rpc502_policy_transition.py','rpc502_rsa_models.py','rpc502_startup_tools.py']},'verified_counts':counts,'case_summaries':summaries,'native_target_executed':False,'all_checks_pass':True,'full_goal_complete':False};(ROOT/'rpc502_policy_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
