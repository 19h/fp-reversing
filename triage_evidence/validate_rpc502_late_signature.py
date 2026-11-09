#!/usr/bin/env python3
"""Independent nonzero1024-bit public-output,source-byte/epoch and fresh replay.

Original input,leaf modulus/exponent,exact mapped signature reads and complete
128-byte source export versus Python pow. No validity/acceptance assertion.
O(B+V+E+S) work/space plus bounded integer arithmetic and one whole fresh run.
No native target/API or IDB action.
"""
import hashlib,json,struct
from pathlib import Path
from daemon_receive_tools import IMAGE,SOURCE,ROOT,CS,verify_original_fixups
from daemon_import_bindings import binding
from rpc502_startup_tools import unpack,journals,visits,certificate_view
from rpc502_rsa_models import integer_at
from probe_rpc502_late_signature import cases,run_case
K=0x8b3dc651

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 assertions=0;pool={};counts={'retained_source_visits':0,'fresh_source_visits':0,'fresh_runs':0,'source_stack_bytes':0}
 def check(v,label):
  nonlocal assertions
  assert v,label;assertions+=1
 p=json.loads((ROOT/'rpc502_late_signature_profiles.json').read_text());check(p['generator_sha256']==sha(ROOT/'probe_rpc502_late_signature.py'),'producer pin');check(p['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e','source identity')
 for n,h in p['dependencies'].items():check(sha(ROOT/n)==h,'dependency '+n)
 check([w['case']for w in p['cases']]==cases(),'fresh input definition')
 for e in p['original_instruction_pool']:
  a=int(e['ea'],16);b=IMAGE.read(a,4);i=next(CS.disasm(b,a));check(b.hex()==e['bytes']and i.mnemonic==e['mnemonic']and i.op_str==e['operands'],'original opcode');pool[a]=struct.pack('<Q',a)+b
 w=p['cases'][0];case=w['case'];r=unpack(w);check(r['late_generator_sha256']==sha(ROOT/'probe_rpc502_late.py'),'observer pin');check(r['startup_returned']and r['stop_reason']=='returned_to_fixture'and r['records'][-1]['result']=='0xffff5bd9','complete original callback/worker return');check(not r['native_target_executed']and not r['target_host_ipc_files_or_system_calls_executed']and not r['idb_mutated']and not r['full_goal_complete'],'native boundary');fix={}
 for d in journals(r):
  seq=visits(d);check(len(seq)==d['source_visit_count'],'journal extent');h=hashlib.sha256()
  for a in seq:check(a in pool,'source visit');h.update(pool[a])
  check(h.hexdigest()==d['ordered_source_bytes_sha256'],'ordered original source bytes');counts['retained_source_visits']+=len(seq)
  for e in d['original_fixup_reads']:fix[int(e['address'],16)]=e['original_fixup']
 for a,e in fix.items():
  if e['kind'].endswith('bind'):check(binding(a)['word']==hex(int.from_bytes(IMAGE.read(a,8),'little')),'original bound pointer')
  else:check(verify_original_fixups([a])['records'][0]['address']==hex(a),'original rebase pointer')
 points={a['pc']:a for a in r['late_points']};keypoint=points['0x100a8b8b0'];certptr=int(keypoint['registers31'][11],16);v=keypoint['pointed_views']['11'];pseudo={'pointed_views':{'0':{'prefix':v,'nested_views':{}}}};n=integer_at(pseudo,certptr+0x210);e=integer_at(pseudo,certptr+0x320);leaf=certificate_view(bytes.fromhex(case['body_hex']));N=int(leaf['modulus_hex'],16);check(n['value']==N and e['value']==leaf['exponent']==65537 and N.bit_length()==1024,'actual nonzero-case key versus original leaf DER');raw=bytes.fromhex(case['second_hex']);off=12+len(bytes.fromhex(case['body_hex']))+4;S=int(case['signature_hex'],16);check(raw[off:off+128].hex()==case['signature_hex']and 1<S<N,'actual nonzero within-range wire signature');expected=pow(S,65537,N).to_bytes(128,'big');check(any(expected),'nonzero independent public output')
 start=r['late_points'][0]['step'];reads=[q for q in r['body_mapping_reads']if q['step']>=start];sig=[q for q in reads if q['pc']=='0x10008eaf4'];check([q['offset_bytes']for q in sig]==list(range(off+127,off-1,-1)),'exact128 input-byte source reads')
 for q in reads:check(q['size_bytes']==1 and q['bytes_hex']==raw[q['offset_bytes']:q['offset_bytes']+1].hex(),'actual nonzero mapping byte')
 op=next(c for c in r['late_calls']if c['pc']=='0x100657488');P=int(op['registers31'][0],16);record=bytes.fromhex(op['pointed_views']['0']['bytes_hex']);output=struct.unpack_from('<Q',record,56)[0];lengthptr=struct.unpack_from('<Q',record,40)[0];check(struct.unpack_from('<Q',record,8)[0]==certptr+0x320 and struct.unpack_from('<Q',record,32)[0]==certptr+0x210 and struct.unpack_from('<Q',record,64)[0]==0x5300000000+off,'actual public-operation input pointer ABI')
 mem={};regions=[(P+16,4),(output,128),(lengthptr,4)]
 for q in r['core_stack_stores']:
  if q['step_index']>op['return_step']:break
  address=int(q['address'],16)
  for j,value in enumerate(bytes.fromhex(q['actual_after_hex'])):
   if any(a<=address+j<a+n for a,n in regions):mem[address+j]=value
 status=bytes(mem.get(P+16+j,0xcc)for j in range(4));encoded=bytes(mem.get(output+j,0xcc)for j in range(128));extent=bytes(mem.get(lengthptr+j,0xcc)for j in range(4));check(int.from_bytes(status,'little')==K and int.from_bytes(extent,'little')==128,'actual original local success/export extent');check(bytes(x^0x98 for x in encoded)==expected,'full nonzero exported result versus independent modular exponentiation')
 first=points['0x100950fd8'];sp=int(first['sp'],16);frame=bytes.fromhex(first['frame700_hex']);rel=output-sp;check(0<=rel and rel+128<=len(frame)and frame[rel:rel+128]==encoded,'actual nonzero output snapshot');check(points['0x10095103c']['registers31'][14]=='0x74c29d8a','later local status still rejects')
 events=[(first['step'],output,encoded)]
 for value in[n,e]:
  for address,nbytes in[(int(value['address'],16),16),(int(value['limb_pointer'],16),4*abs(value['signed_count']))]:
   rel=address-certptr;events.append((keypoint['step'],address,bytes.fromhex(v['bytes_hex'])[rel:rel+nbytes]))
 mem={};cursor=0;stores=r['core_stack_stores']
 for step,address,b in sorted(events):
  while cursor<len(stores)and stores[cursor]['step_index']<=step:
   q=stores[cursor];a=int(q['address'],16)
   for j,value in enumerate(bytes.fromhex(q['actual_after_hex'])):mem[a+j]=value
   cursor+=1
  for j,value in enumerate(b):check(mem.get(address+j)==value,'original nonzero key/output byte epoch');counts['source_stack_bytes']+=1
 mallocs=[c for c in r['late_calls']if c['import_name']=='libSystem/_malloc'];check([int(c['registers31'][0],16)for c in mallocs]==[8,32],'prefix/digest allocation inputs');owner=next(v for v in r['final_owned_regions']if v['address']==mallocs[1]['returned_registers31'][0]);check(bytes.fromhex(owner['known_mask_hex'])==b'\1'*32 and bytes(x^0x98 for x in bytes.fromhex(owner['bytes_hex']))==hashlib.sha256(raw[:8]).digest(),'same independently hashed raw prefix');check(not r['incomplete_late_call_indices']and all('return_step'in c for c in r['late_calls']),'complete observed calls')
 fr=json.loads(json.dumps(run_case(case)[0]));check(fr==r,'fresh canonical complete nonzero execution');counts['fresh_runs']=1;counts['fresh_source_visits']=sum(len(visits(d))for d in journals(fr));counts.update(assertions=assertions,cases=1,original_instructions=len(pool),pointer_records=len(fix),signature_source_bytes=len(sig),public_output_bytes=len(encoded),nonzero_full_public_outputs=1,observed_Montgomery_squares=sum(c['target']=='0x100539ea0'for c in r['late_calls']),observed_Montgomery_products=sum(c['target']=='0x10094593c'for c in r['late_calls']),observed_late_calls=len(r['late_calls']))
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in['rpc502_late_signature_profiles.json','probe_rpc502_late_signature.py','probe_rpc502_late.py','rpc502_rsa_models.py','rpc502_startup_tools.py']},'verified_counts':counts,'signature_hex':case['signature_hex'],'actual_encoded_output_hex':encoded.hex(),'independent_public_output_hex':expected.hex(),'local_public_operation_status':hex(K),'worker_result':'0xffff5bd9','native_target_executed':False,'all_checks_pass':True,'full_goal_complete':False};(ROOT/'rpc502_late_signature_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
