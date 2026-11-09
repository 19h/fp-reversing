#!/usr/bin/env python3
"""Independent exported-block regions,byte folds,hashes,epochs and fresh replay.

Reads two retained and two distinct fresh complete original worker sequences.
O(C*(B+V+E+S)) work/space plus public exponentiation and bounded solvers.
Local proofs/finite observations are not complete malformed-input acceptance.
No native target/API or IDB action.
"""
import hashlib,json,struct,subprocess
from pathlib import Path
from daemon_receive_tools import IMAGE,SOURCE,ROOT,CS,verify_original_fixups
from daemon_import_bindings import binding
from recover_rpc502_parser_ownership import starts
from rpc502_startup_tools import unpack,journals,visits
from rpc502_padding_oracles import PREFIX,H0,H1,H2,regions,stage_oracles,header_error,pad_error,separator_error,prefix_error,first_difference
K=0x8b3dc651

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 assertions=0;pool={};counts={n:0 for n in['retained_source_visits','fresh_source_visits','fresh_runs','exported_blocks','public_output_bytes','post_export_read_events','encoded_block_reads','padding_bytes','separator_bytes','prefix_pairs','digest_pairs','complete_digest_matches','digest_mismatches','source_stack_bytes','source_heap_bytes','ROM_literal_bytes','first_statuses']};summaries=[]
 def check(v,label):
  nonlocal assertions
  assert v,label;assertions+=1
 p=json.loads((ROOT/'rpc502_padding_profiles.json').read_text());replay=json.loads((ROOT/'rpc502_padding_replays.json').read_text());c=json.loads((ROOT/'rpc502_padding_contracts.json').read_text());source_sha=sha(SOURCE)
 for obj,producer in[(p,'probe_rpc502_padding_cases.py'),(replay,'probe_rpc502_padding_replay.py'),(c,'recover_rpc502_padding.py')]:
  check(obj['generator_sha256']==sha(ROOT/producer),'producer pin');check(obj['source_sha256']==source_sha=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e','source identity')
  for n,h in obj['dependencies'].items():check(sha(ROOT/n)==h,'dependency '+n)
 check(p['original_instruction_pool']==replay['original_instruction_pool'],'fresh complete source pool')
 for e in p['original_instruction_pool']:
  a=int(e['ea'],16);b=IMAGE.read(a,4);i=next(CS.disasm(b,a));check(b.hex()==e['bytes']and i.mnemonic==e['mnemonic']and i.op_str==e['operands'],'original opcode');pool[a]=struct.pack('<Q',a)+b
 for e in c['source_ranges']:
  a=int(e['start'],16);z=int(e['end'],16);b=IMAGE.read(a,z-a);check(b.hex()==e['bytes']and hashlib.sha256(b).hexdigest()==e['sha256'],'source span');check(e['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a)],'source disassembly')
 f,meta=starts();check(meta==c['LC_FUNCTION_STARTS'],'compiler starts')
 for e in c['compiler_ranges']:
  a=int(e['start'],16);j=f.index(a);check(f[j+1]==int(e['end'],16)and hashlib.sha256(IMAGE.read(a,f[j+1]-a)).hexdigest()==e['sha256'],'physical compiler interval')
 for e in c['consumed_pointer_import_records']:check((binding(int(e['slot'],16))if'slot'in e else verify_original_fixups([int(e['address'],16)])['records'][0])==e,'original fixup/import')
 for e in c['proofs']:
  path=ROOT/e['path'];check(sha(path)==e['sha256'],'proof identity');q=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);check(q.stdout.strip()=='unsat'and not q.stderr,'fresh local proof')
 for e in c['DigestInfo_literals']:
  raw=IMAGE.read(int(e['address'],16),e['extent_bytes']);check(raw.hex()==e['original_encoded_hex']and bytes(x^0x98 for x in raw)==PREFIX[e['digest_extent_bytes']],'original encoded DigestInfo prefix')
 check(len(p['cases'])==len(replay['cases'])==2,'two original/fresh complete cases')
 for w,fw in zip(p['cases'],replay['cases']):
  check(w['case']==fw['case'],'identical external inputs');r=unpack(w);fr=unpack(fw);case=w['case'];check(r==fr,'fresh canonical whole worker equality');counts['fresh_runs']+=1;check(r['startup_returned']and r['stop_reason']=='returned_to_fixture'and r['records'][-1]['result']=='0xffff5bd9','complete callback/worker returns');check(not r['native_target_executed']and not r['target_host_ipc_files_or_system_calls_executed']and not r['idb_mutated'],'native/IDB boundary');check(r['padding_generator_sha256']==sha(ROOT/'probe_rpc502_padding.py'),'observer pin');check(r['padding_active_at_stop']is None and len(r['padding_stages'])==3,'three closed observation windows');events=[];oracles=stage_oracles(case,SOURCE)
  for d in journals(r):
   seq=visits(d);check(len(seq)==d['source_visit_count'],'journal extent');h=hashlib.sha256()
   for a in seq:check(a in pool,'retained original instruction visit');h.update(pool[a])
   check(h.hexdigest()==d['ordered_source_bytes_sha256'],'ordered original source bytes');counts['retained_source_visits']+=len(seq)
  counts['fresh_source_visits']+=sum(len(visits(d))for d in journals(fr));case_rows=[]
  for j,(stage,oracle)in enumerate(zip(r['padding_stages'],oracles)):
   width=stage['encoded_extent'];hsize=stage['digest_extent'];v=regions(width,hsize);em=oracle['public_output'];digest=oracle['digest'];encoded=bytes.fromhex(stage['exported_view']['bytes_hex']);base=int(stage['export_output'],16);check(stage['complete_end']and stage['post_export'],'actual export return and closed window');check(width==len(em)and hsize==len(digest)and bytes(x^0x98 for x in encoded)==em,'full exported block versus public exponentiation');events.append((stage['export_return_step'],base,encoded));counts['exported_blocks']+=1;counts['public_output_bytes']+=width
   reads=[q for q in r['padding_reads']if q['stage_index']==j];edges=[q for q in r['padding_edges']if q['stage_index']==j];points=[q for q in r['padding_points']if q['stage_index']==j];counts['post_export_read_events']+=len(reads)
   def at(pc):return[q for q in reads if q['pc']==pc]
   def byte(q):check(q['size_bytes']==1,'byte load width');return int(q['bytes_hex'],16)
   for q in reads:
    if q['within_export']:
     off=int(q['address'],16)-base;n=q['size_bytes'];check(q['bytes_hex']==encoded[off:off+n].hex(),'actual exported-block read bytes');counts['encoded_block_reads']+=1;events.append((q['step'],int(q['address'],16),bytes.fromhex(q['bytes_hex'])))
   a=at('0x1009d8fd0');b=at('0x1009d8fd4');check(len(a)==len(b)==1 and int(a[0]['address'],16)==base and int(b[0]['address'],16)==base+1,'header positions');check(int(a[0]['registers31'][25],16)==0x7249,'header dispatch seed');error=header_error(byte(a[0]),byte(b[0]));pads=at('0x100a75bf8');pad_edges=[q for q in edges if q['pc']=='0x100a75c78'];check(len(pads)==len(pad_edges)==v['pad_count'],'complete padding-region extent')
   for k,(q,edge)in enumerate(zip(pads,pad_edges)):
    check(int(q['address'],16)==base+2+k and int(q['registers31'][8],16)==H0^error and int(q['registers31'][10],16)==0x67d0,'padding pointer/state/seed');error=pad_error(error,byte(q));check(int(edge['registers31'][8],16)==H0^error,'actual byte-fold successor');counts['padding_bytes']+=1
   sep=at('0x1009329b4');check(len(sep)==1 and int(sep[0]['address'],16)==base+v['separator']and int(sep[0]['registers31'][8],16)==H0^error,'separator position/state');error=separator_error(error,byte(sep[0]));se=next(q for q in edges if q['pc']=='0x100932a00');check(int(se['registers31'][8],16)==H2^error,'actual separator fold');counts['separator_bytes']+=1
   left=at('0x100656dbc');right=at('0x100656dc4');pe=[q for q in edges if q['pc']=='0x100656df8'];check(len(left)==len(right)==len(pe)==len(PREFIX[hsize]),'complete fixed-prefix comparison');literal=0x100ee5a50 if hsize==20 else 0x100f1fc42
   for k,(a,b,edge)in enumerate(zip(left,right,pe)):
    check(int(a['address'],16)==base+v['prefix_start']+k and int(b['address'],16)==literal+k and byte(b)==PREFIX[hsize][k]^0x98 and IMAGE.read(literal+k,1).hex()==b['bytes_hex'],'candidate versus original ROM prefix');check(int(a['registers31'][8],16)==H1^error,'prefix accumulator state');error=prefix_error(error,byte(a),byte(b));check(int(edge['registers31'][8],16)==H1^error,'actual prefix-fold successor');counts['prefix_pairs']+=1;counts['ROM_literal_bytes']+=1
   left=at('0x100882dd0');right=at('0x100882dd4');n,difference=first_difference(em[-hsize:],digest);check(len(left)==len(right)==n,'digest comparison extent/early exit');check(int(left[0]['registers31'][8],16)==H2^error,'post-prefix accumulator normalization')
   for k,(a,b)in enumerate(zip(left,right)):
    check(int(a['address'],16)==base+v['digest_start']+k and byte(a)==em[-hsize+k]^0x98 and byte(b)==digest[k]^0x98,'actual candidate/expected digest pair');check(int(b['registers31'][20],16)==byte(a),'actual first LDRB result at second load');owner=b['owner_view'];check(owner is not None,'expected digest owner')
    if owner['role']=='private_stack':events.append((b['step'],int(b['address'],16),bytes.fromhex(b['bytes_hex'])))
    elif owner['role']=='private_heap':check(bytes.fromhex(owner['known_mask_hex'])==b'\1','source-known expected heap byte');counts['source_heap_bytes']+=1
    else:raise AssertionError(owner['role'])
    counts['digest_pairs']+=1
   first=next(q for q in points if q['pc']=='0x100950fd8');out=next(q for q in points if q['pc']=='0x10095103c');regs=[int(x,16)for x in first['registers31']];check(regs[9]==regs[10]==1,'actual status reduction seeds');check(int(out['registers31'][14],16)==(K if regs[8]&255==0xa2 else 0x74c29d8a),'local raw-status byte predicate');check((stage['first_reduction_result']==hex(K))==(em==oracle['expected']),'finite complete-block oracle versus observed reduction');counts['first_statuses']+=1
   differences=[q for q in edges if q['pc']=='0x100a46ccc']
   if difference:
    counts['digest_mismatches']+=1;check(len(differences)==1,'actual mismatch path');q=differences[0];rr=[int(x,16)&0xffffffff for x in q['registers31']];check(rr[15]==0x4a29 and rr[14]==difference&0xffffffff,'decoded signed-byte difference and source seed');check(rr[20]==byte(left[-1])and rr[5]==byte(right[-1]),'actual mismatch inputs');fold=next(q for q in edges if q['pc']=='0x100a7c6b8');check(int(fold['registers31'][8],16)==0x40df015d and regs[8]==0x40df015d,'observed fixed failure word survives auxiliary fold')
   else:counts['complete_digest_matches']+=1;check(not differences,'match path bypasses mismatch difference block')
   if j<2:
    combined=next(q for q in points if q['pc']=='0x1008969a8');check(int(combined['registers31'][1],16)==K,'later certificate-local conjunction');check(stage['end_pc']=='0x1008969a8','certificate window end')
   else:check(stage['end_pc']=='0x10095103c'and difference!=0,'file window ends at observed failing reduction')
   case_rows.append({'stage_index':j,'block_width_bytes':width,'digest_extent_bytes':hsize,'padding_bytes':v['pad_count'],'DigestInfo_prefix_bytes':len(PREFIX[hsize]),'byte_mismatch_mask':error,'digest_bytes_compared':n,'signed_first_difference':difference,'first_reduction_result':stage['first_reduction_result'],'complete_block_equal_to_independent_encoding':em==oracle['expected']})
  mem={};cursor=0;stores=r['core_stack_stores']
  for step,address,b in sorted(events):
   while cursor<len(stores)and stores[cursor]['step_index']<=step:
    q=stores[cursor];a=int(q['address'],16)
    for k,value in enumerate(bytes.fromhex(q['actual_after_hex'])):mem[a+k]=value
    cursor+=1
   for k,value in enumerate(b):check(mem.get(address+k)==value,'last original source stack-store epoch');counts['source_stack_bytes']+=1
  summaries.append({'case':case['label'],'steps':r['steps'],'stages':case_rows,'worker_result':'0xffff5bd9'});print('VERIFIED',case['label'],assertions,flush=True)
 counts.update(assertions=assertions,cases=len(p['cases']),original_instructions=len(pool),source_ranges=len(c['source_ranges']),compiler_ranges=len(c['compiler_ranges']),pointer_records=len(c['consumed_pointer_import_records']),proofs_unsat=len(c['proofs']))
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':source_sha,'dependencies':{n:sha(ROOT/n)for n in['rpc502_padding_profiles.json','rpc502_padding_replays.json','rpc502_padding_contracts.json','rpc502_padding_oracles.py','rpc502_startup_tools.py','rpc502_startup_root.der']},'verified_counts':counts,'case_summaries':summaries,'complete_acceptance_language_unknown':True,'native_target_executed':False,'all_checks_pass':True,'full_goal_complete':False};(ROOT/'rpc502_padding_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
