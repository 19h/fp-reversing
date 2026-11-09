#!/usr/bin/env python3
"""Independent source/byte/cursor/record/owner/fallback and whole-worker checks.

Re-read original image,decode fixups,verify local proofs/SDK view,reconstruct
source-built record and pathname byte epochs,check all retained cases and
freshly execute every case from original public-worker entry in four isolated Python processes (ordered,bounded result queue). O(C*(B+V+E+S))
time/retained space plus bounded SMT cost. No native target or host API runs.
"""
import base64,bisect,hashlib,json,multiprocessing,struct,subprocess,zlib
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from daemon_receive_tools import IMAGE,SOURCE,ROOT,CS,FIXUPS,verify_original_fixups
from daemon_import_bindings import binding
from recover_rpc502_parser_ownership import starts
from probe_rpc502_supp_cases import run_case

K=0x8b3dc651;MASK=0xffffffff

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def unpack(w):return json.loads(zlib.decompress(base64.b64decode(w['payload_zlib_base64'])))
def visits(r):
 b=zlib.decompress(base64.b64decode(r['original_visits_zlib_base64']));return struct.unpack('<'+'Q'*(len(b)//8),b)
def word(b,o):return int.from_bytes(b[o:o+4],'big')
def layout(raw):
 v=raw[0]
 if v in [1,4]:
  base=24 if v==1 else 4;A=word(raw,base);pos=base+4+32*A;B=word(raw,pos);return {'A':A,'B':B,'C':128,'D':pos+4,'word_offsets':[base,pos]}
 A=word(raw,4);B=word(raw,8+A);pos=12+A+B;C=word(raw,pos);return {'A':A,'B':B,'C':C,'D':12+A,'word_offsets':[4,8+A,pos]}


def fresh_result(case):return run_case(case)[0]

def main():
 checks=0;count={n:0 for n in ['retained_original_visits','fresh_original_visits','fresh_worker_runs','supplemental_reads','core_records','core_reads','core_writes','predecessor_stores','source_path_snapshots','source_path_bytes','source_owner_stores','source_owner_bytes','owner_snapshots','whole_worker_returns','further_file_boundaries','unknown_metadata_boundaries','unknown_mapping_boundaries','guarded_extent_boundaries']}
 def check(v,label):
  nonlocal checks
  assert v,label
  checks+=1
 p=json.loads((ROOT/'rpc502_supp_profiles.json').read_text());c=json.loads((ROOT/'rpc502_supp_contracts.json').read_text());source_sha=sha(SOURCE)
 for obj,name in [(p,'probe_rpc502_supp_cases.py'),(c,'recover_rpc502_supp.py')]:
  check(obj['source_sha256']==source_sha=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e','original thin source');check(obj['generator_sha256']==sha(ROOT/name),'generator source pin')
  for n,h in obj['dependencies'].items():check(sha(ROOT/n)==h,'dependency '+n)
  check(not obj['native_target_executed']and not obj['full_goal_complete'],'scope')
 identity=json.loads((ROOT/'rpc502_parser_source_identity.json').read_text());univ=Path(identity['universal_path']).read_bytes();check(hashlib.sha256(univ).hexdigest()==identity['universal_sha256'],'universal source');thin=SOURCE.read_bytes();check(len(thin)==17668912 and univ[3407872:3407872+len(thin)]==thin,'exact arm64e slice')
 bank={}
 for e in p['original_instruction_pool']:
  a=int(e['ea'],16);b=IMAGE.read(a,4);i=next(CS.disasm(b,a));check(b.hex()==e['bytes']and i.mnemonic==e['mnemonic']and i.op_str==e['operands'],'original opcode independent decode');bank[a]=b
 for e in c['original_ranges']:
  a=int(e['start'],16);z=int(e['end'],16);b=IMAGE.read(a,z-a);check(b.hex()==e['bytes']and hashlib.sha256(b).hexdigest()==e['sha256'],'original bounded source range');check(e['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a)],'range decoder')
 funcs,meta=starts();check(meta==c['LC_FUNCTION_STARTS']and len(funcs)==c['compiler_start_count'],'original compiler metadata')
 for e in c['compiler_ranges']:
  a=int(e['start'],16);i=funcs.index(a);z=funcs[i+1];check(z==int(e['end'],16)and hashlib.sha256(IMAGE.read(a,z-a)).hexdigest()==e['sha256'],'whole physical compiler range')
 for e in c['range_ownership']:
  cursor=int(e['start'],16)
  for t in e['segments']:
   a=int(t['start'],16);z=int(t['end'],16);j=funcs.index(int(t['compiler_range_start'],16));check(cursor==a and funcs[j]<=a<z<=funcs[j+1],'compiler partition');cursor=z
  check(cursor==int(e['end'],16),'full range partition')
 for e in c['original_fixup_records']:
  check((binding(int(e['slot'],16))if 'slot'in e else verify_original_fixups([int(e['address'],16)])['records'][0])==e,'original chained pointer/import decode')
 for e in c['proofs']:
  path=ROOT/e['path'];check(sha(path)==e['sha256'],'proof bytes');query=path.read_text();assert query.count(':timeout 30000')==1;verified_query=query.replace(':timeout 30000',':timeout 120000');r=subprocess.run(['z3','-in'],input=verified_query,capture_output=True,text=True,check=True);check(r.stdout.strip()=='unsat'and not r.stderr,'fresh local proof '+e['path']+' '+r.stdout.strip())
 sdk=c['sdk_compile'];check(sha(ROOT/'rpc502_supp_layouts.c')==sdk['source_sha256']and sha(ROOT/'rpc502_supp_layouts.s')==sdk['assembly_sha256'],'SDK source and retained assembly');cmd=list(sdk['command']);cmd[-1]='/tmp/rpc502-supp-verified-layouts.s';rr=subprocess.run(cmd,capture_output=True,text=True);check(rr.returncode==0 and not rr.stderr,'fresh arm64e compile only');check(sha(Path(cmd[-1]))==sdk['assembly_sha256'],'fresh assembly equality')
 summaries=[];byte_results={};reader_contexts=set();core_offsets=set();status_values=set()
 with ProcessPoolExecutor(max_workers=4,mp_context=multiprocessing.get_context('spawn'))as executor:
  fresh_results=executor.map(fresh_result,[w['case']for w in p['cases']],buffersize=4)
  for wrapper in p['cases']:
   case=wrapper['case'];label=case['label'];r=unpack(wrapper);raw=bytes.fromhex(case['file_hex']);seq=visits(r);seqset=set(seq);digest=hashlib.sha256()
   check(r['guest_source_opcodes_checked_each_visit']and len(seq)==r['original_visit_count'],'live private guest instruction byte attestation')
   for a in seq:check(a in bank,'retained original visit');digest.update(struct.pack('<Q',a));digest.update(bank[a])
   check(digest.hexdigest()==r['original_ordered_bytes_sha256'],'ordered original opcode digest');count['retained_original_visits']+=len(seq)
   check(r['source_sha256']==source_sha and r['declared_second_file_bytes_hex']==case['file_hex']and r['supp_fixture']==case['fixture'],'declared inputs');check(not r['native_target_executed']and not r['target_host_ipc_files_or_system_calls_executed']and not r['idb_mutated']and not r['full_goal_complete'],'native evidence boundary');check(r['supp_copy_pointer']is None,'no source supplemental copy allocation in this corpus')
   for e in r['supplemental_reads']:
    off=e['offset_bytes'];n=e['size_bytes'];check(e['kind']=='supp_mapping'and 0<=off and off+n<=len(raw)and raw[off:off+n].hex()==e['bytes_hex']and int(e['pc'],16)in seqset,'exact known file byte read');count['supplemental_reads']+=1
   for e in r['supplemental_points']:
    if e['pc']=='0x1008b5200':check(int(e['registers_x0_x30'][11],16)&MASK==case['fixture'].get('second_size_u64',len(raw))&MASK,'source initial extent decoder')
    if e['pc']=='0x10049bc34':
     view=layout(raw);check(int.from_bytes(bytes.fromhex(e['frame_ad80_hex']),'little')==view['D']&MASK,'source data cursor frame');check(int.from_bytes(bytes.fromhex(e['frame_ad6c_hex']),'little')==(case['fixture'].get('second_size_u64',len(raw))+0x4b224d13)&MASK,'source encoded length frame')
   for call in r['core_argument_calls']:
    check(call['file_epoch']==2 and call['entry']=='0x10099ab1c'and call['return_pc']=='0x1009d5628','original wrapper-to-carrier call');ptr=int(call['pointer'],16);prefix=bytes.fromhex(call['prefix128_hex']);key=((ptr^0xc6d66014)*0x6b86592f)&MASK;view=layout(raw);u32=lambda off:int.from_bytes(prefix[off:off+4],'little')
    check(u32(0)^key==(0x38411d07 if raw[0]in[4,5]else 0x38411d06),'two source carrier tags');check(int.from_bytes(prefix[16:24],'little')==0x5300000000,'exact mapping pointer field');check(((u32(24)^key)+0xc898a600)&MASK==view['D']&MASK,'source cursor encoding');check(((u32(36)-key)&MASK)^K==view['B'],'source body length encoding');check(((u32(28)+key)&MASK)^K==view['C'],'opaque trailing parameter codec');check('returned_at_step'in call,'observed carrier return')
    rebuilt=bytearray(44);known=bytearray(44)
    for e in call['predecessor_source_stores']:
     a=int(e['address'],16);value=bytes.fromhex(e['actual_after_hex']);check(e['step_index']<call['entry_step']and int(e['pc'],16)in seqset and len(value)==e['size_bytes'],'source predecessor store provenance')
     for j,b in enumerate(value):
      off=a+j-ptr
      if 0<=off<44:rebuilt[off]=b;known[off]=1
     count['predecessor_stores']+=1
    for off in [0,4,8,16,20,24,28,36,40]:check(all(known[off:off+4])and rebuilt[off:off+4]==prefix[off:off+4],'source-written record field epoch')
    for off in range(44):
     if known[off]:check(rebuilt[off]==prefix[off],'all previous source stores agree at record entry')
    count['core_records']+=1
   for e in r['core_argument_reads']:
    call=r['core_argument_calls'][e['call_index']];off=e['offset_bytes'];n=e['size_bytes'];b=bytes.fromhex(call['prefix128_hex']);check(0<=off and off+n<=44 and e['bytes_hex']==b[off:off+n].hex()and int(e['pc'],16)in seqset,'actual carrier field consumer bytes');core_offsets.add(off);count['core_reads']+=1
   for e in r['core_argument_writes']:
    check(e['offset_bytes']==32 and e['size_bytes']==4 and e['pc']=='0x10065f11c','original carrier status producer');v=int.from_bytes(bytes.fromhex(e['actual_after_hex']),'little');status_values.add(hex(v^K));count['core_writes']+=1
   # Independent chronological source-store reconstruction for private heap owners.
   owners={}
   for e in r['records']:
    kind=e['kind'];name=e.get('name','')
    if kind=='import'and name=='libSystem/_malloc_type_malloc':a=int(e['private_address'],16);n=e['size_bytes'];owners[a]={'bytes':bytearray(b'\xa5'*n),'known':bytearray(n),'retired':False}
    if kind=='private_malloc_result_model'and int(e['return_bits'],16):a=int(e['return_bits'],16);n=e['requested_extent_bytes'];owners[a]={'bytes':bytearray(n),'known':bytearray(n),'retired':False}
    if kind in ['explicit_parser_API_model','explicit_supp_API_model']and name=='libSystem/_malloc'and e['result'].startswith('0x')and int(e['result'],16):a=int(e['result'],16);n=e['requested_size_bytes'];owners[a]={'bytes':bytearray(b'\xa5'*n),'known':bytearray(n),'retired':False}
    if kind=='source_owner_store':
     t=e['store'];a=int(t['owner'],16);off=t['offset_bytes'];b=bytes.fromhex(t['actual_after_hex']);check(a in owners and not owners[a]['retired']and 0<=off and off+len(b)<=len(owners[a]['bytes']),'owner store live extent');owners[a]['bytes'][off:off+len(b)]=b;owners[a]['known'][off:off+len(b)]=bytes([1])*len(b);count['source_owner_stores']+=1;count['source_owner_bytes']+=len(b)
    if kind in ['explicit_parser_API_model','explicit_supp_API_model']and name=='libSystem/_free':
     a=int(e['retired_pointer'],16)
     if a:check(a in owners and not owners[a]['retired']and owners[a]['bytes'].hex()==e['retired_bytes_hex'],'exact source-retired bytes');owners[a]['retired']=True
   for e in r['owner_snapshots']:
    a=int(e['address'],16);check(a in owners and e['bytes_hex']==owners[a]['bytes'].hex()and e['initialized_mask_hex']==owners[a]['known'].hex()and e['retired']==owners[a]['retired'],'full final owner snapshot');count['owner_snapshots']+=1
   # Path byte epochs include the v5.supf -> v4.supp fallback,without native opens.
   for e in r['source_open_observations']:
    ptr=int(e['path_pointer'],16);expected=bytes.fromhex(e['path_hex'])+b'\0';b=bytearray(len(expected));known=bytearray(len(expected))
    for s in r['source_path_stores']:
     if s['step_index']>e['observed_at_step']:continue
     a=int(s['address'],16);value=bytes.fromhex(s['actual_after_hex'])
     for j,v in enumerate(value):
      off=a+j-ptr
      if 0<=off<len(b):b[off]=v;known[off]=1;count['source_path_bytes']+=1
    check(all(known)and b==expected and e['site']=='0x100d94494'and e['flags_u32']==0,'source path reconstruction');count['source_path_snapshots']+=1
   for fd,owner in r['declared_FD_owners'].items():
    close=[e['result_signed32']for e in r['explicit_parser_models']if e['name']=='libSystem/_close'and int(e['args_x0_x7'][0],16)==int(fd)];check(close==owner['close_requests']and owner['declared_closed']==(0 in close),'per-FD cleanup request/effect')
   for ptr,owner in r['declared_mapping_owners'].items():
    unm=[e['result_signed32']for e in r['explicit_parser_models']if e['name']=='libSystem/_munmap'and e['args_x0_x7'][0]==ptr];check(unm==owner['unmap_requests']and owner['retired']==(0 in unm),'per-map cleanup request/effect');check(not unm if owner['epoch']==2 else True,'no second mapping unmap in this corpus')
   last=r['records'][-1];reason=r['stop_reason']
   if reason=='returned_to_fixture':count['whole_worker_returns']+=1
   elif reason=='further_file_open_epoch':count['further_file_boundaries']+=1
   elif reason=='unknown_fstat_output_read':count['unknown_metadata_boundaries']+=1;check(last['stat_status']==-1 and last['offset_bytes']==96,'failed-stat unknown read separated')
   elif reason=='supp_mapping_unknown_read':count['unknown_mapping_boundaries']+=1
   elif reason=='supp_mapping_extent_read':count['guarded_extent_boundaries']+=1
   if label.startswith('byte_'):
    v=int(label[5:]);byte_results[v]=last.get('result');check(reason=='returned_to_fixture'and last['result']==('0xffff5bde'if v in [1,2,3,4,5]else'0xffff5bef'),'exhaustive fixed-context header byte classifier');check(len(r['core_argument_calls'])==int(v in [1,2,3,4,5]),'selected carrier calls for entire u8 domain')
   if label.startswith('open_errno_'):
    errno=case['fixture']['second_errno_u32'];check((reason=='further_file_open_epoch')==(errno==2),'finite errno fallback polarity')
    if errno==2:check(bytes.fromhex(r['source_open_observations'][-1]['path_hex']).endswith(b'.v4.supp'),'exact source fallback suffix')
   fresh=next(fresh_results);check(fresh==r,'complete fresh whole-worker replay '+label);count['fresh_worker_runs']+=1;count['fresh_original_visits']+=fresh['original_visit_count']
   summaries.append({'case':label,'stop_reason':reason,'result':last.get('result'),'steps':r['steps'],'supplemental_reads':len(r['supplemental_reads']),'core_calls':len(r['core_argument_calls']),'second_FD_closed':r['declared_FD_owners'].get('8',{}).get('declared_closed'),'second_mapping_retired':r['declared_mapping_owners'].get('0x5300000000',{}).get('retired')});print('VERIFIED',label,checks,flush=True)
 check(set(byte_results)==set(range(256)),'all u8 header values covered')
 counts={'cases':len(p['cases']),'original_instructions':len(bank),'original_ranges':len(c['original_ranges']),'compiler_ranges':len(c['compiler_ranges']),'fixup_records':len(c['original_fixup_records']),'local_proofs_unsat':len(c['proofs']),'header_byte_domain':len(byte_results),**count,'assertions':checks}
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in ['rpc502_supp_profiles.json','rpc502_supp_contracts.json','probe_rpc502_supp.py','probe_rpc502_supp_cases.py','rpc502_supp_layouts.c','rpc502_supp_layouts.s']},'source_sha256':source_sha,'verified_counts':counts,'independent_solver_timeout_ms':120000,'header_byte_results':{str(k):v for k,v in byte_results.items()},'observed_carrier_read_offsets_bytes':sorted(core_offsets),'decoded_carrier_statuses':sorted(status_values),'case_summaries':summaries,'all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_supp_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)

if __name__=='__main__':main()
