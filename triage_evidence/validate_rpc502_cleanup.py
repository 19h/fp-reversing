#!/usr/bin/env python3
"""Independent original-byte, caller, mode, invalidation and replay checks.

Two frozen complete worker pairs connect source-built mode0/1 records to the
cleanup helper. Twenty-four distinct new helper replays check exact API
arguments, failure controls and record writes. No native API or IDB action.
O(B+F+C*(V+E+S)) time, O(largest case/journal) retained working space.
"""
import collections,hashlib,json,struct,subprocess
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,TABLE,qword,verify_original_fixups
from daemon_import_bindings import binding
from rpc502_startup_tools import unpack,journals,visits
from probe_rpc502_cleanup import Cleanup,key,RECORD,MAPPING,SIZE_XOR
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 counts=collections.Counter();p=json.loads((ROOT/'rpc502_cleanup_profiles.json').read_text());c=json.loads((ROOT/'rpc502_cleanup_contracts.json').read_text());deps={'probe_rpc502_cleanup.py','recover_rpc502_cleanup.py','rpc502_cleanup_profiles.json','rpc502_cleanup_contracts.json','rpc502_padding_profiles.json','rpc502_padding_replays.json','rpc502_ownership_checks.json','rpc502_startup_tools.py'}
 for obj,producer in[(p,'probe_rpc502_cleanup.py'),(c,'recover_rpc502_cleanup.py')]:
  assert obj['source_sha256']==sha(SOURCE)and obj['generator_sha256']==sha(ROOT/producer)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h;deps.add(n)
 for e in c['source_ranges']:
  a=int(e['start'],16);z=int(e['end'],16);b=IMAGE.read(a,z-a);assert b.hex()==e['bytes']and hashlib.sha256(b).hexdigest()==e['sha256'];assert e['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a)]
 for e in c['original_pointer_import_records']:assert(binding(int(e['slot'],16))if'slot'in e else verify_original_fixups([int(e['address'],16)])['records'][0])==e
 for e in c['proofs']:
  path=ROOT/e['path'];assert sha(path)==e['sha256'];r=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert r.stdout.strip()=='unsat'and not r.stderr;counts['proofs_unsat']+=1
 for e in c['selected_targets']:
  a=int(e['slot'],16);assert a==TABLE+int(e['index'],16)*8 and IMAGE.read(a,8).hex()==e['word_hex']and qword(a)==int(e['target'],16)
 assert [e['target']for e in c['selected_targets']]==['0x1001f1988','0x1003aae74']
 w=int(c['unaligned_counterexample']['argument_low32'],16);primary=lambda v:((((v-2*(v&0x141fcb58)+0x941fcb5c)&0xffffffff)^0x0271934e)*0x592e2f77)&0xffffffff;assert w&3==0 and w&7!=0 and primary(w)!=key(w)
 pool={}
 for e in p['source_instructions']:
  a=int(e['ea'],16);b=IMAGE.read(a,4);i=next(CS.disasm(b,a));assert b.hex()==e['bytes']and i.mnemonic==e['mnemonic']and i.op_str==e['operands'];pool[a]=b
 fresh=[]
 for row in p['cases']:
  q=Cleanup(row['fixture']);r=q.execute();assert r==row;fresh.append(r);counts['fresh_helper_runs']+=1;counts['fresh_helper_source_visits']+=len(r['source_visits']);v=r['fixture'];mode=v['mode_byte']&1;expected=['libSystem/_munmap','libSystem/_close']if mode else['libSystem/_close'];assert [e['name']for e in r['API_requests']]==expected
  assert not r['native_target_executed']and not r['full_worker_executed']and r['stop_reason']=='returned_to_fixture'
  for e in r['API_requests']:
   assert not e['native_API_executed']
   if e['name'].endswith('_munmap'):assert e['site']=='0x1003aaef4'and e['args']==[hex(MAPPING),hex(v['extent_bytes'])]and e['result_signed32']==v['unmap_result'];counts['unmap_requests']+=1
   else:assert e['site']=='0x1001f19c4'and e['args'][0]=='0x8'and e['result_signed32']==v['close_result'];counts['close_requests']+=1
  before=bytearray.fromhex(r['initial_mapping_record32_hex']);struct.pack_into('<I',before,0,0xffffffff);assert bytes(before)==bytes.fromhex(r['final_mapping_record32_hex']);assert r['initial_argument24_hex']==r['final_argument24_hex'];assert len(r['source_record_stores'])==1;store=r['source_record_stores'][0];assert store=={'pc':'0x1001f19cc','address':hex(RECORD),'size_bytes':4,'after_hex':'ffffffff'};counts['descriptor_invalidations']+=1
  for a in r['source_visits']:assert int(a,16)in pool
  if v['close_result']!=0 or v['unmap_result']!=0:counts['failure_control_cases']+=1
 old=json.loads((ROOT/'rpc502_padding_profiles.json').read_text());replay=json.loads((ROOT/'rpc502_padding_replays.json').read_text());whole=[];source_pool={int(e['ea'],16):struct.pack('<Q',int(e['ea'],16))+IMAGE.read(int(e['ea'],16),4)for e in old['original_instruction_pool']}
 for a,b in zip(old['cases'],replay['cases']):
  assert a['case']==b['case'];r=unpack(a);fr=unpack(b);assert r==fr;del fr;assert r['records'][-1]['result']=='0xffff5bd9';counts['reused_whole_worker_pairs']+=1;positions=collections.defaultdict(list);at=0
  selected={0x1007483f0,0x1007484d4,0x100723af8,0x100723bbc,0x100444704,0x1004448f0}
  for j in journals(r):
   seq=visits(j);h=hashlib.sha256()
   for n,ea in enumerate(seq):
    h.update(source_pool[ea])
    if ea in selected:positions[ea].append(at+n)
   assert h.hexdigest()==j['ordered_source_bytes_sha256'];at+=len(seq)
   for start,end in[(0x1007483f0,0x1007484d4),(0x100723af8,0x100723bbc)]:
    if start in seq:
     idx=seq.index(start);expected=tuple(range(start,end+4,4));assert seq[idx:idx+len(expected)]==expected;counts['contiguous_caller_constructors']+=1
  counts['reused_retained_source_visits']+=at;counts['reused_fresh_source_visits']+=at
  calls=[e for e in r['parser_edges']if e['pc']in['0x1007484d4','0x100723bbc']];edges=[e for e in r['parser_edges']if e['pc']=='0x1004448f0'];assert len(calls)==len(edges)==2;rows=[]
  for call,edge,mode,addend in zip(calls,edges,[0,1],[0x3b92,0x44f6]):
   ptr=int(call['registers_x0_x28'][0],16);sp=int(call['sp'],16);assert ptr==sp+0x10cb8 and ptr&15==8;assert call['target']=='0x100444704';base=(int(call['registers_x0_x28'][19],16)+addend)&0xffffffff;assert base==int(edge['registers_x0_x28'][27],16)==0x6922;index=base^(mode*0xd323);assert int(edge['target'],16)==qword(TABLE+index*8);assert int(edge['registers_x0_x28'][28],16)==TABLE
   rows.append({'call_pc':call['pc'],'argument_pointer':hex(ptr),'mapping_record_pointer':edge['registers_x0_x28'][26],'source_mode_store':hex(0x100748450 if mode==0 else 0x100723b48),'stored_mode_byte':mode,'decoded_base_index':hex(base),'selected_index':hex(index),'selected_target':edge['target']});counts['source_built_cleanup_calls']+=1
  assert rows[0]['mapping_record_pointer']!=rows[1]['mapping_record_pointer'];whole.append({'case_label':a['case']['label'],'cleanup_calls':rows,'worker_status':'0xffff5bd9','positions':{hex(k):v for k,v in positions.items()}})
 counts['source_ranges']=len(c['source_ranges']);counts['pointer_import_records']=len(c['original_pointer_import_records']);counts['helper_source_instructions']=len(pool);counts['alignment_counterexamples']=1
 (ROOT/'rpc502_cleanup_replays.json').write_text(json.dumps({'scope':'Twenty-four distinct fresh helper ABI executions;no new whole workers/native actions.','generator_sha256':sha(Path(__file__)),'cases':fresh,'native_target_executed':False},indent=2)+'\n')
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in sorted(deps)},'verified_counts':dict(counts),'source_built_caller_summaries':whole,'fresh_replays_sha256':sha(ROOT/'rpc502_cleanup_replays.json'),'new_whole_worker_executions':0,'native_target_executed':False,'full_mapping_lifetime_proved':False,'all_checks_pass':True,'full_goal_complete':False};(ROOT/'rpc502_cleanup_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(dict(counts)),flush=True)
if __name__=='__main__':main()
