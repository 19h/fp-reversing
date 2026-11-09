#!/usr/bin/env python3
"""Cross-journal record-origin audit, literal-candidate/compiler-envelope
comparison, original fixups/import and live-IDB raw-byte corroboration.
O(prefix visits + function starts + selected bytes) time, O(journal/census) space.
Compiler intervals are address envelopes; actual paths establish frame ownership.
"""
import json,struct
from bisect import bisect_right
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from capture_daemon_record720 import sha
from bootpolicy_cache_reader import uleb
from resolve_kernel_collection_interfaces import commands
from daemon_output_base_dispatch import CS,SPILLS
from daemon_digest_output_access import key
from daemon_import_bindings import binding
from recover_daemon_descriptor_producers import verify_used_fixups

def recover():
 data=SOURCE.read_bytes();at=next(o for o,c,n in commands(data,0)if c==0x26);off,n=struct.unpack_from('<II',data,at+8);cur=off;a=0x100000000;starts=[]
 while cur<off+n:
  v,cur=uleb(data,cur)
  if not v:break
  a+=v;starts.append(a)
 old=json.loads((ROOT/'daemon_cleanup_return_contracts.json').read_text());candidates=[]
 for r in old['literal_STR64_SP_24F8_candidates']:
  pc=int(r['pc'],16);j=bisect_right(starts,pc)-1;candidates.append({**r,'compiler_interval_start':hex(starts[j]),'compiler_interval_end':hex(starts[j+1]),'compiler_interval_establishes_frame_owner':False})
 profiles=json.loads((ROOT/'daemon_descriptor_producers_profiles.json').read_text());audits=[]
 for j,p in enumerate(profiles['cases']):
  entries=[c for c in p['checkpoints']if c['pc']=='0x100a59bb4'];assert len(entries)==1;entry=entries[0];R=int(p['record_address'],16);assert int(entry['registers31'][0],16)==R and R==int(p['entry_FP'],16)-256
  hit=[e for e in p['source_writes']if e['pc']=='0x10097c778'];assert len(hit)==int(p['configuration']['nonnull'])
  if not hit:continue
  e=hit[0];first=entry['source_visit_index'];last=e['source_visit_index'];prefix=p['source_visits'][first:last];x0writes=[];spwrites=[]
  for st in prefix:
   pc=int(st['pc'],16);raw=bytes.fromhex(st['bytes_hex']);assert IMAGE.read(pc,4)==raw if st['image']=='daemon'else True;i=next(CS.disasm(raw,pc));written={key(i.reg_name(r))for r in i.regs_access()[1]}
   if'x0'in written:x0writes.append(st['pc'])
   if'sp'in written:spwrites.append({'pc':st['pc'],'instruction':i.mnemonic+' '+i.op_str})
  assert not x0writes;F=int(entry['SP'],16)-0xdf50;assert int(e['address'],16)==F+0x24f8 and int.from_bytes(bytes.fromhex(e['after_hex']),'little')==R
  branch=next(q for q in p['logical_edges']if q['source_visit_index']==last-1);assert branch['pc']=='0x100b09218'and branch['target']=='0x10097c778'and branch['modifier']=='0x9fed'
  audits.append({'prefix_case_index':j,'configuration':p['configuration'],'entry_PC':entry['pc'],'entry_SP':entry['SP'],'callee_F':hex(F),'caller_record':hex(R),'source_visits_entry_to_spill':len(prefix),'X0_write_PCs_before_spill':x0writes,'SP_write_instructions':spwrites,'spill':e,'incoming_original_branch':branch,'native_reachability_established':False})
 raw=json.loads((ROOT/'daemon_output_base_ida.json').read_text());matches=[]
 for item in raw['content']:
  if item['type']!='text':continue
  t=item['text'];assert '6b117c693e3b'in t;m='[assist:tool-output]';a=t.index(m)+len(m);obj=json.loads(t[a:t.index('[/assist:tool-output]',a)])
  for r in obj['results']:
   pc=int(r['address'],16);b=bytes.fromhex(r['bytes']);assert len(b)==128 and b==IMAGE.read(pc,128);matches.append({'address':hex(pc),'matching_bytes':len(b)})
 dispatch=json.loads((ROOT/'daemon_output_base_dispatch.json').read_text());branches=json.loads((ROOT/'daemon_output_base_branches.json').read_text());slots={int(e['slot'],16)for d in [dispatch]+branches['cases']for p in d['paths']for e in p['edges']};slots.add(0x1010a7e18);routes=[]
 for tag,pc in SPILLS.items():routes.append({'representative_aux':hex(tag),'singleton':tag!=0x7bed772d,'decoded_aux_condition':('0x38ACBB2A <= aux <= 0x7FFFFFFF'if tag==0x7bed772d else'aux == '+hex(tag)),'spill_PC':hex(pc),'saved_register':'X0'})
 for d in branches['cases']:
  assert len(d['paths'])==1 and d['paths'][0]['boundary']['pc']=='0x1009d0624'and len(d['unavailable_frame_byte_variables'])==28 and len(d['borrowed_input_byte_variables'])==8
 rejected=ROOT/'daemon_output_base_rejected_singleton.smt2';solver=z3.Solver();solver.add(z3.parse_smt2_file(str(rejected)));solver.add(z3.BitVec('output_base_aux32',32)==0x7484eeab);assert solver.check()==z3.sat
 return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_cleanup_return_contracts.json','daemon_descriptor_producers_profiles.json','daemon_output_base_dispatch.json','daemon_output_base_branches.json','daemon_output_base_ida.json','daemon_output_base_rejected_singleton.smt2']},'literal_candidates':candidates,'source_frame_origin_audits':audits,'nonNULL_source_prefixes':len(audits),'NULL_source_prefixes_without_spill':24,'routes':routes,'interval_cardinality_u32':0x80000000-0x38acbb2a,'default_cardinality_u32':(1<<32)-(0x80000000-0x38acbb2a)-4,'original_fixups':verify_used_fixups(slots),'CoreFoundation_data_binding':binding(0x1010a7e18),'live_IDA_matches':matches,'rejected_hypothesis':{'claim':'Route 0x100B2CF64 is only aux==0x7BED772D','query_file':rejected.name,'query_sha256':sha(rejected),'counterexample_aux':'0x7484eeab','counterexample_result':'sat','corrected_condition':'0x38ACBB2A <= aux <= 0x7FFFFFFF'},'constructor720_epoch_join':'unknown','native_target_executed':False,'full_goal_complete':False}
if __name__=='__main__':
 r=recover();(ROOT/'daemon_output_base_contracts.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'origin_audits':len(r['source_frame_origin_audits']),'IDA_bytes':sum(r['matching_bytes']for r in r['live_IDA_matches']),'routes':r['routes'],'interval_cardinality':r['interval_cardinality_u32']}),flush=True)
