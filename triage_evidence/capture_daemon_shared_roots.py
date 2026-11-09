#!/usr/bin/env python3
"""Original shared-frame writer ledger, protected-key register projection,
source spans and bounded literal-store census. O(visits + text words) time,
O(journal/census) space. Source-established setup ownership is bounded to the
profiled entry-to-setup interval; no later emitter epoch is joined here.
"""
import json,struct
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from capture_daemon_record720 import sha
from daemon_output_base_dispatch import CS
from daemon_digest_output_access import key
from recover_daemon_iokit_census import text_section
from recover_daemon_descriptor_producers import verify_used_fixups
from probe_daemon_shared_roots import FIELDS,EXPECTED,ENTRY,END

def capture():
 source=json.loads((ROOT/'daemon_shared_roots_profiles.json').read_text());first=source['cases'][0];stop=next(j for j,s in enumerate(first['source_visits'])if s['pc']=='0x10061a5c4');live={'x12'};projection=[]
 for st in reversed(first['source_visits'][:stop+1]):
  i=next(CS.disasm(bytes.fromhex(st['bytes_hex']),int(st['pc'],16)));rr,ww=i.regs_access();writes={key(i.reg_name(r))for r in ww}
  if live&writes:projection.append(st);live-=writes;live|={key(i.reg_name(r))for r in rr}
 assert live=={'x0'}and len(projection)==20;projection.reverse();ledgers=[];used=set()
 for r in source['cases']:
  F=int(r['frame_base'],16);assert F==int(r['entry_SP'],16)-0x10dd0 and int(r['boundary']['registers31'][29],16)==F+0x10dc0;fields=[]
  for off in FIELDS:
   matches=[e for e in r['source_writes']if int(e['address'],16)<F+off+8 and F+off<int(e['address'],16)+e['size_bytes']];assert len(matches)==1;w=matches[0];assert int(w['address'],16)==F+off and w['size_bytes']==8 and int.from_bytes(bytes.fromhex(w['after_hex']),'little')==EXPECTED[off]
   consumers=[e for e in r['source_reads']if e['source_visit_index']>w['source_visit_index']and int(e['address'],16)<F+off+8 and F+off<int(e['address'],16)+e['size_bytes']];fields.append({'offset_bytes':off,'value':hex(EXPECTED[off]),'writer':w,'subsequent_reads':consumers,'subsequent_overwrites_before_stop':0})
  opreads=[e for e in r['source_reads']if e['pc']=='0x1004c244c'];assert len(opreads)==1
  setup=[e for e in r['source_writes']if 0x1004c24a4<=int(e['pc'],16)<END];assert len(setup)==129
  ledgers.append({'configuration':r['configuration'],'frame_base':hex(F),'fields':fields,'setup_source_stores':129,'next_target':r['boundary']['registers31'][8],'phase_word':'0x6cf4','protected_record':r['record_address'],'protected_record_reads_at_setup':opreads})
  for e in r['source_reads']:
   a=int(e['address'],16)
   if a in FIXUPS and e['size_bytes']==8:used.add(a)
 A,N=text_section();text=IMAGE.read(A,N);census=[]
 for off,width in[(0x9d0,8),(0x6c,4),(0x968,8),(0x960,8),(0x9c0,8),(0x9c8,8),(0x9d8,8)]:
  pattern=(0xf90003e0 if width==8 else 0xb90003e0)|((off//width)<<10);rows=[hex(A+4*j)for j,(w,)in enumerate(struct.iter_unpack('<I',text))if w&0xffffffe0==pattern];census.append({'SP_offset_bytes':off,'store_width_bytes':width,'literal_store_PCs':rows,'frame_equivalence_of_other_sites_established':False})
 spans=[]
 for label,a,z in[('entry_saves',ENTRY,0x10061a328),('phase_table_store',0x10061a90c,0x10061a990),('operation_decode',0x1004c244c,0x1004c24a4),('literal_bank_roots',0x10061a73c,0x10061a75c),('setup_tail',0x1004c35f8,0x1004c3638)]:
  spans.append({'label':label,'address':hex(a),'bytes_hex':IMAGE.read(a,z-a).hex()})
 return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_shared_roots_profiles.json','probe_daemon_shared_roots.py','daemon_rpc502_contracts.json','daemon_aux_callers_contracts.json']},'source_spans':spans,'protected_key_projection':projection,'projection_live_inputs':['x0'],'field_ledgers':ledgers,'literal_store_census':census,'census_scope':'Aligned unsigned-immediate STR Wn/Xn with exact SP offsets in original text; pair/alias/register-offset stores and SP movement excluded.','original_fixups':verify_used_fixups(used),'actual_controller_pointer_at_F9C8':'0x1010b8dc8','prior_aux_caller_controller_fixture':'0x1010b66a8','later_emitter_control_epoch_join':'unknown','native_target_executed':False,'full_goal_complete':False}
if __name__=='__main__':
 r=capture();(ROOT/'daemon_shared_roots_source.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'cases':len(r['field_ledgers']),'defined_fields_per_case':len(r['field_ledgers'][0]['fields']),'key_projection_instructions':len(r['protected_key_projection']),'literal_counts':[(hex(g['SP_offset_bytes']),len(g['literal_store_PCs']))for g in r['literal_store_census']]}),flush=True)
