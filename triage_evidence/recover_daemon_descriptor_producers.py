#!/usr/bin/env python3
"""Recover source-produced mode471C,cursor/stack ABI and a distinct lock cell.
O(source spans+events+256*bank rules+fixups) time/space; native reachability of
descriptor readers remains unknown. No host API or IDB mutation executes.
"""
import json,hashlib
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,POOL,TABLE,FIXUPS,selected
from daemon_import_bindings import binding
from recover_daemon_callback_revisit import verify_fixups
from recover_daemon_context_lock import ida_output
from replay_daemon_descriptor_producers import unpack
def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def verify_used_fixups(addresses):
 special={a:binding(a)for a in addresses if FIXUPS[a]['kind'].endswith('bind')and binding(a)['total_addend']!=0};out=verify_fixups(sorted(set(addresses)-set(special)))
 for a,r in sorted(special.items()):
  assert int(FIXUPS[a]['annotation'].split('+',1)[1].strip(),16)==r['total_addend'];out['records'].append({'address':hex(a),'word':r['word'],'pointer_format':12,'authenticated':r['authenticated'],'bind':True,'import_ordinal':r['import_ordinal'],'library_ordinal':r['library_ordinal'],'import_name':r['symbol'],'import_addend':r['import_table_addend'],'pointer_addend':r['pointer_addend'],'total_addend':r['total_addend']})
 return out
def main():
 capture=json.loads((ROOT/'daemon_descriptor_producers_source.json').read_text());p=json.loads((ROOT/'daemon_descriptor_producers_profiles.json').read_text());copies=json.loads((ROOT/'daemon_descriptor_producers_copies.json').read_text());spans=capture['source_spans'].copy()
 for name,a,z in [('opaque_word_decode',0x1009d0198,0x1009d0308),('new_creator_record',0x10097290c,0x1009729d4),('caller_after_allocator',0x1001937e4,0x100193860),('second_auxiliary_gate',0x100a2c7e0,0x100a2c830)]:
  b=IMAGE.read(a,z-a);spans.append({'label':name,'start':hex(a),'end':hex(z),'bytes_hex':b.hex(),'sha256':hashlib.sha256(b).hexdigest(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a)]})
 rules=[('caller_to_adapter',0x100e99a00,0x100f4e390,0x78,0xcc8d,TABLE,0),('adapter_controller_A',0x100e99a00,0x100f4e390,0x6d,0x119e,POOL,0xfffffffffc707ed2),('adapter_controller_B',0x100fc4230,0x101031fa0,0xe4,0x37,POOL,0xffffffffec9e1772),('adapter_LCG_destination',0x101031da0,0x100e99900,0xa,0xa01,POOL,0xffffffffd284cd55),('adapter_dispatch_table',0x100e99700,0x100f4e190,0x56,0x906,POOL,0xffffffffd0c4d1ee),('adapter_to_entry',0x101031da0,0x100e99900,0xa,0xcd30,TABLE,0),('entry_controller_A',0x100e99700,0x100f4e190,0x81,0x1166,POOL,0xffffffff92037f12),('entry_controller_B',0x100e99700,0x100f4e190,0x81,0x4c,POOL,0xffffffffec9e1772),('entry_dispatch_table',0x100e99a00,0x100f4e390,0xd7,0x88e,POOL,0xffffffffd0c4d1ee),('entry_to_creator',0x100e99700,0x100f4e190,0x81,0xcc85,TABLE,0),('eight_byte_allocator',0x100e99a00,0x100f4e390,0x78,0xcb6c,TABLE,0)];banks=[{'label':n,**selected(l,r,k,add,base,bias)}for n,l,r,k,add,base,bias in rules];fix={int(b['slot'],16)for b in banks};fix.update([0x1010b1e18,0x1010b1e28]);pool={};paths=[]
 extra=selected(0x100e99700,0x100f4e190,0x81,0x97a,POOL,0xffffffffade431b6);assert extra['target']=='0x1010c67c0';banks.append({'label':'new_lock_destination',**extra});fix.add(int(extra['slot'],16))
 for r in p['cases']:
  for e in r['source_reads']:
   a=int(e['address'],16)
   if a in FIXUPS and e['size_bytes']==8:fix.add(a)
  pool.update({s['pc']:s['bytes_hex']for s in r['source_visits']if s['image']=='daemon'});paths.append({'configuration':r['configuration'],'calls':r['source_calls'],'checkpoints':r['checkpoints'],'final_record':r['final_record'],'final_counter':r['final_counter'],'boundary':r['boundary']})
 continuations=[]
 for r in copies['cases']:
  t=unpack(r);fix.update(int(a,16)for a in t['used_fixups']);pool.update({pc:s['bytes_hex']for pc,s in t['source_pool'].items()});creator=next(s for s in t['steps']if s['pc']=='0x1009729d0');assert creator['target']=='0x10043a240'and creator['modifier16']=='0x8c6d';F=int(t['initial_SP'],16);events=[e for s in t['steps']for e in s['events']if e['kind']=='write'];a=F+0xde90;record_events=[e for e in events if a<=int(e['address'],16)<a+20];continuations.append({'configuration':r['configuration'],'continuation_source_visits':r['source_visits'],'unknown_input_bytes_retained':r['unknown_input_bytes_used'],'creator_call':creator['pc'],'creator_record_address':hex(a),'creator_record_source_writes':record_events,'creator_destination':'0x1010c67c0','decoded_creator_control32':'0xaed7','first_import_boundary':r['boundary'],'word_decode_store':next(e for s in t['steps']if s['pc']=='0x1009d0304'for e in s['events']if e['kind']=='write')})
 live=[]
 for n in ['daemon_descriptor_producers_live_ida.json','daemon_descriptor_producers_more_ida.json']:
  rows=ida_output(json.loads((ROOT/n).read_text()))['results']
  for r in rows:
   a=int(r['address'],16);b=bytes.fromhex(r['bytes']);assert IMAGE.read(a,len(b))==b
   for i in r['instructions']:
    b2=bytes.fromhex(i['bytes']);assert IMAGE.read(int(i['address'],16),len(b2))==b2 and len(b2)<=i['size']
   live.append({'address':hex(a),'size_bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'instruction_rows_checked':len(r['instructions']),'partial_macro_rows':sum(len(bytes.fromhex(i['bytes']))<i['size']for i in r['instructions'])})
 deps=['daemon_descriptor_producers_source.json','daemon_descriptor_producers_profiles.json','daemon_descriptor_producers_copies.json','daemon_descriptor_producers_live_ida.json','daemon_descriptor_producers_more_ida.json','daemon_descriptor_producers_xrefs_ida.json','daemon_rwlock_lifecycle_contracts.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'spans':spans,'banks_exhaustive256':banks,'original_fixups':verify_used_fixups(fix),'conditional_continuous_paths':paths,'arbitrary_byte_continuations':continuations,'distinct_daemon_source_opcodes':len(pool),'live_IDB_matches':live,'original_bindings':{hex(a):binding(a)for a in [0x1010b1e28,0x10109ff58,0x1010a7e18]},'record_contract':{'minimum_accessed_bytes':24,'control32_offset':0,'pointer64_offset':8,'result32_offset':16,'auxiliary32_offset':20,'caller_mode32':'0x471c','caller_auxiliary32':'0x2be18a5d','null_result32':'0x74c29d88','result_XOR_convention_interpretation_signed32':-42023,'native_original_C_type':'unknown'},'new_lock_cell':'0x1010c67c0','prior_descriptor_G':'0x1010c8218','cells_alias':False,'reader_B_reached':False,'native_incoming_reader_phases':'unknown','fixture_PC_transitions':0,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_descriptor_producers_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'spans':len(spans),'banks256':len(banks),'fixups':len(out['original_fixups']['records']),'daemon_opcodes':len(pool),'IDB_raw_bytes':sum(r['size_bytes']for r in live)}),flush=True)
if __name__=='__main__':main()
