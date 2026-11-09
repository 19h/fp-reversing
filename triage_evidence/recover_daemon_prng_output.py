#!/usr/bin/env python3
"""Original PRNG/global-buffer/counter and comparison-record interfaces.
O(trace bytes+source+256+fixups) time,O(largest journal) space; no target runs.
"""
import hashlib,json
from pathlib import Path
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,FIXUPS,selected,verify_original_fixups
from recover_daemon_iokit_census import native
from replay_daemon_seed_material import unpack

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def value(s):assert'hex'in s;return int.from_bytes(bytes.fromhex(s['hex']),'little')
def events(t,pc,kind=None):return[e for s in t['steps']if s['pc']==hex(pc)for e in s['events']if kind is None or e['kind']==kind]
def main():
 p=json.loads((ROOT/'daemon_prng_output_profiles.json').read_text());prior=json.loads((ROOT/'daemon_context_transfer_profiles.json').read_text());rows=[]
 for row in p['cases']:
  t=unpack(row);F=int(row['frame_SP'],16);H=int(row['heap_base'],16);R=F+0xaf8;old=unpack(next(x for x in prior['cases']if x['prior_case_index']==row['prior_case_index']));publication=events(old,0x1002fb820,'write');assert len(publication)==1 and publication[0]['address']=='0x1010c8278';D=value(publication[0]['value']);assert H<=D<D+512<=H+90000
  key=events(t,0x10029a14c,'read');K=((R^0x823819558515cfbd)*0xc7f6dca7)&((1<<64)-1);assert len(key)==2 and all(value(x['value'])==K for x in key)
  writes=[{'pc':s['pc'],**e}for s in t['steps']for e in s['events']if e['kind']=='write'];state=[w for w in writes if 0x1010c784c<=int(w['address'],16)<0x1010c820c];updates=events(t,0x100350624,'write');assert [int(x['address'],16)for x in updates]==[D,D+4]
  counter_reads=events(t,0x10029a134,'read');counter_writes=events(t,0x1003505b8,'write');index_writes=events(t,0x10029a130,'write');assert [value(x['value'])for x in counter_reads]==[0,1]and all(x['address']=='0x1010c8258'for x in counter_reads+counter_writes)and[value(x['value'])for x in counter_writes]==[1,2]and[value(x['value'])for x in index_writes]==[1,2]and all(x['address']=='0x1010c67dc'for x in index_writes)
  count=Counter(s['pc']for s in t['steps']if s['mnemonic']=='blraa');phase=next(s['registers_after']['x8']for s in t['steps']if s['pc']=='0x1003b0908');assert value(phase)==0x8a9b8560
  history=[{'pc':s['pc'],**e}for s in old['steps']for e in s['events']if e['kind']=='write'and int(e['address'],16)==F+0x358];roots=[{'pc':s['pc'],**e}for s in old['steps']for e in s['events']if e['kind']=='write'and int(e['address'],16)==F+0x1e0]
  bank_reads=[events(t,pc,'read')[0]for pc in [0x10029a1a8,0x10029a1bc]];rows.append({'prior_case_index':row['prior_case_index'],'frame_SP':hex(F),'heap_base':hex(H),'source_visits':len(t['steps']),'SSA_definitions':len(t['definitions']),'finite_read_sites':dict(Counter(x['pc']for x in t['lookups'])),'state_write_sites':dict(Counter(x['pc']for x in state)),'state_words_written':len(state),'data_pointer_publication':{'pc':'0x1002fb820',**publication[0]},'data_pointer':hex(D),'owner_offset_bytes':D-H,'loop_extent_bytes':512,'initial_words':[value(x['value'])for x in events(t,0x100350610,'read')],'word_updates':updates,'counter_reads':counter_reads,'counter_writes':counter_writes,'index_writes':index_writes,'comparison_key64':hex(K),'helper_call_sites':dict(count),'reused_frame358_writes':history,'frame1E0_writes':roots,'current_frame1E0_cell':'0x1010c8278','current_frame2F8_cell':'0x1010c67dc','second_word_nonzero_path_visits':sum(s['pc']=='0x10031cc98'for s in t['steps']),'new_API_calls':0,'last_twist_phase':phase,'bank_left':hex(value(bank_reads[0]['value'])),'bank_right':hex(value(bank_reads[1]['value'])),'frontier':t['boundary']})
 specs=[('twist1',0x10035c6d8,0x10035c72c),('twist2',0x100474038,0x10047408c),('twist3',0x1003b0900,0x1003b0970),('helper40',0x100444d6c,0x100444dfc),('caller40',0x10029a11c,0x10029a1f4),('caller_prekey',0x10032c9fc,0x10032ca54),('key_live_interval',0x10032ca54,0x10032cdc8),('caller_key_multiply',0x10032cdc8,0x10032cdd8),('counter_normal',0x100478558,0x100478590),('counter_reset',0x1002b3d7c,0x1002b3dc0),('word_temper_update',0x1003505b0,0x100350628),('word_advance',0x100350628,0x100350654),('word_loop',0x1004093fc,0x10040944c),('buffer_publish',0x1002fb814,0x1002fb848),('index_reset',0x100406d90,0x100406d94)];spans=[native(n,a,z)for n,a,z in specs];fix={int(a,16)for row in p['cases']for a in row['fixup_addresses']};fix|={TABLE+i*8 for i in [0x17a0,0x17a4,0x3170,0x3195]};bank=selected(int(rows[0]['bank_left'],16),int(rows[0]['bank_right'],16),0x81,0xcbd6,TABLE,0);assert bank['target']=='0x100444d6c'
 matched=[];coverage={}
 for name in ['daemon_prng_output_live_ida.json','daemon_prng_twist_live_ida.json']:
  live=json.loads((ROOT/name).read_text());assert live['target']=='6b117c693e3b'and not live['idb_mutated']
  for item in live['instructions']:
   a=int(item['address'],16);raw=bytes.fromhex(item['bytes']);assert IMAGE.read(a,len(raw))==raw
   for j,b in enumerate(raw,a):assert j not in coverage or coverage[j]==b;coverage[j]=b
   matched.append(item)
 covered=sum(all(int(row['pc'],16)+j in coverage for j in range(4))for row in p['instruction_pool']);slots=[{'index':hex(i),'slot':hex(TABLE+i*8),'fixup':FIXUPS[TABLE+i*8]}for i in [0x17a0,0x17a4,0x3170,0x3195]]
 deps=['daemon_prng_output_profiles.json','daemon_prng_output_symbolic.py','daemon_prng_output_runner.py','daemon_context_transfer_profiles.json','daemon_prng_output_live_ida.json','daemon_prng_twist_live_ida.json','daemon_receive_fixups.txt'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'spans':spans,'bank_rules':[bank],'source_fixup_records':verify_original_fixups(fix),'dispatch_slots':slots,'contexts':rows,'live_IDB_rows_matched':len(matched),'path_pool_instructions':len(p['instruction_pool']),'path_pool_instructions_live_IDB_covered':covered,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_prng_output_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'spans':len(spans),'contexts':len(rows),'fixups':len(fix),'bank_inputs':256,'live_IDB_rows':len(matched),'path_pool':len(p['instruction_pool']),'live_covered':covered}),flush=True)
if __name__=='__main__':main()
