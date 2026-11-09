#!/usr/bin/env python3
"""Original frame/gate/banks, byte-fill call and retained startup write epochs.
O(B+V+stores+256R+F) time,O(largest retained payload+spans) space.
Historical zero-stack journals are readback evidence, not fresh native runs.
"""
import hashlib,json
from pathlib import Path
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE,POOL,selected,verify_original_fixups
from recover_daemon_iokit_census import native
from probe_daemon_frame_entry import RANGES
from rpc502_startup_tools import unpack,journals,visits
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 spans=[native('source_'+str(j),a,z)for j,(a,z)in enumerate(RANGES)]
 spans += [native('join_prefix',0x1003062a4,0x100306360),native('byte_fill',0x10046faf8,0x10046fc5c),native('flag1_frontier',0x1003b5724,0x1003b5740),native('cold_frontier',0x1003ecb8c,0x1003ecb94)]
 rules=[('controller_A',0x100fc4230,0x101031fa0,0xe4,0xd8,POOL,0xffffffff9b317de5),('controller_B',0x100e99a00,0x100f4e390,0x54,-0x22,POOL,0xffffffffec9e1772),('status_cell',0x100e99a00,0x100f4e390,0x54,0x1028,POOL,0xfffffffff40d6a02),('dispatch_table',0x100e99700,0x100f4e190,0x56,0x906,POOL,0xffffffffd0c4d1ee),('initial_dispatch_slot',0x100e99700,0x100f4e190,0x56,0x906,POOL,0xffffffffd0c90aee),('atomic_gate',0x101031da0,0x100e99900,0x9a,0x1a9,POOL,0xffffffffda6d5972),('fill_target',0x100fc4230,0x101031fa0,0xf3,0xcc58,TABLE,0)]
 banks=[]
 for name,l,r,k,add,base,bias in rules:
  row=selected(l,r,k,add,base,bias);row.update(label=name,base=hex(base));banks.append(row)
 profile=json.loads((ROOT/'daemon_frame_entry_profiles.json').read_text());used={int(x['address'],16)for r in profile['cases']for x in r['source_fixup_reads']};used|={int(b['slot'],16)for b in banks};used-={0x1010b1e18};used.add(0x10107d820)
 live=json.loads((ROOT/'daemon_frame_entry_live_ida.json').read_text());matched=[]
 for r in live['disassembly']['results']:
  for i in r['instructions']:
   b=bytes.fromhex(i['bytes']);assert IMAGE.read(int(i['address'],16),len(b))==b;matched.append({'pc':i['address'],'size_bytes':len(b)})
 history=json.loads((ROOT/'rpc502_startup_profiles.json').read_text());old=[]
 for name in ['initialized_worker','quantum250k_prefix','entropy_time_prefix']:
  r=unpack(next(x for x in history['cases']if x['case']['label']==name));E=int(r['entry_sp'],16);F=E-0xbe0;memory={};writers={};events=[];hits=Counter();sequence=[];join_cursor=None;total=0
  for j in journals(r):
   if j['phase']=='worker':break
   v=visits(j);total+=len(v)
   for pc in [0x10045053c,0x1002dab28,0x1002dac48,0x1002dad48,0x1001f1ff8,0x1003062a4,0x10030631c]:hits[hex(pc)]+=v.count(pc)
   sequence += [hex(pc)for pc in v if pc in [0x10045053c,0x1002dab28,0x1002dac48,0x1002dad48,0x1001f1ff8,0x1003062a4,0x10030631c]]
   for w in j['stack_stores']:
    a=int(w['address'],16);b=bytes.fromhex(w['actual_after_hex']);assert len(b)==w['size_bytes']
    if w['pc']=='0x1002dab80':
     assert a==E-0x10-0xd8
     fields=[]
     for off in [0x28,0x348,0x350,0x360,0x368,0x370,0x378,0x390,0x398,0x5c0]:
      bb=bytes(memory[F+off+k]for k in range(8));producers=[writers[F+off+k]for k in range(8)];assert all(p==producers[0]for p in producers)
      fields.append({'offset_bytes':hex(off),'value64':hex(int.from_bytes(bb,'little')),'last_writer':producers[0]})
     events.append({'kind':'before_first_record_control_store','step':w['step_index'],'frame_SP':hex(F),'frame_FP':hex(E-0x10),'record':hex(a),'fields':fields})
    if w['pc']=='0x10030635c':
     join_cursor=hex(int.from_bytes(bytes(memory[F+0x5c0+k]for k in range(8)),'little'));events.append({'kind':'cursor_advance','step':w['step_index'],'before64':join_cursor,'after64':hex(int.from_bytes(b,'little'))})
    for k,x in enumerate(b):memory[a+k]=x;writers[a+k]={'pc':w['pc'],'step':w['step_index']}
  assert sequence==['0x10045053c','0x1002dab28','0x1002dac48','0x1002dad48','0x1001f1ff8','0x1003062a4','0x10030631c']
  assert len(events)==2 and join_cursor=='0x10'
  old.append({'case':name,'stack_initialization':r['stack_initialization'],'startup_returned':r['startup_returned'],'startup_source_visits':total,'ordered_selected_source_sequence':sequence,'source_hit_counts':dict(hits),'events':events,'scope':'Retained source-attested private journal; initial arbitrary stack bytes were zero fixtures. No native or fresh continuous execution added.'})
 deps=['probe_daemon_frame_entry.py','daemon_receive_tools.py','daemon_receive_fixups.txt','recover_daemon_iokit_census.py','rpc502_startup_tools.py','rpc502_startup_profiles.json','daemon_frame_entry_profiles.json','daemon_frame_entry_live_ida.json']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'spans':spans,'bank_rules':banks,'original_fixup_records':verify_original_fixups(used),'live_IDB_source_rows_matched':matched,'historical_startup_readback':old,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_frame_entry_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'spans':len(spans),'banks':len(banks),'fixups':len(used),'IDB_rows':len(matched),'historical_cases':len(old)}),flush=True)
if __name__=='__main__':main()
