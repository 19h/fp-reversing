#!/usr/bin/env python3
"""Recover core source roles, observed helper ABIs and exact original bytes.
O(all case visits/effects+source) time; O(compressed artifacts+largest decoded
journal) space. Observed ABI constants are proof premises, not native callers.
"""
import json
from pathlib import Path
from collections import Counter
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,FIXUPS
from recover_daemon_object_creation import sha,span
from replay_daemon_descriptor_producers import unpack
from recover_daemon_descriptor_producers import verify_used_fixups
from recover_daemon_cache36 import ida_matches
from daemon_sha1_core_model import reference,STATE_XOR,ROUND_MAPS
SPECS=[('frame',0x100abee44,0x100abef18),('entry',0x100b76438,0x100b764ac),('selector0',0x100d9f60c,0x100d9f660),('selector1',0x100b0a24c,0x100b0a29c),('sha1_entry',0x100a361b0,0x100a3623c),('input_words',0x100968c04,0x100968dfc),('schedule',0x100ba8ba4,0x100ba8c48),('round0',0x100a0dd8c,0x100a0e074),('round1',0x100d30e74,0x100d31028),('round2',0x100acc478,0x100acc6c0),('round3',0x100d30c74,0x100d30e1c),('feed_e',0x100908450,0x100908668),('feed_abcd',0x100bdf3bc,0x100bdfaf0)]
COUNTERS={'input_words':(5,0x5706927b,4,0,15),'schedule':(20,0x5706927b,1,16,79),'round0':(21,0x5706927b,1,0,19),'round1':(4,0x5706927b,1,20,39),'round2':(21,0x5706927b,1,40,59),'round3':(20,0x5706927b,1,60,79)}
OUTPUT_MAPS=[[[11],[13,19],[0],[20,30],[5,15]],[[11],[1,13],[0],[20,26],[5,19]],[[11],[1,13],[0],[5,26],[4,19]],[[11],[13,19],[0],[5,21],[1,4]]]
def key(n):return'x'+n[1:]if n.startswith('w')else {'fp':'x29','lr':'x30'}.get(n,n)
def liveins(a,z):
 cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;defined=set();need={}
 for i in cs.disasm(IMAGE.read(a,z-a),a):
  reads,writes=i.regs_access()
  for r in reads:
   n=cs.reg_name(r)
   if n not in ['wzr','xzr']and key(n)not in defined:need[key(n)]=n
  defined.update(key(cs.reg_name(r))for r in writes)
 return need
def helper_abis(t):
 cfg=t['configuration'];C=int(t['context'],16);F=int(t['SP'],16);B=int(t['workspace'],16);model=reference(bytes.fromhex(cfg['block_hex']),cfg['initial_state5']);rows={}
 for name,a,z in SPECS:
  if name not in COUNTERS:continue
  shots=[x['registers31']for x in t['helper_entries']if x['pc']==hex(a)];need=liveins(a,z-4);seeds={};regidx,base,scale,lo,hi=COUNTERS[name];assert len(shots)==hi-lo+1
  for k,n in need.items():
   if k=='sp':seeds[k]={'kind':'frame_pointer'};continue
   idx=int(k[1:]);vals=[r[idx]for r in shots]
   if idx==regidx or name=='schedule'and idx==26:assert vals==[base+scale*j for j in range(lo,hi+1)];seeds[k]={'kind':'counter','base':base,'scale':scale};continue
   state=None
   if name.startswith('round'):
    for j in range(5):
     if vals==[model['working_states81'][r][j]^STATE_XOR for r in range(lo,hi+1)]:state=j;break
   if state is not None:seeds[k]={'kind':'state_word','word_index':state};continue
   assert len(set(vals))==1,(name,k,'unclassified live input',vals[:3]);v=vals[0];seeds[k]={'kind':'workspace_pointer'}if v==B else{'kind':'context_pointer'}if v==C else{'kind':'table_pointer'}if v==TABLE else{'kind':'constant','value':v}
  es=[e for e in t['edges']if e[0]==z-4];assert len(es)==len(shots);assert len({e[2]for e in es[:-1]})==1;rows[name]={'start':hex(a),'end':hex(z),'counter_domain':[lo,hi],'counter_register':'x'+str(regidx),'seeds':seeds,'loop_slot':hex(es[0][2]),'exit_slot':hex(es[-1][2]),'scope':'Classified from the first isolated journal; finite corpus and source proofs independently recheck these cutpoint premises.'}
 return rows
def main():
 p=json.loads((ROOT/'daemon_sha1_core_profiles.json').read_text());first=unpack(p['cases'][0]);abis=helper_abis(first);pool=first['source_pool'];counts=Counter();slots=set()
 for row in p['cases']:
  t=unpack(row);assert t['source_pool']==pool and len(t['round_entries'])==81 and len(t['round_exits'])==80;assert t['boundary']['pc']=='0x100bdfaf0';counts['source_visits']+=len(t['steps']);counts['logical_BRAA_dispatches']+=len(t['edges']);counts['read_effects']+=sum(e['kind']=='read'for e in t['events']);counts['write_effects']+=sum(e['kind']=='write'for e in t['events']);counts['cases']+=1
  for e in t['events']:
   if e['kind']=='read'and e['address']in FIXUPS:slots.add(e['address'])
 for a,b in pool.items():assert IMAGE.read(int(a,16),4).hex()==b
 spans=[span(n,a,z)for n,a,z in SPECS];assert sum((z-a)//4 for n,a,z in SPECS)==len(pool)==1467;live=ida_matches('daemon_sha1_core_ida_bytes.json');deps=['daemon_sha1_core_profiles.json','daemon_sha1_core_model.py','daemon_sha1_core_ida_bytes.json','daemon_compression_frame_checks.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'spans':spans,'source_pool':pool,'helper_ABIs':abis,'round_output_maps':OUTPUT_MAPS,'original_fixups':verify_used_fixups(slots),'live_IDB_matches':live,'trace_totals':dict(counts),'standard_reference':{'url':'https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf','DOI':'10.6028/NIST.FIPS.180-4','sections':['4.1.1','4.2.1','6.1.2'],'checked_UTC_date':'2026-11-03'},'new_port_emission_established':False,'identity_digest_or_cache_publication_established':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_sha1_core_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'source_spans':len(spans),'unique_instructions':len(pool),'fixups':len(out['original_fixups']['records']),'IDB_bytes':sum(x['size_bytes']for x in live),'totals':dict(counts)}),flush=True)
if __name__=='__main__':main()
