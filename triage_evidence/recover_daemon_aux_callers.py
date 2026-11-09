#!/usr/bin/env python3
"""Original literal/record/call census, source-pipeline contracts and readback.
O(text words + journal visits + fixups + bank inputs) time, O(journal/census)
space. Bank roots and incoming phase fields remain explicit component premises.
"""
import json,struct
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,FIXUPS,bank
from capture_daemon_record720 import sha
from recover_daemon_iokit_census import text_section
from recover_daemon_descriptor_producers import verify_used_fixups
from probe_daemon_aux_callers import SPECS,record_address
from daemon_import_bindings import binding

def recover():
 a,n=text_section();data=IMAGE.read(a,n);literals=[];tags=[0xd79bc5de,0xbad70e19,0x2be18a5d,0xeedd0b20,0x38acbb2a];hits={v:[]for v in tags}
 for j in range(0,n-4,4):
  w,z=struct.unpack_from('<II',data,j)
  for v in tags:
   if w&0xffffffe0==0x52800000|((v&65535)<<5)and z&0xffffffe0==0x72a00000|((v>>16)<<5)and(w&31)==(z&31):hits[v].append(a+j)
 callbytes=bytes.fromhex('914a99d211093fd7');calls=[];pos=0
 while (pos:=data.find(callbytes,pos))>=0:
  if pos%4==0:calls.append(a+pos+4)
  pos+=1
 assert len(calls)==16 and {s['call']for s in SPECS}<=set(calls)
 source=json.loads((ROOT/'daemon_aux_callers_profiles.json').read_text());paths=[];used=set();rules={}
 for row in source['cases']:
  p=row['profile'];s=next(s for s in SPECS if s['label']==row['site']);R=int(p['record_address'],16);first=p['source_calls'][0];second=p['source_calls'][1];assert first['pc']==hex(s['call'])and first['target']=='0x100abca64'and second['pc']=='0x100abcc98'and second['target']=='0x100a59bb4'
  assert first['arguments8'][0]==second['arguments8'][0]==hex(R)and first['modifier']=='0xca54'and second['modifier']=='0x1803';raw=bytes.fromhex(first['record']['bytes_hex']);mask=bytes.fromhex(first['record']['known_mask_hex']);K=(((R&0xffffffff)^0xdc40790b)*0x5973a279)&0xffffffff
  assert int.from_bytes(raw[:4],'little')^K==0x471c and(int.from_bytes(raw[20:24],'little')-K)&0xffffffff==s['aux']and int.from_bytes(raw[8:16],'little')==0x6800001000;assert mask[:4]==bytes([1])*4 and mask[8:16]==bytes([1])*8 and mask[20:24]==bytes([1])*4 and not any(mask[4:8]+mask[16:20])
  spill=next(e for e in p['source_writes']if e['pc']==hex(s['spill']));cp=next(c for c in p['checkpoints']if c['pc']=='0x100a59bb4');F=int(cp['SP'],16)-0xdf50;assert spill['address']==hex(F+0x24f8)and int.from_bytes(bytes.fromhex(spill['after_hex']),'little')==R and p['boundary']['pc']==hex(s['spill']+4)and p['fixture_PC_transitions']==0
  paths.append({'site':row['site'],'configuration':p['configuration'],'source_visits':len(p['source_visits']),'record':hex(R),'decoded_mode32':'0x471c','decoded_aux32':hex(s['aux']),'input_pointer':hex(0x6800001000),'adapter_call':first,'entry_call':second,'callee_frame':hex(F),'record_spill':spill,'native_upstream_epoch_established':False})
  for e in p['source_reads']:
   at=int(e['address'],16)
   if at in FIXUPS and e['size_bytes']==8:used.add(at)
 for s in SPECS:
  k=(s['left'],s['right'],s['key'],s['add'])
  if k in rules:continue
  c=bank(k[0],k[1],k[2]);slot=TABLE+(k[3]+c)*8;assert slot==0x1010a0860 and FIXUPS[slot]['target']==0x100abca64;rules[k]={'sites':[t['label']for t in SPECS if(t['left'],t['right'],t['key'],t['add'])==k],'left':hex(k[0]),'right':hex(k[1]),'key':hex(k[2]),'additive':hex(k[3]),'constant':hex(c),'index':hex(k[3]+c),'slot':hex(slot),'target':'0x100abca64','all_byte_inputs_checked':256,'root_provenance':'declared compatibility premise; native frame writer/epoch unknown'}
 pool=[0x100e99700,0x100e99800,0x100e99900,0x100e99a00,0x100f4e190,0x100f4e290,0x100f4e390,0x100fc4130,0x100fc4230,0x101031ba0,0x101031da0,0x101031ea0,0x101031fa0]
 for row in rules.values():
  compatibles=[]
  for left in pool:
   for right in pool:
    x,y=IMAGE.read(left,256),IMAGE.read(right,256);values={j^y[x[j]^int(row['key'],16)]for j in range(256)}
    if len(values)==1 and int(row['additive'],16)+next(iter(values))==0xcd2e:compatibles.append({'left':hex(left),'right':hex(right)})
  row['compatible_pairs_in_bounded_pool']=compatibles
 collisions=[{'slot':hex(at),'target':hex(r['target'])if isinstance(r['target'],int)else r['target'],'original_word':hex(int.from_bytes(IMAGE.read(at,8),'little'))}for at,r in FIXUPS.items()if'div=0xCA54 'in r['line']];assert len(collisions)==4;used|={int(c['slot'],16)for c in collisions};used.add(0x1010a0fc0)
 raw=json.loads((ROOT/'daemon_aux_callers_ida.json').read_text());matches=[]
 for item in raw['content']:
  if item['type']!='text':continue
  t=item['text'];assert '6b117c693e3b'in t;m='[assist:tool-output]';j=t.index(m)+len(m);obj=json.loads(t[j:t.index('[/assist:tool-output]',j)])
  for r in obj['results']:
   at=int(r['address'],16);b=bytes.fromhex(r['bytes']);assert len(b)==256 and b==IMAGE.read(at,256);matches.append({'address':hex(at),'matching_bytes':len(b)})
 rejected=ROOT/'daemon_aux_callers_rejected_unaligned_key.smt2';q=z3.parse_smt2_file(str(rejected));sol=z3.Solver();sol.add(q);sol.add(z3.BitVec('aux_emit_frame_base64',64)==0x6800064001);assert sol.check()==z3.sat
 specs=[]
 for s in SPECS:
  specs.append({**s,'start':hex(s['start']),'call':hex(s['call']),'aux':hex(s['aux']),'spill':hex(s['spill']),'source_bytes_hex':IMAGE.read(s['start'],s['call']+4-s['start']).hex(),'root_provenance':'explicit conditional bank-root premise','mode_contract':'0x471C literal'if s['layout']=='FP100'else'u32(saved_F9D0)-0x25D8; requires low32==0x6CF4'if s['layout']=='SP10CB8'else'u32(saved_F6C)-0x4395; requires value==0x8AB1'})
 return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_aux_callers_profiles.json','probe_daemon_aux_callers.py','daemon_aux_callers_ida.json','daemon_aux_callers_rejected_unaligned_key.smt2']},'source_specs':specs,'literal_aux_census':[{'value':hex(v),'PCs':[hex(p)for p in ps]}for v,ps in hits.items()],'literal_aux_census_scope':'Aligned adjacent MOVZ Wn low16; MOVK same Wn high16 only. Other materializations, computed values and non-text regions excluded.','literal_CA54_call_candidates':[hex(p)for p in calls],'unclassified_literal_CA54_candidates':[hex(p)for p in calls if p not in {s['call']for s in SPECS}],'discriminator_collision_slots':collisions,'candidate_bank_pool':[hex(a)for a in pool],'candidate_bank_pool_scope':'Thirteen256-byte permutation arrays in four nearby known bank regions; other arrays/regions excluded. Compatibility does not establish native frame writers.','conditional_bank_rules':list(rules.values()),'original_fixups':verify_used_fixups(used),'continuous_paths':paths,'live_IDA_matches':matches,'rejected_unaligned_hypothesis':{'query_file':rejected.name,'query_sha256':sha(rejected),'FP_counterexample':'0x6800064001','record_counterexample':'0x6800063f01','result':'sat','corrected_domain':'16-byte-aligned SP/FP; the2BE key identity itself is exact iff its record address is even'},'native_target_executed':False,'native_bank_root_writers_established':False,'native_incoming_phase_writers_established':False,'new_port_emission_established':False,'full_goal_complete':False}
if __name__=='__main__':
 r=recover();(ROOT/'daemon_aux_callers_contracts.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'sites':len(r['source_specs']),'literal_hits':sum(len(v['PCs'])for v in r['literal_aux_census']),'call_candidates':len(r['literal_CA54_call_candidates']),'paths':len(r['continuous_paths']),'bank_rules':len(r['conditional_bank_rules']),'IDA_bytes':sum(v['matching_bytes']for v in r['live_IDA_matches'])}),flush=True)
