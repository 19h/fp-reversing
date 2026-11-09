#!/usr/bin/env python3
"""Fresh source-only append/rejection replay, independent format/epoch audit.

O(B+C*(V+E)+256R) time/space plus source-lift and solver cost. No native
object/request/IPC/ownership/lock publication follows from private fixtures.
"""
import gc,hashlib,json,struct
from collections import Counter
from pathlib import Path
import z3
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
from recover_carrier_control import span
from probe_legacy_tlv import Append,cases,CARRIER,BUFFER,BUFFER_N,P,M64
from legacy_tlv_symbolic import queries
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def inner_key(a):return((((0xc5fb06fa|((a<<1)&0xffffffff))-a+0x1d027c83)^0xac756b1b)*0xcfc386d7)&0xffffffff
def admission(c):
 f=c['carrier_fields'];return c['inputs8'][0]!=0 and c['route']!='null_buffer'and f['header32']==1 and f['entry_count32']<f['entry_limit32']and((f['cursor32']+12)&0xffffffff)<=f['byte_limit32']
def audit(r,c,prior,k,counts):
 state={};known=set();prov={};events={};snapshots={};case=r['input'];initial={}
 globals=prior['mutable_globals']+[c['additional_mutable_global']]
 for j,d in enumerate(globals):
  a=int(d['address'],16);v=int.from_bytes(bytes.fromhex(d['original8_hex']),'little')if case['global_fixture']=='original'else 0 if case['global_fixture']=='zero'else(0x12345678a5a50000+j*0x111111111)&M64
  initial.update({a+n:b for n,b in enumerate(struct.pack('<Q',v))})
 for a,raw in[(CARRIER,bytes.fromhex(r['initial_carrier160_hex'])),(BUFFER,bytes.fromhex(r['initial_buffer512_hex']))]:
  for x,v in enumerate(raw,a):initial[x]=v;known.add(x);prov[x]=3
 guard=int(prior['guard']['address'],16);initial.update({guard+n:b for n,b in enumerate(bytes.fromhex(prior['guard']['original8_hex']))})
 def original(a):
  if a in initial:return initial[a]
  if P<=a<P+0x20000:return 0xa5
  try:return IMAGE.read(a,1)[0]
  except ValueError:return k.read(a,1)[0]
 def bytes_at(a,n):return bytes(state.get(x,original(x))for x in range(a,a+n))
 def snapshot(s):
  a=int(s['address'],16);n=s['size_bytes'];assert bytes_at(a,n).hex()==s['bytes_hex'];assert bytes(int(x in known)for x in range(a,a+n)).hex()==s['known_mask_hex'];assert bytes(prov.get(x,0)for x in range(a,a+n)).hex()==s['provenance_hex']
 for e in r['source_reads']:events.setdefault(e['source_visit_index'],[]).append(('read',e))
 for e in r['source_writes']:events.setdefault(e['source_visit_index'],[]).append(('write',e))
 for call in r['source_calls']:
  snaps=[call[n]for n in['record','payload','source_bytes','destination_before']if n in call];snapshots[call['source_visit_index']]=snaps
 for v in r['source_visits']:
  ix=v['source_visit_index'];assert k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['source_byte_checks']+=4
  for s in snapshots.get(ix,[]):snapshot(s)
  for kind,e in events.get(ix,[]):
   assert e['pc']==v['pc'];a=int(e['address'],16);n=e['size_bytes']
   if kind=='read':
    assert bytes_at(a,n).hex()==e['bytes_hex'],(e['pc'],hex(a));assert not e['probe_only']
    if P<=a<a+n<=P+0x20000:assert all(x in known for x in range(a,a+n)),(e['pc'],hex(a),n)
    counts['read_epochs']+=1
   else:
    b=bytes.fromhex(e['after_hex']);assert len(b)==n
    if not P<=a<a+n<=P+0x20000:assert any(int(d['address'],16)<=a<a+n<=int(d['address'],16)+8 for d in globals)
    for x,byte in enumerate(b,a):state[x]=byte;known.add(x);prov[x]=1
    counts['source_write_epochs']+=1
 for name in['outer_record_after','inner_record_after','source_payload','final_carrier','final_buffer']:snapshot(r[name])
 assert all(v!=2 for v in prov.values()),'modeled provenance';counts['fully_reconstructed_cases']+=1
def main():
 c=read('legacy_tlv_contracts.json');prior=read('legacy_stack_contracts.json');p=read('legacy_tlv_profiles.json');proof=read('legacy_tlv_proofs.json');k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');counts=Counter()
 for obj,name in[(c,'recover_legacy_tlv.py'),(p,'probe_legacy_tlv.py'),(proof,'prove_legacy_tlv.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,n
 assert sha(SOURCE)==c['source_sha256']==p['source_sha256'];assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256']
 for f in c['functions']:assert function(k,e,int(f['start'],16))==f;counts['compiler_envelopes']+=1
 for f in c['kernel_functions']:assert k.function(int(f['start'],16))==f;counts['kernel_functions']+=1
 for s in c['spans']:
  row=span(k,int(s['start'],16),int(s['end'],16));assert all(row[n]==s[n]for n in row);assert IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex'];counts['source_spans']+=1
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 for b in prior['bank_rules']+c['bank_rules']:
  l=int(b['left'],16);r=int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(r,256).hex()==b['right256_hex'];out=selected(l,r,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(out[n]==b[n]for n in out);assert pointer(k,int(b['slot'],16))==b['original_pointer'];counts['exhaustive_banks']+=1;counts['bank_byte_inputs']+=256
 for b in c['dispatch_slots']:assert pointer(k,int(b['original_pointer']['slot'],16))==b['original_pointer'];counts['dispatch_slots']+=1
 for b in c['additional_original_bindings']+[c['copy_binding']]:assert pointer(k,int(b['slot'],16))==b;counts['additional_bindings']+=1
 qs,lift_counts=queries(c);assert lift_counts==proof['source_lift_counts'];assert[n for n,q in qs]==[r['name']for r in proof['proofs']]
 for (name,q),row in zip(qs,proof['proofs']):
  op=ROOT/row['original_file'];np=ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];original=z3.parse_smt2_string(op.read_text());assert len(original)==1
  for formula in[z3.simplify(q),z3.simplify(original[0]),z3.Xor(z3.simplify(q),z3.simplify(original[0])),*z3.parse_smt2_string(np.read_text())]:s=z3.Solver();s.set(timeout=30000);s.add(formula);assert str(s.check())=='unsat',name
  counts['source_derived_proofs_unsat']+=1
 expected=list(cases());assert[r['input']for r in p['cases']]==expected;fresh=[]
 route_steps={'null_carrier':[0xfffffe000a55ea84],'null_buffer':[0xfffffe000a55ea84,0xfffffe000a55fbd4],'bad_header':[0xfffffe000a55ea84,0xfffffe000a55fbd4,0xfffffe000a58887c],'entry_full':[0xfffffe000a55ea84,0xfffffe000a55fbd4,0xfffffe000a58887c,0xfffffe000a54f6f4],'byte_full':[0xfffffe000a55ea84,0xfffffe000a55fbd4,0xfffffe000a58887c,0xfffffe000a54f6f4,0xfffffe000a590010],'append':[0xfffffe000a55ea84,0xfffffe000a55fbd4,0xfffffe000a58887c,0xfffffe000a54f6f4,0xfffffe000a590010,0xfffffe000a69f340,0xfffffe000a51a628]}
 for j,(case,old)in enumerate(zip(expected,p['cases'])):
  a=Append(case);r=a.run();del a;assert r==old,(j,case);fresh.append(r);counts['fresh_cases']+=1;counts['source_visits']+=len(r['source_visits']);assert not r['models']and not r['API_effect_models_used']and r['inner_record_operations_executed']and r['inner_record_operation_executed_in_private_guest']and not r['native_API_executed']and not r['native_reachability_proved']and not r['undefined_private_value_reads'];assert not r['probe_only_reads'];assert[v['source_visit_index']for v in r['source_visits']]==list(range(len(r['source_visits'])));audit(r,c,prior,k,counts)
  success=admission(case);assert success==(case['route']=='append');status=0x5e561849 if success else 0x5e5571af;assert r['boundary']['kind']=='returned'and int(r['boundary']['SP'],16)==int(r['entry_SP'],16)and int(r['boundary']['registers31'][0],16)==(status+0xa1a9e7b7)&0xffffffff;assert[int(d['pc'],16)for d in r['source_dispatches']]==route_steps[case['route']]
  calls=r['source_calls'];assert[c['kind']for c in calls]==(['outer_bridge','inner_operation','payload_copy']if success else['outer_bridge','inner_operation']);assert all(c['target_executed_in_private_guest']and r['source_visits'][c['source_visit_index']+1]['pc']==c['target']for c in calls)
  q=int(calls[1]['record']['address'],16);raw=bytes.fromhex(calls[1]['record']['bytes_hex']);key=inner_key(q);assert int.from_bytes(raw[12:16],'little')^key==0x224;assert(int.from_bytes(raw[8:10],'little')+key-0x6601)&0xffff==8;assert(int.from_bytes(raw[10:12],'little')-key)&0xffff==(case['inputs8'][1]^0x8151)&0xffff;assert int.from_bytes(raw[:8],'little')==q-8;assert int.from_bytes(raw[24:32],'little')==case['inputs8'][0];assert calls[1]['payload']['bytes_hex']==case['inputs8'][2].to_bytes(8,'big').hex()and calls[1]['payload']['known_mask_hex']=='01'*8 and calls[1]['payload']['provenance_hex']=='01'*8;counts['source_staged_payload_bytes']+=8
  obs=next(v for v in r['source_visits']if v['pc']=='0xfffffe000a55e9f8');assert int(obs['observed_registers31'][1],16)==0x224
  sw=[w for w in r['source_writes']if w['pc']=='0xfffffe000a5355f8'];assert len(sw)==1 and sw[0]['address']==hex(q+16)and sw[0]['after_hex']==struct.pack('<I',status).hex();copied=[w for w in r['source_writes']if w['pc']=='0xfffffe000a5302b4'];assert len(copied)==1 and copied[0]['after_hex']==sw[0]['after_hex']and copied[0]['source_visit_index']>sw[0]['source_visit_index'];counts['source_status_pairs']+=1
  carrier=bytearray.fromhex(r['initial_carrier160_hex']);buffer=bytearray.fromhex(r['initial_buffer512_hex']);f=case['carrier_fields'];cursor=f['cursor32'];bw=[w for w in r['source_writes']if BUFFER<=int(w['address'],16)<BUFFER+BUFFER_N];cw=[w for w in r['source_writes']if CARRIER<=int(w['address'],16)<CARRIER+160]
  if success:
   packet=struct.pack('>HHQ',case['inputs8'][1]&0xffff,8,case['inputs8'][2]);buffer[cursor:cursor+12]=packet;struct.pack_into('<I',carrier,152,(f['entry_count32']+1)&0xffffffff);struct.pack_into('<I',carrier,156,(cursor+12)&0xffffffff);assert{a for w in bw for a in range(int(w['address'],16),int(w['address'],16)+w['size_bytes'])}==set(range(BUFFER+cursor,BUFFER+cursor+12));assert{a for w in cw for a in range(int(w['address'],16),int(w['address'],16)+w['size_bytes'])}==set(range(CARRIER+152,CARRIER+160));assert calls[2]['registers8'][:3]==[hex(BUFFER+cursor+4),hex(q-8),'0x8'];assert calls[2]['source_bytes']['bytes_hex']==packet[4:].hex()
   header=[w for w in bw if w['pc']in['0xfffffe000a51a4bc','0xfffffe000a51a4c4','0xfffffe000a51a598','0xfffffe000a51a5a4']];assert len(header)==4 and b''.join(bytes.fromhex(w['after_hex'])for w in header)==packet[:4];assert max(w['source_visit_index']for w in header)<calls[2]['source_visit_index'];kernel_writes=[w for w in bw if int(w['pc'],16)>=0xfffffe000c647f10];assert sum(w['size_bytes']for w in kernel_writes)==8 and min(w['source_visit_index']for w in kernel_writes)>calls[2]['source_visit_index'];updates=[w for w in cw if w['pc']=='0xfffffe000a51a614'];assert sum(w['size_bytes']for w in updates)==8 and min(w['source_visit_index']for w in updates)>max(w['source_visit_index']for w in kernel_writes);counts['append_cases']+=1;counts['source_written_packet_bytes']+=12;counts['original_copy_bytes']+=8
  else:assert not bw and not cw;counts['rejection_cases']+=1;counts[case['route']+'_cases']+=1
  assert r['final_carrier']['bytes_hex']==carrier.hex()and r['final_buffer']['bytes_hex']==buffer.hex()
  if j%12==0:gc.collect()
 assert counts['fresh_cases']==312 and counts['source_visits']==246972 and counts['append_cases']==192 and counts['rejection_cases']==120 and counts['source_written_packet_bytes']==2304
 deps={n:sha(ROOT/n)for n in['recover_legacy_tlv.py','probe_legacy_tlv.py','legacy_tlv_symbolic.py','prove_legacy_tlv.py','legacy_tlv_contracts.json','legacy_tlv_profiles.json','legacy_tlv_proofs.json','legacy_stack_contracts.json','probe_legacy_stack.py','kernel_native_reader.py','kext_port_tools.py']};replays={'scope':'Distinct fresh source-only private compositions; complete retained/fresh equality.','generator_sha256':sha(Path(__file__)),'dependencies':deps,'cases':fresh,'API_effect_models_used':False,'native_target_executed':False,'full_goal_complete':False};(ROOT/'legacy_tlv_replays.json').write_text(json.dumps(replays,indent=2)+'\n');out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'kernel_collection_sha256':k.sha256,'source_sha256':sha(SOURCE),'source_lift_counts':lift_counts,'verified_counts':dict(counts),'fresh_replays_sha256':sha(ROOT/'legacy_tlv_replays.json'),'all_checks_pass':True,'API_effect_models_used':False,'native_target_executed':False,'external_TLV_emission_proved':False,'cached_FairPlay_lock_publication_proved':False,'full_goal_complete':False};(ROOT/'legacy_tlv_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts)}),flush=True)
if __name__=='__main__':main()
