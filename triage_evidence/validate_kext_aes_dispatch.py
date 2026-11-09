#!/usr/bin/env python3
"""Independent source/context/bank/slice/classifier/codec readback.

All authenticated calls stop before execution. Local classifier has no calls.
O(B+I+C*J+E) time/retained space plus fixed-word solver work; frame reaching
definitions, alias preservation and native reachability remain unproved.
"""
import collections,hashlib,json,struct
from pathlib import Path
import z3
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,POOL,TABLE,qword
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from recover_kext_aes_handoff import starts,function
from recover_kext_aes_dispatch import census,modifier_sites,TRACK
from probe_kext_aes_dispatch import Slice,UPPER
from probe_kext_record_classifier import Classifier,POINTERS
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 counts=collections.Counter();c=json.loads((ROOT/'kext_aes_dispatch_contracts.json').read_text());p=json.loads((ROOT/'kext_aes_dispatch_profiles.json').read_text());leaf=json.loads((ROOT/'kext_record_classifier_profiles.json').read_text());proof=json.loads((ROOT/'kext_aes_dispatch_proofs.json').read_text());deps=set()
 for obj,name in[(c,'recover_kext_aes_dispatch.py'),(p,'probe_kext_aes_dispatch.py'),(leaf,'probe_kext_record_classifier.py'),(proof,'prove_kext_aes_dispatch.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete'];deps.add(name)
  for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h;deps.add(n)
 k=Kernel();assert k.sha256==c['kernel_collection_sha256']and sha(SOURCE)==c['source_sha256']==p['source_sha256']==leaf['source_sha256'];fp=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');catalog=starts(k,fp);assert len(catalog)==c['compiler_function_starts_count']==450
 def checkspan(r):
  a,z=int(r['start'],16),int(r['end'],16);raw=IMAGE.read(a,z-a);assert raw.hex()==r['bytes_hex']and hashlib.sha256(raw).hexdigest()==r['sha256'];assert [{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)]==r['instructions'];assert raw==k.read(a,z-a)
 for r in c['source_spans']:checkspan(r);counts['source_spans']+=1;counts['source_span_bytes']+=int(r['end'],16)-int(r['start'],16)
 for ctx in c['contexts']:
  a,z=int(ctx['compiler_start'],16),int(ctx['compiler_end'],16);ix=catalog.index(a);assert catalog[ix+1]==z;raw=k.read(a,z-a);assert hashlib.sha256(raw).hexdigest()==ctx['compiler_source_sha256']and raw==IMAGE.read(a,z-a)and ctx['normalized_source_equal'];assert census(a,z,TRACK.get(ctx['name'],[]))==ctx['literal_stack_store_census'];counts['compiler_envelopes']+=1;counts['compiler_envelope_bytes']+=len(raw);counts['literal_stack_store_overlaps']+=len(ctx['literal_stack_store_census']['writes']);counts['indexed_SP_store_sites']+=len(ctx['literal_stack_store_census']['indexed_SP_store_sites'])
 for name,f in c['families'].items():assert IMAGE.read(int(f['left'],16),256).hex()==f['left256_hex']and IMAGE.read(int(f['right'],16),256).hex()==f['right256_hex'];counts['bank_families']+=1;counts['bank_source_bytes']+=512
 for line in c['literal_bank_pointer_lineages']:
  checkspan(line['source']);assert(qword(int(line['source_pool_slot'],16))+line['signed_adjustment'])&((1<<64)-1)==int(line['source_pointer_value'],16);assert not line['preserved_until_call_proved'];assert line['source']['instructions'][0]['mnemonic']=='ldr';counts['literal_pointer_lineages']+=1
 def bank(rule,base,category):
  left=IMAGE.read(int(rule['left'],16),256);right=IMAGE.read(int(rule['right'],16),256);key=int(rule['key'],16);constant=int(rule['constant'],16);assert all(x^right[left[x]^key]==constant for x in range(256));ix=int(rule['additive'],16)+constant;assert ix==int(rule['index'],16)and base+ix*8==int(rule['slot'],16);assert(qword(int(rule['slot'],16))+int(rule['bias'],16))&((1<<64)-1)==int(rule['target'],16);counts[category+'_bank_rules']+=1;counts[category+'_byte_inputs']+=256
 for ctx in c['contexts']:bank(ctx['base_rule'],POOL,'base');assert int(ctx['base_rule']['target'],16)==TABLE
 expected={0xfffffe000a60db50:0xfffffe000a5086a0,0xfffffe000a6227b4:0xfffffe000a5085e0,0xfffffe000a6825d0:0xfffffe000a5a962c,0xfffffe000a6968f4:0xfffffe000a6674d0,0xfffffe000a698168:0xfffffe000a6674d0,0xfffffe000a698258:0xfffffe000a6674d0,0xfffffe000a6080ac:0xfffffe000a62259c,0xfffffe000a623680:0xfffffe000a5c22b8,0xfffffe000a6257e8:0xfffffe000a509c08,0xfffffe000a6869f0:0xfffffe000a5c22b8,0xfffffe000a686c44:0xfffffe000a508b8c}
 assert len(c['sites'])==11
 for s in c['sites']:
  bank(s['choice'],TABLE,'site');checkspan(s['slice']);assert int(s['choice']['target'],16)==expected[int(s['call_pc'],16)];actual=pointer(k,int(s['choice']['slot'],16));assert actual==s['original_slot'];assert k.symbols([int(s['choice']['target'],16)])[s['choice']['target']]==s['exact_target_symbols'];assert s['slice']['instructions'][-1]['mnemonic']=='blraa'and s['slice']['instructions'][-1]['operands']=='x8, x17';assert s['slice']['instructions'][-2]['operands']=='x17, #'+actual['diversity'];assert not s['entry_reachability_proved'];counts['context_mapped_sites']+=1
 assert modifier_sites()==c['modifier_census'];assert{e['call_pc']for e in c['modifier_census']}=={s['call_pc']for s in c['sites']};counts['modifier_ed6d_sites']=sum(e['diversity']=='0xed6d'for e in c['modifier_census']);counts['modifier_d939_sites']=sum(e['diversity']=='0xd939'for e in c['modifier_census']);counts['distinct_target_addresses']=len(set(expected.values()))
 # Pin source producer/consumer word operations independently of the lifted SMT.
 ops={int(i['ea'],16):(i['mnemonic'],i['operands'])for r in c['source_spans']for i in r['instructions']}
 facts={0xfffffe000a608038:('eor','w8, w24, w8'),0xfffffe000a60804c:('stp','x22, x27, [x24]'),0xfffffe000a608050:('madd','w8, w8, w9, w19'),0xfffffe000a608054:('add','w8, w8, #0x451'),0xfffffe000a608058:('str','w8, [x24, #0x18]'),0xfffffe000a60805c:('str','x26, [x24, #0x10]'),0xfffffe000a6226a4:('orn','w12, w12, w0'),0xfffffe000a6226ac:('add','w11, w11, w12'),0xfffffe000a6226b0:('sub','w11, w13, w11'),0xfffffe000a6226bc:('eor','w11, w11, w12'),0xfffffe000a6226c8:('ldr','w13, [x0, #0x18]'),0xfffffe000a6226cc:('msub','w28, w11, w12, w13'),0xfffffe000a6226d0:('ldp','x19, x1, [x0, #8]')}
 for a,v in facts.items():assert ops[a]==v;counts['record_codec_source_facts']+=1
 for r in c['target_roles']:assert function(k,fp,int(r['start'],16))==r;counts['target_role_functions']+=1
 role={int(r['start'],16):r for r in c['target_roles']};co={int(i['ea'],16):(i['mnemonic'],i['operands'])for i in role[0xfffffe000a5a962c]['instructions']}
 for a,v in{0xfffffe000a5a9640:('and','w9, w0, w8'),0xfffffe000a5a9648:('sub','w8, w8, w9, lsl #1'),0xfffffe000a5a9664:('ldr','w9, [x0, #0x30]'),0xfffffe000a5a966c:('ldr','w10, [x0, #0x10]'),0xfffffe000a5a9688:('ccmp','w9, w8, #0, ne'),0xfffffe000a5a969c:('csel','w8, w9, w8, ne'),0xfffffe000a5a96a0:('str','w8, [x0, #0x24]')}.items():assert co[a]==v;counts['classifier_source_facts']+=1
 do={int(i['ea'],16):(i['mnemonic'],i['operands'])for i in role[0xfffffe000a6674d0]['instructions']}
 for a,v in{0xfffffe000a667548:('orn','w10, w10, w11'),0xfffffe000a667564:('ldr','w10, [x0, #8]'),0xfffffe000a66756c:('ldr','w12, [x0, #0x28]'),0xfffffe000a66757c:('add','w11, w11, w12'),0xfffffe000a667584:('cset','w17, eq'),0xfffffe000a66758c:('mul','w17, w17, w12'),0xfffffe000a6675c0:('eor','w15, w17, w10'),0xfffffe000a6675e0:('ldr','x15, [x13, w15, sxtw #3]'),0xfffffe000a6675f0:('braa','x15, x17')}.items():assert do[a]==v;counts['dispatcher_source_facts']+=1
 assert proof['contracts_sha256']==sha(ROOT/'kext_aes_dispatch_contracts.json')
 for e in proof['proofs']:
  path=ROOT/e['file'];assert sha(path)==e['sha256'];s=z3.Solver();s.set(timeout=30000);s.from_string(path.read_text());assert str(s.check())==e['result']=='unsat';counts['proofs_unsat']+=1;deps.add(e['file'])
 rows=p['cases'];assert len(rows)==11*4*256;g=Slice(c);fresh=[];j=0
 for site in c['sites']:
  targets=set()
  for upper in UPPER:
   for byte in range(256):
    old=rows[j];j+=1;new=g.run(site,byte,upper);assert new==old;fresh.append(new);counts['fresh_dispatch_runs']+=1;counts['fresh_dispatch_source_visits']+=len(new['source_visits']);obs=new['call_observation'];assert obs['target']==site['choice']['target']and obs['modifier']==site['original_slot']['diversity']and not obs['authenticated_call_executed'];assert new['stop_reason']=='before_authenticated_call'and not new['native_API_executed']and not new['entry_reachability_proved'];targets.add(obs['target']);counts['fresh_data_read_events']+=len(new['source_reads']);counts['fresh_stack_write_events']+=len(new['source_writes'])
    target_read=[r for r in new['source_reads']if r['address']==site['choice']['slot']];assert len(target_read)==1 and target_read[0]['size_bytes']==8 and bytes.fromhex(target_read[0]['bytes_hex'])==int(site['choice']['target'],16).to_bytes(8,'little');counts['source_target_pointer_reads']+=1
  assert len(targets)==1
 (ROOT/'kext_aes_dispatch_replays.json').write_text(json.dumps({'scope':'Distinct fresh original dispatch slices, stopped before every authenticated call.','generator_sha256':sha(Path(__file__)),'cases':fresh,'native_target_executed':False},indent=2)+'\n')
 lg=Classifier();lf=[];j=0
 for record in POINTERS:
  for a in[False,True]:
   for b in[False,True]:
    old=leaf['cases'][j];j+=1;new=lg.run(record,a,b);assert new==old;lf.append(new);want=0xce51e4ec if not a and b else 0x31ae0066;assert int(new['marker24_u32'],16)==want and int(new['return_pointer'],16)==record;assert[(e['offset'],e['size_bytes'])for e in new['source_writes']]==[(0x24,4)];assert[e['offset']for e in new['source_reads']]==[0x30,0x10];counts['fresh_classifier_runs']+=1;counts['fresh_classifier_source_visits']+=len(new['source_visits']);counts['classifier_special_markers'if want==0xce51e4ec else'classifier_default_markers']+=1
 (ROOT/'kext_record_classifier_replays.json').write_text(json.dumps({'scope':'Distinct fresh original classifier leaf; records are declared fixtures.','generator_sha256':sha(Path(__file__)),'cases':lf,'native_target_executed':False},indent=2)+'\n');deps.update(['kext_aes_dispatch_contracts.json','kext_aes_dispatch_profiles.json','kext_record_classifier_profiles.json','kext_aes_dispatch_proofs.json']);out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'dependencies':{n:sha(ROOT/n)for n in sorted(deps)},'verified_counts':dict(counts),'fresh_dispatch_replays_sha256':sha(ROOT/'kext_aes_dispatch_replays.json'),'fresh_classifier_replays_sha256':sha(ROOT/'kext_record_classifier_replays.json'),'native_target_executed':False,'authentication_executed':False,'all_native_dispatch_contexts_proved':False,'native_cleanup_reachability_proved':False,'all_checks_pass':True,'full_goal_complete':False};(ROOT/'kext_aes_dispatch_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(dict(counts)),flush=True)
if __name__=='__main__':main()
