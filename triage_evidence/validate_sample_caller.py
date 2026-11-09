#!/usr/bin/env python3
"""Fresh original caller/builders, source-defined records, widths and cleanup.

O(C*(B+V)+I+E) work and O(B+C*V+I+E) retained space, plus solver work. No native API,
task mapping, crypto, target file or IDB operation executes.
"""
import collections,hashlib,json,re,struct
from pathlib import Path
import z3
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,qword,TABLE,POOL
from kernel_native_reader import Kernel
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
from probe_sample_caller import Caller,cases,STACK
from probe_sample_builders import Builder,cases as builder_cases
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def epoch(writes,address,n,before):
 result={}
 for w in writes:
  if w['source_visit_index']>=before:continue
  a=int(w['address'],16)
  for j,b in enumerate(bytes.fromhex(w['after_hex'])):
   if address<=a+j<address+n:result[a+j-address]=b
 assert set(result)==set(range(n)),(hex(address),n,sorted(result))
 return bytes(result[j]for j in range(n))
def main():
 counts=collections.Counter();deps=set();c=json.loads((ROOT/'sample_caller_contracts.json').read_text());p=json.loads((ROOT/'sample_caller_profiles.json').read_text());bp=json.loads((ROOT/'sample_caller_builder_profiles.json').read_text());proof=json.loads((ROOT/'sample_caller_proofs.json').read_text());k=Kernel();fp=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit')
 for obj,name in[(c,'recover_sample_caller.py'),(p,'probe_sample_caller.py'),(bp,'probe_sample_builders.py'),(proof,'prove_sample_caller.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete'];deps.add(name)
  for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,n;deps.add(n)
 assert c['source_sha256']==p['source_sha256']==bp['source_sha256']==sha(SOURCE)and c['kernel_collection_sha256']==k.sha256
 f=function(k,fp,0xfffffe000a6247a4);assert f==c['function'];assert IMAGE.read(0xfffffe000a6247a4,7844).hex()==f['bytes_hex'];counts['original_caller_functions']+=1
 facts={0xfffffe000a6248dc:('mul','x14, x13, x14'),0xfffffe000a6248e0:('ldr','w13, [x0, #0x40]'),0xfffffe000a6248e4:('add','w24, w13, w14'),0xfffffe000a6248ec:('stur','x13, [x29, #-0x68]'),0xfffffe000a6248f0:('add','x0, x13, #0x140'),0xfffffe000a6248f4:('ldr','x1, [x27, #0x48]'),0xfffffe000a6248f8:('ldp','x13, x15, [x27, #0x28]'),0xfffffe000a624900:('ldr','x13, [x27, #0x38]'),0xfffffe000a624908:('ldr','w13, [x27, #0x50]'),0xfffffe000a624910:('sub','w22, w13, w14'),0xfffffe000a624914:('ldr','x13, [x27, #0x18]'),0xfffffe000a624b24:('ubfiz','x1, x8, #2, #0x20'),0xfffffe000a624b38:('ldur','x0, [x29, #-0x70]'),0xfffffe000a624b3c:('ldur','x2, [x29, #-0x90]'),0xfffffe000a624b48:('cmp','w0, #0'),0xfffffe000a624bec:('cmp','w0, w8'),0xfffffe000a624c2c:('ldr','x8, [x27, #0x58]'),0xfffffe000a624c34:('ldr','x11, [x27, #0x20]'),0xfffffe000a624c5c:('ldr','w9, [x11, #0x2c]'),0xfffffe000a62511c:('ldr','x8, [x8, #0x10]'),0xfffffe000a625180:('add','x1, x10, x8'),0xfffffe000a625184:('ldr','x0, [sp, #0x30]'),0xfffffe000a625188:('ldur','x2, [x29, #-0x90]'),0xfffffe000a625854:('ldur','w8, [x29, #-0x94]'),0xfffffe000a625858:('str','w8, [x27, #8]')}
 ops={int(i['ea'],16):(i['mnemonic'],i['operands'])for i in f['instructions']}
 for a,v in facts.items():assert ops[a]==v,(hex(a),ops[a],v);counts['caller_source_facts']+=1
 for b in c['bank_rules']:
  l=IMAGE.read(int(b['left'],16),256);rr=IMAGE.read(int(b['right'],16),256);assert l.hex()==b['left256_hex']and rr.hex()==b['right256_hex'];key=int(b['key'],16);v=int(b['constant'],16);assert all(x^rr[l[x]^key]==v for x in range(256));index=int(b['additive'],16)+v;slot=int(b['base'],16)+index*8;assert slot==int(b['slot'],16);assert(qword(slot)+int(b['bias'],16))&((1<<64)-1)==int(b['target'],16);assert pointer(k,slot)==b['original_pointer'];counts['exhaustive_bank_rules']+=1;counts['bank_byte_inputs']+=256
 for b in c['selected_routes']:assert pointer(k,int(b['slot'],16))==b['original_pointer']and qword(int(b['slot'],16))==int(b['target'],16);counts['source_routes']+=1
 assert pointer(k,0xfffffe000847aa38)==c['entry_pointer']and c['entry_pointer']['diversity']=='0x6353';counts['entry_pointer_bindings']+=1
 g=c['bounds_helper'];raw=IMAGE.read(0xfffffe000a687ecc,20);assert raw==k.read(0xfffffe000a687ecc,20)and raw.hex()==g['bytes_hex'];assert [(i.mnemonic,i.op_str)for i in CS.disasm(raw,0xfffffe000a687ecc)]==[('bti','c'),('cmp','x0, x1'),('b.hi','#0xfffffe000a687edc'),('ret',''),('brk','#1')]
 for b in c['builder_contexts']:
  parent=function(k,fp,int(b['parent_compiler_start'],16));assert parent['end']==b['parent_compiler_end']and parent['sha256']==b['parent_sha256']and len(parent['instructions'])==b['parent_instructions'];counts['original_builder_parent_functions']+=1
  for sp in[b['fragment'],b['entry_prefix']]:
   a,z=int(sp['start'],16),int(sp['end'],16);raw=k.read(a,z-a);assert raw==IMAGE.read(a,z-a)and raw.hex()==sp['bytes_hex']and hashlib.sha256(raw).hexdigest()==sp['sha256'];assert [{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)]==sp['instructions'];counts['original_builder_spans']+=1
  for st in b['literal_SP_store_census']:
   assert any(all(st[n]==i[n]for n in ['ea','mnemonic','operands'])for i in parent['instructions']);counts['literal_frame_store_records']+=1
  rule=b['call_rule'];left=IMAGE.read(int(rule['left'],16),256);right=IMAGE.read(int(rule['right'],16),256);assert all(x^right[left[x]^int(rule['key'],16)]==int(rule['constant'],16)for x in range(256));assert int(rule['slot'],16)==0xfffffe000847aa38 and int(rule['target'],16)==0xfffffe000a6247a4;counts['builder_bank_rules']+=1;counts['builder_bank_byte_inputs']+=256
 assert proof['contracts_sha256']==sha(ROOT/'sample_caller_contracts.json')
 for q in proof['proofs']:
  assert sha(ROOT/q['file'])==q['sha256'];s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_file(str(ROOT/q['file'])));assert str(s.check())==q['result']=='unsat';counts['proofs_unsat']+=1
 assert[c['input']for c in p['cases']]==list(cases());fresh=[]
 for old in p['cases']:
  r=Caller(old['input']).run();assert r==old;fresh.append(r);counts['fresh_caller_runs']+=1;counts['fresh_caller_source_visits']+=len(r['source_visits']);assert not r['undefined_private_reads']and not r['native_API_executed'];case=r['input'];record=int(r['record'],16);raw=bytes.fromhex(r['record_fixture_hex']);final=bytes.fromhex(r['final_record_hex']);word=lambda off,n:int.from_bytes(raw[off:off+n],'little');kk=((record^0x0f6f4af997099bc0)*0xef54ff65)&((1<<64)-1);N=(word(0x50,4)-(kk&0xffffffff)+0x8899d805)&0xffffffff;assert N==case['element_count32']and(word(0x40,4)+kk)&0xffffffff==0x507;obs=r['helper_observations'];guard=obs[0];assert guard['kind']=='bounds_helper_source'and list(map(lambda x:int(x,16),guard['registers8'][:2]))==[((word(0,8)+0x140)&((1<<64)-1)),word(0x48,8)]
  if((word(0,8)+0x140)&((1<<64)-1))>word(0x48,8):assert r['stop_reason']=='source_BRK_boundary'and len(obs)==1;counts['guard_trap_boundaries']+=1;continue
  for e in obs:
   if e['kind']=='bounds_helper_source':continue
   group=e.get('group');kind=e['kind'];regs=[int(v,16)for v in e['registers8']];sp=int(e['SP'],16);idx=e['source_visit_index']
   if kind=='create':
    assert regs[2]==word(0x38,8);assert epoch(r['source_writes'],sp+0xa0,8,idx)==raw[0x38:0x40];counts['task_stack_epochs']+=1
    if group=='sample_sizes':assert regs[:3]==[word(0x18,8),4*N,word(0x38,8)];assert epoch(r['source_writes'],sp+0xc0,8,idx)==raw[0x18:0x20];counts['size_descriptor_calls']+=1
    else:assert group=='samples'and regs[:3]==[word(0x58,8),(word(0x10,8)+kk+0xecb67a32353f2154)&((1<<64)-1),word(0x38,8)];assert regs[1]==case['sample_length64'];assert int.from_bytes(epoch(r['source_writes'],sp+0x68,8,idx),'little')==kk;assert epoch(r['source_writes'],sp+0x30,8,idx)==raw[0x58:0x60];counts['samples_descriptor_calls']+=1
   if kind=='initialize':assert(((int(e['registers31'][21],16)+0x380)^int(e['registers31'][19],16))&0xffffffff)==0x31ae0066;counts['initializer_status_bases']+=1
   if kind=='complete':assert e['pc']=='0xfffffe000a6257e8'and e['target']=='0xfffffe000a509c08';counts['completion_requests']+=1
   if kind=='release':assert e['pc']=='0xfffffe000a625840'and e['target']=='0xfffffe000a509bd4';counts['release_requests']+=1
  if r['stop_reason']=='wrapper_return':
   kinds=[e['kind']for e in obs];result=int.from_bytes(final[8:12],'little');model=case['modeled_results']
   if model['create']&0xffffffff:assert kinds==['bounds_helper_source','create'];wanted=0xce515bb2;counts['creation_error_returns']+=1
   elif model['prepare']&0xffffffff:assert kinds==['bounds_helper_source','create','prepare','release'];wanted=0xce515bb2;counts['preparation_error_returns']+=1
   elif case['secondary_word2c']!=0:assert kinds==['bounds_helper_source','create','prepare','complete','release'];wanted=0x31ae0066;counts['secondary_word_unwind_returns']+=1
   elif model.get('initialize',0)&0xffffffff:assert kinds==['bounds_helper_source','create','prepare','initialize','complete','release'];wanted=(model['initialize']^0x31ae0066)&0xffffffff;counts['initializer_error_returns']+=1
   else:assert model.get('samples.create',0)&0xffffffff;assert kinds==['bounds_helper_source','create','prepare','initialize','create','complete','release'];wanted=0xce515bb2;counts['samples_creation_error_returns']+=1
   assert result==wanted;assert epoch(r['source_writes'],record+8,4,len(r['source_visits']))==final[8:12];counts['source_output_status_bytes']+=4
  else:assert r['stop_reason']in['unmodeled_helper','unknown_call_boundary'];counts['stopped_call_boundaries']+=1
 fresh_builders=[];assert[c['input']for c in bp['cases']]==list(builder_cases())
 for old in bp['cases']:
  r=Builder(old['input']).run();assert r==old;fresh_builders.append(r);counts['fresh_builder_runs']+=1;counts['fresh_builder_source_visits']+=len(r['source_visits']);case=r['input'];e=r['observation'];record=int(r['record'],16);raw=bytes.fromhex(e['record_hex']);read=lambda off,n:int.from_bytes(raw[off:off+n],'little');kk=((record^0x0f6f4af997099bc0)*0xef54ff65)&((1<<64)-1);assert e['target']=='0xfffffe000a6247a4'and e['modifier']=='0x6353'and int(e['record_pointer'],16)==record;assert(read(0x40,4)+kk)&0xffffffff==0x507;assert(read(0x10,8)+kk+0xecb67a32353f2154)&((1<<64)-1)==case['source_samples_length64'];assert[read(o,8)for o in[0x18,0x38,0x58]]==[case['sizes_address64'],case['task64'],case['samples_address64']]
  n=(read(0x50,4)-(kk&0xffffffff)+0x8899d805)&0xffffffff
  if case['builder']=='first':assert n==case['source_count32'];counts['builder1_count_roundtrips']+=1
  else:
   v=case['source_count32'];mix=(((v^0x925f31a6)+0x6da0ce5a)^((v^0xe972fb37)+0x168d04c9)^((v^0x4a83caf7)+0xb57c3509))&0xffffffff;assert n==(mix+((0x753-0x1bb)^0xa9142df9)+0x8899d805)&0xffffffff;counts['builder2_count_expression_checks']+=1
  for off,w in[(0,8),(0x10,8),(0x18,8),(0x20,8),(0x28,8),(0x30,8),(0x38,8),(0x40,4),(0x48,8),(0x50,4),(0x58,8)]:assert epoch(r['source_writes'],record+off,w,len(r['source_visits']))==raw[off:off+w];counts['builder_source_record_bytes']+=w
  counts['builder_length_roundtrips']+=1;counts['builder_task_forwarding_records']+=1
 replay={'scope':'Distinct fresh original caller and post-initializer builder cases under declared source/model state.','generator_sha256':sha(Path(__file__)),'caller_cases':fresh,'builder_cases':fresh_builders,'native_target_executed':False};(ROOT/'sample_caller_replays.json').write_text(json.dumps(replay,indent=2)+'\n');deps.update(['sample_caller_contracts.json','sample_caller_profiles.json','sample_caller_builder_profiles.json','sample_caller_proofs.json']);out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in sorted(deps)},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'verified_counts':dict(counts),'fresh_replays_sha256':sha(ROOT/'sample_caller_replays.json'),'all_checks_pass':True,'native_target_executed':False,'native_lifetime_proved':False,'complete_lifecycle_proved':False,'full_goal_complete':False};(ROOT/'sample_caller_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(dict(counts)),flush=True)
if __name__=='__main__':main()
