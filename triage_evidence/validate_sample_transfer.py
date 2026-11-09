#!/usr/bin/env python3
"""Fresh metadata/buffer prefixes and wrapper-to-provider ABI composition.

O(C*(B+V+L)+I+E) time and O(B+retained cases/events) space plus solver work.
No crypto, native I/O, provider, task, descriptor or heap action executes.
"""
import collections,hashlib,json,struct
from pathlib import Path
import z3
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,POOL,TABLE
from kernel_native_reader import Kernel
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
from probe_sample_transfer import Transfer,cases,GLOBAL_BUFFER,GLOBAL_CAPACITY,STACK,ARENA
from probe_sample_transfer_handoff import Composed
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def prefix_expectation(c):
 """Classify only the declared source prefix, ending before its first AES call."""
 metadata=[];reads=[];offset=buffered=slots=0
 for i,size in enumerate(c['sample_words32']):
  result=c['metadata_return64']if c['metadata_returns64']is None else c['metadata_returns64'][i];metadata.append((i,4*i,result))
  if result&0xffffffff!=4:return metadata,reads,('error',None)
  aligned=size&0xfffffff0
  if size<16:offset=(offset+size)&0xffffffff;continue
  assert size+buffered<1<<32,'classification excludes wrapped capacity sums'
  if size+buffered>8192:
   return metadata,reads,('global',buffered)if buffered else('direct',(aligned,offset))
  result=16 if c['tail_return64']is None else c['tail_return64'];reads.append(('tail',(offset+aligned-16)&0xffffffff,ARENA+16*slots,16,result))
  if result&0xffffffff!=16:return metadata,reads,('error',None)
  result=aligned if c['bulk_return64']is None else c['bulk_return64'];reads.append(('bulk',offset,GLOBAL_BUFFER+buffered,aligned,result))
  if result&0xffffffff!=aligned:return metadata,reads,('error',None)
  buffered+=aligned;slots+=1;offset=(offset+size)&0xffffffff
 return metadata,reads,('global',buffered)if buffered else('empty',None)
def word_epoch(writes,address,n,before):
 out={}
 for w in writes:
  if w['source_visit_index']>=before:continue
  a=int(w['address'],16)
  for j,b in enumerate(bytes.fromhex(w['after_hex'])):
   if address<=a+j<address+n:out[a+j-address]=b
 assert set(out)==set(range(n)),(hex(address),n)
 return bytes(out[j]for j in range(n))
def main():
 counts=collections.Counter();deps=set();c=json.loads((ROOT/'sample_transfer_contracts.json').read_text());p=json.loads((ROOT/'sample_transfer_profiles.json').read_text());hp=json.loads((ROOT/'sample_transfer_handoff_profiles.json').read_text());proof=json.loads((ROOT/'sample_transfer_proofs.json').read_text());k=Kernel();entry=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit')
 for obj,name in[(c,'recover_sample_transfer.py'),(p,'probe_sample_transfer.py'),(hp,'probe_sample_transfer_handoff.py'),(proof,'prove_sample_transfer.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete'];deps.add(name)
  for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,n;deps.add(n)
 assert c['source_sha256']==p['source_sha256']==hp['source_sha256']==sha(SOURCE)and c['kernel_collection_sha256']==k.sha256
 for f in c['functions']:assert function(k,entry,int(f['start'],16))==f;assert IMAGE.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes_hex'];counts['original_functions']+=1
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols'];slot=c['nominal_provider_slot'];actual=pointer(k,int(slot['slot'],16));assert all(slot[n]==v for n,v in actual.items());assert slot['offset_from_vptr']==0x890 and slot['diversity']=='0x17dc';assert 'P7IOAESIV14IOAESOperationP12IOAESKeyData'in slot['exact_symbols'][0]['name'];counts['nominal_provider_bindings']+=1
 for b in c['bank_rules']:
  l=IMAGE.read(int(b['left'],16),256);r=IMAGE.read(int(b['right'],16),256);assert l.hex()==b['left256_hex']and r.hex()==b['right256_hex'];constant=int(b['constant'],16);assert all(x^r[l[x]^int(b['key'],16)]==constant for x in range(256));assert int(b['index'],16)==constant+int(b['additive'],16);assert int(b['slot'],16)==int(b['base'],16)+int(b['index'],16)*8;assert pointer(k,int(b['slot'],16))==b['original_pointer'];counts['exhaustive_bank_rules']+=1;counts['bank_byte_inputs']+=256
 ops={int(i['ea'],16):(i['mnemonic'],i['operands'])for f in c['functions']for i in f['instructions']}
 facts={0xfffffe000a625c4c:('ubfiz','x0, x8, #2, #0x20'),0xfffffe000a625c60:('add','x1, x3, #0xc4'),0xfffffe000a625c64:('mov','w2, #4'),0xfffffe000a625c8c:('cmp','w0, w8'),0xfffffe000a625cc4:('ldur','w8, [x3, #0xc4]'),0xfffffe000a625cc8:('cmp','x8, #0xf'),0xfffffe000a625d58:('add','w11, w8, w16'),0xfffffe000a625d5c:('cmp','w11, #2, lsl #12'),0xfffffe000a625ddc:('ldrb','w9, [x9]'),0xfffffe000a625de4:('cset','w2, eq'),0xfffffe000a625e1c:('mov','w4, w11'),0xfffffe000a625e30:('and','x0, x8, #0xfffffff0'),0xfffffe000a625e34:('add','x1, x3, #0xb0'),0xfffffe000a625e38:('mov','x5, x4'),0xfffffe000a625ee0:('and','x24, x8, #0xfffffff0'),0xfffffe000a625ef0:('sub','w0, w8, #0x10'),0xfffffe000a625f28:('add','x25, x10, w25, uxtw'),0xfffffe000a625f40:('mov','w2, #0x10'),0xfffffe000a625f64:('cmp','w0, #0x10'),0xfffffe000a626010:('add','x1, x8, w11, uxtw'),0xfffffe000a626024:('mov','x2, x24'),0xfffffe000a626048:('cmp','w0, w24'),0xfffffe000a62607c:('str','w9, [sp, #0x80]'),0xfffffe000a626084:('add','w9, w9, #1'),0xfffffe000a626138:('ldrb','w3, [x10]'),0xfffffe000a62614c:('add','x1, x0, #0xb0'),0xfffffe000a626150:('ldr','w2, [sp, #0x80]'),0xfffffe000a50849c:('mov','x4, x1'),0xfffffe000a5084a0:('mov','x6, x0'),0xfffffe000a5084a8:('ldr','x0, [x8, #0xb08]'),0xfffffe000a5084b0:('ldr','x1, [x8, #0xb10]'),0xfffffe000a5084d8:('eor','w5, w3, #1'),0xfffffe000a5084e0:('mov','x2, x1'),0xfffffe000a5084e8:('mov','x7, #0'),0xfffffe000a50a008:('ldr','x0, [x8, #0x860]'),0xfffffe000a50a00c:('mov','x1, x0')}
 for a,v in facts.items():assert ops[a]==v,(hex(a),ops[a],v);counts['source_instruction_facts']+=1
 assert proof['contracts_sha256']==sha(ROOT/'sample_transfer_contracts.json')
 for q in proof['proofs']:
  assert sha(ROOT/q['file'])==q['sha256'];s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_file(str(ROOT/q['file'])));assert str(s.check())==q['result']=='unsat';counts['proofs_unsat']+=1
 assert[r['input']for r in p['cases']]==list(cases());fresh=[]
 for old in p['cases']:
  r=Transfer(old['input']).run();assert r==old;fresh.append(r);counts['fresh_transfer_cases']+=1;counts['fresh_transfer_source_visits']+=len(r['source_visits']);assert not r['undefined_private_reads']and not r['native_API_executed'];case=r['input'];obj=case['object64'];metadata,reads,outcome=prefix_expectation(case);actual=r['metadata_models'];assert len(actual)==len(metadata)
  for e,(index,offset,result)in zip(actual,metadata):
   assert e['metadata_index']==index and e['registers8'][:3]==[hex(offset),hex(obj+0xc4),'0x4']and int(e['result64'],16)==result;word=case['sample_words32'][index];written=min(result&0xffffffff,4);after=bytearray(bytes.fromhex(e['before_hex']));after[:written]=word.to_bytes(4,'little')[:written];assert after.hex()==e['after_hex'];counts['metadata_read_models']+=1;counts['modeled_metadata_bytes']+=written;counts['metadata_upper_width_cases']+=int(result>4)
  assert len(r['sample_read_models'])==len(reads);global_expected=bytearray();workspace={};iv=bytes.fromhex(r['header_fixture_hex'])[0x12:0x22]
  for e,(phase,offset,dest,n,result)in zip(r['sample_read_models'],reads):
   assert e['phase']==phase and e['registers8'][:3]==[hex(offset),hex(dest),hex(n)]and int(e['result64'],16)==result;written=min(result&0xffffffff,n);data=bytes((offset+i+0x21)&255 for i in range(written));assert data.hex()==e['payload_hex'];counts['modeled_sample_reads']+=1;counts['modeled_sample_bytes']+=written
   if phase=='bulk':
    goff=dest-GLOBAL_BUFFER;assert goff==len(global_expected);global_expected.extend(data);counts['bulk_read_models']+=1
   else:
    moff=dest-ARENA;assert n==16;counts['tail_read_models']+=1
    for j,b in enumerate(data):workspace[moff+j]=b
    if result&0xffffffff==16:
     expected=bytes(x^y for x,y in zip(data,iv));next_index=next((x['source_visit_index']for x in r['sample_read_models']if x['source_visit_index']>e['source_visit_index']),len(r['source_visits']));assert word_epoch(r['source_writes'],dest,16,next_index)==expected;counts['source_xor_masks']+=1;counts['source_xor_bytes']+=16
     for j,b in enumerate(expected):workspace[moff+j]=b
  assert r['global_defined_prefix_hex']==global_expected.hex()and r['global_defined_prefix_bytes']==len(global_expected);assert not r['global_buffer_reads'];assert r['global_buffer_fixture']['declared_pointer']==hex(GLOBAL_BUFFER)and r['global_buffer_fixture']['capacity_bytes']==GLOBAL_CAPACITY
  assert set(workspace)==set(range(r['workspace_defined_prefix_bytes']));assert bytes(workspace[i]for i in range(len(workspace))).hex()==r['workspace_defined_prefix_hex'];counts['defined_global_bytes']+=len(global_expected)
  kind,value=outcome
  if kind in['error','empty']:
   assert r['stop_reason']=='wrapper_return'and not r['crypto_boundaries'];status=int.from_bytes(bytes.fromhex(r['final_record_hex'])[8:12],'little');assert status==(0xce515bb2 if kind=='error'else 0x31ae0066);assert len([e for e in r['memory_models']if e['kind']=='workspace_free_model'])==1;counts['error_return_cases'if kind=='error'else'empty_return_cases']+=1
  else:
   assert r['stop_reason']=='before_crypto_call'and len(r['crypto_boundaries'])==1;b=r['crypto_boundaries'][0];regs=[int(v,16)for v in b['registers8']];h=case['header_byte0']
   if kind=='direct':length,offset=value;assert b['target']=='0xfffffe000a509fe8'and b['pc']=='0xfffffe000a625e40'and regs[:6]==[length,obj+0xb0,int(h==0),obj,offset,offset];counts['descriptor_submission_boundaries']+=1;counts['nonzero_direct_offset_cases']+=int(offset!=0)
   else:assert b['target']=='0xfffffe000a508484'and b['pc']=='0xfffffe000a626158'and regs[:4]==[obj,obj+0xb0,value,h];assert value==len(global_expected);counts['buffered_submission_boundaries']+=1
   counts['operation_domain_difference_cases']+=int((h^1)!=int(h==0));assert not b['target_executed']
  counts['multi_sample_prefix_cases']+=int(len(case['sample_words32'])>1);counts['metadata_caller_clobber_cases']+=int(case['metadata_clobber'])
 handoff_fresh=[];compose=Composed();want=[(i,b)for i,r in enumerate(p['cases'])for b in r['crypto_boundaries']];assert[(r['source_case_index'],r['input_boundary'])for r in hp['cases']]==want
 for old in hp['cases']:
  b=old['input_boundary'];r=compose.run_boundary(b);r['source_case_index']=old['source_case_index'];assert r==old;handoff_fresh.append(r);counts['fresh_composed_cases']+=1;counts['fresh_composed_source_visits']+=len(r['source_visits']);obs=r['provider_observation'];regs=[int(x,16)for x in obs['registers8']];args=[int(x,16)for x in b['registers8']];direct=b['target']=='0xfffffe000a509fe8';descriptor=int(r['nominal_sample_descriptor']if direct else r['nominal_global_descriptor'],16);length=args[0]if direct else args[2]&0xffffffff;iv=args[1];key=args[3]if direct else args[0];op=args[2]&0xffffffff if direct else(args[3]^1)&0xffffffff;offseta=args[4]if direct else 0;offsetb=args[5]if direct else 0
  assert regs==[int(r['nominal_provider'],16),descriptor,descriptor,length,iv,op,key,offseta];assert bytes.fromhex(obs['stack24_hex'])==struct.pack('<3Q',offsetb,0,0);assert word_epoch(r['source_writes'],int(obs['SP'],16),24,obs['source_visit_index'])==bytes.fromhex(obs['stack24_hex']);assert obs['target']==slot['target']and not obs['target_executed']and not r['provider_code_executed']and not r['crypto_operation_executed'];counts['provider_stack_source_bytes']+=24;counts['composed_IV_key_links']+=1
 (ROOT/'sample_transfer_replays.json').write_text(json.dumps({'scope':'Distinct fresh metadata/transfer and wrapper-to-provider compositions under declared models.','generator_sha256':sha(Path(__file__)),'transfer_cases':fresh,'handoff_cases':handoff_fresh,'native_target_executed':False,'crypto_operation_executed':False},indent=2)+'\n');deps.update(['sample_transfer_contracts.json','sample_transfer_profiles.json','sample_transfer_handoff_profiles.json','sample_transfer_proofs.json']);out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in sorted(deps)},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'verified_counts':dict(counts),'fresh_replays_sha256':sha(ROOT/'sample_transfer_replays.json'),'all_checks_pass':True,'native_target_executed':False,'crypto_operation_executed':False,'native_provider_class_proved':False,'full_goal_complete':False};(ROOT/'sample_transfer_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(dict(counts)),flush=True)
if __name__=='__main__':main()
