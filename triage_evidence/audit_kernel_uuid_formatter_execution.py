#!/usr/bin/env python3
"""Original formatter obligations, guarded cases and continuous startup replay.
Linear source/formula DAG/journals/RAM construction; timeline O(J log J).
SMT search separate, 30 s/query. No target execution or new return model.
"""
import json,struct
from collections import Counter
from hashlib import sha256
import z3
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_kernel_startup_registry_abi import Model as Parent
from audit_kernel_tunable_batch_execution import source_proofs as prior_proofs,semantic_count as prior_count
from audit_kernel_mapping_context import DEC
from lskd_values_symbolic import resize
import recover_kernel_uuid_formatter_execution as R
import probe_kernel_uuid_formatter_execution as CPU
import probe_kernel_uuid_formatter_cases as DIRECT
from replay_kernel_uuid_formatter_execution import oracle,direct_oracle,Replay,DirectReplay,prior_row,B

class Model(Parent):
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.mnemonic=='blraa' and i.op_str=='x21, x17':
    if self.next is not None:self.edge_checks.append(self.next==i.address)
    self.next=self.read('x21');self.pc=i.address;self.visited.add(i.address);self.count+=1;self.write('x30',i.address+4)
   else:
    old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one');self.e,self.c=old_e,old_c
  return self

def source_proofs(e):
 proofs=[];coverage=[]
 def local():v=Model(e);v.regions=[];return v
 def cut(v,a,b,linked=False):
  f=next(f for f in e['functions'] if int(f['start'],16)<=a<b<=int(f['end'],16));off=a-int(f['start'],16);v.e=v.c={'spans':[{'label':'cut','start':hex(a),'bytes_hex':bytes.fromhex(f['bytes'])[off:off+b-a].hex()}]};return v.run('cut') if linked else v.enter('cut')
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad));s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label);s.add(*v.bindings_for([*common,counter]),counter);result=s.check();assert result==z3.unsat,(label,str(result),s.reason_unknown())
  proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV'});coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,'linked_edge_obligations':len(v.edge_checks)});print(label,flush=True)
 dst,capacity,fmt,lr=z3.BitVecs('UF_destination64 UF_capacity64 UF_format64 UF_LR64',64);v=local();v.seed('x0',dst);v.seed('x1',capacity);v.seed('x2',fmt);v.seed('x30',lr);cut(v,R.FORMAT,0xfffffe000c3003f8);context=v.sp0-0x20
 prove('wrapper_core_ABI_varargs_context_radix_flags_logical_PAC',v,z3.Or(v.next!=R.ENGINE,v.read('x0')!=fmt,v.read('x1')!=v.sp0,v.read('x2')!=R.EMIT,v.read('x3')!=context,v.read('x4')!=10,v.read('x5')!=0,v.read('x17')!=0xae56,v.load(context,8)!=dst,v.load(context+8,8)!=capacity))
 v=local();v.setmem(v.sp0+0x18,8,capacity);cut(v,0xfffffe000c3003f8,0xfffffe000c300400);prove('wrapper_zero_remaining_capacity_skips_terminator',v,v.next!=z3.If(capacity==0,resize(0xfffffe000c300408,64),resize(0xfffffe000c300400,64)))
 context=R.B.B.BASE;destination=context+64;v=local();v.regions=[(destination,1)];v.setmem(v.sp0+0x10,8,destination);cut(v,0xfffffe000c300400,0xfffffe000c300408);prove('wrapper_nonzero_capacity_stores_NUL_at_final_cursor',v,v.load(destination,1)!=0)
 v=local();v.regions=[(context,16)];v.setmem(context+8,8,capacity);v.seed('x1',context);cut(v,R.EMIT+4,0xfffffe000c300424);prove('emitter_admits_unsigned_remaining_at_least2',v,v.next!=z3.If(z3.ULT(capacity,2),resize(0xfffffe000c300440,64),resize(0xfffffe000c300424,64)))
 byte=z3.BitVec('UF_character32',32);v=local();v.regions=[(context,16),(destination,1)];v.setmem(context,8,destination);v.setmem(context+8,8,capacity);v.seed('x0',z3.ZeroExt(32,byte));v.seed('x1',context);cut(v,0xfffffe000c300424,0xfffffe000c300440);prove('emitter_stores_low_byte_advances_cursor_and_decrements_capacity',v,z3.Or(v.load(destination,1)!=z3.Extract(7,0,byte),v.load(context,8)!=destination+1,v.load(context+8,8)!=capacity-1),[z3.UGE(capacity,2)])
 v=local();v.regions=[(context,16),(destination,1)];v.setmem(context,8,destination);v.setmem(context+8,8,capacity);old=v.load(destination,1);v.seed('x1',context);v.seed('x30',lr);cut(v,R.EMIT+4,0xfffffe000c300424);cut(v,0xfffffe000c300440,0xfffffe000c300444,True);prove('emitter_remaining0_or1_preserves_context_destination_and_returns',v,z3.Or(v.next!=lr,v.load(context,8)!=destination,v.load(context+8,8)!=capacity,v.load(destination,1)!=old),[z3.ULT(capacity,2)])
 callback,argument=z3.BitVecs('UF_callback64 UF_context64',64);v=local();v.seed('x21',callback);v.seed('x20',argument);v.seed('w0',byte);cut(v,0xfffffe000bd14724,0xfffffe000bd14730);prove('engine_logical_callback_forwards_character_context_modifier_and_LR',v,z3.Or(v.next!=callback,v.read('x0')!=z3.ZeroExt(32,byte),v.read('x1')!=argument,v.read('x17')!=0xae56,v.read('x30')!=0xfffffe000bd14730))
 count=z3.BitVec('UF_attempted_count64',64);v=local();v.seed('x23',count);cut(v,0xfffffe000bd153e0,0xfffffe000bd153e4);prove('engine_returns_attempted_character_counter',v,v.read('x0')!=count)
 v=local();v.setmem(v.sp0+0x18,8,argument);cut(v,0xfffffe000bd149c8,0xfffffe000bd149d4);prove('conversion_fetch_advances_variadic_pointer_by8_mod64',v,v.load(v.sp0+0x18,8)!=argument+8)
 value=z3.BitVec('UF_byte_value32',32);v=local();v.seed('w8',value);v.seed('x25',16);cut(v,0xfffffe000bd150a8,0xfffffe000bd150b0);prove('hexadecimal_division_of_byte_has_nibble_quotient_and_remainder',v,z3.Or(v.read('x11')!=z3.ZeroExt(32,z3.LShR(value,4)),v.read('x12')!=z3.ZeroExt(32,value&15)),[z3.ULE(value,255)])
 nibble=z3.BitVec('UF_nibble64',64);upper=0xfffffe000704e7a7;v=local();v.regions=[(upper,16)]
 for j,ch in enumerate(b'0123456789ABCDEF'):v.setmem(upper+j,1,ch)
 v.seed('x12',nibble);v.seed('x14',upper);cut(v,0xfffffe000bd150b0,0xfffffe000bd150cc);expected=z3.If(z3.ULT(nibble,10),nibble+48,nibble+55);prove('uppercase_digit_lookup_is_ASCII_for_all16_nibbles',v,v.read('w9')!=z3.Extract(31,0,expected),[z3.ULE(nibble,15)])
 conversion=z3.BitVec('UF_conversion32',32);v=local();v.seed('w12',conversion);cut(v,0xfffffe000bd14984,0xfffffe000bd1498c);prove('conversion_above0x78_selects_default_before_table_lookup',v,v.next!=z3.If(z3.UGT(conversion,120),resize(0xfffffe000bd14cb4,64),resize(0xfffffe000bd1498c,64)),[z3.ULE(conversion,255)])
 ordinal=z3.BitVec('UF_ordinal16',16);base=z3.BitVec('UF_embedded_base64',64);thread=context+0x200;v=local();v.regions=[(thread,0x1ba)];v.setmem(thread+0x1b8,2,ordinal);v.seed('x9',thread);v.seed('x8',base);cut(v,0xfffffe000c62f3b0,0xfffffe000c62f3bc);prove('embedded_per_CPU_pointer_uses_full_u16_ordinal_and_stride128',v,v.read('x10')!=base-(z3.ZeroExt(48,ordinal)<<7))
 xor=z3.BitVec('UF_pointer_xor64',64);v=local();v.seed('x16',xor);cut(v,0xfffffe000c62f3c0,0xfffffe000c62f3c8);prove('per_CPU_pointer_high_span_check_selects_poison_path',v,v.next!=z3.If(xor&0xffc0000000000000==0,resize(0xfffffe000c62f3cc,64),resize(0xfffffe000c62f3c8,64)))
 v=local();v.regions=[(context,32)];v.seed('x19',context);v.seed('x10',base);cut(v,0xfffffe000c62f3cc,0xfffffe000c62f3d0);prove('early_per_CPU_initializer_publishes_pointer_in_object_word10',v,v.load(context+16,8)!=base)
 rounded=z3.BitVec('UF_stack_rounded64',64);v=local();v.regions=[(0xfffffe0007e64500,16)];v.seed('x8',rounded);v.seed('x19',0xfffffe0007e64000);cut(v,0xfffffe000bd3a5c8,0xfffffe000bd3a5dc);prove('stack_initializer_publishes_rounded_minus1_and_negative_masks',v,z3.Or(v.load(0xfffffe0007e64500,8)!=rounded-1,v.load(0xfffffe0007e64508,8)!=-rounded))
 return proofs,coverage

def static_contracts(e,image):
 checks=[]
 def ok(k,p):assert p,('UUID_static_contract',k);checks.append(k)
 for f in e['functions']:ok('body_'+f['start'],image.k.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes'] and sha256(bytes.fromhex(f['bytes'])).hexdigest()==f['sha256'])
 for s in e['strings']:ok('string_'+s['address'],image.k.read(int(s['address'],16),len(bytes.fromhex(s['bytes_hex']))).hex()==s['bytes_hex'] and bytes.fromhex(s['bytes_hex'])[:-1].decode()==s['text'])
 t=e['conversion_dispatch'];raw=image.k.read(int(t['address'],16),484);ok('dispatch_raw',raw.hex()==t['bytes_hex'])
 for j,v in enumerate(struct.unpack('<121i',raw)):ok('conversion_'+str(j),t['entries'][j]=={'conversion_byte':j,'target':hex(int(t['signed_offset_base'],16)+v)} and R.ENGINE<=int(t['entries'][j]['target'],16)<int(t['address'],16))
 d=e['digit_table'];ok('digit_table',image.k.read(int(d['address'],16),33).hex()==d['bytes_hex'] and bytes.fromhex(d['bytes_hex'])==b'0123456789abcdef0123456789ABCDEF\0')
 reg=json.loads(read(ROOT/(R.B.B.P+'_checks.json')))['registry']['entries']
 for o in e['per_CPU_objects']:ok('object_'+o['address'],image.k.read(int(o['address'],16),32).hex()==o['header_bytes_hex'])
 for r in e['per_CPU_object_registrations']:
  prior=reg[r['registry_index']];ok('object_registration_'+str(r['registry_index']),prior['phase_u32']==r['phase_u32'] and prior['rank_u32']==r['rank_u32'] and prior['argument_pointer']==r['argument_pointer'] and prior['argument_pointer']['target']==r['object_address'] and int(prior['callback_pointer']['target'],16)==R.PERCPU)
 c=e['optional_capability_record'];ok('optional_capability_record',image.k.read(int(c['address'],16),24).hex()==c['bytes_hex'] and c['callback_pointer'] is None)
 return {'checks':checks,'original_bodies_checked':len(e['functions']),'conversion_slots_checked':121,'per_CPU_object_registrations_checked':8}

def semantic_count(o):return len(o['checks'])+prior_count(o['prior_batch_contracts'])+len(o['formatter_contracts']['checks'])+len(o['full_option_API_contracts']['checks'])+len(o['full_string_contracts']['checks'])

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,coverage=source_proofs(e);retained,retained_coverage=prior_proofs(e);image=Image();static=static_contracts(e,image);components=[];direct=[];totals=Counter();main_totals=Counter();direct_totals=Counter()
 for c in CPU.cases():
  row=CPU.Probe(image,c).run();row['independent_oracle']=oracle(row,e);q=Replay(image,row).run();row['independent_replay']=q;components.append(row);totals.update(q);main_totals.update(q);print('main',c['label'],len(row['source_visits']),flush=True)
 for c in DIRECT.cases():
  row=DIRECT.Probe(image,c).run();row['independent_oracle']=direct_oracle(row);q=DirectReplay(image,row).run();row['independent_replay']=q;direct.append(row);totals.update(q);direct_totals.update(q)
 old=B.hydrate(json.loads(read(ROOT/(R.B.P+'_audit.json')))['components'][0],image);new=prior_row(components[0]);keys=['source_visits','source_reads','source_writes','API_models','logical_effects','original_call_entries','original_API_entries','original_API_returns','callback_entries','callback_returns','final_private_RAM','final_image_globals','final_vectors','final_page_sha256','final_system'];assert all(old[k]==new[k] for k in keys)
 assert all(old['boundary'][k]==new['boundary'][k] for k in ['pc','registers31','SP','NZCV'])
 preservation={'prior_audit_sha256':sha(ROOT/(R.B.P+'_audit.json')),'prior_component':old['configuration']['label'],'compared_fields':keys+['boundary_pc','boundary_GPR31','boundary_SP','boundary_NZCV'],'exact_match':True,'call_frame_epochs':0,'new_callback_result_models':0}
 controls=[]
 for kind,producer,case,pc in [('main',CPU,CPU.cases()[0],0xfffffe000c300430),('direct',DIRECT,DIRECT.cases()[3],0xfffffe000c300404)]:
  row=producer.Probe(image,case,pc).run();positive=components[0] if kind=='main' else direct[3];initial_keys=['configuration','entry_PC','entry_SP','entry_registers31','entry_NZCV','initial_private_RAM','initial_private_fixtures','initial_image_fixtures','initial_image_pages'];assert all(row[k]==positive[k] for k in initial_keys)
  try:oracle(row,e) if kind=='main' else direct_oracle(row)
  except AssertionError as error:rejection=list(error.args[0])
  else:raise AssertionError(('changed_source_accepted',hex(pc)))
  journal={k:row[k] for k in ['source_visits','source_reads','source_writes','final_private_RAM']};digest=sha256(json.dumps(journal,sort_keys=True,separators=(',',':')).encode()).hexdigest();controls.append({'kind':kind,'configuration':row['configuration'],'source_word_mutated_to_NOP':hex(pc),'original_bytes_hex':image.k.read(pc,4).hex(),'replacement_bytes_hex':'1f2003d5','same_positive_initial_fields':initial_keys,'all_initial_fields_match':True,'source_visits':len(row['source_visits']),'boundary':row['boundary'],'oracle_rejection':rejection,'journal_canonical_sha256':digest,'full_control_journal_retained':False,'control_journal_rebuilt_by_delivery_verifier':True});print('control_rejected',kind,hex(pc),flush=True)
 visited={v['pc'] for c in components+direct for v in c['source_visits']};source={i['ea'] for f in e['functions'] for i in f['instructions']};assert visited<=source and not visited&{i['ea'] for f in e['functions'] for i in f['instructions'] if i['mnemonic'] in ['opaque','udf']}
 stats={'source_queries_unsat':len(proofs),'retained_batch_queries_rebuilt':len(retained),'proved_source_PCs':len({p for q in coverage for p in q['PCs']}),'proof_instruction_instances':sum(q['instruction_instances'] for q in coverage),'linked_edge_obligations':sum(q['linked_edge_obligations'] for q in coverage),'main_components':len(components),'direct_formatter_components':len(direct),'source_visits':sum(len(c['source_visits']) for c in components+direct),'main_source_visits':sum(len(c['source_visits']) for c in components),'direct_source_visits':sum(len(c['source_visits']) for c in direct),'executed_source_PCs':len(visited),'changed_source_controls':len(controls),'main_semantic_checks':sum(semantic_count(c['independent_oracle']) for c in components),'direct_formatter_checks':sum(len(c['independent_oracle']['formatter_contracts']['checks']) for c in direct),'static_contracts':len(static['checks']),'original_registry_callbacks_returned':sum(len(c['callback_returns']) for c in components),'phase_one_callbacks_returned_per_case':392,'formatted_results':len(components)+len(direct),'formatter_byte_output_calls':36*(len(components)+len(direct)),'main_API_entries':sum(len(c['original_API_entries']) for c in components),'main_API_returns':sum(len(c['original_API_returns']) for c in components),'direct_API_entries_and_returns':sum(len(c['original_API_entries']) for c in direct),'direct_nonstack_bytes_checked':sum(c['independent_oracle']['whole_nonstack_private_bytes_checked'] for c in direct),'direct_guarded_output_bytes_checked':128*len(direct),'main_callback_output_and_final_global_bytes_compared':sum(c['independent_oracle']['mutable_bytes_compared'] for c in components),'main_nonstack_private_bytes_checked':sum(c['independent_oracle']['private_nonstack_bytes_checked'] for c in components),'call_frame_epochs':0,'new_callback_result_models':0,'native_target_executions':0}
 components=[B.publication_row(c,image) for c in components];direct=[B.publication_row(c,image) for c in direct]
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'direct_probe_sha256':sha(DIRECT.__file__),'replay_sha256':sha(ROOT/'replay_kernel_uuid_formatter_execution.py'),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'scope':R.SCOPE,'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'source_proofs':proofs,'retained_source_proofs_rebuilt':retained,'proof_coverage':coverage,'retained_proof_coverage':retained_coverage,'independent_static_contracts':static,'components':components,'direct_components':direct,'negative_controls':controls,'prior_published_checkpoint_preservation':preservation,'independent_totals':stats,'independent_replay_totals':dict(totals),'main_replay_totals':dict(main_totals),'direct_replay_totals':dict(direct_totals),'executed_function_coverage':[{'start':f['start'],'captured_words':len(f['instructions']),'executed_unique_PCs':len({i['ea'] for i in f['instructions']}&visited)} for f in e['functions']],'conditional_kernel_uuid_formatter_execution_contract_established':True,**{n:True for n in R.TRUE},**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True);print(json.dumps(a['independent_replay_totals']),flush=True)
