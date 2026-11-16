#!/usr/bin/env python3
"""Timeout source obligations, sequential contracts and continuous replay.
Linear source/formula/journal/RAM construction; SMT search separate.
"""
import json,struct
from collections import Counter
from hashlib import sha256
import z3
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_kernel_uuid_formatter_execution import Model as Parent,source_proofs as prior_proofs,semantic_count as prior_count
from audit_kernel_mapping_context import DEC
from lskd_values_symbolic import resize
import recover_kernel_timeout_execution as R
import probe_kernel_timeout_execution as CPU
from replay_kernel_timeout_execution import oracle,Replay,prefix,B

class Model(Parent):
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.mnemonic not in ['umulh','csinv']:
    old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one');self.e,self.c=old_e,old_c;continue
   if self.next is not None:self.edge_checks.append(self.next==i.address)
   self.next=resize(i.address+4,64);self.pc=i.address;self.visited.add(i.address);self.count+=1;o=i.operands
   if i.mnemonic=='umulh':value=z3.Extract(127,64,z3.ZeroExt(64,self.read(i.reg_name(o[1].reg)))*z3.ZeroExt(64,self.read(i.reg_name(o[2].reg))))
   else:value=z3.If(self.condition(i.op_str.rsplit(',',1)[1].strip()),self.read(i.reg_name(o[1].reg)),~self.read(i.reg_name(o[2].reg)))
   self.write(i.reg_name(o[0].reg),value)
  return self

def source_proofs(e):
 proofs=[];coverage=[]
 def local():v=Model(e);v.regions=[];return v
 def cut(v,a,b,linked=False):
  f=next(f for f in e['functions'] if int(f['start'],16)<=a<b<=int(f['end'],16));off=a-int(f['start'],16);v.e=v.c={'spans':[{'label':'cut','start':hex(a),'bytes_hex':bytes.fromhex(f['bytes'])[off:off+b-a].hex()}]};return v.run('cut') if linked else v.enter('cut')
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad));s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label);s.add(*v.bindings_for([*common,counter]),counter);result=s.check();assert result==z3.unsat,(label,str(result),s.reason_unknown());proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV'});coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,'linked_edge_obligations':len(v.edge_checks)});print(label,flush=True)
 arg,lr,value,local_scale,global_scale=z3.BitVecs('TO_argument64 TO_LR64 TO_value64 TO_local_scale64 TO_global_scale64',64)
 for target,flag,label in [(R.ORDINARY,0,'ordinary'),(R.SPECIAL,1,'special')]:
  v=local();v.seed('x0',arg);v.seed('x30',lr);cut(v,target,target+20);prove(label+'_tail_forwards_descriptor_empty_prefix_flag_and_LR',v,z3.Or(v.next!=R.COMMON,v.read('x0')!=arg,v.read('x1')!=0xfffffe00070eb2c9,v.read('x2')!=flag,v.read('x30')!=lr))
 flags=z3.BitVec('TO_flags32',32);v=local();v.seed('w2',flags);cut(v,0xfffffe000bd109cc,0xfffffe000bd109d0);prove('special_bit0_bypasses_ordinary_admission',v,v.next!=z3.If(flags&1==0,resize(0xfffffe000bd10c70,64),resize(0xfffffe000bd109d0,64)))
 v=local();v.regions=[(0xfffffe0007e63ff8,8)];v.setmem(0xfffffe0007e63ff8,8,value);cut(v,0xfffffe000bd10c70,0xfffffe000bd10c80);prove('ordinary_watchdog_minus1_selects_zero_publication',v,v.next!=z3.If(value==0xffffffffffffffff,resize(0xfffffe000bd10ca0,64),resize(0xfffffe000bd10c80,64)))
 base=R.B.B.B.BASE;v=local();v.regions=[(base,64),(base+128,8)];v.setmem(base,8,base+128);v.seed('x19',base);cut(v,0xfffffe000bd10ca0,0xfffffe000bd10cac);prove('disabled_timeout_publishes_zero_through_descriptor_destination',v,z3.Or(v.load(base+128,8)!=0,v.next!=0xfffffe000bd10fc4))
 status=z3.BitVec('TO_status32',32);previous=z3.BitVec('TO_previous64',64);v=local();v.setmem(v.sp0-0x80,8,value);v.seed('x29',v.sp0);v.seed('w0',status);v.seed('x26',previous);cut(v,0xfffffe000bd10d28,0xfffffe000bd10d38);prove('present_boot_value_replaces_previous_u64_only_when_status_nonzero',v,v.read('x26')!=z3.If(status!=0,value,previous))
 v=local();v.seed('x8',global_scale);v.seed('x28',local_scale);v.seed('x29',v.sp0);v.setmem(v.sp0-0xa4,4,status);cut(v,0xfffffe000bd10f04,0xfffffe000bd10f10);prove('local_and_global_scale_product_wraps_at64_bits',v,v.read('x8')!=global_scale*local_scale)
 v=local();v.seed('x26',value);v.seed('w9',status);cut(v,0xfffffe000bd10f10,0xfffffe000bd10f20);prove('zero_value_suppresses_override_conversion',v,v.next!=z3.If(z3.If(value==0,resize(0,32),status)==1,resize(0xfffffe000bd10f20,64),resize(0xfffffe000bd10fa8,64)))
 v=local();v.regions=[(base,8),(base+128,8)];v.setmem(base,8,base+128);v.seed('x19',base);v.seed('x26',value);v.seed('x8',local_scale);cut(v,0xfffffe000bd10fa8,0xfffffe000bd10fc0);product=z3.ZeroExt(64,value)*z3.ZeroExt(64,local_scale);expected=z3.If(z3.Extract(127,64,product)==0,z3.Extract(63,0,product),resize(MASK,64));prove('final_unsigned_product_saturates_to_u64_max_before_publication',v,v.load(base+128,8)!=expected)
 cached=z3.BitVec('TO_cache_byte8',8);v=local();v.regions=[(0xfffffe000cb62710,1)];v.setmem(0xfffffe000cb62710,1,cached);v.seed('x21',0xfffffe000cb62000);cut(v,0xfffffe000bd10df8,0xfffffe000bd10e08);prove('only_cache_byte_exactly1_selects_cached_scale',v,v.next!=z3.If(cached==1,resize(0xfffffe000bd10e08,64),resize(0xfffffe000bd10e18,64)))
 v=local();v.seed('x9',value);v.seed('x10',62500);cut(v,0xfffffe000c63acf8,0xfffffe000c63ad00);prove('mtxspin_option_uses_unsigned_minimum_with62500',v,v.read('x9')!=z3.If(z3.ULT(value,62500),value,resize(62500,64)))
 v=local();v.seed('x24',value);cut(v,0xfffffe000c63acb8,0xfffffe000c63acbc);prove('absent_ticket_override_uses_unsigned_half_of_nonzero_lock_value',v,v.read('x8')!=z3.LShR(value,1))
 return proofs,coverage

MASK=(1<<64)-1

def static_contracts(e,image):
 checks=[]
 def ok(label,p):assert p,('timeout_static_contract',label);checks.append(label)
 for f in e['functions']:ok('body_'+f['start'],image.k.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes'] and sha256(bytes.fromhex(f['bytes'])).hexdigest()==f['sha256'])
 old=json.loads(read(ROOT/(R.B.P+'_checks.json')));ok('prior_capture_rebuilt',old==R.B.build() and e['prior_checks_sha256']==sha(ROOT/(R.B.P+'_checks.json')))
 registry=json.loads(read(ROOT/(R.B.B.B.P+'_checks.json')))['registry']['entries']
 for r in e['timeout_registrations']:ok('registration_'+str(r['index']),r==registry[r['index']] and r['phase_u32']==2 and r['callback_pointer']['auth']==1 and r['callback_pointer']['diversity']=='0x2abe')
 for d in e['timeout_descriptors']:
  a=int(d['address'],16);raw=image.k.read(a,64);ok('descriptor_'+d['address'],raw.hex()==d['bytes_hex'] and image.pointer(a)==d['destination_pointer'] and int.from_bytes(raw[8:16],'little')==d['default_u64'] and int.from_bytes(raw[16:24],'little')==d['divisor_u64']==0 and raw[24:56].split(b'\0')[0].decode()==d['name'] and raw[56:64]==bytes(8) and d['filter_pointer'] is None)
 for s in e['strings']:ok('string_'+s['address'],image.k.read(int(s['address'],16),len(bytes.fromhex(s['bytes_hex']))).hex()==s['bytes_hex'] and bytes.fromhex(s['bytes_hex'])[:-1].decode()==s['text'])
 p=e['stack_probe_pointer'];ok('stack_probe_pointer',image.pointer(int(p['slot'],16))==p and p['target']==hex(R.STACK_STUB) and p['auth']==p['address_diversity']==1 and p['diversity']=='0x0' and p['key']==0)
 return {'checks':checks,'original_bodies_checked':len(e['functions']),'timeout_descriptors_checked':9,'timeout_registrations_checked':10,'prior_capture_rebuilt':True}

def semantic_count(o):return len(o['checks'])+prior_count(o['prior_formatter_contracts'])+sum(len(o[k]['checks']) for k in ['full_option_API_contracts','full_tree_API_contracts','full_copy_API_contracts','helper_contracts'])

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,coverage=source_proofs(e);retained,retained_coverage=prior_proofs(e);image=Image();static=static_contracts(e,image);components=[];totals=Counter()
 for c in CPU.cases():
  row=CPU.Probe(image,c).run();row['independent_oracle']=oracle(row,e);q=Replay(image,row).run();row['independent_replay']=q;components.append(row);totals.update(q);print('main',c['label'],len(row['source_visits']),row['independent_oracle']['timeout_results'][0],flush=True)
 old=B.hydrate(json.loads(read(ROOT/(R.B.P+'_audit.json')))['components'][0],image);new=prefix(components[0]);keys=['source_visits','source_reads','source_writes','API_models','logical_effects','original_call_entries','original_API_entries','original_API_returns','callback_entries','callback_returns','final_private_RAM','final_image_globals','final_vectors','final_system'];assert all(old[k]==new[k] for k in keys),[k for k in keys if old[k]!=new[k]]
 assert all(old['boundary'][k]==new['boundary'][k] for k in ['pc','registers31','SP','NZCV'])
 wanted=old['final_page_sha256'];actual=new['final_page_sha256'];assert wanted.keys()<=actual.keys() and all(actual[p]==h for p,h in wanted.items())
 for p in actual.keys()-wanted.keys():assert actual[p]==sha256(image.logical_page(int(p,16))).hexdigest()
 preservation={'prior_audit_sha256':sha(ROOT/(R.B.P+'_audit.json')),'prior_component':old['configuration']['label'],'compared_fields':keys+['boundary_pc','boundary_GPR31','boundary_SP','boundary_NZCV'],'exact_match':True,'known_original_page_hashes_exact_match':True,'additional_original_page_bytes':4096*len(actual.keys()-wanted.keys()),'call_frame_epochs':0,'new_callback_result_models':0}
 controls=[]
 for label,index,pc in [('shared_output_store',1,0xfffffe000bd10fbc),('chosen_tree_value_load',3,0xfffffe000bd10cf0)]:
  row=CPU.Probe(image,CPU.cases()[index],pc).run();positive=components[index];initial_keys=['configuration','entry_PC','entry_SP','entry_registers31','entry_NZCV','initial_private_RAM','initial_private_fixtures','initial_image_fixtures','initial_image_pages'];assert all(row[k]==positive[k] for k in initial_keys)
  try:oracle(row,e)
  except AssertionError as error:rejection=list(error.args[0])
  else:raise AssertionError(('changed_source_accepted',hex(pc)))
  journal={k:row[k] for k in ['source_visits','source_reads','source_writes','final_private_RAM']};controls.append({'label':label,'configuration':row['configuration'],'source_word_mutated_to_NOP':hex(pc),'original_bytes_hex':image.k.read(pc,4).hex(),'replacement_bytes_hex':'1f2003d5','same_positive_initial_fields':initial_keys,'all_initial_fields_match':True,'source_visits':len(row['source_visits']),'boundary':row['boundary'],'oracle_rejection':rejection,'journal_canonical_sha256':sha256(json.dumps(journal,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'full_control_journal_retained':False,'control_journal_rebuilt_by_delivery_verifier':True});print('control_rejected',label,flush=True)
 visited={v['pc'] for c in components for v in c['source_visits']};source={i['ea'] for f in e['functions'] for i in f['instructions']};assert visited<=source and not visited&{i['ea'] for f in e['functions'] for i in f['instructions'] if i['mnemonic'] in ['opaque','udf']}
 stats={'source_queries_unsat':len(proofs),'retained_formatter_queries_rebuilt':len(retained),'proved_source_PCs':len({p for q in coverage for p in q['PCs']}),'proof_instruction_instances':sum(q['instruction_instances'] for q in coverage),'linked_edge_obligations':sum(q['linked_edge_obligations'] for q in coverage),'components':len(components),'source_visits':sum(len(c['source_visits']) for c in components),'executed_source_PCs':len(visited),'changed_source_controls':len(controls),'independent_semantic_checks':sum(semantic_count(c['independent_oracle']) for c in components),'static_contracts':len(static['checks']),'original_API_entries':sum(len(c['original_API_entries']) for c in components),'original_API_returns':sum(len(c['original_API_returns']) for c in components),'original_registry_callbacks_returned':sum(len(c['callback_returns']) for c in components),'callbacks_returned_per_case':402,'phase_two_callbacks_per_case':10,'timeout_descriptor_publications_per_case':9,'helper_calls_checked':sum(len(c['independent_oracle']['helper_contracts']['calls']) for c in components),'mutable_region_count_per_case':len(components[0]['final_image_globals']),'mutable_region_bytes_per_case':sum(len(bytes.fromhex(r['bytes_hex'])) for r in components[0]['final_image_globals']),'callback_output_and_final_global_bytes_compared':sum(c['independent_oracle']['mutable_bytes_compared'] for c in components),'private_nonstack_bytes_checked':sum(c['independent_oracle']['private_nonstack_bytes_checked'] for c in components),'call_frame_epochs':0,'new_callback_result_models':0,'native_target_executions':0}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_timeout_execution.py'),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'scope':R.SCOPE,'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'source_proofs':proofs,'retained_source_proofs_rebuilt':retained,'proof_coverage':coverage,'retained_proof_coverage':retained_coverage,'independent_static_contracts':static,'components':[B.publication_row(c,image) for c in components],'negative_controls':controls,'prior_published_checkpoint_preservation':preservation,'independent_totals':stats,'independent_replay_totals':dict(totals),'executed_function_coverage':[{'start':f['start'],'captured_words':len(f['instructions']),'executed_unique_PCs':len({i['ea'] for i in f['instructions']}&visited)} for f in e['functions']],'conditional_kernel_timeout_execution_contract_established':True,**{n:True for n in R.TRUE},**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True);print(json.dumps(a['independent_replay_totals']),flush=True)
