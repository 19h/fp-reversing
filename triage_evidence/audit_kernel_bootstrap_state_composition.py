#!/usr/bin/env python3
"""Source composition obligations, complete private runs and independent replay.
O(source+formula DAG+visits+journals+RAM) construction/space; SMT search separate,
30 s/query. No native startup, authentication or target IPC.
"""
import json
from collections import Counter
import z3
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_kernel_boot_environment_publication import Model as Parent
from audit_kernel_mapping_context import DEC
from audit_kernel_platform_environment_execution import source_proofs as platform_proofs,semantic_count as prefix_count
from audit_kernel_cpu_topology_handoff import source_proofs as topology_proofs
from lskd_values_symbolic import resize
import recover_kernel_bootstrap_state_composition as R
import probe_kernel_bootstrap_state_composition as CPU
from replay_kernel_bootstrap_state_composition import oracle,Replay,prefix_row
K=R.K;T=R.T

class Model(Parent):
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.mnemonic=='pacda':
    assert i.op_str=='x16, x17'
    if self.next is not None:self.edge_checks.append(self.next==i.address)
    self.next=resize(i.address+4,64);self.pc=i.address;self.visited.add(i.address);self.count+=1;continue
   old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one');self.e,self.c=old_e,old_c
  return self

def source_proofs(e):
 proofs=[];coverage=[]
 def local():v=Model(e);v.regions=[];return v
 def cut(v,a,b):
  f=next(f for f in e['functions'] if int(f['start'],16)<=a<b<=int(f['end'],16));off=a-int(f['start'],16)
  v.e=v.c={'spans':[{'label':'cut','start':hex(a),'bytes_hex':bytes.fromhex(f['bytes'])[off:off+b-a].hex()}]};return v.enter('cut')
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad));s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label)
  s.add(*v.bindings_for([*common,counter]),counter);result=s.check();assert result==z3.unsat,(label,str(result),s.reason_unknown())
  proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV'});coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,'linked_edge_obligations':len(v.edge_checks)});print(label,flush=True)
 for label,base,n in [('zero_initialized_array_slot_reaches_null_first_record_store',0,0),('original_initialized_array_slot_selects_136_byte_ordinal',K.ARRAY,z3.BitVec('SC_ordinal32',32))]:
  v=local();v.regions=[(K.GLOBALS,0x30)];v.setmem(K.GLOBALS+0x1c,8,base);v.seed('x24',K.GLOBALS);v.seed('w8',n);cut(v,0xfffffe000be832fc,0xfffffe000be83324)
  expected=resize(base,64)+resize(n,64)*136;premises=[] if isinstance(n,int) else [z3.ULT(n,16)]
  prove(label,v,z3.Or(v.read('x26')!=expected,v.load(K.GLOBALS,4)!=resize(n,32)+1,v.next!=0xfffffe000be83324),premises)
 for label,pc,target in [('actual_main_enumeration_call',0xfffffe000c639cb8,K.ENUM),('actual_main_post_helper_call',0xfffffe000c639cbc,T.POST)]:
  v=local();cut(v,pc,pc+4);prove(label,v,z3.Or(v.next!=target,v.read('x30')!=pc+4))
 virtual,physical=z3.BitVecs('SC_virtual_base64 SC_physical_base64',64);v=local();v.regions=[(K.ARGS+8,16)];v.setmem(K.ARGS+8,8,virtual);v.setmem(K.ARGS+16,8,physical);v.seed('x26',K.CPU);cut(v,0xfffffe000c639d54,0xfffffe000c639d68)
 prove('CPU_map_physical_word_is_modular_bootarg_translation',v,v.read('x9')!=physical+K.CPU-virtual)
 n=z3.BitVec('SC_map_ordinal32',32);value=z3.BitVec('SC_map_physical_word64',64)
 v=local();v.regions=[(K.CPU_MAP,256)];v.seed('w8',n);v.seed('x26',K.CPU);cut(v,0xfffffe000c639d28,0xfffffe000c639d54)
 prove('bounded_ordinal_selects_exact_CPU_map_virtual_slot',v,v.load(K.CPU_MAP+z3.ZeroExt(32,n)*16+8,8)!=K.CPU,[z3.ULT(n,16)])
 v=local();v.regions=[(K.CPU_MAP,256)];v.seed('x8',z3.ZeroExt(32,n)*16);v.seed('x9',value);v.seed('x10',K.CPU_MAP);cut(v,0xfffffe000c639d68,0xfffffe000c639d80)
 prove('bounded_ordinal_selects_exact_CPU_map_physical_slot',v,v.load(K.CPU_MAP+z3.ZeroExt(32,n)*16,8)!=value,[z3.ULT(n,16)])
 v=local();v.regions=[(K.THREAD,1472),(K.SLOT_PTR,8),(K.SLOT,8)];v.setmem(K.SLOT_PTR,8,K.SLOT);v.seed('x19',K.THREAD);cut(v,0xfffffe000c639da8,0xfffffe000c639dc4)
 prove('copied_thread_flags_and_original_slot_pointer_publication',v,z3.Or(v.load(K.THREAD+0x214,2)!=0x5f,v.load(K.SLOT,8)!=K.THREAD,v.load(K.THREAD+0x518,4)!=0xfffff))
 v=local();v.regions=[(K.THREAD+0x1c8,4)];v.seed('x19',K.THREAD);cut(v,0xfffffe000c639dd4,0xfffffe000c639dd8);prove('thread_status_is_cleared_after_original_setter_return',v,v.load(K.THREAD+0x1c8,4)!=0)
 for label,a,b,offset,target,tag in [('first_CPU_pointer_pair',0xfffffe000c639ce0,0xfffffe000c639d04,0x10,0xfffffe000cbb4000,0xe94d),('second_CPU_pointer_pair',0xfffffe000c639d04,0xfffffe000c639d28,0x20,0xfffffe000cbbc000,0x467)]:
  v=local();v.regions=[(K.CPU,0x40)];v.seed('x26',K.CPU);cut(v,a,b)
  modifier=((K.CPU+offset)&0xffffffffffff)|(tag<<48)
  prove('logical_PAC_'+label+'_retains_target_and_address_modifier',v,z3.Or(v.load(K.CPU+offset,8)!=target,v.load(K.CPU+offset+8,8)!=target,v.read('x17')!=modifier))
 return proofs,coverage

def semantic_count(o):return len(o['checks'])+prefix_count(o['prefix_contracts'])+sum(len(o[k]['checks']) for k in ['tree_API_contracts','option_API_contracts','copy_contracts'])

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,coverage=source_proofs(e);retained=[];retained_coverage=[]
 for module,fn in [(R.B.P,platform_proofs),(R.B.O.B.B.P,topology_proofs)]:
  p,c=fn(e);retained += [{**q,'prior_source_artifact_sha256':sha(ROOT/(module+'_checks.json'))} for q in p];retained_coverage += c
 image=Image();components=[];totals=Counter()
 for c in CPU.cases():
  row=CPU.Probe(image,c).run();row['independent_oracle']=oracle(row,e);q=Replay(image,row).run();totals.update(q);row['independent_replay']=q;components.append(row);print(c['label'],len(row['source_visits']),flush=True)
 old=json.loads(read(ROOT/(R.B.P+'_audit.json')))['components'][0];new=prefix_row(components[0]);cut=components[0]['pre_enumeration_checkpoint']
 keys=['source_visits','source_reads','source_writes','API_models','original_API_entries','original_API_returns','final_private_RAM','final_image_globals','final_vectors']
 assert all(old[k]==new[k] for k in keys)
 assert all(old['boundary'][k]==new['boundary'][k] for k in ['pc','registers31','SP','NZCV'])
 assert all(cut['system'][k]==v for k,v in old['final_system'].items())
 preservation={'prior_audit_sha256':sha(ROOT/(R.B.P+'_audit.json')),'prior_component':old['configuration']['label'],'compared_fields':keys+['boundary_pc','boundary_GPR31','boundary_SP','boundary_NZCV','common_logical_system_registers'],'exact_match':True,'additional_logical_system_inputs_declared':True}
 left,right=components[:2];lcut,rcut=[c['pre_enumeration_checkpoint'] for c in [left,right]]
 assert left['initial_private_RAM']==right['initial_private_RAM'] and left['entry_registers31']==right['entry_registers31'] and left['initial_system']==right['initial_system']
 assert left['source_visits'][:lcut['before_visit']]==right['source_visits'][:rcut['before_visit']]
 assert all(lcut[k]==rcut[k] for k in ['PC','SP','NZCV','registers31','private_RAM','vectors','system'])
 lm,rm=[{int(r['address'],16):bytes.fromhex(r['bytes_hex']) for r in c['initial_image_pages']} for c in [left,right]]
 for pg in lm.keys()^rm.keys():assert (lm.get(pg) or rm[pg])==image.logical_page(pg)
 assert {pg for pg in lm.keys()&rm.keys() if lm[pg]!=rm[pg]}=={0xfffffe0007ef8000}
 assert lm[0xfffffe0007ef8000]==bytes(4096) and rm[0xfffffe0007ef8000]==image.logical_page(0xfffffe0007ef8000)
 preservation['paired_initial_image_difference_is_only_original_topology_page']=True;preservation['paired_pre_enumeration_source_and_registers_and_private_RAM_identical']=True
 preservation['additional_demand_mapped_pages_match_original_logical_image']=True
 controls=[]
 for index,pc in [(1,0xfffffe000be834b8),(1,0xfffffe000be83244),(1,T.POST+76),(1,0xfffffe000c639dc0),(1,K.SETTER+28)]:
  row=CPU.Probe(image,CPU.cases()[index],pc).run()
  try:oracle(row,e)
  except AssertionError as error:controls.append({'component':row,'oracle_rejection':list(error.args[0])})
  else:raise AssertionError(('changed_source_accepted',hex(pc)))
 visited={v['pc'] for c in components for v in c['source_visits']};source={i['ea'] for f in e['functions'] for i in f['instructions']};assert visited<=source and not visited&{i['ea'] for f in e['functions'] for i in f['instructions'] if i['mnemonic'] in ['opaque','udf']}
 stats={'source_composition_queries_unsat':len(proofs),'retained_source_queries_rebuilt':len(retained),'proved_composition_source_PCs':len({pc for q in coverage for pc in q['PCs']}),'composition_instruction_instances':sum(q['instruction_instances'] for q in coverage),'composition_linked_edge_obligations':sum(q['linked_edge_obligations'] for q in coverage),'components':len(components),'source_visits':sum(len(c['source_visits']) for c in components),'executed_source_PCs':len(visited),'changed_source_controls':len(controls),'independent_semantic_checks':sum(semantic_count(c['independent_oracle']) for c in components),'completed_admitted_CPU_records':sum(len(c['independent_oracle']['admitted_records']) for c in components),'source_enumeration_returns':sum(c['original_enumeration_return'] is not None for c in components),'source_post_helper_returns':sum(c['original_post_helper_return'] is not None for c in components),'source_thread_setups':sum(c['independent_oracle']['source_thread_setup_complete'] for c in components),'preserved_prior_zero_page_failures':1,'call_frame_epochs':0,'generic_initializer_calls':0,'selector0e_declared_returns':sum(len(c['declared_selector0e_calls']) for c in components),'original_API_entries':sum(len(c['original_API_entries']) for c in components),'original_API_returns':sum(len(c['original_API_returns']) for c in components),'whole_mutable_checkpoint_bytes_checked':sum(c['independent_oracle']['whole_mutable_checkpoint_bytes_checked'] for c in components),'private_nonstack_bytes_checked':sum(c['independent_oracle']['private_nonstack_bytes_checked'] for c in components),'copy_contract_destination_bytes_checked':sum(c['independent_oracle']['copy_contracts']['destination_bytes_checked'] for c in components)}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_bootstrap_state_composition.py'),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'scope':R.SCOPE,'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'source_proofs':proofs,'retained_source_proofs_rebuilt':retained,'proof_coverage':coverage,'retained_proof_coverage':retained_coverage,'components':components,'negative_controls':controls,'prior_published_checkpoint_preservation':preservation,'independent_totals':stats,'independent_replay_totals':dict(totals),'executed_function_coverage':[{'start':f['start'],'captured_words':len(f['instructions']),'executed_unique_PCs':len({i['ea'] for i in f['instructions']}&visited)} for f in e['functions']],'conditional_kernel_bootstrap_state_composition_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True);print(json.dumps(a['independent_replay_totals']),flush=True)
