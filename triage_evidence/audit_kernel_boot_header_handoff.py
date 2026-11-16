#!/usr/bin/env python3
"""Source boot/copy contracts and original bulk-root producer witnesses.
O(source + query DAG + visits + journals + RAM) construction/space;
solver search separate,30 s/query. Native loader and ownership unproved.
"""
import json
from collections import Counter
import z3
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_kernel_sptm_boot_inputs import Model as Parent
from audit_kernel_mapping_context import DEC
from lskd_values_symbolic import resize
import recover_kernel_boot_header_handoff as R
import probe_kernel_boot_header_handoff as CPU
from replay_kernel_boot_header_handoff import Replay

class Model(Parent):
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   post=i.mnemonic=='ldr' and i.writeback
   if post:
    assert len(i.operands)==3 and i.operands[1].mem.disp==0 and i.reg_name(i.operands[0].reg)!=i.reg_name(i.operands[1].mem.base)
    base=i.reg_name(i.operands[1].mem.base);before=self.read(base)
   old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one');self.e,self.c=old_e,old_c
   if post:self.write(base,before+i.operands[2].imm)
  return self

def source_proofs(e):
 proofs=[];coverage=[]
 def local():v=Model(e);v.regions=[];return v
 def cut(v,a,b):
  f=next(f for f in e['functions'] if int(f['start'],16)<=a<b<=int(f['end'],16));off=a-int(f['start'],16)
  v.e=v.c={'spans':[{'label':'cut','start':hex(a),'bytes_hex':bytes.fromhex(f['bytes'])[off:off+b-a].hex()}]};return v.enter('cut')
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad));s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000)
  s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label)
  s.add(*v.bindings_for([*common,counter]),counter);r=s.check();assert r==z3.unsat,(label,str(r),s.reason_unknown())
  proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV'})
  coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,'linked_edge_obligations':len(v.edge_checks),'checked_read_store_rewrites':list(v.separation_rewrites.values())});print(label,flush=True)
 mode=z3.BitVec('BH_entry_mode64',64)
 v=local();v.seed('x0',mode);cut(v,R.ENTRY+4,R.ENTRY+12)
 prove('entry_mode4_is_full64_equality_before_ordinary_path',v,v.next!=z3.If(mode==4,resize(R.ENTRY+0x20,64),resize(R.ENTRY+12,64)))
 v=local();v.seed('x0',mode);cut(v,R.ENTRY+12,R.ENTRY+20)
 prove('entry_mode5_is_full64_equality_else_common_thread_clear_path',v,v.next!=z3.If(mode==5,resize(R.ENTRY+20,64),resize(R.COMMON,64)))
 first,second=z3.BitVecs('BH_external_X1_64 BH_external_X2_64',64)
 v=local();v.seed('x1',first);v.seed('x2',second);cut(v,R.ENTRY+20,R.ENTRY+32)
 prove('mode5_forwards_original_X1_X2_to_external_exception_handoff',v,z3.Or(v.read('x0')!=first,v.read('x1')!=second,v.next!=0xfffffe000bc9bbdc))
 v=local();v.regions=[(0xfffffe000ca93df8,1)];v.seed('x1',first);v.seed('x2',second);cut(v,R.ENTRY+32,R.ENTRY+48)
 prove('mode4_writes_low8_X2_and_passes_X1_to_diagnostic_entry',v,z3.Or(v.load(0xfffffe000ca93df8,1)!=z3.Extract(7,0,second),v.read('x0')!=first,v.next!=0xfffffe000c660000))
 v=local();v.seed('x0',mode);cut(v,R.COMMON+12,R.COMMON+24)
 prove('ordinary_mode0_selects_cold_entry_else_secondary_entry',v,v.next!=z3.If(mode==0,resize(R.COLD,64),resize(R.COMMON+24,64)))
 v=local();cut(v,R.COMMON+24,R.COLD)
 prove('ordinary_nonzero_mode_branches_to_secondary_body',v,v.next!=R.SECONDARY)
 v=local();v.seed('x1',first);v.seed('x2',second);cut(v,R.COLD+32,R.COLD+44)
 prove('cold_entry_saves_external_inputs_X26_X27_before_self_relocator',v,z3.Or(v.read('x26')!=first,v.read('x27')!=second,v.next!=R.PREINIT,v.read('x30')!=R.COLD+44))
 v=local();v.seed('x26',first);cut(v,R.COLD+44,R.COLD+52)
 prove('cold_entry_passes_saved_X1_to_original_device_initializer',v,z3.Or(v.read('x0')!=first,v.next!=R.DEVICE_INIT))
 v=local();v.seed('x27',second);cut(v,R.COLD+68,R.COLD+76)
 prove('cold_entry_passes_saved_X2_to_original_magic_and_record_caller',v,z3.Or(v.read('x0')!=second,v.next!=R.B.BOOT_CALLER))
 v=local();v.regions=[(R.B.C.T.TRANSPORT_FLAG,1)];flag=v.load(R.B.C.T.TRANSPORT_FLAG,1);cut(v,R.COLD+76,R.COLD+92)
 prove('source_published_flag_selects_selector15_original_opaque_word_boundary',v,z3.Or(v.read('x16')!=15,v.next!=z3.If(flag!=0,resize(R.COLD+100,64),resize(R.COLD+92,64))))
 v=local();v.seed('x26',first);v.seed('x27',second);cut(v,R.COLD+104,R.COLD+116)
 prove('declared_selector15_return_handoff_restores_entry_X1_X2_as_main_X0_X1',v,z3.Or(v.read('x0')!=first,v.read('x1')!=second,v.next!=R.MAIN))
 v=local();v.seed('x0',first);v.seed('x1',second);cut(v,R.MAIN+32,R.MAIN+40)
 prove('main_preserves_bootargs_and_header_across_pre_copy_calls',v,z3.Or(v.read('x21')!=first,v.read('x20')!=second))
 v=local();v.seed('x21',first);cut(v,R.MAIN+92,R.MAIN+116)
 prove('first_original_memcpy_request_is_1152_bytes_to_bootargs_destination',v,z3.Or(v.read('x0')!=R.ARGS_DEST,v.read('x1')!=first,v.read('x2')!=1152,v.next!=R.COPY,v.read('x30')!=R.MAIN+116))
 v=local();v.regions=[(0xfffffe0007ef9168,8)];v.seed('x19',R.ARGS_DEST);v.seed('x20',second);cut(v,R.MAIN+116,R.MAIN+148)
 prove('second_original_memcpy_request_is_856_bytes_to_header_destination',v,z3.Or(v.load(0xfffffe0007ef9168,8)!=R.ARGS_DEST,v.read('x0')!=R.HEADER_DEST,v.read('x1')!=second,v.read('x2')!=856,v.next!=R.COPY,v.read('x30')!=R.MAIN+148))
 v=local();v.regions=[(R.HEADER_DEST,856),(R.DEVICE_PTR,8),(0xfffffe0007e6d9b8,8),(0xfffffe0007e6d148,8)];x=v.load(R.HEADER_DEST+0x198,8);y=v.load(R.HEADER_DEST+0x18,8);v.seed('x21',R.HEADER_DEST);cut(v,R.MAIN+148,R.MAIN+180)
 prove('copied_header_pointer_and_exact_auxiliary_fields_are_original_stores',v,z3.Or(v.load(R.DEVICE_PTR,8)!=R.HEADER_DEST,v.load(0xfffffe0007e6d9b8,8)!=x,v.load(0xfffffe0007e6d148,8)!=y))
 v=local();v.regions=[(CPU.BOOTARGS,0x480)];v.seed('x0',CPU.BOOTARGS);base=v.load(CPU.BOOTARGS+0x60,8);size=v.load(CPU.BOOTARGS+0x68,4);cut(v,R.DEVICE_INIT+24,R.DEVICE_INIT+40)
 prove('device_tree_base_plus_zeroextended_u32_size_carry_gates_all_publication',v,v.next!=z3.If(z3.ULT(base+z3.ZeroExt(32,size),base),resize(R.DEVICE_INIT+260,64),resize(R.DEVICE_INIT+40,64)))
 v=local();v.regions=[(0xfffffe0007f8b508,32)];base=z3.BitVec('BH_DT_base64',64);size=z3.BitVec('BH_DT_size32',32);v.seed('x0',CPU.BOOTARGS);v.seed('x8',base);v.seed('x9',z3.ZeroExt(32,size));cut(v,R.DEVICE_INIT+40,R.DEVICE_INIT+88)
 prove('device_tree_globals_publish_base_size_modular_end_and_nonnull_flag',v,z3.Or(v.load(0xfffffe0007f8b508,8)!=base,v.load(0xfffffe0007f8b510,8)!=z3.ZeroExt(32,size),v.load(0xfffffe0007f8b518,8)!=base+z3.ZeroExt(32,size),v.load(0xfffffe0007f8b520,4)!=z3.If(base!=0,resize(1,32),resize(0,32))))
 v=local();node=CPU.P+0x8000;owner=CPU.P+0x9000;v.regions=[(node,16),(owner,24)];tag=z3.BitVec('BH_link_tag2',2);head=v.load(owner+8,8);count=v.load(owner+4,4)
 v.setmem(node+8,8,resize(owner,64)|z3.ZeroExt(62,tag));v.seed('x9',node+16);v.seed('x10',node);cut(v,R.DEVICE_INIT+116,R.DEVICE_INIT+156)
 prove('one_original_reverse_link_iteration_preserves_tag_links_old_head_and_increments_count32',v,z3.Or(v.load(node+8,8)!=(head|z3.ZeroExt(62,tag)),v.load(owner+8,8)!=node,v.load(owner+4,4)!=count+1))
 v=local();v.regions=[(R.CALLBACKS,32)];target=v.load(R.CALLBACKS,8);v.seed('x21',R.CALLBACKS);v.seed('x19',first);cut(v,R.DEVICE_INIT+204,R.DEVICE_INIT+216)
 prove('early_callback_loop_loads_original_slot_and_passes_bootargs_plus6c_modifier2abe_at_authenticated_call',v,z3.Or(v.read('x8')!=target,v.read('x21')!=R.CALLBACKS+8,v.read('x0')!=first+0x6c,v.read('x17')!=0x2abe,v.next!=R.DEVICE_INIT+216))
 return proofs,coverage

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,coverage=source_proofs(e);prior=[]
 retained={R.B.P+'_audit.json':{'all15_baseline_pointer_scalar_fields_copy_with_exact_widths'},R.B.C.P+'_audit.json':{'ARM_root_pair_physical_word_and_original_P2V_call_share_exact_boot_root','context_words0_and1_receive_virtual_and_raw_physical_root_pair'}}
 for filename,labels in retained.items():
  for p in json.loads(read(ROOT/filename))['source_proofs']:
   if p['label'] not in labels:continue
   s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert s.check()==z3.unsat;prior.append({**p,'source_artifact_sha256':sha(ROOT/filename)})
 assert len(prior)==3
 image=Image();components=[];replays=[];joins=[];totals=Counter();chains=[]
 def component(c,phase,parent_index=None):
  parent=components[parent_index] if parent_index is not None else None;row=CPU.Probe(image,c,phase,parent).run();row['independent_oracle_checks']=CPU.oracle(row);index=len(components)
  if parent is not None:joins.append({'parent_component':parent_index,'child_component':index,'scope':'All predecessor private RAM and tracked image bytes retained; registers/system-register/thread/stack and opaque-return/new-call epoch assumptions remain explicit'})
  components.append(row);replay=Replay(image,row,parent).run();replays.append(replay);totals.update(replay);return index
 for mode in [0,1,4,5,0xffffffff,0x100000000]:component(CPU.B.configuration(mode='chain',entry_mode=mode),'dispatch')
 extras=[dict(bad_magic=True),dict(DT_base=0xffffffffffffffff,DT_size=1),dict(DT_base=0,DT_size=0),dict(DT_base=0,DT_size=0xffffffff),dict(DT_base=0xffffffff00000000,DT_size=0xffffffff)]
 for kw in extras:component(CPU.B.configuration(mode='chain',**kw),'cold')
 for c in CPU.B.chain_cases():
  parent=None;chain=[]
  for phase in ['cold','handoff','root','context','gate','backend']:
   parent=component(c,phase,parent);chain.append(parent)
   if components[parent]['boundary']['kind'] not in ['source_component_complete','before_original_selector15_opaque_word']:break
  chains.append(chain);print('chain',c,'components',len(chain),flush=True)
 negatives=[];base=CPU.B.chain_cases()[0]
 for phase,pc,parent in [('cold',R.COLD+76,None),('cold',R.DEVICE_INIT+136,None),('handoff',R.MAIN+144,components[chains[0][0]]),('handoff',R.MAIN+152,components[chains[0][0]])]:
  row=CPU.Probe(image,base,phase,parent,pc).run()
  try:CPU.oracle(row)
  except AssertionError as error:negatives.append({'component':row,'oracle_rejection':error.args[0][0]})
  else:raise AssertionError(('changed source accepted',hex(pc)))
 source={i['ea'] for f in e['functions'] for i in f['instructions']};visited={v['pc'] for c in components for v in c['source_visits']};opaque={p['pc'] for p in e['opaque_words']};assert not opaque&visited
 stats={'source_queries_unsat':len(proofs),'prior_source_queries_rechecked':len(prior),'components':len(components),'component_source_visits':sum(len(c['source_visits']) for c in components),
  'executed_source_PCs':len(source&visited),'proved_source_PCs':len({pc for c in coverage for pc in c['PCs']}),'proof_instruction_instances':sum(c['instruction_instances'] for c in coverage),
  'linked_edge_obligations':sum(c['linked_edge_obligations'] for c in coverage),'independent_oracle_checks':sum(len(c['independent_oracle_checks']) for c in components),
  'changed_source_controls':len(negatives),'exact_state_joins':len(joins),'complete_six_component_chains':sum(len(c)==6 for c in chains),'root_bulk_copy_components':sum(c['phase']=='handoff' for c in components),
  'original_reverse_link_iterations':sum(c['phase']=='cold' and len(c['early_callback_entries'])==4 for c in components)*271,'original_header_copy_bytes_per_handoff':856,'original_bootargs_copy_bytes_per_handoff':1152}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_boot_header_handoff.py'),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
  'scope':R.SCOPE,'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'source_proofs':proofs,'rechecked_prior_source_proofs':prior,'coverage':coverage,
  'components':components,'independent_replays':replays,'exact_state_joins':joins,'component_chains':chains,'negative_controls':negatives,'independent_totals':stats,'independent_replay_totals':dict(totals),
  'unexecuted_source_PCs':sorted(source-visited),'conditional_kernel_boot_header_handoff_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True);print(json.dumps(a['independent_replay_totals']),flush=True)
