#!/usr/bin/env python3
"""Source contracts, closed boot CFG and nested producer/consumer witnesses.
O(source + query DAG + visits + journals + RAM) construction/space; solver
search separate,30 s/query. Native boot/SPTM/DT/backing effects unproved.
"""
import json
from collections import Counter
import z3
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_kernel_mapping_context import Model as Parent,DEC
from lskd_values_symbolic import resize
import recover_kernel_sptm_boot_inputs as R
import probe_kernel_sptm_boot_inputs as CPU
from replay_kernel_sptm_boot_inputs import Replay

class Model(Parent):
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.mnemonic!='cmn':
    old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one');self.e,self.c=old_e,old_c;continue
   if self.next is not None:self.edge_checks.append(self.next==i.address)
   self.next=resize(i.address+4,64);self.pc=i.address;self.visited.add(i.address);self.count+=1;o=i.operands;n=self.width(i.reg_name(o[0].reg))
   a=self.operand(i,o[0],n);b=self.operand(i,o[1],n);self.equal=(a+b)==0;self.carry=z3.ULT(a+b,a);self.arithmetic_flags=(self.equal,self.carry)
  return self

def source_proofs(e):
 proofs=[];coverage=[]
 def local():v=Model(e);v.regions=[];return v
 def cut(v,label,a,b):
  f=next(f for f in e['functions'] if int(f['start'],16)<=a<b<=int(f['end'],16));off=a-int(f['start'],16)
  v.e=v.c={'spans':[{'label':label,'start':hex(a),'bytes_hex':bytes.fromhex(f['bytes'])[off:off+b-a].hex()}]};return v.enter(label)
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad))
  s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label)
  s.add(*v.bindings_for([*common,counter]),counter);r=s.check();assert r==z3.unsat,(label,str(r),s.reason_unknown())
  proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV'})
  coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,'linked_edge_obligations':len(v.edge_checks),
   'checked_read_store_rewrites':list(v.separation_rewrites.values())});print(label,flush=True)
 v=local();v.regions=[(CPU.HEADER,0x2a0)];magic=v.load(CPU.HEADER,8);v.seed('x0',CPU.HEADER)
 cut(v,'loader_magic',0xfffffe000c660558,0xfffffe000c660568)
 prove('loader_header_magic_d00f000000000000_gates_record_call_or_WFE',v,v.next!=z3.If(magic==CPU.MAGIC,resize(0xfffffe000c660568,64),resize(0xfffffe000c66057c,64)))
 v=local();header=z3.BitVec('SB_header64',64);v.seed('x0',header)
 cut(v,'loader_record',0xfffffe000c660568,0xfffffe000c660570)
 prove('loader_passes_embedded_record_at_header_plus1a0_to_original_initializer',v,z3.Or(v.next!=R.BOOT,v.read('x0')!=header+0x1a0,v.read('x30')!=0xfffffe000c660570))
 v=local();status=z3.BitVec('SB_boot_status32',32);v.seed('w0',status)
 cut(v,'loader_result',0xfffffe000c660570,0xfffffe000c660574)
 prove('loader_accepts_only_raw_zero_else_enters_original_WFE',v,v.next!=z3.If(status==0,resize(0xfffffe000c660584,64),resize(0xfffffe000c660574,64)))
 v=local();pointer=z3.BitVec('SB_input64',64);v.seed('x0',pointer)
 cut(v,'null_input',R.BOOT,R.BOOT+8)
 prove('null_record_selects_return2_before_any_record_load',v,v.next!=z3.If(pointer==0,resize(0xfffffe000c662afc,64),resize(R.BOOT+8,64)))
 v=local();cut(v,'null_return',0xfffffe000c662afc,R.BOOT_END)
 prove('null_record_returns_raw2_to_original_LR',v,z3.Or(v.read('x0')!=2,v.next!=v.initial[30]))
 v=local();v.regions=[(CPU.RECORD,256),(R.GLOBALS,R.GLOBAL_BYTES)];v.seed('x0',CPU.RECORD)
 fields=[f for f in CPU.published_fields() if f[3]==0];values=[v.load(CPU.RECORD+src,n) for src,dst,n,ver in fields]
 cut(v,'baseline_fields',R.BOOT+8,0xfffffe000c6629c4)
 prove('all15_baseline_pointer_scalar_fields_copy_with_exact_widths',v,z3.Or(*[v.load(R.GLOBALS+dst,n)!=value for (src,dst,n,ver),value in zip(fields,values)]))
 gates=[(3,0xfffffe000c6629c4,0xfffffe000c6629d0,0xfffffe000c6629d0,None),
  (4,0xfffffe000c6629dc,0xfffffe000c6629e4,0xfffffe000c6629e4,3),
  (5,0xfffffe000c6629f0,0xfffffe000c6629f8,0xfffffe000c6629f8,None),
  (6,0xfffffe000c662a10,0xfffffe000c662a1c,0xfffffe000c662a1c,None),
  (7,0xfffffe000c662a28,0xfffffe000c662a30,0xfffffe000c662a30,6),
  (8,0xfffffe000c662a48,0xfffffe000c662a50,0xfffffe000c662a50,None),
  (9,0xfffffe000c662a80,0xfffffe000c662a8c,0xfffffe000c662a8c,None),
  (10,0xfffffe000c662a98,0xfffffe000c662aa0,0xfffffe000c662aa0,9),
  (11,0xfffffe000c662aac,0xfffffe000c662ab4,0xfffffe000c662ab4,None),
  (12,0xfffffe000c662ad4,0xfffffe000c662adc,0xfffffe000c662adc,11)]
 version=z3.BitVec('SB_version32',32)
 for minimum,a,b,nextpc,prior in gates:
  v=local();v.regions=[(CPU.RECORD,256)];v.setmem(CPU.RECORD,4,version);v.seed('x0',CPU.RECORD);v.seed('w8',version);cut(v,'version_gate',a,b)
  prove('unsigned_version_gate_at_least'+str(minimum),v,v.next!=z3.If(z3.UGE(version,minimum),resize(nextpc,64),resize(0xfffffe000c662ae8,64)),[z3.UGE(version,prior)] if prior is not None else [])
 blocks=[(3,0xfffffe000c6629d0,0xfffffe000c6629dc),(4,0xfffffe000c6629e4,0xfffffe000c6629f0),
  (5,0xfffffe000c6629f8,0xfffffe000c662a10),(6,0xfffffe000c662a1c,0xfffffe000c662a28),
  (7,0xfffffe000c662a30,0xfffffe000c662a48),(8,0xfffffe000c662a50,0xfffffe000c662a80),
  (9,0xfffffe000c662a8c,0xfffffe000c662a98),(10,0xfffffe000c662aa0,0xfffffe000c662aac),
  (11,0xfffffe000c662ab4,0xfffffe000c662ad4),(12,0xfffffe000c662adc,0xfffffe000c662ae8)]
 for minimum,a,b in blocks:
  v=local();v.regions=[(CPU.RECORD,256),(R.GLOBALS,R.GLOBAL_BYTES)];v.seed('x0',CPU.RECORD);fields=[f for f in CPU.published_fields() if f[3]==minimum]
  values=[v.load(CPU.RECORD+src,n) for src,dst,n,ver in fields];cut(v,'version_fields',a,b)
  bad=[v.load(R.GLOBALS+dst,n)!=value for (src,dst,n,ver),value in zip(fields,values)]
  if minimum==7:bad.append(v.load(R.C.T.TRANSPORT_FLAG,1)!=z3.ZeroExt(7,z3.Extract(6,6,values[0])))
  prove('version'+str(minimum)+'_field_copies'+('_and_flag_from_bit6' if minimum==7 else ''),v,z3.Or(*bad))
 v=local();v.regions=[(R.GLOBALS,R.GLOBAL_BYTES)];cut(v,'publish_enable',0xfffffe000c662ae8,0xfffffe000c662afc)
 prove('normal_boot_initializer_publishes_feature1_and_returns_raw0',v,z3.Or(v.load(R.GLOBALS,1)!=1,v.read('x0')!=0,v.next!=v.initial[30]))
 v=local();v.regions=[(R.C.BUMP,8)];bump=v.load(R.C.BUMP,8)
 cut(v,'pool_alignment_carry',0xfffffe000be712d4,0xfffffe000be712e8)
 prove('pool_first_roundup_checks_add16383_carry',v,v.next!=z3.If(z3.ULT(bump+16383,bump),resize(0xfffffe000be71430,64),resize(0xfffffe000be712e8,64)))
 v=local();memory=z3.BitVec('SB_memory_bytes64',64);v.seed('x23',memory);v.seed('w22',629)
 cut(v,'pool_budget',0xfffffe000be712e8,0xfffffe000be71314)
 units=z3.Extract(31,0,z3.LShR(memory,24))&0xfffffffe;first=z3.LShR(z3.ZeroExt(32,units)*0x6830d6e5,40);objects=z3.Extract(31,0,first)*629
 pages=z3.LShR(z3.ZeroExt(32,objects+629)*0x6830d6e5,40)
 prove('pool_budget_preserves_u32_truncations_and_two_magic_multiply_shift40_steps',v,z3.Or(v.read('w24')!=objects,v.read('x22')!=pages,v.read('w25')!=(z3.Extract(31,0,pages)<<14)))
 v=local();objects=z3.BitVec('SB_pool_guard_objects32',32);v.regions=[(0xfffffe0007e6d0a0,4)];v.seed('x21',0xfffffe0007e6d000);v.seed('w24',objects)
 cut(v,'pool_link_guard',0xfffffe000be71378,0xfffffe000be71384)
 prove('pool_link_loop_skips_only_when_u32_object_count_exceeds_fffffd8a',v,v.next!=z3.If(z3.UGT(objects,0xfffffd8a),resize(0xfffffe000be713cc,64),resize(0xfffffe000be71384,64)))
 v=local();v.regions=[(R.C.BUMP,8)];end=v.load(R.C.BUMP,8);converted=z3.BitVec('SB_old_bump_alias64',64);old=z3.BitVec('SB_old_bump64',64);status=z3.BitVec('SB_pool_conversion_status32',32)
 v.setmem(v.sp0+0x18,8,converted);v.seed('x20',0xfffffe0007e6d000);v.seed('x19',old);v.seed('w0',status)
 cut(v,'pool_clear',0xfffffe000be71360,0xfffffe000be71378)
 prove('pool_clear_uses_original_old_bump_alias_and_reserved_end_minus_old_bump',v,z3.Or(v.next!=R.C.Z.BZERO,v.read('x0')!=z3.If(status==0,converted,resize(0,64)),v.read('x1')!=end-old))
 v=local();v.regions=[(R.C.BUMP,8),(0xfffffe0007e6d0a0,40)];old=v.load(R.C.BUMP,8);v.seed('x20',0xfffffe0007e6d000)
 cut(v,'shared_reserve',0xfffffe000be713ec,0xfffffe000be71408)
 prove('shared_base_is_old_bump_and_unflagged_524288_byte_reservation_advances_both_ends',v,z3.Or(v.load(R.C.SHARED,8)!=old,v.load(R.C.BUMP,8)!=old+524288,v.load(0xfffffe0007e6d0c0,8)!=old+524288))
 v=local();page=z3.BitVec('SB_pool_page64',64);head=z3.BitVec('SB_old_pool_head64',64);remaining=z3.BitVec('SB_pool_remaining32',32)
 v.regions=[(page,16384)];v.seed('x23',page);v.seed('x10',head);v.seed('x11',628*24);v.seed('w12',remaining)
 cut(v,'pool_link',0xfffffe000be7139c,0xfffffe000be713c8)
 prove('one_pool_iteration_links_last24_byte_record_and_advances_one_16384_byte_page',v,z3.Or(v.load(page+628*24,8)!=head,v.read('x10')!=page,v.read('x23')!=page+16384,
  v.read('w12')!=remaining-1,v.next!=z3.If(remaining-1!=0,resize(0xfffffe000be7139c,64),resize(0xfffffe000be713c8,64))))
 v=local();objects,pages=z3.BitVecs('SB_objects_per_page32 SB_pool_pages32',32);v.regions=[(0xfffffe000cb890b0,4)];v.seed('w8',objects);v.seed('w22',pages)
 cut(v,'pool_count',0xfffffe000be713cc,0xfffffe000be713d8)
 prove('pool_count_publication_is_modular_u32_objects_times_pages',v,v.load(0xfffffe000cb890b0,4)!=objects*pages)
 v=local();v.regions=[(CPU.THREAD,0x280)];v.thread=resize(CPU.THREAD,64);index=v.load(CPU.THREAD+0x1b8,2);lr=v.load(v.sp0+0x68,8)
 cut(v,'CPU_tail',0xfffffe000be71408,0xfffffe000be71430)
 prove('pool_restores_caller_frame_and_tail_calls_CPU_with_thread_low16',v,z3.Or(v.read('w0')!=z3.ZeroExt(16,index),v.next!=R.C.CPUINIT,v.read('sp')!=v.sp0+0x70,v.read('x30')!=lr))
 return proofs,coverage

def boot_cfg(e):
 f=next(f for f in e['functions'] if f['start']==hex(R.BOOT));raw=bytes.fromhex(f['bytes']);instructions={i.address:i for i in DEC.disasm(raw,R.BOOT)}
 assert len(instructions)*4==len(raw) and instructions[R.BOOT_END-4].mnemonic=='ret';todo=[R.BOOT];seen=set();edges=[];returns=[]
 while todo:
  pc=todo.pop()
  if pc in seen:continue
  seen.add(pc);i=instructions[pc];m=i.mnemonic
  assert m not in ['bl','blr','br','blraa','brk','svc','hvc','smc','udf']
  if m=='ret':returns.append(hex(pc));continue
  successors=[pc+4]
  if m.startswith('b.') or m in ['cbz','cbnz']:successors.append(i.operands[-1].imm&((1<<64)-1))
  for target in successors:assert R.BOOT<=target<R.BOOT_END and target in instructions;edges.append({'from':hex(pc),'to':hex(target)});todo.append(target)
 assert len(seen)==len(instructions) and len(returns)==2
 return {'entry':hex(R.BOOT),'end_exclusive':hex(R.BOOT_END),'reachable_words':len(seen),'direct_successor_edges':edges,'returns':sorted(returns),
  'scope':'Complete syntactic CFG over last compiler start to file-backed boot segment end; no indirect/call successor. Native reachability and object validity remain unproved.'}

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,coverage=source_proofs(e);cfg=boot_cfg(e);prior=[]
 retained={R.C.T.P+'_audit.json':{'wrapper_selector2_and_transport_word_choice','selected_transport_receives_root_VA_descriptor_and_zero','result_record_word0_copies_to_argument5_word1_to_argument2'},
  R.C.P+'_audit.json':{'identifier_saved_full64_stored_low16_and_shared_indexed_by_zero_extended_low32_shift15','context_words0_and1_receive_virtual_and_raw_physical_root_pair','original_Q_literal_sets_lower_ffff800000000000_upper_ffffffffffffffff'}}
 for filename,labels in retained.items():
  old=json.loads(read(ROOT/filename))
  for p in old['source_proofs']:
   if p['label'] not in labels:continue
   s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert s.check()==z3.unsat;prior.append({**p,'source_artifact_sha256':sha(ROOT/filename)})
 assert len(prior)==6
 image=Image();components=[];replays=[];totals=Counter();joins=[]
 def component(c,phase,parent_index=None,scope='Exact previous private RAM and all tracked globals transferred into a new declared call epoch'):
  parent=components[parent_index] if parent_index is not None else None;row=CPU.Probe(image,c,phase,parent).run();row['independent_oracle_checks']=CPU.oracle(row);index=len(components)
  if parent is not None:joins.append({'parent_component':parent_index,'child_component':index,'scope':scope})
  components.append(row);r=Replay(image,row,parent).run();replays.append(r);totals.update(r);return index
 parent_high=None
 for c in CPU.record_cases()+[CPU.configuration(null=True),CPU.configuration(bad_magic=True)]:
  j=component(c,'boot' if c.get('null') else 'loader')
  if c['version']==12 and c['flag']==1:parent_high=j
 assert parent_high is not None
 for c in [CPU.configuration(version=2),CPU.configuration(null=True)]:component(c,'boot',parent_high,'Exact prior enabled-version12 state transferred; new declared record input exercises downgrade/null preservation')
 chain_roots=[]
 for c in CPU.chain_cases():
  previous=None
  for phase in ['loader','root','context','gate','backend']:
   j=component(c,phase,previous);previous=j
   if phase=='root':chain_roots.append(j)
   if components[j]['boundary']['kind']!='source_component_complete':break
  print('configuration',c,'complete',flush=True)
 negative=[]
 controls=[(CPU.configuration(version=12,flag=1),'loader',None,0xfffffe000c662a44),
  (CPU.configuration(version=12,flag=1),'loader',None,0xfffffe000c6629a0),
  (CPU.chain_cases()[0],'context',components[chain_roots[0]],0xfffffe000be713f4),
  (CPU.chain_cases()[0],'context',components[chain_roots[0]],0xfffffe000be7142c)]
 for c,phase,parent,pc in controls:
  row=CPU.Probe(image,c,phase,parent,pc).run()
  try:CPU.oracle(row)
  except AssertionError as error:negative.append({'component':row,'oracle_rejection':error.args[0][0]})
  else:raise AssertionError('changed source accepted')
 source={i['ea'] for f in e['functions'] for i in f['instructions']};visited={i['pc'] for c in components for i in c['source_visits']}
 stats={'source_queries_unsat':len(proofs),'prior_source_queries_rechecked':len(prior),'components':len(components),
  'component_source_visits':sum(len(c['source_visits']) for c in components),'executed_source_PCs':len(source&visited),
  'proved_source_PCs':len({pc for c in coverage for pc in c['PCs']}),'proof_instruction_instances':sum(c['instruction_instances'] for c in coverage),
  'linked_edge_obligations':sum(c['linked_edge_obligations'] for c in coverage),'independent_oracle_checks':sum(len(c['independent_oracle_checks']) for c in components),
  'changed_source_controls':len(negative),'exact_state_joins':len(joins),'complete_five_component_chains':sum(c['phase']=='backend' for c in components),
  'original_nested_context_executions':sum(c['phase']=='context' for c in components),'version_profiles':len(CPU.record_cases()),
  'boot_CFG_reachable_words':cfg['reachable_words'],'boot_CFG_direct_edges':len(cfg['direct_successor_edges']),'boot_CFG_returns':len(cfg['returns'])}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_sptm_boot_inputs.py'),
  'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'scope':R.SCOPE,'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],
  'source_proofs':proofs,'rechecked_prior_source_proofs':prior,'coverage':coverage,'closed_boot_CFG':cfg,'components':components,'independent_replays':replays,
  'exact_state_joins':joins,'independent_replay_totals':dict(totals),'negative_controls':negative,'unexecuted_source_PCs':sorted(source-visited),
  'independent_totals':stats,'conditional_kernel_sptm_boot_inputs_contract_established':True,**{k:False for k in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True);print(json.dumps(a['independent_replay_totals']),flush=True)
