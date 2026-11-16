#!/usr/bin/env python3
"""Nonvacuous original-source proofs, byte oracles and independent CPU replay.
O(source+formula DAG+visits+journals+RAM) construction/space; SMT search separate,
30 s/query. Static/private evidence, no native boot or IPC.
"""
import json,struct
from collections import Counter
import z3
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_kernel_boot_option_execution import Model as Parent
from audit_kernel_mapping_context import DEC
from lskd_values_symbolic import resize
import recover_kernel_boot_environment_publication as R
import probe_kernel_boot_environment_publication as CPU
from replay_kernel_boot_environment_publication import oracle,Replay

class Model(Parent):
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.mnemonic=='ldur' and i.reg_name(i.operands[0].reg).startswith('q'):
    if self.next is not None:self.edge_checks.append(self.next==i.address)
    self.next=resize(i.address+4,64);self.pc=i.address;self.visited.add(i.address);self.count+=1
    self.vectors['v'+i.reg_name(i.operands[0].reg)[1:]]=self.load(self.address(i,i.operands[1]),16);continue
   old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one');self.e,self.c=old_e,old_c
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
  s.add(*v.bindings_for([*common,counter]),counter);result=s.check();assert result==z3.unsat,(label,str(result),s.reason_unknown())
  proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV'});coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,'linked_edge_obligations':len(v.edge_checks)});print(label,flush=True)
 v=local();v.regions=[(R.STATE,4)];guard=v.load(R.STATE,4);cut(v,0xfffffe000c5e6644,0xfffffe000c5e6650)
 prove('u32_guard_zero_selects_first_publication',v,v.next!=z3.If(guard==0,resize(0xfffffe000c5e6674,64),resize(0xfffffe000c5e6650,64)))
 mode=z3.BitVec('EP_mode64',64);v=local();v.seed('x0',mode);cut(v,0xfffffe000c5e6640,0xfffffe000c5e6644);prove('saved_mode_retains_full64_register_value',v,v.read('x20')!=mode)
 v=local();v.seed('w20',z3.Extract(31,0,mode));cut(v,0xfffffe000c5e6650,0xfffffe000c5e6654)
 prove('initialized_mode_zero_reuses_previous_environment',v,v.next!=z3.If(z3.Extract(31,0,mode)==0,resize(0xfffffe000c5e66fc,64),resize(0xfffffe000c5e6654,64)))
 pointer=z3.BitVec('EP_context64',64);v=local();v.seed('x19',pointer);cut(v,0xfffffe000c5e6654,0xfffffe000c5e6658);prove('mode_nonzero_forwards_second_argument_as_context',v,v.read('x0')!=pointer)
 inp=CPU.INPUT;v=local();v.regions=[(inp,1152),(R.STATE,176),(0xfffffe0007f8b5e8,4)];base=v.load(inp+0x60,8);extent=v.load(inp+0x68,4);field=v.load(inp+0x28,8);v.seed('x19',inp);cut(v,0xfffffe000c5e6674,0xfffffe000c5e66ac)
 prove('first_publication_stores_guard_pointer_tree_u32_extent_and_field28',v,z3.Or(v.load(R.STATE,4)!=1,v.load(0xfffffe0007f8b5e8,4)!=2,v.load(R.STATE+0xa0,8)!=inp,v.load(R.STATE+0x98,8)!=base,v.load(R.STATE+0xa8,8)!=z3.ZeroExt(32,extent),v.load(R.STATE+8,8)!=field))
 v=local();v.regions=[(inp,1152),(R.STATE,176)];block=v.load(inp+0x38,16);v.seed('x19',inp);v.seed('x8',R.STATE);cut(v,0xfffffe000c5e66ac,0xfffffe000c5e66b4)
 prove('unaligned_original_Q_copy_transfers_exact16_bytes',v,v.load(R.STATE+0x10,16)!=block)
 v=local();v.regions=[(inp,1152),(R.STATE,176)];first=v.load(inp+0x48,8);packed=v.load(inp+0x50,8);byte=v.load(inp+0x52,1);v.seed('x19',inp);v.seed('x8',R.STATE);cut(v,0xfffffe000c5e66b4,0xfffffe000c5e66dc)
 lo=z3.Extract(31,0,packed);flags=z3.Extract(7,0,(z3.LShR(lo,8)+z3.LShR(lo,24))&3)
 prove('packed_video_fields_preserve_u64_and_apply_u8_wrap',v,z3.Or(v.load(R.STATE+0x20,8)!=first,v.load(R.STATE+0x28,8)!=(packed&255),v.load(R.STATE+0x88,1)!=flags,v.load(R.STATE+0x89,1)!=byte+1))
 v=local();v.regions=[(inp,1152),(R.STATE,176)];field=v.load(inp+0x30,8);v.seed('x19',inp);v.seed('x8',R.STATE);cut(v,0xfffffe000c5e66dc,0xfffffe000c5e66e4);prove('state_offset30_copies_argument_offset30_u64',v,v.load(R.STATE+0x30,8)!=field)
 v=local();v.seed('x8',R.STATE);cut(v,0xfffffe000c5e66e4,0xfffffe000c5e66f8)
 prove('initial_format_string_copy_ABI_has_capacity64',v,z3.Or(v.next!=R.STRLCPY,v.read('x0')!=R.STATE+0x38,v.read('x1')!=R.PATTERN,v.read('x2')!=64))
 v=local();v.seed('w20',z3.Extract(31,0,mode));cut(v,0xfffffe000c5e66f8,0xfffffe000c5e66fc)
 prove('post_string_copy_nonzero_mode_selects_context_tail',v,v.next!=z3.If(z3.Extract(31,0,mode)!=0,resize(0xfffffe000c5e6654,64),resize(0xfffffe000c5e66fc,64)))
 v=local();v.regions=[(R.STATE,176)];base=v.load(R.STATE+0x98,8);extent=v.load(R.STATE+0xa8,8);cut(v,0xfffffe000c5e6708,0xfffffe000c5e6720)
 prove('saved_tree_pair_unsigned_carry_precedes_tree_publication',v,v.next!=z3.If(z3.ULT(base+extent,base),resize(0xfffffe000c5e6afc,64),resize(0xfffffe000c5e6720,64)))
 base,extent=z3.BitVecs('EP_tree_base64 EP_tree_extent64',64);v=local();v.regions=[(R.TREE,32)];v.seed('x8',base);v.seed('x9',extent);cut(v,0xfffffe000c5e6720,0xfffffe000c5e674c)
 prove('inline_tree_publisher_matches_base_extent_end_nonnull_contract',v,z3.Or(v.load(R.TREE,8)!=base,v.load(R.TREE+8,8)!=extent,v.load(R.TREE+16,8)!=base+extent,v.load(R.TREE+24,4)!=z3.If(base!=0,resize(1,32),resize(0,32))))
 v=local();v.seed('x19',R.ARGS);cut(v,0xfffffe000c639b90,0xfffffe000c639b9c)
 prove('actual_main_initial_call_supplies_mode0_copied_bootargs',v,z3.Or(v.next!=R.PLATFORM,v.read('x0')!=0,v.read('x1')!=R.ARGS))
 v=local();cut(v,0xfffffe000c63a19c,0xfffffe000c63a1b0)
 prove('actual_main_later_call_supplies_mode1_CPU_context',v,z3.Or(v.next!=R.PLATFORM,v.read('x0')!=1,v.read('x1')!=CPU.CPU))
 v=local();cut(v,0xfffffe000be75e44,0xfffffe000be75e50)
 prove('secondary_caller_supplies_mode1_null_context',v,z3.Or(v.next!=R.PLATFORM,v.read('x0')!=1,v.read('x1')!=0))
 v=local();v.regions=[(R.STATE+0xa0,8)];args=v.load(R.STATE+0xa0,8);v.seed('x21',0xfffffe0007f8b000);cut(v,0xfffffe000c639c18,0xfffffe000c639c40)
 prove('later_main_option_ABI_user_ts_jop_has_stack_default1',v,z3.Or(v.next!=0xfffffe000c5e48a4,v.read('x0')!=args+0x6c,v.read('x1')!=0xfffffe0007062148,v.read('x2')!=v.sp0+0x30,v.read('x3')!=4,v.read('x4')!=0,v.load(v.sp0+0x30,4)!=1))
 for label,a,b,key,out,width in [('icdsb',0xfffffe000c639be8,0xfffffe000c639c10,0xfffffe00070644e0,0xfffffe0007ef9164,4),('diversify_user_jop',0xfffffe000c639c58,0xfffffe000c639c7c,0xfffffe0007062154,0xfffffe0007e6d154,4),('sptm_stability_hacks',0xfffffe000c639c90,0xfffffe000c639cb8,0xfffffe0007062167,0xfffffe0007e6d159,1)]:
  v=local();v.regions=[(R.STATE+0xa0,8)];args=v.load(R.STATE+0xa0,8);v.seed('x21',0xfffffe0007f8b000);cut(v,a,b)
  prove('later_main_option_ABI_'+label,v,z3.Or(v.next!=0xfffffe000c5e48a4,v.read('x0')!=args+0x6c,v.read('x1')!=key,v.read('x2')!=out,v.read('x3')!=width,v.read('x4')!=0))
 return proofs,coverage

def independent_census(e,image):
 targets=set(e['direct_branch_census']['targets']);rows=[];candidates=0
 for s in image.k.kernel['segments']:
  if s['name'] not in R.SCAN_NAMES:continue
  raw=image.k.read(s['address'],s['file_size'])
  for j in range(0,len(raw),4):
   word=int.from_bytes(raw[j:j+4],'little')
   if word>>26 not in [5,37]:continue
   candidates+=1;pc=s['address']+j;ins=next(image.k.cs.disasm(raw[j:j+4],pc));assert ins.mnemonic in ['b','bl'];target=ins.op_str.removeprefix('#')
   if target in targets:rows.append((hex(pc),ins.mnemonic,target))
 assert rows==[(r['PC'],r['kind'],r['target']) for r in e['direct_branch_census']['edges']]
 return {'aligned_words_checked':sum(s['words'] for s in e['direct_branch_census']['segments']),'branch_candidates_independently_disassembled':candidates,'matching_edges':len(rows)}

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,coverage=source_proofs(e);image=Image();census=independent_census(e,image);components=[];parents={};totals=Counter()
 for c in CPU.cases():
  parent=parents.get(c.get('parent'));row=CPU.Probe(image,c,parent).run();row['independent_oracle']=oracle(row,e,parent);q=Replay(image,row).run();totals.update(q);row['independent_replay']=q;components.append(row);parents[c['label']]=row;print(c['label'],len(row['source_visits']),flush=True)
 controls=[]
 for index,pc in [(0,0xfffffe000c5e6690),(2,0xfffffe000c5e66d8),(0,0xfffffe000c5e6748),(0,0xfffffe000c639ab8)]:
  row=CPU.Probe(image,CPU.cases()[index],mutate=pc).run()
  try:oracle(row,e)
  except AssertionError as error:controls.append({'component':row,'oracle_rejection':list(error.args[0])})
  else:raise AssertionError(('changed_source_accepted',hex(pc)))
 visited={v['pc'] for c in components for v in c['source_visits']};source={i['ea'] for f in e['functions'] for i in f['instructions']};opaque={i['ea'] for f in e['functions'] for i in f['instructions'] if i['mnemonic']=='opaque'};assert visited<=source and not visited&opaque
 stats={'source_queries_unsat':len(proofs),'proved_source_PCs':len({pc for q in coverage for pc in q['PCs']}),'proof_instruction_instances':sum(q['instruction_instances'] for q in coverage),'linked_edge_obligations':sum(q['linked_edge_obligations'] for q in coverage),'components':len(components),'source_visits':sum(len(c['source_visits']) for c in components),'executed_source_PCs':len(visited),'changed_source_controls':len(controls),'independent_semantic_checks':sum(len(c['independent_oracle']['checks']) for c in components),'same_mutable_image_transfers':sum(c['same_mutable_image_predecessor'] is not None for c in components),'original_main_bootargs_header_copy_pairs':sum(c['configuration'].get('main',False) for c in components),'original_call_entries':sum(len(c['original_call_entries']) for c in components),'whole_mutable_bytes_checked':sum(c['independent_oracle']['whole_mutable_bytes_checked'] for c in components),'private_nonstack_bytes_checked':sum(c['independent_oracle']['private_nonstack_bytes_checked'] for c in components)}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_boot_environment_publication.py'),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'scope':R.SCOPE,'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'source_proofs':proofs,'proof_coverage':coverage,'independent_branch_census':census,'components':components,'negative_controls':controls,'independent_totals':stats,'independent_replay_totals':dict(totals),'executed_function_coverage':[{'start':f['start'],'captured_words':len(f['instructions']),'executed_unique_PCs':len({i['ea'] for i in f['instructions']}&visited)} for f in e['functions']],'conditional_kernel_boot_environment_publication_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True);print(json.dumps(a['independent_replay_totals']),flush=True)
