#!/usr/bin/env python3
"""Original local contracts, independent component oracles and fresh replay.
O(source + query DAG + visits + journals + RAM) construction/space; SMT search
separate with30 s/query. No native SPTM, translation or exclusion effects.
"""
import json
from collections import Counter
import z3
from capstone.arm64 import ARM64_SFT_ASR,ARM64_OP_REG
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_kernel_refill_publication import Model as Parent,DEC
from lskd_values_symbolic import resize
import recover_kernel_mapping_transport as R
import probe_kernel_mapping_transport as CPU
from replay_kernel_mapping_transport import Replay

class Model(Parent):
 def __init__(self,e):super().__init__({**e,'spans':[]})
 def operand(self,i,o,n):
  if o.shift.type==ARM64_SFT_ASR:
   assert o.type==ARM64_OP_REG and o.ext==0;return resize(self.read(i.reg_name(o.reg)),n)>>o.shift.value
  return super().operand(i,o,n)
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.mnemonic not in ['mrs','stlr','dmb']:
    old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one');self.e,self.c=old_e,old_c;continue
   if self.next is not None:self.edge_checks.append(self.next==i.address)
   self.next=resize(i.address+4,64);self.pc=i.address;self.visited.add(i.address);self.count+=1;o=i.operands
   if i.mnemonic=='mrs':assert i.op_str.endswith(', tpidr_el1');self.write(i.reg_name(o[0].reg),self.thread)
   elif i.mnemonic=='stlr':self.store(self.address(i,o[1]),self.width(i.reg_name(o[0].reg))//8,self.read(i.reg_name(o[0].reg)),i.address)
  return self

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs=[];coverage=[]
 def local():v=Model(e);v.regions=[];return v
 def cut(v,label,a,b,linked=False):
  f=next(f for f in e['functions'] if int(f['start'],16)<=a<b<=int(f['end'],16));off=a-int(f['start'],16)
  v.e=v.c={'spans':[{'label':label,'start':hex(a),'bytes_hex':bytes.fromhex(f['bytes'])[off:off+b-a].hex()}]}
  return v.run(label) if linked else v.enter(label)
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad))
  s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label)
  s.add(*v.bindings_for([*common,counter]),counter);result=s.check();assert result==z3.unsat,(label,str(result),s.reason_unknown())
  proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV'})
  coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,'linked_edge_obligations':len(v.edge_checks),'checked_read_store_rewrites':list(v.separation_rewrites.values())});print(label,flush=True)
 v=local();base=z3.BitVec('MT_rows64',64);index=z3.BitVec('MT_selector32',32);v.seed('x8',base);v.seed('w3',index)
 cut(v,'row_address',0xfffffe000be5b36c,0xfffffe000be5b38c);offset=z3.ZeroExt(32,index)*56+8;signed=z3.SignExt(32,z3.Extract(31,0,offset));poison=((base+offset)&0x0000ffffffffffff)|0x2bad000000000000
 prove('geometry_row_address_uses56_byte_stride_and_signed32_poison_gate',v,v.read('x10')!=z3.If(offset==signed,base+signed,poison))
 v=local();mask,va=z3.BitVecs('MT_align_mask64 MT_VA64',64);v.seed('x9',mask);v.seed('x26',va);cut(v,'VA_alignment',0xfffffe000be5b390,0xfffffe000be5b398)
 prove('VA_alignment_checks_arbitrary_geometry_mask',v,v.next!=z3.If((mask&va)!=0,resize(0xfffffe000be5c070,64),resize(0xfffffe000be5b398,64)))
 v=local();ctx=z3.BitVec('MT_ctx64',64);v.regions=[(ctx,128)];lo=v.load(ctx+0x10,8);v.seed('x19',ctx);v.seed('x26',va);cut(v,'lower_bound',0xfffffe000be5b3d8,0xfffffe000be5b3e4)
 prove('context_lower_bound_is_unsigned_inclusive',v,v.next!=z3.If(z3.ULT(va,lo),resize(0xfffffe000be5bf4c,64),resize(0xfffffe000be5b3e4,64)))
 v=local();v.regions=[(ctx,128)];hi=v.load(ctx+0x18,8);v.seed('x19',ctx);v.seed('x26',va);cut(v,'upper_bound',0xfffffe000be5b3e4,0xfffffe000be5b3f0)
 prove('context_upper_bound_is_unsigned_exclusive',v,v.next!=z3.If(z3.UGE(va,hi),resize(0xfffffe000be5bf4c,64),resize(0xfffffe000be5b3f0,64)))
 v=local();v.seed('x26',va);cut(v,'reserved_low',0xfffffe000be5b3a8,0xfffffe000be5b3c0)
 prove('reserved_window_lower_edge_is_fffffecfffd00000',v,v.next!=z3.If(z3.ULT(va,0xfffffecfffd00000),resize(0xfffffe000be5b3d0,64),resize(0xfffffe000be5b3c0,64)))
 v=local();v.seed('x26',va);cut(v,'reserved_high',0xfffffe000be5b3c0,0xfffffe000be5b3d0)
 prove('reserved_window_upper_edge_is_fffffecfffe00000',v,v.next!=z3.If(z3.ULT(va,0xfffffecfffe00000),resize(0xfffffe000be5bf54,64),resize(0xfffffe000be5b3d0,64)))
 v=local();pa=z3.BitVec('MT_PA64',64);mode,flag,options,tag=z3.BitVecs('MT_mode32 MT_flag64 MT_options64 MT_tag64',64);mode32=z3.Extract(31,0,mode)
 v.seed('x19',ctx);v.seed('x24',pa);v.seed('x28',options);v.seed('x27',flag);v.seed('x21',tag);v.setmem(v.sp0+0x90,4,mode32)
 cut(v,'descriptor_ABI',0xfffffe000be5b430,0xfffffe000be5b450)
 prove('gateway_descriptor_arguments_preserve_all_six_fields_and_u16_output_location',v,z3.Or(v.next!=R.DESC,v.read('x0')!=ctx,v.read('x1')!=pa,v.read('w2')!=mode32,v.read('x3')!=options,v.read('x4')!=flag,v.read('x5')!=tag,v.read('x6')!=v.read('x29')-0xa2))
 v=local();flag32=z3.BitVec('MT_descriptor_flag32',32);v.seed('w4',flag32);cut(v,'descriptor_initial',0xfffffe000be5ca1c,0xfffffe000be5ca30)
 prove('descriptor_initial_flags_are3_or_bit58_plus3',v,v.read('x8')!=z3.If(flag32==0,resize(3,64),resize(0x0400000000000003,64)))
 v=local();template=z3.BitVec('MT_template64',64);v.seed('x8',template);v.seed('x1',pa);cut(v,'descriptor_PA',0xfffffe000be5ca38,0xfffffe000be5ca40)
 prove('descriptor_includes_only_PA_mask_fffffffff000_at_this_stage',v,v.read('x8')!=(template|(pa&0xfffffffff000)))
 v=local();v.seed('x8',template);cut(v,'descriptor_final',0xfffffe000be5cbb8,0xfffffe000be5cbbc)
 prove('descriptor_always_sets_bit10_on_normal_return',v,v.read('x0')!=(template|0x400))
 v=local();thread=CPU.THREAD;block=R.CPU_BASE;epoch=z3.BitVec('MT_epoch64',64);nest=z3.BitVec('MT_nest32',32)
 v.regions=[(thread,0x280),(block,0x1280)];v.seed('x25',thread);v.setmem(thread+0x1c8,4,nest);v.setmem(thread+0x1b8,8,0);v.setmem(block+0x1278,8,epoch)
 cut(v,'request_epoch',0xfffffe000be5cf78,0xfffffe000be5cfa8)
 prove('request_publishes_modular_epoch_plus1_and_nesting_plus1',v,z3.Or(v.load(thread+0x1c8,4)!=nest+1,v.load(block+0x1278,8)!=epoch+1,v.load(block+0x1270,8)!=epoch+1))
 v=local();v.regions=[(ctx,128)];root=v.load(ctx+8,8);v.seed('x20',ctx);v.seed('x24',va);v.seed('x21',template);cut(v,'transport_ABI',0xfffffe000be5d02c,0xfffffe000be5d040)
 prove('selected_transport_receives_root_VA_descriptor_and_zero',v,z3.Or(v.next!=R.WRAPPERS[1],v.read('x0')!=root,v.read('x1')!=va,v.read('x2')!=template,v.read('x3')!=0))
 v=local();status=z3.BitVec('MT_status32',32);v.seed('w0',status);cut(v,'result_gate',0xfffffe000be5d040,0xfffffe000be5d048)
 prove('unsigned_raw_status_below2_selects_result_copy_path',v,v.next!=z3.If(z3.UGE(status,2),resize(0xfffffe000be5d168,64),resize(0xfffffe000be5d048,64)))
 v=local();v.regions=[(thread,0x280),(block,0x1280),(CPU.RESULT,16),(CPU.OUT,16)];v.seed('x25',thread);v.seed('x27',block);v.seed('x22',CPU.OUT+8);v.seed('x23',CPU.OUT)
 v.setmem(thread+0x1b8,8,0);v.setmem(block,8,CPU.RESULT);a=v.load(CPU.RESULT,8);b=v.load(CPU.RESULT+8,8)
 cut(v,'result_copy',0xfffffe000be5d048,0xfffffe000be5d064)
 prove('result_record_word0_copies_to_argument5_word1_to_argument2',v,z3.Or(v.load(CPU.OUT+8,8)!=a,v.load(CPU.OUT,8)!=b))
 v=local();v.regions=[(block,0x1280)];v.seed('x26',block);cut(v,'active_clear',0xfffffe000be5d0bc,0xfffffe000be5d0c8)
 prove('normal_completion_release_store_clears_active_marker',v,v.load(block+0x1270,8)!=0)
 v=local();slot,bits=z3.BitVecs('MT_bitmap_slot64 MT_bitmap_word64',64);v.seed('x8',slot);v.seed('x9',bits);v.seed('x21',template)
 cut(v,'bitmap_select',0xfffffe000be5d018,0xfffffe000be5d02c);shift=(slot&31)<<1
 prove('selected_two_bit_bitmap_field_sets_descriptor_bit11_only_when_high_bit_set',v,v.read('x21')!=z3.If((z3.LShR(bits,shift)&2)==0,template,template|0x800))
 v=local();v.regions=[(CPU.OUT,2)];v.seed('x3',CPU.OUT);v.seed('x4',CPU.OUT+1)
 cut(v,'classify_defaults',0xfffffe000be5deac,0xfffffe000be5deb8)
 prove('mapping_categories_initialize_two_bytes_to0b',v,z3.Or(v.load(CPU.OUT,1)!=11,v.load(CPU.OUT+1,1)!=11))
 v=local();v.regions=[(R.TAG_FLAG,1)];feature=v.load(R.TAG_FLAG,1);cut(v,'tag23_feature',0xfffffe000be5dfbc,0xfffffe000be5dfc8)
 prove('explicit_tag23_uses_feature_bit0_to_choose_fallback_or_tag23',v,v.next!=z3.If((feature&1)==0,resize(0xfffffe000be5dff0,64),resize(0xfffffe000be5dfc8,64)))
 v=local();v.regions=[(CPU.OUT,1)];v.seed('x4',CPU.OUT);cut(v,'tag23_fallback',0xfffffe000be5dff0,0xfffffe000be5dffc)
 prove('tag23_feature_clear_stores_desired_category0b',v,z3.Or(v.load(CPU.OUT,1)!=11,v.next!=0xfffffe000be5df70))
 for j,w in enumerate(R.WRAPPERS):
  v=local();v.regions=[(R.TRANSPORT_FLAG,1)];choice=v.load(R.TRANSPORT_FLAG,1);cut(v,'wrapper'+str(j),w+16,w+32)
  prove('wrapper_selector'+str(j+1)+'_and_transport_word_choice',v,z3.Or(v.read('x16')!=j+1,v.next!=z3.If(choice!=0,resize(w+40,64),resize(w+32,64))))
 prior=[]
 old=json.loads(read(ROOT/'kernel_refill_publication_audit.json'))
 for p in old['source_proofs']:
  if p['label'] not in ['lower_pmap_receives_exact_virtual_physical_fields_register_arguments_and_stack_byte','mapper_reconstructs_same_low32_object_stride_PFN_expression_as_zero_request']:continue
  s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert s.check()==z3.unsat;prior.append({**p,'source_artifact_sha256':sha(ROOT/'kernel_refill_publication_audit.json')})
 assert len(prior)==2
 image=Image();components=[];replays=[];totals=Counter()
 for c in CPU.cases():
  row=CPU.Probe(image,c).run();row['independent_oracle_checks']=CPU.oracle(row);components.append(row);r=Replay(image,row).run();replays.append(r);totals.update(r)
 negative=[]
 for c,pc in [({'kind':'implementation','cpu':0,'result':0,'bitmap':None},0xfffffe000be5cf9c),
  ({'kind':'implementation','cpu':0,'result':0,'bitmap':None},0xfffffe000be5d058),
  ({'kind':'wrapper','wrapper':1,'transport_flag':0,'thread':True,'depth':5},R.WRAPPERS[1]+16)]:
  row=CPU.Probe(image,c,pc).run()
  try:CPU.oracle(row)
  except AssertionError as error:negative.append({'component':row,'oracle_rejection':error.args[0][0]})
  else:raise AssertionError('changed source accepted')
 source={i['ea'] for f in e['functions'] for i in f['instructions']};visited={i['pc'] for c in components for i in c['source_visits']}
 desc=next(i for i,c in enumerate(components) if c['configuration']=={'kind':'descriptor','kernel':True,'mode':3,'geometry_flag':0,'nonzero_flag':1})
 links=[];value=components[desc]['boundary']['registers31'][0]
 for j,c in enumerate(components):
  if c['configuration']['kind']=='implementation' and c['configuration']['bitmap'] is None:
   assert c['entry_registers31'][2]==value
   links.append({'descriptor_component':desc,'implementation_component':j,'descriptor_value':value,'scope':'Exact same-value composition across declared component calls; no continuous native epoch'})
 stats={'source_queries_unsat':len(proofs),'prior_source_queries_rechecked':len(prior),'components':len(components),
  'component_source_visits':sum(len(c['source_visits']) for c in components),'executed_source_PCs':len(source&visited),
  'proved_source_PCs':len({p for c in coverage for p in c['PCs']}),'proof_instruction_instances':sum(c['instruction_instances'] for c in coverage),
  'linked_edge_obligations':sum(c['linked_edge_obligations'] for c in coverage),'independent_oracle_checks':sum(len(c['independent_oracle_checks']) for c in components),
  'changed_source_controls':len(negative),'descriptor_value_links':len(links)}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_mapping_transport.py'),
  'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'scope':R.SCOPE,'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],
  'source_proofs':proofs,'rechecked_prior_source_proofs':prior,'coverage':coverage,'components':components,'independent_replays':replays,'descriptor_value_links':links,
  'independent_replay_totals':dict(totals),'negative_controls':negative,'unexecuted_source_PCs':sorted(source-visited),'independent_totals':stats,
  'conditional_kernel_mapping_transport_contract_established':True,**{k:False for k in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True);print(json.dumps(a['independent_replay_totals']),flush=True)
