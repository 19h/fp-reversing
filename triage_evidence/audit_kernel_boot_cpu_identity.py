#!/usr/bin/env python3
"""Original-source obligations, byte oracles, fresh replay and source controls.
O(source + formula DAG + visits + journals + mapped bytes) construction/space;
SMT search separate,30 s/query. Native execution and complete boot unproved.
"""
import json
from collections import Counter
import z3
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_kernel_boot_header_handoff import Model as Parent
from audit_kernel_mapping_context import DEC
from lskd_values_symbolic import resize
import recover_kernel_boot_cpu_identity as R
import probe_kernel_boot_cpu_identity as CPU
from replay_kernel_boot_cpu_identity import Replay,oracle

class Model(Parent):
 def __init__(self,e):super().__init__(e);self.system={}
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.mnemonic not in ['mrs','msr','ldrsw','movi']:
    old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one');self.e,self.c=old_e,old_c;continue
   if self.next is not None:self.edge_checks.append(self.next==i.address)
   self.next=resize(i.address+4,64);self.pc=i.address;self.visited.add(i.address);self.count+=1
   if i.mnemonic=='ldrsw':
    self.write(i.reg_name(i.operands[0].reg),z3.SignExt(32,self.load(self.address(i,i.operands[1]),4)));continue
   if i.mnemonic=='movi':
    assert i.op_str=='v0.2d, #0000000000000000';self.vectors['v0']=resize(0,128);continue
   left,right=i.op_str.split(', ')
   if i.mnemonic=='mrs':self.write(left,self.system[right])
   else:self.system[left]=self.read(right)
  return self

def source_proofs(e):
 proofs=[];coverage=[]
 def local():v=Model(e);v.regions=[];return v
 def cut(v,a,b):
  f=next(f for f in e['functions'] if int(f['start'],16)<=a<b<=int(f['end'],16));offset=a-int(f['start'],16)
  v.e=v.c={'spans':[{'label':'cut','start':hex(a),'bytes_hex':bytes.fromhex(f['bytes'])[offset:offset+b-a].hex()}]};return v.enter('cut')
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad));s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000)
  s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label)
  s.add(*v.bindings_for([*common,counter]),counter);result=s.check();assert result==z3.unsat,(label,str(result),s.reason_unknown())
  proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV'})
  coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,'linked_edge_obligations':len(v.edge_checks)});print(label,flush=True)
 n=z3.BitVec('BC_logical_ordinal32',32);base=z3.BitVec('BC_topology_array64',64);offset=z3.ZeroExt(32,n)*136;signed=z3.SignExt(32,z3.Extract(31,0,offset))
 v=local();v.seed('w8',n);v.seed('x9',base);cut(v,0xfffffe000be83300,0xfffffe000be8331c)
 prove('CPU_record_stride136_and_signed32_address_poison_gate',v,v.read('x26')!=z3.If(offset==signed,base+signed,((base+offset)&0xffffffffffff)|0x2bad000000000000))
 node=CPU.P+0x1000;v=local();v.regions=[(R.GLOBALS,8),(node,136)];maximum=v.load(R.GLOBALS+4,4);v.seed('x24',R.GLOBALS);v.seed('x26',node);v.seed('w8',n);cut(v,0xfffffe000be8331c,0xfffffe000be83338)
 prove('admitted_CPU_record_stores_count_ordinal_and_unsigned_maximum',v,z3.Or(v.load(R.GLOBALS,4)!=n+1,v.load(node,4)!=n,v.load(R.GLOBALS+4,4)!=z3.If(z3.UGT(maximum,n),maximum,n)))
 state=z3.BitVec('BC_state_compare32',32);v=local();v.seed('w28',state);cut(v,0xfffffe000be83248,0xfffffe000be8324c)
 prove('state_comparison_zero_selects_boot_record_publication',v,v.next!=z3.If(state==0,resize(0xfffffe000be833a4,64),resize(0xfffffe000be8324c,64)))
 record,cluster=z3.BitVecs('BC_boot_CPU_record64 BC_boot_cluster_record64',64);v=local();v.regions=[(R.RECORD_PTR,16)];v.seed('x26',record);v.seed('x23',cluster);cut(v,0xfffffe000be833a4,0xfffffe000be833b4)
 prove('boot_CPU_and_cluster_pointers_are_one_original_paired_store',v,z3.Or(v.load(R.RECORD_PTR,8)!=record,v.load(R.RECORD_PTR+8,8)!=cluster,v.next!=0xfffffe000be8324c))
 cluster32=z3.BitVec('BC_cluster_index32',32);v=local();v.regions=[(R.RECORD_PTR,8),(node,12)];v.setmem(R.RECORD_PTR,8,node);v.setmem(node,4,n);v.setmem(node+8,4,cluster32);v.seed('x19',R.RECORD_PTR);cut(v,0xfffffe000be83d28,0xfffffe000be83d44)
 packed=z3.ZeroExt(32,(n&0xfff)|((cluster32&255)<<12))
 prove('topology_initial_TPIDR_EL0_is_low12_ordinal_and_low8_cluster_at_bit12',v,z3.Or(v.system['tpidr_el0']!=packed,v.system['tpidrro_el0']!=0))
 v=local();v.regions=[(R.RECORD_PTR,8),(node,4),(R.CPU,2),(0xfffffe0007f8b4f0,4)];v.setmem(R.RECORD_PTR,8,node);v.setmem(node,4,n);cut(v,0xfffffe000c639cc0,0xfffffe000c639ce0)
 prove('main_loads_signed_ordinal_at_record_offset0_and_publishes_low32_low16',v,z3.Or(v.read('x8')!=z3.SignExt(32,n),v.load(0xfffffe0007f8b4f0,4)!=n,v.load(R.CPU,2)!=z3.Extract(15,0,n),v.read('x26')!=R.CPU))
 v=local();v.regions=[(R.TEMPLATE+0x328,16)];cut(v,0xfffffe000c639d80,0xfffffe000c639da8)
 prove('original_bootstrap_memcpy_ABI_uses_template_and1472_bytes_after16_byte_clear',v,z3.Or(v.read('x0')!=R.THREAD,v.read('x1')!=R.TEMPLATE,v.read('x2')!=1472,v.next!=R.COPY,v.load(R.TEMPLATE+0x328,16)!=0))
 v=local();v.regions=[(R.CPU,2),(R.THREAD+0x1b8,16)];v.setmem(R.CPU,2,z3.Extract(15,0,n));v.seed('x26',R.CPU);v.seed('x19',R.THREAD);cut(v,0xfffffe000c639dc4,0xfffffe000c639dd4)
 field=z3.ZeroExt(48,z3.Extract(15,0,n))
 prove('bootstrap_thread_field_zeroextends_CPU_low16_and_binds_fixed_CPU_pointer',v,z3.Or(v.load(R.THREAD+0x1b8,8)!=field,v.load(R.THREAD+0x1c0,8)!=R.CPU,v.read('x0')!=R.THREAD,v.next!=R.SETTER))
 old,low,ro,context=z3.BitVecs('BC_old_TPIDR0_64 BC_CPU_low48_input64 BC_thread_RO64 BC_context64',64)
 v=local();v.regions=[(R.THREAD,0x5c0),(R.CPU,0xa40)];v.setmem(R.THREAD+0x1c0,8,R.CPU);v.setmem(R.THREAD+0x148,8,ro);v.setmem(R.THREAD+0x510,8,context);v.setmem(R.CPU+0xa38,8,low);v.seed('x0',R.THREAD);v.system['tpidr_el0']=old;cut(v,R.SETTER+4,R.SETTER+48)
 prove('thread_setter_writes_system_registers_backpointer_and_preserves_TPIDR0_high16',v,z3.Or(v.system['tpidr_el1']!=R.THREAD,v.load(R.CPU+0x30,8)!=R.THREAD,v.system['tpidr_el0']!=((old&0xffff000000000000)|(low&0xffffffffffff)),v.system['tpidrro_el0']!=ro,v.system['contextidr_el1']!=context))
 v=local();v.system['tpidr_el1']=resize(R.THREAD,64);v.regions=[(R.THREAD,0x5c0),(R.CPU,0xa40)];v.setmem(R.THREAD+0x1c0,8,R.CPU);v.setmem(R.THREAD+0x1b8,8,field);v.seed('w0',n);cut(v,R.SPTM+28,R.SPTM+56)
 prove('actual_boot_thread_field_selects_zero_ASR16_SPTM_block_offset',v,z3.Or(v.load(R.CPU+0x8e8,4)!=n,v.read('x21')!=0xfffffe000cac8000))
 v=local();v.system['tpidr_el1']=resize(R.THREAD,64);v.regions=[(R.THREAD,0x5c0),(R.CPU,8)];v.setmem(R.THREAD+0x1c0,8,R.CPU);magic=v.load(R.CPU+4,4);cut(v,0xfffffe000be7810c,0xfffffe000be78128)
 prove('CPU_magic0100000c_selects_common_reset_without_initialization_body',v,v.next!=z3.If(magic==0x0100000c,resize(0xfffffe000be7821c,64),resize(0xfffffe000be78128,64)))
 cpudata=z3.BitVec('BC_current_CPU_data64',64);v=local();v.seed('x19',cpudata);cut(v,0xfffffe000be78150,0xfffffe000be78160)
 prove('fixed_boot_CPU_data_address_skips_direct_SPTM_initialization_call',v,v.next!=z3.If(cpudata==R.CPU,resize(0xfffffe000be7816c,64),resize(0xfffffe000be78160,64)))
 v=local();v.regions=[(R.THREAD,0x5c0)];x=v.load(R.THREAD+0x1b8,2);v.seed('x8',R.THREAD);cut(v,0xfffffe000be78160,0xfffffe000be78168)
 prove('nonboot_SPTM_call_argument_is_zeroextended_thread_low16',v,z3.Or(v.read('x0')!=z3.ZeroExt(48,x),v.next!=R.SPTM))
 midr=z3.BitVec('BC_MIDR64',64);v=local();v.system['midr_el1']=midr;v.regions=[(0xfffffe0007ef81c8,4)];cut(v,0xfffffe000be7816c,0xfffffe000be78180)
 prove('boot_CPU_forces_MIDR_bits16_through19_to_d_before_capability_selection',v,v.load(0xfffffe0007ef81c8,4)!=((z3.Extract(31,0,midr)&0xfff0ffff)|0xd0000))
 for width,a,b,dest in [(1,0xfffffe000be84044,0xfffffe000be84050,'w20'),(2,0xfffffe000be83ff4,0xfffffe000be84000,'w20'),(4,0xfffffe000be84050,0xfffffe000be84058,'w20'),(8,0xfffffe000be84038,0xfffffe000be84044,'x20')]:
  v=local();v.regions=[(node,8)];v.seed('x29',v.sp0);v.setmem(v.sp0-0x18,8,node);value=v.load(node,width);cut(v,a,b)
  prove('scalar_property_unsigned_little_endian_load_'+str(width)+'_bytes',v,v.read(dest)!=resize(value,32 if width<8 else 64))
 fallback=z3.BitVec('BC_property_fallback64',64);v=local();v.seed('x20',fallback);cut(v,0xfffffe000be84000,0xfffffe000be84008)
 prove('absent_scalar_property_allones_fallback_selects_mandatory_diagnostic',v,v.next!=z3.If(fallback==(2**64-1),resize(0xfffffe000be84008,64),resize(0xfffffe000be84058,64)))
 return proofs,coverage

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,coverage=source_proofs(e);im=Image();components=[];replays=[];totals=Counter()
 for c in CPU.cases():
  row=CPU.Probe(im,c).run();row['independent_oracle']=oracle(row);replay=Replay(im,row).run();components.append(row);replays.append(replay);totals.update(replay)
 controls=[];cases=CPU.cases()
 for c,pc in [(cases[0],0xfffffe000c639dc0),(cases[0],0xfffffe000be7815c),(cases[-2],R.SETTER+28),(cases[11],0xfffffe000be84054)]:
  row=CPU.Probe(im,c,pc).run()
  try:oracle(row)
  except AssertionError as error:controls.append({'component':row,'oracle_rejection':{'kind':error.args[0][0],'label':error.args[0][1]}})
  else:raise AssertionError(('changed_source_accepted',hex(pc)))
 visits={v['PC'] for row in components for v in row['source_visits']};source={i['ea'] for f in e['functions'] for i in f['instructions']}
 assert visits<=source and not visits&{r['PC'] for r in e['opaque_words']}
 stats={'source_queries_unsat':len(proofs),'proved_source_PCs':len({pc for c in coverage for pc in c['PCs']}),'proof_instruction_instances':sum(c['instruction_instances'] for c in coverage),
  'linked_edge_obligations':sum(c['linked_edge_obligations'] for c in coverage),'components':len(components),'executed_source_PCs':len(visits),'source_visits':sum(len(c['source_visits']) for c in components),
  'independent_oracle_checks':sum(len(c['independent_oracle']['checks']) for c in components),'independent_nonstack_bytes_checked':sum(c['independent_oracle']['independent_nonstack_bytes_checked'] for c in components),
  'changed_source_controls':len(controls),'original1472_byte_copies':sum(len(c['original_copy_entries']) for c in components),'same_RAM_explicit_caller_epochs':sum(len(c['epochs']) for c in components)}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_boot_cpu_identity.py'),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
  'scope':R.SCOPE,'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'source_proofs':proofs,'coverage':coverage,'components':components,'independent_replays':replays,
  'negative_controls':controls,'independent_totals':stats,'independent_replay_totals':dict(totals),'unexecuted_source_PCs':sorted(source-visits),
  'conditional_kernel_boot_cpu_identity_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True);print(json.dumps(a['independent_replay_totals']),flush=True)
