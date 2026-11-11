#!/usr/bin/env python3
"""Nominal descriptor-AES guards, mutable key header and command scheduling ABI.

Original KC source certificates. Native objects, complete key policy, accepted
descriptor extents and hardware completion remain unproved. O(N+I) source and
expression time/space; SMT cost separate. No target or IDB operation executes.
"""
import argparse
import json

import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_EXT_SXTW

from kernel_native_reader import Kernel
from kext_port_tools import ROOT
from recover_kext_aes_handoff import function,definitions
from recover_kext_cold_init import pointer
from recover_lskd_hardware_staging import StagingLift
from lskd_values_symbolic import resize,part
from verify_daemon_reader_record_payloads_publication import read,sha

F=0xfffffe0053000000
LIMIT=8388608
OP_TABLE=0xfffffe0007abf4f8
FUNCTIONS={
 'provider':('com.apple.iokit.IOCryptoAcceleratorFamily',0xfffffe000abff358),
 'base_options':('com.apple.iokit.IOCryptoAcceleratorFamily',0xfffffe000abfd2c0),
 'queue':('com.apple.iokit.IOCryptoAcceleratorFamily',0xfffffe000abfd2d8),
 'start':('com.apple.iokit.IOCryptoAcceleratorFamily',0xfffffe000abfd4bc),
 'hardware_options':('com.apple.driver.AppleS8000AES',0xfffffe0009d51ad8),
}


class ProviderLift(StagingLift):
 def load(self,address,n):
  key=(z3.simplify(resize(address,64)).sexpr(),n)
  assert key in self.fixed,('undefined provider cell',hex(self.pc),key)
  return self.fixed[key]
 def store(self,address,n,value,pc):
  address=z3.simplify(resize(address,64));key=(address.sexpr(),n)
  assert key in self.fixed_stores or (z3.is_bv_value(address) and F<=address.as_long()<address.as_long()+n<=F+0x350)
  value=resize(value,n*8);self.fixed[key]=value
  self.stores.append({'pc':pc,'address':address,'size_bytes':n,'value':value})
 def operand(self,ins,operand,width):
  if operand.ext==ARM64_EXT_SXTW:
   assert width==64 and not operand.shift.type
   return z3.SignExt(32,resize(self.read(ins.reg_name(operand.reg)),32))
  return super().operand(ins,operand,width)
 def run(self,label):
  saved=self.c;row=next(s for s in saved['spans'] if s['label']==label)
  cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
  raw=bytes.fromhex(row['bytes_hex']);insns=list(cs.disasm(raw,int(row['start'],16)))
  assert len(insns)*4==len(raw)
  for ins in insns:
   self.pc=ins.address;ops=ins.operands
   if ins.mnemonic=='cmn':
    width=self.width(ins.reg_name(ops[0].reg));a=self.operand(ins,ops[0],width);b=self.operand(ins,ops[1],width)
    self.carry=z3.Extract(width,width,z3.ZeroExt(1,a)+z3.ZeroExt(1,b))==1
    self.equal=a+b==0;self.count+=1
   elif ins.mnemonic=='ldr' and ins.writeback:
    address=self.address(ins,ops[1]);self.write(ins.reg_name(ops[0].reg),self.load(address,self.width(ins.reg_name(ops[0].reg))//8))
    self.write(ins.reg_name(ops[1].mem.base),address);self.count+=1
   elif ins.mnemonic=='csel' and ins.op_str.endswith(', hi'):
    d,a,b=[ins.reg_name(o.reg) for o in ops[:3]]
    self.write(d,z3.If(z3.UGT(self.cmp_left,self.cmp_right),self.read(a),self.read(b)));self.count+=1
   else:
    self.c={'spans':[{'label':label,'start':hex(ins.address),'bytes_hex':bytes(ins.bytes).hex()}]};super().run(label)
  self.c=saved;return self


def prove(capture):
 q={};pieces={};counts={}
 provider,inp,out,iv,key,command=z3.BitVecs('provider64 input_descriptor64 output_descriptor64 IV64 original_key_data64 command64',64)
 length,offset_a,offset_b,callback,callback_context=z3.BitVecs('length64 offset_A64 offset_B64 callback64 callback_context64',64)
 operation,header=z3.BitVecs('operation32 original_key_header24_32',32)
 def run(name,a,z,seeds,cells=(),writes=()):
  obj=ProviderLift(part(capture,name,a,z))
  for reg,value in seeds.items():obj.seed(reg,value)
  for at,n,value in cells:obj.fixed[(z3.simplify(resize(at,64)).sexpr(),n)]=resize(value,n*8)
  for at,n in writes:obj.fixed_stores.add((z3.simplify(resize(at,64)).sexpr(),n))
  obj.run(name);assert obj.count==(z-a)//4
  pieces[name]={'start':hex(a),'end':hex(z),'instructions':obj.count};counts[name]=obj.count;return obj
 def cell(obj,at,n):return obj.fixed[(z3.simplify(resize(at,64)).sexpr(),n)]
 obj=run('arguments',0xfffffe000abff380,0xfffffe000abff3a8,
  {'sp':F,'x29':F+0x80,'x0':provider,'x1':inp,'x2':out,'x3':length,'x4':iv,'x5':resize(operation,64),'x6':key,'x7':offset_a},
  [(F+0x90,8,offset_b),(F+0x98,8,callback),(F+0xa0,8,callback_context)])
 q['arguments']=z3.Or(obj.read('x19')!=provider,obj.read('x22')!=inp,obj.read('x20')!=out,obj.read('x25')!=length,
  obj.read('w21')!=operation,obj.read('x26')!=key,obj.read('x24')!=offset_a,obj.read('x28')!=offset_b,
  obj.read('x27')!=callback,obj.read('x23')!=callback_context,cell(obj,F+0x28,8)!=iv)
 obj=run('length_alignment',0xfffffe000abff3d8,0xfffffe000abff3dc,{'x25':length})
 q['length_alignment']=obj.equal!=((length&15)==0)
 obj=run('length_range',0xfffffe000abff3e0,0xfffffe000abff3ec,{'x25':length})
 q['length_range']=obj.carry!=z3.And(z3.UGE(length,1),z3.ULE(length,LIMIT))
 q['aligned_length_domain']=z3.And(z3.UGE(length,1),z3.ULE(length,LIMIT),(length&15)==0,
  z3.Or(z3.ULT(length,16),z3.UGT(length,LIMIT)))
 obj=run('key_control_strip',0xfffffe000abff3f4,0xfffffe000abff404,{'x26':key},[(key+0x24,4,header)],[(key+0x24,4)])
 q['key_control_strip']=z3.Or(obj.read('x23')!=key+0x24,obj.read('w8')!=header,
  obj.read('w9')!=(header&0x7fffffff),cell(obj,key+0x24,4)!=(header&0x7fffffff))
 selector=z3.BitVec('selected_key_selector32',32)
 for name,a,z,lower,upper in [
  ('selector_4000_4004',0xfffffe000abff430,0xfffffe000abff438,4000,4004),
  ('selector_3000_3999',0xfffffe000abff448,0xfffffe000abff450,3000,3999),
  ('selector_2100_2999',0xfffffe000abff490,0xfffffe000abff498,2100,2999),
 ]:
  obj=run(name,a,z,{'w9':selector})
  q[name]=z3.ULE(obj.cmp_left,obj.cmp_right)!=z3.And(z3.UGE(selector,lower),z3.ULE(selector,upper))
 entry=z3.BitVec('matching_provider_key_entry64',64);entry_selector=z3.BitVec('entry_selector32',32)
 obj=run('key_entry_selection',0xfffffe000abff54c,0xfffffe000abff558,{'x14':entry},[(entry+0x2c,4,entry_selector)])
 q['key_entry_selection']=z3.Or(obj.read('x26')!=entry+8,obj.read('w9')!=entry_selector,obj.read('x23')!=entry+0x2c)
 index=z3.BitVec('provider_key_entry_index64',64);base=z3.BitVec('provider_key_table64',64)
 obj=run('key_entry_stride',0xfffffe000abff4b8,0xfffffe000abff4c4,{'x11':index,'x12':52,'x13':base})
 q['key_entry_stride']=obj.read('x15')!=base+52*index
 flag=z3.BitVec('provider_options_root64',64)
 obj=run('base_options',0xfffffe000abfd2c4,0xfffffe000abfd2d4,{'x0':provider},[(provider+0xa8,8,flag)])
 q['base_options']=obj.read('w0')!=z3.If(flag!=0,resize(3,32),resize(1,32))
 version=z3.BitVec('hardware_version_field128_32',32)
 obj=run('hardware_options',0xfffffe0009d51adc,0xfffffe0009d51af0,{'x0':provider},[(provider+0x128,4,version)])
 q['hardware_options']=obj.read('w0')!=z3.If(z3.UGT(version,4),resize(0x3d,32),resize(0x1d,32))
 obj=run('prepare_input_args',0xfffffe000abff5bc,0xfffffe000abff5c4,{'x22':inp})
 q['prepare_input_args']=z3.Or(obj.read('x0')!=inp,obj.read('w1')!=0)
 obj=run('prepare_output_args',0xfffffe000abff6b4,0xfffffe000abff6bc,{'x20':out})
 q['prepare_output_args']=z3.Or(obj.read('x0')!=out,obj.read('w1')!=0)
 physical=z3.BitVec('physical_base64',64);mask_parameter=z3.BitVec('provider_alignment_parameter32',32)
 obj=run('physical_alignment',0xfffffe000abff710,0xfffffe000abff71c,{'x19':provider,'x0':physical},[(provider+0xb0,4,mask_parameter)])
 q['physical_alignment']=obj.equal!=((physical&z3.ZeroExt(32,mask_parameter-1))==0)
 obj=run('physical_segment_args',0xfffffe000c53c2ec,0xfffffe000c53c2f8,{})
 q['physical_segment_args']=z3.Or(obj.read('x1')!=0,obj.read('x2')!=0,obj.read('w3')!=0)
 obj=run('command_first_fields',0xfffffe000abff7f4,0xfffffe000abff80c,
  {'sp':F,'x0':command,'x22':inp,'x20':out,'x24':offset_a,'x28':offset_b,'x25':length,'w21':operation},[(F+0x28,8,iv)],
  [(command+o,n) for o,n in [(0x20,8),(0x28,8),(0x50,8),(0x58,8),(0x30,8),(0x38,8),(0x40,4)]])
 q['command_first_fields']=z3.Or(obj.read('x2')!=command,*[cell(obj,command+o,n)!=resize(v,n*8) for o,n,v in
  [(0x20,8,inp),(0x28,8,out),(0x50,8,offset_a),(0x58,8,offset_b),(0x30,8,length),(0x38,8,iv),(0x40,4,operation)]])
 obj=run('operation_one_table_address',0xfffffe000abff814,0xfffffe000abff820,{'w21':1})
 q['operation_one_table_address']=z3.Or(obj.read('x8')!=8,obj.read('x9')!=OP_TABLE)
 obj=run('operation_one_offset',0xfffffe000abff834,0xfffffe000abff838,{'x10':OP_TABLE+8},[(OP_TABLE+8,8,0xe8)])
 q['operation_one_offset']=obj.read('x8')!=0xe8
 quantum=z3.BitVec('provider_quantum_e8_64',64)
 obj=run('operation_one_quantum',0xfffffe000abff844,0xfffffe000abff860,
  {'x8':0xe8,'x19':provider,'x2':command},[(provider+0xe8,8,quantum)],[(command+0x60,8)])
 q['operation_one_quantum']=cell(obj,command+0x60,8)!=quantum
 selected_key=z3.BitVec('selected_key_data64',64)
 obj=run('command_key',0xfffffe000abff860,0xfffffe000abff864,{'x26':selected_key,'x2':command},writes=[(command+0x48,8)])
 q['command_key']=cell(obj,command+0x48,8)!=selected_key
 obj=run('command_completion',0xfffffe000abff874,0xfffffe000abff884,
  {'x2':command,'x11':callback,'x10':callback_context,'x19':provider},
  [(provider+0xb8,8,7),(provider+0xf0,8,9)],[(command+0x80,8),(command+0x88,8),(command+0x68,8)])
 q['command_completion']=z3.Or(cell(obj,command+0x80,8)!=callback,cell(obj,command+0x88,8)!=callback_context,
  cell(obj,command+0x68,8)!=0,obj.read('x0')!=7,obj.read('x1')!=9)
 obj=run('gate_zero_args',0xfffffe000abff8b0,0xfffffe000abff8bc,{})
 q['gate_zero_args']=z3.Or(obj.read('x3')!=0,obj.read('x4')!=0,obj.read('x5')!=0)
 threshold=z3.BitVec('immediate_threshold_a8_64',64)
 obj=run('queue_length_comparison',0xfffffe000abfd300,0xfffffe000abfd30c,{'x19':command,'x20':provider},
  [(command+0x30,8,length),(provider+0xa8,8,threshold)])
 q['queue_length_comparison']=z3.Or(obj.cmp_left!=length,obj.cmp_right!=threshold)
 progress=z3.BitVec('command_progress64',64)
 obj=run('scheduler_quantum',0xfffffe000abfd53c,0xfffffe000abfd560,{'x0':provider,'x1':command},
  [(command+0x30,8,length),(command+0x60,8,quantum),(command+0x68,8,progress)],
  [(command+0x10,8),(command+0x18,8),(command+0x70,8),(provider+0x110,1)])
 amount=z3.If(z3.ULT(length-progress,quantum),length-progress,quantum)
 q['scheduler_quantum']=z3.Or(cell(obj,command+0x70,8)!=amount,cell(obj,command+0x10,8)!=0,
  cell(obj,command+0x18,8)!=0,cell(obj,provider+0x110,1)!=1)
 q['scheduler_bounded_quantum']=z3.And(z3.ULT(progress,length),quantum!=0,
  z3.Or(amount==0,z3.UGT(amount,quantum),z3.UGT(amount,length-progress)))
 obj=run('sleep_args',0xfffffe000abfd3e8,0xfffffe000abfd3f0,{'x19':command})
 q['sleep_args']=z3.Or(obj.read('x1')!=command,obj.read('w2')!=0)
 status=z3.BitVec('command_status32',32)
 obj=run('wait_status',0xfffffe000abfd3fc,0xfffffe000abfd404,{'x19':command,'x20':provider},
  [(command+0x78,4,status),(provider+0xf8,8,11)])
 q['wait_status']=z3.Or(obj.read('w21')!=status,obj.read('x0')!=11)
 obj=run('queue_return_status',0xfffffe000abfd42c,0xfffffe000abfd430,{'w21':status})
 q['queue_return_status']=obj.read('x0')!=z3.ZeroExt(32,status)
 results={}
 for name,query in q.items():
  solver=z3.Solver();solver.set(timeout=15000);solver.add(query);r=solver.check();print(name,r,flush=True)
  assert r==z3.unsat,(name,str(r),solver.reason_unknown());results[name]={'result':'unsat','query':solver.sexpr()}
 return {'proofs':results,'source_pieces':pieces,'source_lift_counts':counts,
  'verified_counts':{'queries_unsat':len(results),'source_pieces':len(pieces),'source_lifted_instances':sum(counts.values())},
  'selected_contract':{'provider_length_full64':True,'provider_maximum_length_B':LIMIT,'provider_length_alignment_B':16,
   'operation_one_quantum_provider_offset_B':0xe8,'key_selector_field_offset_B':0x24,'key_selector_high_bit_cleared':True,
   'provider_key_entry_stride_B':52,'matched_key_data_entry_offset_B':8,
   'scheduler_quantum_command_offset_B':0x70,'full_key_policy_proven':False,'native_descriptor_extent_matched':False,
   'native_provider_class_matched':False,'native_completion_proven':False,'daemon_request_lineage_proven':False},
  'new_IDA_access':False,'new_native_execution':False,'new_IDB_mutations':False,'full_goal_complete':False}


def build():
 k=Kernel();spans=[]
 for label,(name,address) in FUNCTIONS.items():
  entry=next(e for e in k.entries if e['name']==name);row=function(k,entry,address);row['label']=label;spans.append(row)
 row=k.function(0xfffffe000c53c2c4);row['bytes_hex']=row.pop('bytes');row['label']='physical_address';spans.append(row)
 address=0xfffffe000abffaf4;raw=k.read(address,16)
 spans.append({'label':'physical_stub','start':hex(address),'end':hex(address+16),'bytes_hex':raw.hex(),
  'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in k.cs.disasm(raw,address)]})
 output=prove({'spans':spans})
 frozen=json.loads(read(ROOT/'kext_aes_handoff_contracts.json'))
 chosen=[p for p in frozen['nominal_slots'] if
  (p['kind']=='aes' and p['offset_from_vptr'] in [0x8a0,0x8b8,0x8d0,0x8d8]) or
  p['kind'] in ['command_pool','command_gate'] or
  (p['kind']=='buffer' and p['offset_from_vptr'] in [0x218,0x220])]
 hardware=definitions(k,['__ZTV24AppleS8000AESAccelerator'])['__ZTV24AppleS8000AESAccelerator']
 assert len(hardware)==1;hardware_vptr=int(hardware[0]['address'],16)+16
 slots={p['slot']:pointer(k,int(p['slot'],16)) for p in chosen}
 for address in [hardware_vptr+o for o in [0x8a0,0x8a8,0x8b8]]+[0xfffffe000858a620,0xfffffe0007f85d80+0x158]:
  slots[hex(address)]=pointer(k,address)
 output['verified_counts'].update(spans=len(spans),instructions=sum(len(s['instructions']) for s in spans),
  code_B=sum(len(bytes.fromhex(s['bytes_hex'])) for s in spans),original_slots=len(slots))
 return {'scope':__doc__,'generator_sha256':sha(__file__),'kernel_collection_sha256':k.sha256,
  'spans':spans,'slots':slots,'exact_symbols':k.symbols([int(p['target'],16) for p in slots.values()]),
  'hardware_vtable_definition':hardware,'operation_offset_table':{'address':hex(OP_TABLE),'bytes_hex':k.read(OP_TABLE,40).hex(),
   'values_u64':[int.from_bytes(k.read(OP_TABLE+8*i,8),'little') for i in range(5)]},
  'solver_version':z3.get_version_string(),'dependencies':{n:sha(ROOT/n) for n in [
   'recover_lskd_hardware_staging.py','lskd_hardware_staging_checks.json','kext_aes_handoff_contracts.json',
   'kernel_native_reader.py','kext_port_tools.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py',
   'lskd_values_symbolic.py','verify_daemon_reader_record_payloads_publication.py',
   'sample_state_contracts.json','sample_transfer_contracts.json']},**output}


if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--verify',action='store_true');args=parser.parse_args()
 output=build();path=ROOT/'aes_provider_admission_checks.json'
 if args.verify:assert json.loads(read(path))==output
 else:path.write_text(json.dumps(output,indent=2)+'\n')
 print(json.dumps(output['verified_counts']))
