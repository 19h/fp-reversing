#!/usr/bin/env python3
"""Operation 1/5 middle-span staging and nominal hardware-provider ABI.

Original source/fixup certificates; API effects, native object/descriptor epochs,
whole-operation overlap and public operation meanings remain premises/open.
O(N+I+256R) extraction/expression time and space; SMT cost separate.
No target execution, provider operation or IDB mutation.
"""
import argparse
import json

import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN

from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_kext_cold_init import pointer
from recover_aes_cleanup_epoch import span
from recover_lskd_byte_spans import ByteLift,C,F
from recover_lskd_operation_preflight import PreflightLift
from recover_lskd_context_return import TABLE
from lskd_values_symbolic import resize,part
from verify_daemon_reader_record_payloads_publication import read,sha

BANK_B=(0xfffffe00079172c0,0xfffffe0007919cb0)
BANK_E=(0xfffffe00079174c0,0xfffffe0007919db0)
BANK_G=(0xfffffe00079171c0,0xfffffe0007919bb0)
CAP=81920
SPANS={
 'middle_frontier':(0xfffffe000a518008,0xfffffe000a51805c),
 'context_window':(0xfffffe000a5722b8,0xfffffe000a57231c),
 'phase_hop':(0xfffffe000a52e530,0xfffffe000a52e54c),
 'pointer_dispatch':(0xfffffe000a52dfc4,0xfffffe000a52e028),
 'count_gate':(0xfffffe000a55a878,0xfffffe000a55a8c0),
 'initial_copy':(0xfffffe000a54a9e0,0xfffffe000a54aa90),
 'chunk':(0xfffffe000a526a20,0xfffffe000a526b34),
 'copy_out':(0xfffffe000a536648,0xfffffe000a536704),
 'finish':(0xfffffe000a591e64,0xfffffe000a591e80),
 'aes_wrapper':(0xfffffe000a5083d8,0xfffffe000a508484),
 'copy_thunk':(0xfffffe000a508cf4,0xfffffe000a508cfc),
 'copy_stub':(0xfffffe000a69f334,0xfffffe000a69f344),
}
RULES={
 'initial_copy':(BANK_B,0x8d,0x9be,0xfffffe000a508cf4),
 'copy_in':(BANK_B,0x27,0x9a9,0xfffffe000a508cf4),
 'hardware':(BANK_E,0x0d,0xa05,0xfffffe000a5083d8),
 'copy_out':(BANK_G,0xca,0x951,0xfffffe000a508cf4),
}


class StagingLift(ByteLift):
 def load(self,address,n):
  if n==1:return PreflightLift.load(self,address,n)
  return super().load(address,n)
 def run(self,label):
  saved=self.c;row=next(s for s in saved['spans'] if s['label']==label)
  cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
  raw=bytes.fromhex(row['bytes_hex']);insns=list(cs.disasm(raw,int(row['start'],16)))
  assert len(insns)*4==len(raw)
  for ins in insns:
   self.pc=ins.address
   if ins.mnemonic=='csel' and ins.op_str.endswith(', lo'):
    d,a,b=[ins.reg_name(o.reg) for o in ins.operands[:3]]
    self.write(d,z3.If(z3.ULT(self.cmp_left,self.cmp_right),self.read(a),self.read(b)));self.count+=1
   else:
    self.c={'spans':[{'label':label,'start':hex(ins.address),'bytes_hex':bytes(ins.bytes).hex()}]};super().run(label)
  self.c=saved;return self


def prove(capture):
 q={};pieces={};counts={};loads={};banks={}
 context,src,dst,buffer=z3.BitVecs('working_context64 prepared_source64 prepared_destination64 cached_bytes64',64)
 total,offset=z3.BitVecs('total_middle_bytes32 chunk_offset32',32)
 remaining=total-offset;chunk=z3.If(z3.ULT(remaining,CAP),remaining,resize(CAP,32))
 valid=z3.And(z3.ULT(offset,total),(total&15)==0,(offset&15)==0)
 a,b=z3.BitVecs('controller_A32 controller_B32',32)
 def run(name,start,end,seeds,cells=(),instances=1):
  obj=StagingLift(part(capture,name,start,end))
  for reg,value in seeds.items():obj.seed(reg,value)
  for at,n,value in cells:obj.fixed[(z3.simplify(resize(at,64)).sexpr(),n)]=resize(value,n*8)
  obj.run(name);assert obj.count==(end-start)//4
  pieces[name]={'start':hex(start),'end':hex(end),'instructions':obj.count,'instances':instances}
  counts[name]=obj.count*instances
  for row in obj.table_loads:loads[row['slot']]=row['target']
  return obj
 def value(obj,off,n):return obj.fixed[(resize(F+off,64).sexpr(),n)]
 obj=run('middle_frontier',0xfffffe000a51800c,0xfffffe000a518054,{'sp':F,'w9':0x17,'x28':TABLE},
  [(F+0x90,8,context+0x134),(F+0x38,8,dst),(F+0x40,8,src),(F+0x74,4,total)])
 q['middle_frontier']=z3.Or(value(obj,0x6c,4)!=0,obj.read('w8')!=0x6e3,obj.read('w0')!=total,
  obj.read('x14')!=context+0x134,obj.read('x12')!=C,obj.read('x10')!=0xfffffe000a5722b8,
  value(obj,0xd8,8)!=dst,value(obj,0xe0,8)!=src,obj.read('w1')!=0x2b,obj.read('x21')!=resize(-0x6e7,64))
 obj=run('context_window',0xfffffe000a5722bc,0xfffffe000a572314,
  {'sp':F,'x29':F+0x340,'x28':TABLE,'w8':0x6e3,'w9':0x17,'x12':C},[(F+0x1f8,8,context)])
 q['context_window']=z3.Or(obj.read('x15')!=F+0x280,obj.read('w8')!=0x12c,obj.read('w11')!=0x389,
  obj.read('x13')!=0xfffffe000a52e530,obj.read('x9')!=C-16,value(obj,0x78,8)!=0xfffffe000a527b24,
  value(obj,0x60,8)!=context,obj.read('x10')!=0x7ed6766d7e6951b1,obj.read('x12')!=0x4360c2459cc8eba4,
  obj.read('w16')!=0x3a0,obj.read('w22')!=0x53)
 q['context_window_length']=(resize(obj.read('x9'),32)^resize(C,32))!=16
 obj=run('phase_save_count',0xfffffe000a52e534,0xfffffe000a52e544,
  {'sp':F,'x28':TABLE,'w11':0x389,'w16':0x3a0,'w1':0x2b,'w0':total})
 q['phase_save_count']=z3.Or(value(obj,0x120,4)!=total,obj.read('w16')!=0x6e3,obj.read('x11')!=0xfffffe000a5237d8)
 obj=run('context_copy_dispatch',0xfffffe000a52dfc8,0xfffffe000a52e01c,
  {'x28':TABLE,'w8':0x12c,'w13':0x78b,'x12':0x4360c2459cc8eba4,'x10':0x7ed6766d7e6951b1,
   'x14':context+0x134,'x15':F+0x280})
 q['context_copy_dispatch']=z3.Or(obj.read('x11')!=0xfffffe000a55a878,obj.read('x8')!=0,obj.read('x10')!=0,
  obj.read('w12')!=z3.If(z3.UGT(context+0x134,resize(F+0x280,64)),resize(0x7a6,32),resize(0x78b,32)))
 obj=run('count_gate',0xfffffe000a55a87c,0xfffffe000a55a898,
  {'sp':F,'x30':0x6e3},[(F+0x120,4,total)])
 q['count_gate']=z3.Or(obj.read('w27')!=total,obj.read('w8')!=z3.If(total==0,resize(0x850,32),resize(0x87e,32)))
 obj=run('count_gate_constants',0xfffffe000a55a89c,0xfffffe000a55a8b8,
  {'sp':F},[(F+0x1d8,8,0xfffffe000ccc2c80)])
 q['count_gate_constants']=z3.Or(obj.read('x20')!=0x6c627538298d3f88,obj.read('w25')!=0xea5ebdeb,obj.read('x24')!=0xfffffe000ccc2c80)
 obj=run('initial_phases',0xfffffe000a54a9e4,0xfffffe000a54aa1c,
  {'sp':F,'x24':0xfffffe000ccc2c80,'x20':0x6c627538298d3f88,'w25':0xea5ebdeb},
  [(F+0x1f4,4,0x6e3),(F+0x1b0,8,0xfffffe000ccc2c60),
   (0xfffffe000ccc2c80,4,a),(0xfffffe000ccc2c60,4,b)])
 q['initial_phases']=z3.Or(obj.read('w19')!=0x8c8,obj.read('w23')!=0x1f4,obj.read('w22')!=0x1f4,
  obj.read('w8')!=((b-a)^0x298d3f88)*0xea5ebdeb)
 obj=run('key_data_address',0xfffffe000a54aa38,0xfffffe000a54aa44,{'sp':F},[(F+0x60,8,context)])
 q['key_data_address']=value(obj,0xa0,8)!=context+0x184
 obj=run('initial_copy_args',0xfffffe000a54aa54,0xfffffe000a54aa60,{'x29':F+0x340})
 q['initial_copy_args']=z3.Or(obj.read('x0')!=F+0x270,obj.read('x1')!=F+0x280,obj.read('x2')!=16)
 flag=z3.BitVec('middle_control_flag32',32)
 obj=run('initial_continuation',0xfffffe000a54aa68,0xfffffe000a54aa84,
  {'sp':F,'w22':0x1f4,'w19':0x8c8},[(F+0x6c,4,flag)])
 q['initial_continuation']=z3.Or(obj.read('w8')!=0,obj.read('w9')!=z3.If(flag==0,resize(0x906,32),resize(0x8c8,32)))
 obj=run('chunk_count_and_buffer',0xfffffe000a526a24,0xfffffe000a526a40,
  {'sp':F,'w27':total,'w8':offset},[(F+0xf0,8,0xfffffe000ccc7848),(0xfffffe000ccc7848,8,buffer)])
 q['chunk_count_and_buffer']=z3.Or(obj.read('w22')!=chunk,obj.read('x0')!=buffer)
 q['chunk_partition']=z3.And(valid,z3.Or(chunk==0,z3.UGT(chunk,CAP),(chunk&15)!=0,
  z3.UGT(offset+chunk,total),z3.ULE(offset+chunk,offset)))
 obj=run('chunk_controller',0xfffffe000a526a40,0xfffffe000a526a60,
  {'sp':F,'x24':0xfffffe000ccc2c80,'x20':0x6c627538298d3f88},
  [(F+0x1b0,8,0xfffffe000ccc2c60),(0xfffffe000ccc2c80,4,a),(0xfffffe000ccc2c60,4,b)])
 q['chunk_controller']=z3.Or(obj.read('x19')!=0xfffffe000ccc2c60,obj.read('w21')!=0xea5ebdeb,
  obj.read('w9')!=((a+b)^0x298d3f88)*0xea5ebdeb)
 obj=run('chunk_save_offset',0xfffffe000a526a7c,0xfffffe000a526a80,{'w8':offset})
 q['chunk_save_offset']=obj.read('w25')!=offset
 obj=run('chunk_copy_args',0xfffffe000a526a90,0xfffffe000a526a9c,
  {'sp':F,'x25':resize(offset,64),'x22':resize(chunk,64)},[(F+0xe0,8,src)])
 q['chunk_copy_args']=z3.Or(obj.read('x1')!=src+resize(offset,64),obj.read('x2')!=resize(chunk,64))
 obj=run('hardware_args',0xfffffe000a526aec,0xfffffe000a526afc,
  {'sp':F,'x29':F+0x340,'x27':resize(total,64)},[(F+0xa0,8,context+0x184)])
 q['hardware_args']=z3.Or(obj.read('x0')!=context+0x184,obj.read('x1')!=F+0x270,obj.read('x2')!=resize(total,64),obj.read('x3')!=1)
 result=z3.BitVec('wrapper_result64',64)
 obj=run('hardware_result_gate',0xfffffe000a526b04,0xfffffe000a526b1c,{'x0':result,'w23':0x1f4})
 q['hardware_result_gate']=obj.read('w8')!=z3.If(resize(result,32)==0,resize(0x8a1,32),resize(0x1f4,32))
 obj=run('hardware_failure_status',0xfffffe000a526b20,0xfffffe000a526b2c,{})
 q['hardware_failure_status']=obj.read('w21')!=0x06371eb6
 obj=run('output_phase_and_pointer',0xfffffe000a53664c,0xfffffe000a536674,
  {'sp':F,'w23':0x1f4,'x25':resize(offset,64)},[(F+0xd8,8,dst)])
 tagmask=resize(0xffc0000000000000,64)
 q['output_phase_and_pointer']=z3.Or(obj.read('w19')!=0x6e3,obj.read('x0')!=dst+resize(offset,64),
  obj.equal!=(((dst^(dst+resize(offset,64)))&tagmask)==0))
 raw=z3.BitVec('output_pointer_before_tag64',64)
 obj=run('output_tag_replacement',0xfffffe000a536678,0xfffffe000a53667c,{'x0':raw})
 q['output_tag_replacement']=obj.read('x0')!=((raw&0x0000ffffffffffff)|0xc8a2000000000000)
 obj=run('output_buffer',0xfffffe000a5366b0,0xfffffe000a5366b8,{'sp':F},
  [(F+0xf0,8,0xfffffe000ccc7848),(0xfffffe000ccc7848,8,buffer)])
 q['output_buffer']=obj.read('x1')!=buffer
 obj=run('output_copy_count',0xfffffe000a5366c8,0xfffffe000a5366cc,{'x22':resize(chunk,64)})
 q['output_copy_count']=obj.read('x2')!=resize(chunk,64)
 obj=run('output_continuation',0xfffffe000a5366d4,0xfffffe000a5366f0,
  {'w22':chunk,'w25':offset,'w27':total,'w19':0x6e3,'w23':0x1f4})
 q['output_continuation']=z3.Or(obj.read('w8')!=offset+chunk,
  obj.read('w9')!=z3.If(z3.ULT(offset+chunk,total),resize(0x70d,32),resize(0x1f4,32)))
 obj=run('output_success_status',0xfffffe000a5366f4,0xfffffe000a5366fc,{})
 q['output_success_status']=obj.read('w21')!=0x06371ecc
 obj=run('finish',0xfffffe000a591e68,0xfffffe000a591e78,{'sp':F},
  [(F+0x1f4,4,0x6e3),(F+0x1b0,8,0xfffffe000ccc2c60),(F+0x78,8,0xfffffe000a527b24)])
 q['finish']=z3.Or(obj.read('w30')!=0x6e3,obj.read('x8')!=0x6e3,obj.read('x24')!=0xfffffe000ccc2c60,obj.read('x9')!=0xfffffe000a527b24)
 q['conditional_outer_statuses']=z3.Or(resize(0x06371ecc,32)+0xf9c8e134!=0,resize(0x06371eb6,32)+0xf9c8e134!=0xffffffea)
 provider,descriptor=z3.BitVecs('native_provider64 native_descriptor64',64)
 obj=run('provider_arguments',0xfffffe000a5083f0,0xfffffe000a508410,
  {'x0':context+0x184,'x1':F+0x270,'x2':resize(total,64),'x3':1},
  [(0xfffffe000ccceb08,8,provider),(0xfffffe000ccceb10,8,descriptor)])
 q['provider_arguments']=z3.Or(obj.read('x0')!=provider,obj.read('x1')!=descriptor,obj.read('x3')!=resize(total,64),
  obj.read('x4')!=F+0x270,obj.read('x5')!=1,obj.read('x6')!=context+0x184)
 obj=run('provider_tail',0xfffffe000a508420,0xfffffe000a508440,
  {'sp':F,'x16':0xfffffe0008588380,'x1':descriptor},[(0xfffffe0008588c10,8,0xfffffe000abff358)])
 q['provider_tail']=z3.Or(obj.read('x8')!=0xfffffe000abff358,obj.read('x2')!=descriptor,obj.read('x7')!=0,
  value(obj,0,8)!=0,value(obj,8,8)!=0,value(obj,16,8)!=0)
 obj=run('wrapper_failure',0xfffffe000a508458,0xfffffe000a508460,{})
 q['wrapper_failure']=z3.Or(obj.read('w19')!=0xffffffea,obj.read('w0')!=0xffffffea)
 obj=run('wrapper_success',0xfffffe000a50846c,0xfffffe000a508474,{})
 q['wrapper_success']=obj.read('x0')!=0
 obj=run('wrapper_error_return',0xfffffe000a508470,0xfffffe000a508474,{'w19':0xffffffea})
 q['wrapper_error_return']=obj.read('x0')!=0xffffffea
 cuts={
  'initial_copy':(0xfffffe000a54aa1c,0xfffffe000a54aa54,'w8','x8',{0x130:BANK_B[0],0x128:BANK_B[1]}),
  'copy_in':(0xfffffe000a526a60,0xfffffe000a526a90,'w9','x8',{0x130:BANK_B[0],0x128:BANK_B[1]}),
  'hardware':(0xfffffe000a526ac0,0xfffffe000a526aec,'w8','x8',{0x190:BANK_E[0],0x1c0:BANK_E[1]}),
  'copy_out':(0xfffffe000a536694,0xfffffe000a5366c8,'w8','x8',{0x140:BANK_G[0],0x138:BANK_G[1],0xf0:0xfffffe000ccc7848}),
 }
 for name,(start,end,reg,out,cells) in cuts.items():
  upper=z3.BitVec('bank_upper24_'+name,24);rows=[];obligations=[];wanted=RULES[name][3]
  for byte in range(256):
   obj=run('bank_'+name,start,end,{'sp':F,'x28':TABLE,**({'w8':offset} if name=='copy_in' else {}),reg:z3.Concat(upper,resize(byte,8))},
    [(F+o,8,v) for o,v in cells.items()]+([(0xfffffe000ccc7848,8,buffer)] if name=='copy_out' else [])+
    ([(F+0x60,8,context)] if name=='initial_copy' else []),256)
   target=z3.simplify(obj.read(out));assert z3.is_bv_value(target) and target.as_long()==wanted
   assert len(obj.bank_reads)==2;obligations.append(target!=wanted)
   rows.append({'input_byte':byte,'target':hex(wanted),'reads':obj.bank_reads})
  q['bank_'+name]=z3.Or(*obligations)
  banks[name]={'start':hex(start),'end':hex(end),'input_register':reg,'arbitrary_upper_input_bits':24,'rows':rows}
 results={}
 for name,query in q.items():
  solver=z3.Solver();solver.set(timeout=15000);solver.add(query);r=solver.check();print(name,r,flush=True)
  assert r==z3.unsat,(name,str(r),solver.reason_unknown());results[name]={'result':'unsat','query':solver.sexpr()}
 query=z3.And(result!=0,resize(result,32)==0);solver=z3.Solver();solver.add(query);assert solver.check()==z3.sat
 return {'proofs':results,'negative_controls':{'upper_result_bits_are_not_tested':{'result':'sat','query':solver.sexpr(),
  'result64':hex(solver.model().eval(result).as_long()),'native_target_state':False}},
  'source_pieces':pieces,'source_lift_counts':counts,'table_loads':loads,'bank_source_cuts':banks,
  'verified_counts':{'queries_unsat':len(results),'negative_controls_sat':1,'source_pieces':len(pieces),
   'source_lifted_instances':sum(counts.values()),'bank_rules':4,'bank_byte_inputs':1024,
   'bank_source_lifted_instances':sum(counts['bank_'+n] for n in cuts)},
  'selected_contract':{'original_operations':[1,5],'context_window_offset_B':0x134,'context_window_length_B':16,
   'key_data_offset_B':0x184,'context_copy_frame_offset_B':0x280,'working_IV_frame_offset_B':0x270,
   'staging_cap_B':CAP,'provider_operation32':1,'provider_length_is_saved_total32':True,
   'copy_length_is_chunk32':True,'conditional_outer_success32':'0x0','conditional_outer_failure32':'0xffffffea',
   'public_operation_meanings_proven':False,'whole_operation_overlap_contract_proven':False,
   'native_descriptor_capacity_matched':False,'native_epoch_matched':False,'daemon_request_lineage_proven':False},
  'new_IDA_access':False,'new_native_execution':False,'new_IDB_mutations':False,'full_goal_complete':False}


def build():
 k=Kernel();spans=[]
 for label,(a,z) in SPANS.items():
  row=span(k,a,z);row['bytes_hex']=row.pop('bytes');row['label']=label;spans.append(row)
 output=prove({'spans':spans});addresses={int(a,16) for a in output['table_loads']}
 addresses|={TABLE+8*i for i in [0x17,0x12c,0x6ab,0x389,0x33c,0x850,0x87e,0x906,0x8c8,0x8a1,0x1f4,0x70d]}
 addresses|={0xfffffe000847c4c8,0xfffffe0008588c10}
 slots={hex(a):pointer(k,a) for a in sorted(addresses)}
 rules={}
 for name,(pair,key,add,target) in RULES.items():
  row=selected(*pair,key,add,TABLE);assert int(row['target'],16)==target
  row['banks_hex']=[IMAGE.read(a,256).hex() for a in pair];row['original_fixup']=pointer(k,int(row['slot'],16));rules[name]=row
 output['verified_counts'].update(spans=len(spans),instructions=sum(len(s['instructions']) for s in spans),
  code_B=sum(len(bytes.fromhex(s['bytes_hex'])) for s in spans),original_loaded_slots=len(output['table_loads']),original_slots=len(slots))
 source=ROOT.parent/'com.apple.driver.FairPlayIOKit.c';lines=read(source).splitlines(keepends=True)
 return {'scope':__doc__,'generator_sha256':sha(__file__),'kernel_collection_sha256':k.sha256,
  'normalized_image_sha256':sha(SOURCE),'spans':spans,'slots':slots,'rules':rules,'solver_version':z3.get_version_string(),
  'exact_symbols':k.symbols([0xfffffe000abff358,0xfffffe000c647f10]),
  'supplied_reference':{'path':source.name,'sha256':sha(source),'excerpts':[
   {'first_line':a,'last_line':z,'text':''.join(lines[a-1:z])} for a,z in [(98474,98515),(69081,69175)]]},
  'dependencies':{n:sha(ROOT/n) for n in ['recover_lskd_byte_spans.py','lskd_byte_spans_checks.json',
   'lskd_context_return_checks.json','lskd_reader_lineage_checks.json','kext_aes_handoff_contracts.json',
   'kernel_native_reader.py','kext_port_tools.py','recover_kext_cold_init.py','recover_aes_cleanup_epoch.py',
   'lskd_values_symbolic.py','verify_daemon_reader_record_payloads_publication.py']},**output}


if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--verify',action='store_true');args=parser.parse_args()
 output=build();path=ROOT/'lskd_hardware_staging_checks.json'
 if args.verify:assert json.loads(read(path))==output
 else:path.write_text(json.dumps(output,indent=2)+'\n')
 print(json.dumps(output['verified_counts']))
