#!/usr/bin/env python3
"""Shared operation preflight, AES initializer bridge and post-call admission.

Original scalar source certificates and exhaustive 256-byte bank cuts with
arbitrary upper input bits. Valid frames, returning calls and native epochs
remain premises. O(N+I+256R) extraction/expression work and space for consumed
source/index bytes N, scalar instances I and bank rules R; SMT cost separate.
No target execution, Mach/IOKit operation or IDB mutation.
"""
import argparse
import json

import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN

from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_aes_cleanup_epoch import span
from recover_kext_cold_init import pointer
from recover_lskd_context_return import ReturnLift,TABLE
from lskd_values_symbolic import resize,part
from verify_daemon_reader_record_payloads_publication import read,sha

POOL=0xfffffe00084716e0
B=(0xfffffe00079172c0,0xfffffe0007919cb0)
C=(0xfffffe0007920d10,0xfffffe00079173c0)
E=(0xfffffe00079174c0,0xfffffe0007919db0)
F=(0xfffffe0007920c10,0xfffffe00079170c0)
G=(0xfffffe00079171c0,0xfffffe0007919bb0)
SPANS={
 'caller':(0xfffffe000a52a7d8,0xfffffe000a52a990),
 'noop':(0xfffffe000a55c9c4,0xfffffe000a55c9cc),
 'wrapper':(0xfffffe000a5607e4,0xfffffe000a56099c),
 'initializer':(0xfffffe000a508030,0xfffffe000a5081b0),
 'success_hop':(0xfffffe000a59b718,0xfffffe000a59b72c),
 'post_dispatch':(0xfffffe000a52a990,0xfffffe000a52aa54),
 'low_dispatch':(0xfffffe000a520554,0xfffffe000a520584),
 'high_dispatch':(0xfffffe000a536798,0xfffffe000a5367d0),
 'count_gate':(0xfffffe000a535ad8,0xfffffe000a535b34),
 'state4_frontier':(0xfffffe000a5238f8,0xfffffe000a52391c),
}
RULES={
 'noop':(C,0xbb,0x8d2,TABLE,0,0xfffffe000a55c9c4),
 'wrapper':(G,0x58,0x976,TABLE,0,0xfffffe000a5607e4),
 'controller_C':(E,0x18,-0xb4,POOL,0,0xfffffe000ccc2dd0),
 'controller_B':(B,0x27,-0xf,POOL,0,0xfffffe000ccc2c60),
 'table':(C,0xbb,-0x58,POOL,0,0xfffffe000846c428),
 'initializer':(F,0xaa,0x959,TABLE,0,0xfffffe000a508030),
 'cached_bytes_cell':(E,0x50,-0xae,POOL,-4,0xfffffe000ccc7848),
}
INDICES=[0x17,0x979,0x849,0x659,0x628,0x2f6,0x302,0x928,0x996,0x988]


class PreflightLift(ReturnLift):
 def __init__(self,*args):super().__init__(*args);self.pool_reads={};self.bank_reads=[]
 def load(self,address,n):
  a=z3.simplify(resize(address,64));key=(a.sexpr(),n)
  if key in self.fixed:return super().load(a,n)
  if z3.is_bv_value(a):
   at=a.as_long()
   if n==8 and POOL<=at<at+n<=POOL+0x880:
    raw=IMAGE.read(at,n);self.pool_reads[hex(at)]=raw.hex();return resize(int.from_bytes(raw,'little'),64)
   if n==1 and any(b<=at<b+256 for pair in [B,C,E,F,G] for b in pair):
    value=IMAGE.read(at,1)[0];self.bank_reads.append({'pc':hex(self.pc),'address':hex(at),'value':value});return resize(value,8)
  return super().load(a,n)
 def run(self,label):
  saved=self.c;row=next(s for s in saved['spans'] if s['label']==label)
  cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
  data=bytes.fromhex(row['bytes_hex']);insns=list(cs.disasm(data,int(row['start'],16)));assert len(insns)*4==len(data)
  for ins in insns:
   self.pc=ins.address
   if ins.mnemonic=='csel' and ins.op_str.endswith(', eq'):
    d,a,b=[ins.reg_name(o.reg) for o in ins.operands[:3]]
    self.write(d,z3.If(self.equal,self.read(a),self.read(b)));self.count+=1
   else:
    self.c={'spans':[{'label':label,'start':hex(ins.address),'bytes_hex':bytes(ins.bytes).hex()}]};super().run(label)
  self.c=saved;return self


def prove(capture):
 q={};pieces={};counts={};pool_reads={};bank_cuts={};f=0xfffffe0052000000
 r,p,key,raw64,arg2=z3.BitVecs('preflight_record64 context64 entry_key64 initializer_result64 original_X2_64',64)
 op,count=z3.BitVecs('original_W1_32 original_X4_low32',32)
 private=resize(raw64,32)+0x06371ecc
 address_key=(resize(r,32)^0x69e35e3f)*0x7a59c441
 def run(name,a,z,seeds,cells=(),writes=(),instances=1):
  obj=PreflightLift(part(capture,name,a,z))
  for reg,value in seeds.items():obj.seed(reg,value)
  for at,n,value in cells:obj.fixed[(z3.simplify(resize(at,64)).sexpr(),n)]=resize(value,n*8)
  for at,n in writes:obj.fixed_stores.add((z3.simplify(resize(at,64)).sexpr(),n))
  obj.run(name);assert obj.count==(z-a)//4
  pieces[name]={'start':hex(a),'end':hex(z),'instructions':obj.count,'instances':instances}
  counts[name]=obj.count*instances;pool_reads.update(obj.pool_reads);return obj
 def value(obj,at,n):return obj.fixed[(z3.simplify(resize(at,64)).sexpr(),n)]
 obj=run('hook_record',0xfffffe000a52a7dc,0xfffffe000a52a854,
  {'sp':f,'x29':r+0xb0,'w20':op,'w22':0x6e3},[(f+0x1f8,8,p)],[(r,8),(r+8,4),(r+12,4)])
 q['hook_record_key_and_fields']=z3.Or(obj.read('x19')!=r,obj.read('w9')!=address_key,
  obj.read('w27')!=0x7a59c441,value(obj,r,8)!=p,
  value(obj,r+8,4)!=address_key+0x5d7334cb,value(obj,r+12,4)!=(op^0x0c529166^address_key))
 obj=run('initializer_record',0xfffffe000a52a8c4,0xfffffe000a52a90c,
  {'x19':r,'x29':r+0xb0,'w27':0x7a59c441,'w22':0x6e3},writes=[(r,4)])
 q['initializer_record_key_and_field']=value(obj,r,4)!=address_key+0x4c88d07a
 obj=run('wrapper_record_root',0xfffffe000a5607f8,0xfffffe000a5607fc,{'x0':r})
 q['wrapper_record_root']=obj.read('x19')!=r
 ac,bc=z3.BitVecs('old_controller_C64 old_controller_B64',64)
 ca,cb=0xfffffe000ccc2dd0,0xfffffe000ccc2c60
 obj=run('controller_old_C',0xfffffe000a560868,0xfffffe000a56086c,{'x14':ca},[(ca,8,ac)])
 q['controller_old_C']=obj.read('x15')!=ac
 obj=run('controller_update',0xfffffe000a5608a4,0xfffffe000a5608cc,
  {'x14':ca,'x13':cb,'x15':ac,'sp':f,'x10':0x6c627538298d3f88,'w11':0xea5ebdeb},
  [(ca,8,ac),(cb,8,bc)],[(ca,8),(cb,8)])
 t=(ac^bc)+(f+8)
 q['controller_update']=z3.Or(value(obj,ca,8)!=(t-0x6c627538298d3f88)*0xea5ebdeb,
  value(obj,cb,8)!=(t^0x6c627538298d3f88)*0xea5ebdeb)
 obj=run('initializer_call_target',0xfffffe000a56094c,0xfffffe000a560958,
  {'x12':POOL,'w8':0x8b,'w13':0x9fd},[(TABLE+8*0x9fd,8,0xfffffe000a508030)])
 q['initializer_call_target']=obj.read('x8')!=0xfffffe000a508030
 obj=run('wrapper_status_projection',0xfffffe000a560960,0xfffffe000a56098c,
  {'x0':raw64,'x19':r},writes=[(r+4,4)])
 q['wrapper_status_projection']=z3.Or(value(obj,r+4,4)!=private,obj.read('x0')!=raw64)
 obj=run('caller_status_gate',0xfffffe000a52a95c,0xfffffe000a52a980,
  {'sp':f,'x29':r+0xb0,'w23':0x17},[(f+0x1f4,4,0x6e3),(r+4,4,private)])
 q['caller_status_gate']=z3.Or(obj.read('w21')!=private,obj.read('w30')!=0x6e3,
  obj.read('w8')!=z3.If(resize(raw64,32)==0,resize(0x979,32),resize(0x17,32)))
 obj=run('caller_phase_copy',0xfffffe000a52a984,0xfffffe000a52a988,{'x22':0x6e3})
 q['caller_phase_copy']=obj.read('x8')!=0x6e3
 obj=run('success_hop',0xfffffe000a59b71c,0xfffffe000a59b720,{'w22':0x6e3})
 q['success_hop']=obj.read('w8')!=0x849
 q['nonzero_initializer_result_forwarding']=(private+0xf9c8e134)!=resize(raw64,32)
 obj=run('post_selector_and_count',0xfffffe000a52a994,0xfffffe000a52a9d4,
  {'sp':f,'w22':0x6e3,'w20':op},[(f+0x110,8,r),(r+8,4,count-resize(key,32)),(f+0xe8,8,key)],[(f+0xc8,8)])
 q['post_selector_and_count']=z3.Or(value(obj,f+0xc8,8)!=z3.ZeroExt(32,count),obj.read('w8')!=0x2f6,
  obj.read('w9')!=z3.If(op<4,resize(0x659,32),resize(0x628,32)))
 obj=run('post_original_X2',0xfffffe000a52a9d8,0xfffffe000a52a9e0,
  {'sp':f,'x12':r},[(r+0x28,8,arg2)],[(f+0x1e8,8)])
 q['post_original_X2']=value(obj,f+0x1e8,8)!=arg2
 obj=run('cached_bytes_cell_root',0xfffffe000a52aa38,0xfffffe000a52aa4c,
  {'sp':f,'w10':7},writes=[(f+0xf0,8)])
 q['cached_bytes_cell_root']=value(obj,f+0xf0,8)!=0xfffffe000ccc7848
 obj=run('low_selector',0xfffffe000a520558,0xfffffe000a520578,{'w8':0x2f6,'w20':op})
 q['low_selector']=z3.Or(obj.read('w11')!=0x988,obj.read('w8')!=0x2f6,
  obj.read('w9')!=z3.If(op>=2,resize(0x302,32),resize(0x2f6,32)))
 obj=run('high_selector',0xfffffe000a53679c,0xfffffe000a5367c4,{'w22':0x6e3,'w20':op})
 q['high_selector']=z3.Or(obj.read('w9')!=0x43e,obj.read('w11')!=0x988,
  obj.read('w8')!=z3.If(op<5,resize(0x928,32),resize(0x2f6,32)))
 obj=run('count_gate',0xfffffe000a535adc,0xfffffe000a535b28,
  {'sp':f,'w11':0x988,'w20':op},[(f+0xc8,8,z3.ZeroExt(32,count))])
 threshold=z3.If(op==1,resize(32,32),resize(16,32))
 q['count_gate']=z3.Or(obj.read('x5')!=z3.ZeroExt(32,count),
  obj.read('w9')!=z3.If(z3.UGE(count,threshold),resize(0x996,32),resize(0x988,32)))
 # The ready-bit arm reads only the byte and returns zero; it does not read CCC7848.
 flag=z3.BitVec('initialized_flag8',8)
 obj=run('initializer_ready_byte',0xfffffe000a508048,0xfffffe000a508050,{},[(0xfffffe000ccceb00,1,flag)])
 q['initializer_ready_byte']=z3.Or(obj.read('w8')!=z3.ZeroExt(24,flag),obj.read('x20')!=0xfffffe000ccce000)
 obj=run('initializer_ready_status',0xfffffe000a508054,0xfffffe000a508058,{})
 q['initializer_ready_status']=obj.read('w19')!=0
 getter=z3.BitVec('getter_result64',64)
 obj=run('cached_bytes_publication',0xfffffe000a508174,0xfffffe000a50817c,
  {'x0':getter},writes=[(0xfffffe000ccc7848,8)])
 q['cached_bytes_publication']=value(obj,0xfffffe000ccc7848,8)!=getter
 state=z3.BitVec('working_context_state144_32',32)
 obj=run('state4_frontier',0xfffffe000a5238fc,0xfffffe000a523910,
  {'sp':f,'w9':0x43e},[(f+0x1f8,8,p),(p+0x144,4,state)],[(f+0x80,8)])
 q['state4_frontier']=z3.Or(value(obj,f+0x80,8)!=p+0x144,obj.read('w12')!=state,obj.read('w8')!=0x348)
 # Each byte is concrete, upper24 remains universally symbolic. Original bank
 # loads must reduce to exact concrete source bytes; unsupported reads fail.
 cuts={
  'noop':(0xfffffe000a52a888,0xfffffe000a52a8b4,'w8','w8',{'sp':f,'w22':0x6e3},[(f+0x188,8,C[0]),(f+0x180,8,C[1])],0x9b5),
  'wrapper':(0xfffffe000a52a924,0xfffffe000a52a94c,'w8','w8',{'sp':f},[(f+0x140,8,G[0]),(f+0x138,8,G[1])],0xa01),
  'controller_C':(0xfffffe000a560830,0xfffffe000a560864,'w12','w14',{},[],0x2b),
  'controller_B':(0xfffffe000a560878,0xfffffe000a5608a0,'w13','w13',{'x12':POOL},[],0x52),
  'table':(0xfffffe000a56091c,0xfffffe000a56094c,'w8','w8',{},[],0x8b),
  'initializer':(0xfffffe000a5608dc,0xfffffe000a560908,'w13','w13',{'x12':POOL},[],0x9fd),
  'cached_bytes_cell':(0xfffffe000a52aa10,0xfffffe000a52aa38,'w10','w10',{'sp':f},[(f+0x190,8,E[0]),(f+0x1c0,8,E[1])],7),
 }
 for name,(a,z,reg,out,seeds,cells,wanted) in cuts.items():
  upper=z3.BitVec('upper24_'+name,24);rows=[];obligations=[]
  for byte in range(256):
   obj=run('bank_'+name,a,z,{**seeds,reg:z3.Concat(upper,resize(byte,8))},cells,instances=256)
   result=z3.simplify(obj.read(out));assert z3.is_bv_value(result) and result.as_long()==wanted,(name,byte,result)
   assert len(obj.bank_reads)==2
   obligations.append(result!=wanted)
   if name=='noop':obligations.append(obj.read('w23')!=0x17)
   rows.append({'input_byte':byte,'index':hex(result.as_long()),'reads':obj.bank_reads})
  q['bank_'+name]=z3.Or(*obligations)
  bank_cuts[name]={'start':hex(a),'end':hex(z),'input_register':reg,'output_register':out,
   'arbitrary_upper_input_bits':24,'rows':rows,'source_lifted_instances':256*(z-a)//4}
 results={}
 for name,query in q.items():
  s=z3.Solver();s.set(timeout=10000);s.add(query);result=s.check();print(name,result,flush=True)
  assert result==z3.unsat,(name,str(result),s.reason_unknown());results[name]={'result':'unsat','query':s.sexpr()}
 cached=z3.BitVec('cached_bytes64',64)
 query=z3.And((flag&1)!=0,cached==0,resize(0x06371ecc,32)+0xf9c8e134==0)
 s=z3.Solver();s.add(query);assert s.check()==z3.sat
 negative={'ready_bit_does_not_itself_validate_cached_bytes':{'result':'sat','query':s.sexpr(),
  'model':{str(v):hex(s.model()[v].as_long()) for v in s.model()},'native_state_reachability_proven':False}}
 return {'proofs':results,'negative_controls':negative,'source_pieces':pieces,'source_lift_counts':counts,
  'pool_reads':pool_reads,'bank_source_cuts':bank_cuts,'verified_counts':{'queries_unsat':len(results),
   'negative_controls_sat':1,'source_pieces':len(pieces),'source_lifted_instances':sum(counts.values()),
   'bank_source_lifted_instances':sum(x['source_lifted_instances'] for x in bank_cuts.values()),'bank_rules':len(cuts),'bank_byte_inputs':256*len(cuts)},
  'selected_contract':{'phase32':'0x6e3','original_operations':[1,2,4,5],'context_extent_B':512,
   'initializer_result_test_width_bits':32,'operation_1_minimum_original_X4_low32':32,
   'operation_5_minimum_original_X4_low32':16,'X4_units_proven':False,
   'cached_bytes_cell':'0xfffffe000ccc7848','cached_root_is_address_of_cell':True,
   'complete_operation_semantics_proven':False,'native_epoch_matched':False,'daemon_request_lineage_proven':False},
  'new_IDA_access':False,'new_native_execution':False,'new_IDB_mutations':False,'full_goal_complete':False}


def build():
 k=Kernel();spans=[]
 for label,(a,z) in SPANS.items():
  row=span(k,a,z);row['bytes_hex']=row.pop('bytes');row['label']=label;spans.append(row)
 output=prove({'spans':spans});rules={}
 for name,(banks,key,add,base,bias,target) in RULES.items():
  row=selected(*banks,key,add,base=base,bias=bias);assert int(row['target'],16)==target
  row['original_fixup']=pointer(k,int(row['slot'],16));row['banks_hex']=[k.read(a,256).hex() for a in banks]
  assert (int(row['original_fixup']['target'],16)+bias)%(1<<64)==target
  rules[name]=row
 pool={a:pointer(k,int(a,16)) for a in output['pool_reads']}
 source=ROOT.parent/'com.apple.driver.FairPlayIOKit.c';lines=read(source).splitlines(keepends=True)
 output['verified_counts'].update(spans=len(spans),instructions=sum(len(s['instructions']) for s in spans),
  code_B=sum(len(bytes.fromhex(s['bytes_hex'])) for s in spans),original_continuation_slots=len(INDICES),original_pool_slots=len(pool))
 return {'scope':__doc__,'generator_sha256':sha(__file__),'kernel_collection_sha256':k.sha256,
  'normalized_image_sha256':sha(SOURCE),'spans':spans,'rules':rules,'pool_slots':pool,
  'continuations':{hex(i):pointer(k,TABLE+8*i) for i in INDICES},'solver_version':z3.get_version_string(),
  'supplied_reference':{'path':source.name,'sha256':sha(source),'excerpts':[
   {'first_line':a,'last_line':z,'text':''.join(lines[a-1:z])} for a,z in [(44277,44390),(83537,83573)]]},
  'dependencies':{n:sha(ROOT/n) for n in ['recover_lskd_context_return.py','lskd_context_return_checks.json',
   'lskd_reader_lineage_checks.json','aes_cleanup_epoch_source.json','kext_buffer_contracts.json',
   'kernel_native_reader.py','kext_port_tools.py','recover_kext_cold_init.py','recover_aes_cleanup_epoch.py',
   'lskd_values_symbolic.py','verify_daemon_reader_record_payloads_publication.py']},**output}


if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--verify',action='store_true');args=parser.parse_args()
 output=build();path=ROOT/'lskd_operation_preflight_checks.json'
 if args.verify:assert json.loads(read(path))==output
 else:path.write_text(json.dumps(output,indent=2)+'\n')
 print(json.dumps(output['verified_counts']))
