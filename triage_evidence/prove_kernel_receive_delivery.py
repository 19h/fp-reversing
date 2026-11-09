#!/usr/bin/env python3
"""Original source identities for destination names, header packing and copyout.
Disjoint fixed objects, valid converted-name inputs and logical PAC are premises.
O(source/BV/array DAGs + solver resources) time/space. No native target operation.
"""
import json
import z3
from daemon_receive_tools import ROOT
from daemon_output_base_dispatch import CS
from prove_kernel_reply_send import Local as ParentLocal,Bytes
from lskd_values_symbolic import resize,mem,cell
from capture_daemon_record720 import sha
class Local(ParentLocal):
 def run(self,label):
  row=self.c['spans'][0];old=self.c
  for i in CS.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.mnemonic=='csinv':
    assert i.address in [0xfffffe000bcc53d0,0xfffffe000bcc53d8]and i.op_str.endswith(', ne');o=i.operands;self.write(i.reg_name(o[0].reg),z3.If(self.condition('ne'),self.read(i.reg_name(o[1].reg)),~self.read(i.reg_name(o[2].reg))));self.count+=1
   else:self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one')
  self.c=old
class V(Bytes):
 def read(self,name):
  if name.startswith('d')and 'q'+name[1:]in self.regs:return z3.Extract(63,0,self.regs['q'+name[1:]])
  return super().read(name)
 def write(self,name,value):
  if name.startswith('d'):self.regs['q'+name[1:]]=z3.ZeroExt(64,resize(value,64))
  else:super().write(name,value)
 def run(self,label):
  row=self.c['spans'][0];old=self.c
  for i in CS.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.mnemonic=='xtn':
    assert i.address==0xfffffe000bcc663c and i.op_str=='v1.2s, v1.2d';q=self.read('q1');self.write('q1',z3.ZeroExt(64,z3.Concat(z3.Extract(95,64,q),z3.Extract(31,0,q))));self.count+=1
   else:self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one')
  self.c=old
class Atomic(Local):
 def run(self,label):
  row=self.c['spans'][0];i=next(CS.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)))
  if i.mnemonic=='ldaddl':
   assert i.address in [0xfffffe000bcdce04,0xfffffe000bcca2c0];base='x8'if i.address==0xfffffe000bcdce04 else'x0';dest='w9'if base=='x8'else'w8';a=self.read(base);old=self.load(a,4);self.store(a,4,old+self.read(dest),i.address);self.write(dest,old);self.count+=1;return self
  return super().run(label)
def obligations():
 c=json.loads((ROOT/'kernel_receive_delivery_source.json').read_text());qs=[];counts={}
 def raw(a,z):
  f=next(f for f in c['functions']if int(f['start'],16)<=a<z<=int(f['end'],16));s=int(f['start'],16);return bytes.fromhex(f['bytes'])[a-s:z-s]
 def run(name,a,z,seeds=(),memory=(),cls=Local):
  m=cls({'spans':[{'label':name,'start':hex(a),'bytes_hex':raw(a,z).hex()}]})
  for r,v in seeds:m.seed(r,v)
  for at,n,v in memory:
   if issubclass(cls,Bytes):m.store(z3.BitVecVal(at,64),n,resize(v,n*8),0)
   else:mem(m,at,n,v)
  m.negative,m.equal,m.carry,m.overflow=[z3.Bool('rd_'+name+'_'+f)for f in ['N','Z','C','V']];m.run(name);counts[name]=m.count;return m
 D,H,S,OUT,R,T=0x6500018000,0x6500012040,0x65000ef000,0x6500058000,0x6500038000,0x650001206c
 C=z3.BitVec('rd_object_counter32',32);bad=[]
 for pc,base,dest in [(0xfffffe000bcdce04,'x8','w9'),(0xfffffe000bcca2c0,'x0','w8')]:
  m=run('object_release_'+hex(pc),pc,pc+4,[(base,D+4),(dest,0xffffffff)],[(D+4,4,C)],Atomic);bad.extend([cell(m,D+4,4)!=C-1,m.read(dest)!=C])
 qs.append(('all_object_reference_decrements',z3.Or(*bad)))
 TYPE=z3.BitVec('rd_port_type8',8);m=run('receiver_port_class',0xfffffe000bcca25c,0xfffffe000bcca26c,[('x20',D)],[(D+1,1,TYPE)]);qs.append(('all_receiver_port_class_bytes',m.condition('hi')!=z3.Not(z3.Or((TYPE&7)==1,(TYPE&7)==2))))
 A,B=z3.BitVecs('rd_port_receiver_space64 rd_current_space64',64);m=run('space_identity',0xfffffe000bcca284,0xfffffe000bcca288,[('x16',A),('x0',B)]);qs.append(('all_receiver_space_pointer_words',m.condition('eq')!=(A==B)))
 m=run('send_once_release',0xfffffe000bcca29c,0xfffffe000bcca2a8,[('x20',D)],[(D+0x8c,4,C)]);qs.append(('all_send_once_counter_words',z3.Or(cell(m,D+0x8c,4)!=C-1,m.read('w8')!=C)))
 NAME=z3.BitVec('rd_receive_name32',32);m=run('receive_name',0xfffffe000bcca2ac,0xfffffe000bcca2b4,[('x20',D)],[(D+0x34,4,NAME)]);n=run('name_output',0xfffffe000bcca2d0,0xfffffe000bcca2d4,[('x19',OUT),('w23',m.read('w23'))]);qs.append(('all_destination_receive_name_words',cell(n,OUT,4)!=NAME))
 BITS,REMOTE,VOUCHER,LOCAL=z3.BitVecs('rd_old_bits32 rd_remote_type32 rd_voucher_type32 rd_local_type32',32);m=run('header_bits',0xfffffe000bcc53a4,0xfffffe000bcc53c8,[('x22',H),('w28',REMOTE),('w24',VOUCHER),('w23',BITS),('sp',S)],[(S+0x18,4,0),(S+0x1c,4,LOCAL)]);qs.append(('all_rebuilt_header_bits',cell(m,H,4)!=((REMOTE<<8)|(VOUCHER<<16)|(BITS&0xffe0e0e0)|LOCAL)))
 RN,LN=z3.BitVecs('rd_user_remote_name32 rd_user_local_name32',32);m=run('name_widening',0xfffffe000bcc53c8,0xfffffe000bcc53e0,[('sp',S),('x22',H)],[(S+0x48,4,RN),(S+0x4c,4,LN)]);wide=lambda x:z3.If(x==0xffffffff,z3.BitVecVal((1<<64)-1,64),z3.ZeroExt(32,x));qs.append(('all_converted_name_widening_words',z3.Or(cell(m,H+8,8)!=wide(RN),cell(m,H+16,8)!=wide(LN))))
 SIZE,ID,VN,EXT,AS=z3.BitVecs('rd_kernel_size32 rd_message_id32 rd_voucher_name32 rd_trailer_extent32 rd_aux_extent32',32);RP,LP=z3.BitVecs('rd_converted_remote64 rd_converted_local64',64);header=z3.Concat(ID,VN,LP,RP,SIZE,BITS)
 m=run('header_packing',0xfffffe000bcc6630,0xfffffe000bcc6658,[('x8',H),('x0',H),('w10',SIZE),('w13',0),('w9',EXT),('w12',BITS),('x21',OUT),('w27',AS)],[(H,32,header)],V);qs.append(('all_simple_header_and_result_words',z3.Or(m.load(z3.BitVecVal(H+8,64),4)!=BITS,m.load(z3.BitVecVal(H+12,64),4)!=SIZE-8,m.load(z3.BitVecVal(H+16,64),4)!=z3.Extract(31,0,RP),m.load(z3.BitVecVal(H+20,64),4)!=z3.Extract(31,0,LP),m.load(z3.BitVecVal(H+24,64),4)!=VN,m.load(z3.BitVecVal(H+28,64),4)!=ID,m.load(z3.BitVecVal(OUT,64),4)!=SIZE-8,m.load(z3.BitVecVal(OUT+4,64),4)!=EXT,m.load(z3.BitVecVal(OUT+8,64),4)!=AS)))
 SEQ=z3.BitVec('rd_sequence32',32);CTX=z3.BitVec('rd_port_context64',64);AUDIT=z3.BitVec('rd_audit_bytes256',256)
 m=run('trailer_fields',0xfffffe000bcc6468,0xfffffe000bcc6488,[('x14',T),('w9',EXT),('x21',OUT),('x11',0xffffffffffffffff)],[(OUT+0x10,4,SEQ),(OUT+0x18,8,CTX),(T+20,32,AUDIT)],Bytes);m.c={'spans':[{'label':'context','start':'0xfffffe000bcc649c','bytes_hex':raw(0xfffffe000bcc649c,0xfffffe000bcc64a0).hex()}]};m.run('context');qs.append(('all_map64_trailer_fields_and_audit_bytes',z3.Or(m.load(z3.BitVecVal(T+4,64),4)!=EXT,m.load(z3.BitVecVal(T+8,64),4)!=SEQ,m.load(z3.BitVecVal(T+52,64),8)!=CTX,m.load(z3.BitVecVal(T+60,64),8)!=0,m.load(z3.BitVecVal(T+20,64),32)!=AUDIT)))
 U,CAP,TR=z3.BitVecs('rd_user_inline32 rd_capacity32 rd_requested_trailer32',32);m=run('capacity_gate',0xfffffe000bcc665c,0xfffffe000bcc6664,[('x1',R),('w8',U)],[(R+0x10,4,CAP)]);n=run('trailer_fit',0xfffffe000bcc6668,0xfffffe000bcc666c,[('w24',U+TR),('w9',CAP)]);b=run('trailer_truncate',0xfffffe000bcc6670,0xfffffe000bcc6678,[('w8',m.read('w8')),('x21',OUT),('x1',R)],[(R+0x10,4,CAP)]);qs.append(('all_scalar_capacity_and_truncation_words',z3.Or(m.condition('lo')!=z3.ULT(CAP,U),n.condition('ls')!=z3.ULE(U+TR,CAP),cell(b,OUT+4,4)!=CAP-U,b.read('w24')!=CAP)))
 USER,BODY,SRC=z3.BitVecs('rd_user_address64 rd_split_body64 rd_kernel_source64',64);TOTAL,PREFIX=z3.BitVecs('rd_total_copy32 rd_split_prefix32',32)
 m=run('joined_copy',0xfffffe000bcc6700,0xfffffe000bcc6708,[('x0',SRC),('x23',USER),('w24',TOTAL)]);qs.append(('all_joined_copy_argument_words',z3.Or(m.read('x0')!=SRC,m.read('x1')!=USER,m.read('x2')!=z3.ZeroExt(32,TOTAL))))
 m=run('split_first',0xfffffe000bcc66b4,0xfffffe000bcc66bc,[('x0',SRC),('x23',USER),('w26',PREFIX)]);n=run('split_second',0xfffffe000bcc66c4,0xfffffe000bcc66d0,[('x23',USER),('w26',PREFIX),('w24',TOTAL),('x25',BODY)]);qs.append(('all_split_copy_argument_words',z3.Or(m.read('x0')!=SRC,m.read('x1')!=USER,m.read('x2')!=z3.ZeroExt(32,PREFIX),n.read('x0')!=BODY,n.read('x1')!=USER+z3.ZeroExt(32,PREFIX),n.read('x2')!=z3.ZeroExt(32,TOTAL-PREFIX))))
 m=run('copy_fault_record',0xfffffe000bcc6730,0xfffffe000bcc6740,[('x21',OUT)],[(OUT+0x10,4,SEQ),(OUT+0x18,8,CTX)],Bytes);qs.append(('copy_fault_result_zeroing_and_preserved_metadata',z3.Or(m.load(z3.BitVecVal(OUT,64),8)!=0,m.load(z3.BitVecVal(OUT+8,64),4)!=0,m.read('w19')!=0x10004008,m.load(z3.BitVecVal(OUT+0x10,64),4)!=SEQ,m.load(z3.BitVecVal(OUT+0x18,64),8)!=CTX)))
 RET=z3.BitVec('rd_packing_result32',32);m=run('packing_return',0xfffffe000bcc67a4,0xfffffe000bcc67a8,[('w19',RET)]);qs.append(('all_packing_result_words',m.read('x0')!=z3.ZeroExt(32,RET)))
 RECORD=z3.BitVec('rd_optional_result_record320',320);m=run('optional_record_copy',0xfffffe000bcdcff8,0xfffffe000bcdd008,[('sp',S),('x19',OUT)],[(S+0x10,40,RECORD)],Bytes);qs.append(('all_optional_result_record_bytes',m.load(z3.BitVecVal(OUT,64),40)!=RECORD))
 return qs,counts
if __name__=='__main__':
 qs,counts=obligations();rows=[]
 for name,q in qs:
  a=ROOT/('kernel_receive_delivery_'+name+'_original.smt2');b=ROOT/('kernel_receive_delivery_'+name+'.smt2');s=z3.Solver();s.add(q);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));answer=str(s.check());assert answer=='unsat',(name,answer,s.model()if answer=='sat'else s.reason_unknown());b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer});print(name,answer,flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_receive_delivery_source.json','prove_kernel_reply_send.py','daemon_arena_lifetime_symbolic.py','lskd_values_symbolic.py']},'proofs':rows,'source_lift_counts':counts,'native_target_executed':False,'native_MAC_or_PAC_executed':False,'full_goal_complete':False};(ROOT/'kernel_receive_delivery_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
