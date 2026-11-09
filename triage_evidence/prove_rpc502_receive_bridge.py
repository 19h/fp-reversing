#!/usr/bin/env python3
"""Source-lifted VM-copy/descriptor/MIG identities under explicit private premises.
O(source/BV/array DAGs+solver resources) time/space. No native VM or IPC.
"""
import json
import z3
from daemon_receive_tools import ROOT
from daemon_output_base_dispatch import CS
from prove_kernel_reply_send import Local as Parent,Bytes
from lskd_values_symbolic import resize,mem,cell
from capture_daemon_record720 import sha
class Local(Parent):
 def run(self,label):
  row=self.c['spans'][0];old=self.c
  for i in CS.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.mnemonic=='adds'and i.address==0xfffffe000bdd1494:
    a=self.read('x1');b=z3.BitVecVal(48,64);r=a+b;self.write('x8',r);self.negative=z3.Extract(63,63,r)==1;self.equal=r==0;self.carry=z3.UGE(z3.ZeroExt(1,a)+z3.ZeroExt(1,b),1<<64);self.overflow=z3.And(z3.Extract(63,63,a)==z3.Extract(63,63,b),z3.Extract(63,63,r)!=z3.Extract(63,63,a));self.count+=1
   elif i.mnemonic=='sxtw'and i.address in [0xfffffe000bdd1538,0xfffffe000bcc5858]:self.write(i.reg_name(i.operands[0].reg),z3.SignExt(32,self.read(i.reg_name(i.operands[1].reg))));self.count+=1
   elif i.mnemonic=='ccmp'and i.address in [0xfffffe000bdd14ac,0xfffffe000bdd14b0]:
    a,b=[self.operand(i,o,64)for o in i.operands[:2]];take=self.condition(i.op_str.rsplit(',',1)[1].strip());r=a-b;flags=[z3.Extract(63,63,r)==1,r==0,z3.UGE(a,b),z3.And(z3.Extract(63,63,a)!=z3.Extract(63,63,b),z3.Extract(63,63,r)!=z3.Extract(63,63,a))];imm=i.operands[2].imm;self.negative,self.equal,self.carry,self.overflow=[z3.If(take,f,z3.BoolVal(bool(imm&bit)))for f,bit in zip(flags,[8,4,2,1],strict=True)];self.count+=1
   else:self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one')
  self.c=old
class PackedBytes(Bytes):
 def run(self,label):
  row=self.c['spans'][0];old=self.c
  for i in CS.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.mnemonic=='cinc':assert i.address==0xfffffe000bcc65d8 and i.op_str=='w24, w16, eq';self.write('w24',z3.If(self.condition('eq'),self.read('w16')+1,self.read('w16')));self.count+=1
   else:self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one')
  self.c=old
def obligations():
 c=json.loads((ROOT/'rpc502_receive_bridge_source.json').read_text());prior=json.loads((ROOT/'kernel_receive_delivery_source.json').read_text());qs=[];counts={}
 def raw(a,z):
  if a<0xfffffe0000000000:s=int(c['daemon_guard']['start'],16);return bytes.fromhex(c['daemon_guard']['bytes_hex'])[a-s:z-s]
  f=next(f for f in c['functions']+prior['functions']if int(f['start'],16)<=a<z<=int(f['end'],16));s=int(f['start'],16);return bytes.fromhex(f['bytes'])[a-s:z-s]
 def run(name,a,z,seeds=(),memory=(),cls=Local):
  m=cls({'spans':[{'label':name,'start':hex(a),'bytes_hex':raw(a,z).hex()}]})
  for r,v in seeds:m.seed(r,v)
  for at,n,v in memory:
   if issubclass(cls,Bytes):m.store(z3.BitVecVal(at,64),n,resize(v,8*n),0)
   else:mem(m,at,n,v)
  m.negative,m.equal,m.carry,m.overflow=[z3.Bool('rb_'+name+'_'+f)for f in ['N','Z','C','V']];m.run(name);counts[name]=m.count;return m
 M,S,COPY,MAP,REPLY,USER=0x6500012064,0x65000ef000,0x6500068000,0x650004a000,0x6500080000,0x6500050000
 N=z3.BitVec('rb_descriptor_extent32',32);C=z3.BitVec('rb_copy_extent64',64);PTR,LO,HI=z3.BitVecs('rb_copy_pointer64 rb_pool_lower64 rb_pool_upper64',64)
 m=run('copy_span',0xfffffe000bdd1494,0xfffffe000bdd1498,[('x1',PTR)]);n=run('copy_bounds',0xfffffe000bdd14a8,0xfffffe000bdd14b4,[('x10',LO),('x1',PTR),('x8',m.read('x8')),('x9',HI)]);qs.append(('all_nonoverflow_copy_span_bounds',z3.And(z3.ULE(PTR,(1<<64)-49),n.condition('hi')!=z3.Not(z3.And(z3.ULE(LO,PTR),z3.ULE(PTR+48,HI))))))
 BASE=z3.BitVec('rb_zone_metadata_base64',64);m=run('zone_index',0xfffffe000bdd14c0,0xfffffe000bdd14cc,[('x1',PTR),('x8',BASE)]);qs.append(('all_copy_zone_index_words',m.read('x8')!=BASE+(z3.LShR(PTR,10)&0xffffffff0)))
 META=z3.BitVec('rb_zone_metadata16',16);m=run('zone_class',0xfffffe000bdd14cc,0xfffffe000bdd14d8,[('x8',COPY)],[(COPY,2,META)]);qs.append(('all_copy_zone_metadata_words',m.condition('eq')!=((META&0x3ff)==0x13)))
 m=run('original_extent_widen',0xfffffe000bcc5678,0xfffffe000bcc5680,[('x19',M),('x29',S)],[(M+12,4,N)]);qs.append(('all_original_descriptor_extent_words',cell(m,S-0x58,8)!=z3.ZeroExt(32,N)))
 m=run('kernel_buffer_extent',0xfffffe000bdd14f8,0xfffffe000bdd14fc,[('x9',z3.ZeroExt(32,N)),('x8',C)]);qs.append(('all_kernel_buffer_extent_comparisons',m.condition('eq')!=(C==z3.ZeroExt(32,N))))
 m=run('entry_lower',0xfffffe000bdd1508,0xfffffe000bdd150c,[('x8',C),('x9',z3.ZeroExt(32,N))]);n=run('entry_upper',0xfffffe000bdd1530,0xfffffe000bdd1548,[('w10',14),('x11',0x3fff),('x9',z3.ZeroExt(32,N)),('x8',C)]);rounded=(z3.ZeroExt(32,N)+0x3fff)&0xffffffffffffc000;qs.append(('all_page14_entry_extent_words',z3.Or(n.read('x9')!=rounded,z3.And(z3.Not(m.condition('lo')),n.condition('ls'))!=z3.And(z3.UGE(C,z3.ZeroExt(32,N)),z3.ULE(C,rounded)))))
 m=run('entry_extent_output',0xfffffe000bdd1554,0xfffffe000bdd155c,[('x8',C),('x2',S)]);qs.append(('all_validated_extent_output_words',z3.Or(cell(m,S,8)!=C,m.read('w0')!=1)))
 MAPWORD,COPYWORD,OUTPUT=z3.BitVecs('rb_map64 rb_copy64 rb_address_output64',64);m=run('direct_mapper',0xfffffe000bcc56d0,0xfffffe000bcc56e8,[('x29',S),('x22',MAPWORD),('x24',COPYWORD)],[(S-0x58,8,C)]);qs.append(('all_direct_mapper_argument_words',z3.Or(m.read('x0')!=MAPWORD,m.read('x1')!=S-0x60,m.read('x2')!=COPYWORD,m.read('x3')!=C,m.read('x4')!=1)))
 OFFSET=z3.BitVec('rb_copy_offset64',64);m=run('allocation_span',0xfffffe000bcc5840,0xfffffe000bcc5868,[('w9',14),('x8',OFFSET),('x29',S)],[(S-0x58,8,C)]);qs.append(('all_page14_allocation_span_words',m.read('x25')!=(((OFFSET+C+0x3fff)&0xffffffffffffc000)-(OFFSET&0xffffffffffffc000))))
 ADDRESS=z3.BitVec('rb_mapped_address64',64);m=run('publish_descriptor',0xfffffe000bcc55b4,0xfffffe000bcc55bc,[('x19',M),('x8',ADDRESS),('x26',C)]);qs.append(('all_descriptor_address_and_narrowed_extent_words',z3.Or(cell(m,M,8)!=ADDRESS,cell(m,M+12,4)!=z3.Extract(31,0,C))))
 MASK=z3.BitVec('rb_body_error_mask32',32);m=run('body_result',0xfffffe000bcc5ac4,0xfffffe000bcc5ad8,[('w28',MASK)]);qs.append(('all_aggregated_body_error_words',m.read('w0')!=z3.If(MASK==0,z3.BitVecVal(0,32),MASK|0x1000400c)))
 FLAGS=z3.BitVec('rb_descriptor_flags32',32);ADDRESS=z3.BitVec('rb_descriptor_user_address64',64)
 m=run('map64_descriptor_flags',0xfffffe000bcc65c4,0xfffffe000bcc65dc,[('w6',FLAGS&0xff00),('x0',M),('x15',M+16),('x26',ADDRESS),('w16',FLAGS),('w17',0xff00ff00)],[(M+12,4,N)],PackedBytes);m.c={'spans':[{'label':'store','start':'0xfffffe000bcc64f4','bytes_hex':raw(0xfffffe000bcc64f4,0xfffffe000bcc64f8).hex()}]};m.run('store');expected=(FLAGS&0xff00ff00)|z3.If((FLAGS&0xff00)==0x100,z3.BitVecVal(1,32),z3.BitVecVal(0,32));qs.append(('all_map64_OOL_descriptor_words',z3.Or(m.load(z3.BitVecVal(M,64),8)!=ADDRESS,m.load(z3.BitVecVal(M+8,64),4)!=expected,m.load(z3.BitVecVal(M+12,64),4)!=N)))
 BITS,COUNT,SIZE=z3.BitVecs('rb_user_bits32 rb_user_descriptor_count32 rb_user_size32',32);TYPE=z3.BitVec('rb_user_descriptor_type8',8)
 a=run('daemon_complex',0x1000050c8,0x1000050cc,[('x0',USER)],[(USER,4,BITS)]);b=run('daemon_count',0x1000050d0,0x1000050d8,[('x0',USER)],[(USER+24,4,COUNT)]);d=run('daemon_size',0x1000050dc,0x1000050e4,[('x0',USER)],[(USER+4,4,SIZE)]);e=run('daemon_type',0x1000050e8,0x1000050f0,[('x0',USER)],[(USER+39,1,TYPE)]);got=z3.And((a.read('w8')&0x80000000)!=0,b.condition('eq'),d.condition('eq'),e.condition('eq'));qs.append(('all_daemon_framing_guard_words',got!=z3.And((BITS&0x80000000)!=0,COUNT==1,SIZE==80,TYPE==1)))
 REPEATED=z3.BitVec('rb_repeated_extent32',32);m=run('daemon_extent',0x1000050f4,0x100005100,[('x0',USER)],[(USER+40,4,N),(USER+52,4,REPEATED)]);qs.append(('all_daemon_repeated_extent_words',m.condition('eq')!=(N==REPEATED)))
 TTYPE,TSIZE=z3.BitVecs('rb_trailer_type32 rb_trailer_size32',32);m=run('daemon_trailer_pointer',0x100005118,0x100005120,[('x0',USER)],[(USER+80,4,TTYPE)]);n=run('daemon_trailer_size',0x100005124,0x10000512c,[('x10',m.read('x10'))],[(USER+84,4,TSIZE)]);qs.append(('all_daemon_trailer_guard_words',z3.Or(m.read('x10')!=USER+80,z3.And(m.read('w8')==0,n.condition('hi'))!=z3.And(TTYPE==0,z3.UGT(TSIZE,31)))))
 NAME=z3.BitVec('rb_service_receive_name32',32);CPU,SUB,ORIGIN=z3.BitVecs('rb_cpu64 rb_subtype64 rb_origin64',64);m=run('daemon_application_fields',0x1000051ac,0x1000051c0,[('x0',USER)],[(USER+12,4,NAME),(USER+28,8,ADDRESS),(USER+40,4,N),(USER+56,8,CPU),(USER+64,8,SUB),(USER+72,8,ORIGIN)]);qs.append(('all_daemon_application_input_words',z3.Or(m.read('w8')!=NAME,m.read('x9')!=ADDRESS,m.read('w2')!=N,m.read('x3')!=CPU,m.read('x4')!=SUB,m.read('x5')!=ORIGIN)))
 AUDIT=z3.BitVec('rb_audit_token256',256);m=run('daemon_audit_copy',0x1000051cc,0x1000051d8,[('x10',USER+80),('sp',S)],[(USER+100,32,AUDIT)],Bytes);qs.append(('all_daemon_audit_copy_bytes',m.load(z3.BitVecVal(S+0x30,64),32)!=AUDIT))
 RP=z3.BitVec('rb_daemon_reply_pointer64',64);m=run('daemon_output_pointers',0x1000051c0,0x1000051cc,[('x1',RP)]);qs.append(('all_daemon_second_record_and_count_pointers',z3.Or(m.read('x13')!=RP+0xcc,m.read('x14')!=RP+0x178,m.read('x15')!=RP+0x17c)))
 return qs,counts
if __name__=='__main__':
 qs,counts=obligations();rows=[]
 for name,q in qs:
  a=ROOT/('rpc502_receive_bridge_'+name+'_original.smt2');b=ROOT/('rpc502_receive_bridge_'+name+'.smt2');s=z3.Solver();s.add(q);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));answer=str(s.check());assert answer=='unsat',(name,answer,s.model()if answer=='sat'else s.reason_unknown());b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer});print(name,answer,flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['rpc502_receive_bridge_source.json','kernel_receive_delivery_source.json','prove_kernel_reply_send.py','daemon_arena_lifetime_symbolic.py','lskd_values_symbolic.py']},'proofs':rows,'source_lift_counts':counts,'native_target_executed':False,'native_MAC_or_PAC_executed':False,'full_goal_complete':False};(ROOT/'rpc502_receive_bridge_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
