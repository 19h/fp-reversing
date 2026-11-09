#!/usr/bin/env python3
"""Original-source bounded queue, receiver and counter identities.
Fixed disjoint object placements and declared logical signing are premises.
No native locking, authentication, scheduling or delivery proof.
O(source/BV/byte-array DAGs + solver resources) time/space.
"""
import json
import z3
from daemon_receive_tools import ROOT
from daemon_output_base_dispatch import CS
from prove_kernel_reply_send import Local,Bytes
from lskd_values_symbolic import resize,mem,cell
from capture_daemon_record720 import sha
class Atomic(Local):
 def run(self,label):
  row=next(s for s in self.c['spans']if s['label']==label)
  if int(row['start'],16)==0xfffffe000bcc8228:
   ins=next(CS.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)));assert ins.mnemonic=='ldadd'and ins.op_str=='x9, x8, [x8]';at=self.read('x8');old=self.load(at,8);self.store(at,8,old+self.read('x9'),ins.address);self.write('x8',old);self.count+=1;return self
  return super().run(label)
def obligations():
 c=json.loads((ROOT/'kernel_queue_send_source.json').read_text());qs=[];counts={}
 def raw(a,z):
  f=next(f for f in c['functions']if int(f['start'],16)<=a<z<=int(f['end'],16));b=bytes.fromhex(f['bytes']);return b[a-int(f['start'],16):z-int(f['start'],16)]
 def run(name,a,z,seeds=(),memory=(),cls=Local):
  m=cls({'spans':[{'label':name,'start':hex(a),'bytes_hex':raw(a,z).hex()}]})
  for r,v in seeds:m.seed(r,v)
  for at,n,v in memory:
   if cls is Bytes:m.store(z3.BitVecVal(at,64),n,resize(v,8*n),0)
   else:mem(m,at,n,v)
  m.negative,m.equal,m.carry,m.overflow=[z3.Bool('qs_'+name+'_'+f)for f in ['N','Z','C','V']];m.run(name);counts[name]=m.count;return m
 Q,M,H,T,R=0x6500018028,0x6500012000,0x6500030000,0x6500032000,0x6500028000
 QUEUE,MESSAGE,OPTIONS=z3.BitVecs('qs_queue64 qs_message64 qs_options64',64);m=run('queue_arguments',0xfffffe000bcc7c58,0xfffffe000bcc7c68,[('x0',QUEUE),('x1',MESSAGE),('x2',OPTIONS)]);qs.append(('all_argument_words',z3.Or(m.read('x19')!=QUEUE-0x28,m.read('x20')!=QUEUE,m.read('x21')!=MESSAGE,m.read('x23')!=OPTIONS)))
 C,L=z3.BitVecs('qs_count16 qs_limit16',16);m=run('queue_limit',0xfffffe000bcc7c68,0xfffffe000bcc7c74,[('x0',Q)],[(Q+0x10,2,C),(Q+0x12,2,L)]);qs.append(('all_queue_limit_words',m.condition('hs')!=z3.UGE(C,L)))
 m=run('reserve',0xfffffe000bcc7c78,0xfffffe000bcc7c80,[('w8',z3.ZeroExt(16,C)),('x20',Q)]);qs.append(('all_reserved_count_words',cell(m,Q+0x10,2)!=C+1))
 m=run('hard_limit',0xfffffe000bcc7cc0,0xfffffe000bcc7cc8,[('w8',z3.ZeroExt(16,C))]);n=run('hard_limit_again',0xfffffe000bcc7d14,0xfffffe000bcc7d1c,[('w8',z3.ZeroExt(16,C))]);qs.append(('all_hard_limit_words',z3.Or(m.condition('ls')!=(z3.ULE(C,0xfffd)),n.condition('lo')!=z3.ULT(C,0xfffe))))
 BITS,SIZE=z3.BitVecs('qs_header_bits32 qs_header_size32',32);m=run('send_once',0xfffffe000bcc8078,0xfffffe000bcc8084,[('x16',H)],[(H,4,BITS)]);qs.append(('all_remote_disposition_words',m.condition('eq')!=((BITS&31)==18)))
 m=run('simple_copy_size',0xfffffe000bcc4be8,0xfffffe000bcc4bf0,[('x16',H)],[(H,4,BITS),(H+4,4,SIZE)]);qs.append(('all_simple_message_size_words',m.read('w0')!=SIZE-8))
 m=run('empty_insert',0xfffffe000bcc2c20,0xfffffe000bcc2c30,[('x0',Q),('x1',M)],cls=Bytes);qs.append(('empty_queue_insertion_and_return',z3.Or(m.load(z3.BitVecVal(Q,64),8)!=M,m.load(z3.BitVecVal(M,64),8)!=M,m.load(z3.BitVecVal(M+8,64),8)!=M,m.read('w0')!=1)))
 BAD=[];PRIORITY=z3.BitVec('qs_new_qos8',8)
 for tail in [H,T]:
  m=run('nonempty_insert_'+str(tail),0xfffffe000bcc2be0,0xfffffe000bcc2bf0,[('x10',H),('x8',tail),('x1',M)],[(M+0x3e,1,PRIORITY)],Bytes);BAD.extend([m.load(z3.BitVecVal(M,64),8)!=H,m.load(z3.BitVecVal(M+8,64),8)!=tail,m.load(z3.BitVecVal(H+8,64),8)!=M,m.load(z3.BitVecVal(tail,64),8)!=M])
 qs.append(('one_and_two_node_insertion_links',z3.Or(*BAD)))
 OLD=z3.BitVec('qs_old_qos8',8);m=run('qos_compare',0xfffffe000bcc2bfc,0xfffffe000bcc2c04,[('x8',H),('w9',z3.ZeroExt(24,PRIORITY))],[(H+0x3e,1,OLD)]);n=run('qos_raise',0xfffffe000bcc2c08,0xfffffe000bcc2c0c,[('x8',H),('w9',z3.ZeroExt(24,PRIORITY))]);qs.append(('all_qos_byte_comparisons_and_updates',z3.Or(m.condition('ls')!=z3.ULE(PRIORITY,OLD),cell(n,H+0x3e,1)!=PRIORITY)))
 SEQ=z3.BitVec('qs_sequence32',32);m=run('handoff_signing_context',0xfffffe000bcc7fe8,0xfffffe000bcc7ff4,[('x23',R),('x21',MESSAGE)]);n=run('handoff_fields',0xfffffe000bcc7ff8,0xfffffe000bcc800c,[('x17',MESSAGE),('x23',R),('x20',Q)],[(Q+8,4,SEQ)]);qs.append(('all_receiver_message_and_sequence_words',z3.Or(m.read('x16')!=((R+0x3b8)&0x0000ffffffffffff)|0x33ff000000000000,cell(n,R+0x3b8,8)!=MESSAGE,cell(n,R+0x3a4,4)!=SEQ,cell(n,Q+8,4)!=SEQ+1)))
 m=run('release_reservation',0xfffffe000bcc8014,0xfffffe000bcc802c,[('x20',Q)],[(Q+0x48,8,z3.BitVec('qs_notify64',64)),(Q+0x10,2,C),(Q+0x12,2,L)]);qs.append(('all_released_count_words',z3.Or(cell(m,Q+0x10,2)!=C-1,m.condition('ls')!=z3.ULE(L,C-1))))
 MS,TS,AS,MAX=z3.BitVecs('qs_user_message_size32 qs_trailer_size32 qs_aux_size32 qs_receiver_limit32',32);m=run('receiver_size_gate',0xfffffe000bcc7e60,0xfffffe000bcc7e6c,[('x21',M),('x23',R),('w0',TS),('w25',MS)],[(M+0x30,2,z3.Extract(15,0,AS)),(R+0x388,4,MAX)]);n=run('ordinary_receiver_limit',0xfffffe000bcc7e70,0xfffffe000bcc7e74,[('w9',MAX),('w10',m.read('w10'))]);v=run('linear_receiver_limit',0xfffffe000bcc7e8c,0xfffffe000bcc7e94,[('w9',MAX),('w10',m.read('w10')),('w8',z3.ZeroExt(16,z3.Extract(15,0,AS)))]);qs.append(('all_receiver_message_extent_words',z3.Or(n.condition('lo')!=z3.ULT(MAX,MS+TS),v.condition('hs')!=z3.UGE(MAX,MS+TS+z3.ZeroExt(16,z3.Extract(15,0,AS))))))
 m=run('too_large_fields',0xfffffe000bcc7e98,0xfffffe000bcc7ea8,[('x23',R),('w25',MS),('w8',z3.ZeroExt(16,z3.Extract(15,0,AS))),('w27',0x10004001)]);n=run('rejected_receiver_fields',0xfffffe000bcc7eac,0xfffffe000bcc7ebc,[('x20',Q),('x23',R)],[(Q+0xc,4,SEQ)]);qs.append(('all_too_large_receiver_metadata_words',z3.Or(cell(m,R+0x3a8,4)!=MS,cell(m,R+0x3ac,4)!=z3.ZeroExt(16,z3.Extract(15,0,AS)),cell(m,R+0x3a0,4)!=0x10004004,cell(n,R+0x3b0,4)!=SEQ,cell(n,R+0x3b8,8)!=0,cell(n,R+0x3a4,4)!=0)))
 PTR=z3.BitVec('qs_map_word64',64);bad=[]
 for a,z,large,small in [(0xfffffe000bcc20ac,0xfffffe000bcc20c4,60,56),(0xfffffe000bcc20e8,0xfffffe000bcc2100,68,64)]:
  m=run('trailer_map_'+str(small),a,z,[('x1',H)],[(H+0x18,8,PTR)]);bad.append(m.read('w0')!=z3.If(z3.ULT(PTR,0xf0000001),z3.BitVecVal(small,32),z3.BitVecVal(large,32)))
 qs.append(('all_map_dependent_trailer_size_words',z3.Or(*bad)))
 OLD64=z3.BitVec('qs_sent_counter64',64);m=run('sent_counter',0xfffffe000bcc8228,0xfffffe000bcc822c,[('x8',H),('x9',1)],[(H,8,OLD64)],Atomic);qs.append(('all_sent_counter_words',z3.Or(cell(m,H,8)!=OLD64+1,m.read('x8')!=OLD64)))
 for name,a,z,value in [('wait_timeout',0xfffffe000bcc8190,0xfffffe000bcc8198,0x10000004),('wait_interrupted',0xfffffe000bcc81b8,0xfffffe000bcc81bc,0x10000007),('wait_restart',0xfffffe000bcc81c0,0xfffffe000bcc81cc,0x10000003)]:
  m=run(name,a,z,[('w0',0x10000004)]);qs.append((name+'_status',m.read('w0')!=value))
 return qs,counts
if __name__=='__main__':
 qs,counts=obligations();rows=[]
 for name,q in qs:
  a=ROOT/('kernel_queue_send_'+name+'_original.smt2');b=ROOT/('kernel_queue_send_'+name+'.smt2');s=z3.Solver();s.add(q);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));answer=str(s.check());assert answer=='unsat',(name,answer,s.model()if answer=='sat'else s.reason_unknown());b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer});print(name,answer,flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_queue_send_source.json','prove_kernel_reply_send.py','daemon_arena_lifetime_symbolic.py','lskd_values_symbolic.py']},'proofs':rows,'source_lift_counts':counts,'native_target_executed':False,'native_MAC_or_PAC_executed':False,'full_goal_complete':False};(ROOT/'kernel_queue_send_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
