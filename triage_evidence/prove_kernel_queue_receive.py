#!/usr/bin/env python3
"""Source-lifted receive/dequeue/field/status identities at disjoint placements.
Logical signed-pointer storage and declared helper preservation are premises.
O(source/BV/array DAGs + solver resources) time/space. No native target.
"""
import json
import z3
from daemon_receive_tools import ROOT
from daemon_output_base_dispatch import CS
from prove_kernel_reply_send import Local,Bytes
from lskd_values_symbolic import mem,cell,resize
from capture_daemon_record720 import sha
class Atomic(Local):
 def run(self,label):
  row=self.c['spans'][0]
  if int(row['start'],16)==0xfffffe000bcc87d4:
   i=next(CS.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)));assert i.mnemonic=='ldadd'and i.op_str=='x9, x8, [x8]';a=self.read('x8');old=self.load(a,8);self.store(a,8,old+self.read('x9'),i.address);self.write('x8',old);self.count+=1;return self
  return super().run(label)
def obligations():
 c=json.loads((ROOT/'kernel_queue_receive_source.json').read_text());qs=[];counts={}
 def raw(a,z):
  for f in c['functions']:
   start=int(f['start'],16)
   if start<=a<z<=int(f['end'],16):return bytes.fromhex(f['bytes'])[a-start:z-start]
  f=next(f for f in c['reader_fragments']if int(f['start'],16)<=a<z<=int(f['end'],16));start=int(f['start'],16);return bytes.fromhex(f['bytes_hex'])[a-start:z-start]
 def run(name,a,z,seeds=(),memory=(),cls=Local):
  m=cls({'spans':[{'label':name,'start':hex(a),'bytes_hex':raw(a,z).hex()}]})
  for r,v in seeds:m.seed(r,v)
  for at,n,v in memory:
   if cls is Bytes:m.store(z3.BitVecVal(at,64),n,resize(v,8*n),0)
   else:mem(m,at,n,v)
  m.negative,m.equal,m.carry,m.overflow=[z3.Bool('qr_'+name+'_'+f)for f in ['N','Z','C','V']];m.run(name);counts[name]=m.count;return m
 D,M,R,H,T=0x6500018000,0x6500012000,0x6500038000,0x6500030000,0x6500032000
 WQ,TIME,INTERRUPT,THREAD,CONT=z3.BitVecs('qr_waitq64 qr_timeout64 qr_interrupt64 qr_thread64 qr_continuation64',64)
 m=run('wrapper_inputs',0xfffffe000bcc83d0,0xfffffe000bcc83e4,[('x0',WQ),('x1',TIME),('x2',INTERRUPT),('x3',THREAD),('x4',CONT)]);qs.append(('all_wrapper_argument_words',z3.Or(m.read('x19')!=CONT,m.read('x20')!=THREAD,m.read('x21')!=INTERRUPT,m.read('x22')!=TIME,m.read('x23')!=WQ)))
 m=run('inner_arguments',0xfffffe000bcc83f4,0xfffffe000bcc8404,[('x23',WQ),('x22',TIME),('x21',INTERRUPT),('x20',THREAD)]);qs.append(('all_inner_argument_words',z3.Or(m.read('x0')!=WQ,m.read('x1')!=TIME,m.read('x2')!=INTERRUPT,m.read('x3')!=THREAD)))
 OPTIONS=z3.BitVec('qr_options64',64);m=run('inner_inputs',0xfffffe000bcc8534,0xfffffe000bcc8548,[('x0',WQ),('x1',TIME),('x2',INTERRUPT),('x3',THREAD)],[(THREAD+0x390,8,OPTIONS)]);qs.append(('all_thread_option_and_input_words',z3.Or(m.read('x19')!=THREAD,m.read('x20')!=WQ,m.read('x24')!=TIME,m.read('x23')!=INTERRUPT,m.read('x22')!=OPTIONS)))
 TYPE=z3.BitVec('qr_waitq_bits32',32);m=run('waitq_type',0xfffffe000bcc8548,0xfffffe000bcc8554,[('x0',WQ)],[(WQ,4,TYPE)]);qs.append(('all_waitq_type_words',z3.Or(m.read('w8')!=(TYPE&7),m.condition('eq')!=((TYPE&7)==3))))
 MSG=z3.BitVec('qr_message_pointer64',64);m=run('head',0xfffffe000bcc85a4,0xfffffe000bcc85a8,[('x20',WQ)],[(WQ+0x18,8,MSG)]);n=run('port_from_waitq',0xfffffe000bcc85ac,0xfffffe000bcc85b0,[('x20',WQ)]);qs.append(('all_port_head_pointer_words',z3.Or(m.read('x21')!=MSG,n.read('x20')!=WQ-0x10)))
 MS,TS,MAX,AUXMAX=z3.BitVecs('qr_message_extent32 qr_trailer_extent32 qr_receiver_limit32 qr_aux_limit32',32);AS=z3.BitVec('qr_aux_extent16',16)
 m=run('receive_size_sum',0xfffffe000bcc85e4,0xfffffe000bcc85f0,[('x21',M),('x19',R),('w0',TS),('w23',MS)],[(M+0x30,2,AS),(R+0x388,4,MAX)]);n=run('normal_size_cmp',0xfffffe000bcc85f4,0xfffffe000bcc85f8,[('w8',MAX),('w9',m.read('w9'))]);b=run('linear_size_cmp',0xfffffe000bcc862c,0xfffffe000bcc8634,[('w8',MAX),('w9',m.read('w9')),('w25',z3.ZeroExt(16,AS))]);qs.append(('all_receive_message_extent_words',z3.Or(n.condition('lo')!=z3.ULT(MAX,MS+TS),b.condition('hs')!=z3.UGE(MAX,MS+TS+z3.ZeroExt(16,AS)))))
 m=run('aux_limit',0xfffffe000bcc8604,0xfffffe000bcc860c,[('x19',R),('w25',z3.ZeroExt(16,AS))],[(R+0x38c,4,AUXMAX)]);qs.append(('all_receive_auxiliary_extent_words',m.condition('lo')!=z3.ULT(AUXMAX,z3.ZeroExt(16,AS))))
 NAME=z3.BitVec('qr_receiver_name32',32);m=run('peek_fields',0xfffffe000bcc8654,0xfffffe000bcc8668,[('x20',D),('x19',R),('w23',MS),('w25',z3.ZeroExt(16,AS))],[(D+0x34,4,NAME)]);qs.append(('all_large_receive_metadata_words',z3.Or(cell(m,R+0x3b0,4)!=NAME,cell(m,R+0x3b8,8)!=0,cell(m,R+0x3a8,4)!=MS,cell(m,R+0x3ac,4)!=z3.ZeroExt(16,AS))))
 pair=int.from_bytes(bytes.fromhex(c['peek_state_pair']['bytes_hex']),'little');assert pair==0x10004004;m=run('peek_state_pair',0xfffffe000bcc8668,0xfffffe000bcc8674,[('x19',R)],[(0xfffffe000700dc70,8,pair)],Bytes);qs.append(('peek_status_sequence_pair',z3.Or(m.load(z3.BitVecVal(R+0x3a0,64),4)!=0x10004004,m.load(z3.BitVecVal(R+0x3a4,64),4)!=0)))
 bad=[]
 for prev in [H,T]:
  m=run('unlink_neighbors_'+str(prev),0xfffffe000bcc86c8,0xfffffe000bcc86d0,[('x8',H),('x9',prev)],cls=Bytes);m.c={'spans':[{'label':'finish','start':'0xfffffe000bcc86e4','bytes_hex':raw(0xfffffe000bcc86e4,0xfffffe000bcc86ec).hex()}]};m.seed('x20',D);m.seed('x21',M);m.run('finish');bad.extend([m.load(z3.BitVecVal(prev,64),8)!=H,m.load(z3.BitVecVal(H+8,64),8)!=prev,m.load(z3.BitVecVal(D+0x28,64),8)!=H,m.load(z3.BitVecVal(M,64),8)!=0,m.load(z3.BitVecVal(M+8,64),8)!=0])
 qs.append(('two_and_three_node_head_unlink',z3.Or(*bad)))
 m=run('single_unlink',0xfffffe000bcc86e0,0xfffffe000bcc86ec,[('x20',D),('x21',M)],cls=Bytes);qs.append(('single_node_head_unlink',z3.Or(m.load(z3.BitVecVal(D+0x28,64),8)!=0,m.load(z3.BitVecVal(M,64),8)!=0,m.load(z3.BitVecVal(M+8,64),8)!=0)))
 C,L=z3.BitVecs('qr_count16 qr_limit16',16);m=run('release_count',0xfffffe000bcc86ec,0xfffffe000bcc8704,[('x20',D)],[(D+0x70,8,z3.BitVec('qr_notify64',64)),(D+0x38,2,C),(D+0x3a,2,L)]);qs.append(('all_dequeue_count_words',z3.Or(cell(m,D+0x38,2)!=C-1,m.condition('ls')!=z3.ULE(L,C-1))))
 SEQ=z3.BitVec('qr_sequence32',32);m=run('sequence',0xfffffe000bcc8750,0xfffffe000bcc8760,[('x20',D),('x19',R)],[(D+0x30,4,SEQ)]);qs.append(('all_dequeue_sequence_words',z3.Or(cell(m,D+0x30,4)!=SEQ+1,cell(m,R+0x3a4,4)!=SEQ)))
 RP=z3.BitVec('qr_receiver_pointer64',64);m=run('sign_context',0xfffffe000bcc87a4,0xfffffe000bcc87ac,[('x19',RP)]);qs.append(('all_receiver_signing_modifier_words',m.read('x16')!=((RP+0x3b8)&0x0000ffffffffffff)|0x33ff000000000000))
 STATUS=z3.BitVec('qr_receiver_status32',32);m=run('publish',0xfffffe000bcc87b0,0xfffffe000bcc87b8,[('x19',R),('x17',MSG),('w24',STATUS)]);qs.append(('all_published_message_and_status_words',z3.Or(cell(m,R+0x3b8,8)!=MSG,cell(m,R+0x3a0,4)!=STATUS)))
 OLD=z3.BitVec('qr_receive_counter64',64);m=run('counter',0xfffffe000bcc87d4,0xfffffe000bcc87d8,[('x8',H),('x9',1)],[(H,8,OLD)],Atomic);qs.append(('all_receive_counter_words',z3.Or(cell(m,H,8)!=OLD+1,m.read('x8')!=OLD)))
 m=run('empty_poll_state',0xfffffe000bcc8690,0xfffffe000bcc8698,[('w21',0x10004001),('x19',R)]);qs.append(('empty_poll_status',cell(m,R+0x3a0,4)!=0x10004003))
 bad=[]
 for result,value in [(1,0x10004003),(2,0x10004005),(3,0x10004006)]:
  m=run('result_base_'+str(result),0xfffffe000bcc844c,0xfffffe000bcc8454)
  if result!=1:
   a=0xfffffe000bcc8480 if result==2 else 0xfffffe000bcc84d4;m.c={'spans':[{'label':'adjust','start':hex(a),'bytes_hex':raw(a,a+4).hex()}]};m.run('adjust')
  m.seed('x8',R);m.c={'spans':[{'label':'store','start':'0xfffffe000bcc84d8','bytes_hex':raw(0xfffffe000bcc84d8,0xfffffe000bcc84dc).hex()}]};m.run('store');bad.append(cell(m,R+0x3a0,4)!=value)
 qs.append(('all_selected_wait_result_states',z3.Or(*bad)))
 S=z3.BitVec('qr_completed_state32',32);a=run('state_large',0xfffffe000bcc8490,0xfffffe000bcc849c,[('w9',S)]);b=run('state_other',0xfffffe000bcc84a0,0xfffffe000bcc84ac,[('w9',S)]);qs.append(('all_completed_state_gate_words',z3.Or(S==0,a.condition('eq'),b.condition('eq'))!=z3.Or(S==0,S==0x10004004,S==0x1000400e)))
 OPT=z3.BitVec('qr_consumer_options64',64);m=run('user_fields',0xfffffe000bcdccf8,0xfffffe000bcdcd08,[('x24',R)],[(R+0x398,8,z3.BitVec('qr_receive_object64',64)),(R+0x3a0,4,STATUS),(R+0x390,8,OPT),(R+0x3b8,8,MSG)]);n=run('rpc_fields',0xfffffe000bcf5c48,0xfffffe000bcf5c50,[('x19',R)],[(R+0x3a0,4,STATUS),(R+0x3b8,8,MSG)]);qs.append(('all_consumer_state_and_pointer_words',z3.Or(m.read('w0')!=STATUS,m.read('x21')!=OPT,m.read('x16')!=MSG,n.read('w27')!=STATUS,n.read('x16')!=MSG)))
 a=run('user_auth_context',0xfffffe000bcdcd0c,0xfffffe000bcdcd14,[('x24',RP)]);b=run('rpc_auth_context',0xfffffe000bcf5c54,0xfffffe000bcf5c5c,[('x19',RP)]);qs.append(('all_producer_consumer_modifier_words',z3.Or(a.read('x17')!=b.read('x17'),a.read('x17')!=((RP+0x3b8)&0x0000ffffffffffff)|0x33ff000000000000)))
 return qs,counts
if __name__=='__main__':
 qs,counts=obligations();rows=[]
 for name,q in qs:
  a=ROOT/('kernel_queue_receive_'+name+'_original.smt2');b=ROOT/('kernel_queue_receive_'+name+'.smt2');s=z3.Solver();s.add(q);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));answer=str(s.check());assert answer=='unsat',(name,answer,s.model()if answer=='sat'else s.reason_unknown());b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer});print(name,answer,flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_queue_receive_source.json','prove_kernel_reply_send.py','daemon_arena_lifetime_symbolic.py','lskd_values_symbolic.py']},'proofs':rows,'source_lift_counts':counts,'native_target_executed':False,'native_MAC_or_PAC_executed':False,'full_goal_complete':False};(ROOT/'kernel_queue_receive_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
