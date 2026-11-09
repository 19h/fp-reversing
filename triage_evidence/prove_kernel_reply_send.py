#!/usr/bin/env python3
"""Original local reply-pointer, trailer/tag, queue and cleanup equations.
Valid disjoint fixed memory placements and explicit opaque helper results
are premises. No native PACGA/key, queue, rights, lock or lifetime proof.
O(source/BV/array DAGs + solver resources) time and space.
"""
import json
import z3
from daemon_receive_tools import ROOT
from daemon_output_base_dispatch import CS
from daemon_arena_lifetime_symbolic import LifetimeFlags
from lskd_values_symbolic import mem,cell,resize
from capture_daemon_record720 import sha
class Local(LifetimeFlags):
 def width(self,name):return 128 if name.startswith('q')else super().width(name)
 def write(self,name,value):
  if name.startswith('q'):self.regs[name]=resize(value,128)
  else:super().write(name,value)
 def run(self,label):
  span=next(s for s in self.c['spans']if s['label']==label);old=self.c
  for i in CS.disasm(bytes.fromhex(span['bytes_hex']),int(span['start'],16)):
   if i.mnemonic=='ldaddl':
    assert i.address==0xfffffe000bcc72c0 and i.op_str=='w8, w8, [x0]';a=self.read('x0');oldvalue=self.load(a,4);self.store(a,4,oldvalue+self.read('w8'),i.address);self.write('w8',oldvalue);self.count+=1
   else:self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one')
  self.c=old
class Bytes(Local):
 def __init__(self,c):super().__init__(c);self.array=z3.Array('reply_send_initial_memory',z3.BitVecSort(64),z3.BitVecSort(8))
 def load(self,a,n):return z3.Concat(*[z3.Select(self.array,resize(a,64)+k)for k in reversed(range(n))])if n>1 else z3.Select(self.array,resize(a,64))
 def store(self,a,n,value,pc):
  a=resize(a,64);value=resize(value,8*n)
  for k in range(n):self.array=z3.Store(self.array,a+k,z3.Extract(8*k+7,8*k,value))
def obligations():
 c=json.loads((ROOT/'kernel_reply_send_source.json').read_text());qs=[];counts={}
 def raw(a,n):
  for f in c['functions']:
   p=int(f['start'],16);b=bytes.fromhex(f['bytes'])
   if p<=a and a+n<=p+len(b):return b[a-p:a-p+n]
  raise AssertionError(hex(a))
 def run(name,a,z,seeds=(),memory=(),cls=Local):
  m=cls({'spans':[{'label':name,'start':hex(a),'bytes_hex':raw(a,z-a).hex()}]})
  for r,v in seeds:m.seed(r,v)
  for at,n,v in memory:mem(m,at,n,v)
  m.negative,m.equal,m.carry,m.overflow=[z3.Bool('rs_'+name+'_'+f)for f in ['N','Z','C','V']];m.run(name);counts[name]=m.count;return m
 RP,HP,D,O,W=z3.BitVecs('rs_reply_pointer64 rs_header_pointer64 rs_destination64 rs_options64 rs_wait64',64);META=z3.BitVec('rs_storage_byte8',8);R,H,T,S=0x6500012000,0x6500014000,0x650001604c,0x65000eff00
 m=run('reply_handover',0xfffffe000bcc7348,0xfffffe000bcc7358,[('x0',RP)],[(RP+0x3f,1,META)]);qs.append(('all_reply_pointer_and_storage_bytes',z3.Or(m.read('x19')!=RP,m.read('w8')!=z3.LShR(z3.ZeroExt(24,META),6),m.condition('eq')!=(z3.LShR(META,6)==1))))
 a=run('inline_header',0xfffffe000bcc7360,0xfffffe000bcc7364,[('x19',RP)]);b=run('indirect_header_load',0xfffffe000bcc73d0,0xfffffe000bcc73d8,[('x19',RP)],[(RP+0xe8,8,HP)]);n=run('header_modifier',0xfffffe000bcc73dc,0xfffffe000bcc73e0,[('x17',b.read('x17'))]);qs.append(('all_header_locations_and_logical_modifiers',z3.Or(a.read('x20')!=RP+0x40,b.read('x16')!=HP,n.read('x17')!=((RP+0xe8)&0x0000ffffffffffff)|0x289d000000000000)))
 BYTE=z3.BitVec('rs_destination_byte8',8);m=run('destination_status',0xfffffe000bcc7408,0xfffffe000bcc7420,[('x20',D)],[(D+1,1,BYTE)]);qs.append(('all_destination_status_bytes',z3.Or(m.read('w24')!=z3.If((BYTE&7)==0,z3.BitVecVal(0x10000003,32),z3.BitVecVal(0,32)),m.read('w26')!=1)))
 m=run('queue_arguments',0xfffffe000bcc723c,0xfffffe000bcc724c,[('x20',D),('x19',RP),('x21',O),('x22',W)]);qs.append(('all_queue_argument_words',z3.Or(m.read('x0')!=D+0x28,m.read('x1')!=RP,m.read('x2')!=O,m.read('x3')!=W)))
 STATUS,MODE=z3.BitVecs('rs_send_status32 rs_reply_mode32',32);m=run('failure_delta',0xfffffe000bcc7254,0xfffffe000bcc7264,[('w24',STATUS)]);n=run('failure_mask',0xfffffe000bcc7268,0xfffffe000bcc7278,[('w8',m.read('w8'))]);special=z3.And(m.condition('ls'),n.condition('ne'));qs.append(('all_send_failure_classes',special!=z3.Or(*[STATUS==v for v in [0x10000003,0x10000004,0x10000007,0x1000000d]])))
 b=run('forced_cleanup',0xfffffe000bcc7284,0xfffffe000bcc7290,[('w24',STATUS)]);result=run('returned_status',0xfffffe000bcc72e0,0xfffffe000bcc72e4,[('w24',STATUS)]);reset=run('cleanup_zero_return',0xfffffe000bcc72dc,0xfffffe000bcc72e4,[('w24',STATUS)]);first=next(CS.disasm(raw(0xfffffe000bcc7294,4),0xfffffe000bcc7294));second=next(CS.disasm(raw(0xfffffe000bcc7298,4),0xfffffe000bcc7298));assert first.mnemonic=='cbz'and first.op_str=='w24, #0xfffffe000bcc72e0'and second.mnemonic=='cbnz'and second.op_str=='w26, #0xfffffe000bcc72b8';cleanup=z3.Or(z3.And(special,b.condition('eq')),z3.And(STATUS!=0,MODE!=0));qs.append(('all_failure_status_and_ownership_modes',z3.Or(cleanup!=z3.Or(STATUS==0x10000003,z3.And(STATUS!=0,MODE!=0)),z3.If(cleanup,reset.read('x0'),result.read('x0'))!=z3.If(cleanup,z3.BitVecVal(0,64),z3.ZeroExt(32,STATUS)))))
 LEN,DESC=z3.BitVecs('rs_message_size32 rs_descriptor_count32',32);a=run('contiguous_trailer',0xfffffe000bcc214c,0xfffffe000bcc2150,[('x8',HP),('w9',LEN)]);b=run('split_trailer',0xfffffe000bcc2190,0xfffffe000bcc2198,[('w9',LEN),('w8',32),('x16',RP)]);q=run('complex_header_extent',0xfffffe000bcc2184,0xfffffe000bcc2190,[('x8',H)],[(H+32,4,DESC)]);qs.append(('all_trailer_size_and_pointer_words',z3.Or(a.read('x0')!=HP+z3.ZeroExt(32,LEN),b.read('x0')!=RP+z3.ZeroExt(32,LEN-32),q.read('w8')!=DESC*16+36)))
 template=bytes.fromhex(c['kernel_template']['bytes_hex']);m=Bytes({'spans':[]});m.seed('x20',T)
 for k,v in enumerate(template[:64]):m.store(z3.BitVecVal(0xfffffe0007010a68+k,64),1,z3.BitVecVal(v,8),0)
 before=m.array;m.c={'spans':[{'label':'template','start':'0xfffffe000bcc422c','bytes_hex':raw(0xfffffe000bcc422c,28).hex()}]};m.run('template');counts['template_copy']=m.count;qs.append(('all_initial_trailer_bytes',z3.Or(*[m.load(z3.BitVecVal(T+k,64),1)!=v for k,v in enumerate(template)])));Q=z3.BitVec('rs_unrelated_address64',64);qs.append(('trailer_copy_frame_property',z3.And(z3.And(*[Q!=T+k for k in range(68)]),z3.Select(m.array,Q)!=z3.Select(before,Q))))
 HEADER=z3.BitVec('rs_header_bits256',256);BITS=z3.Extract(31,0,HEADER);bad=[]
 for complex_bit in [False,True]:
  m=Bytes({'spans':[]});m.seed('x16',H);m.seed('sp',S);m.seed('x19',RP);m.store(z3.BitVecVal(H,64),32,HEADER,0);m.store(z3.BitVecVal(H+32,64),4,DESC,0);m.c={'spans':[{'label':'copy','start':'0xfffffe000bcc4274','bytes_hex':raw(0xfffffe000bcc4274,20).hex()}]};m.run('copy')
  if complex_bit:m.c={'spans':[{'label':'count','start':'0xfffffe000bcc428c','bytes_hex':raw(0xfffffe000bcc428c,4).hex()}]};m.run('count')
  m.c={'spans':[{'label':'mask','start':'0xfffffe000bcc4290','bytes_hex':raw(0xfffffe000bcc4290,44).hex()}]};m.run('mask');cond=(z3.Extract(31,31,BITS)==1)==complex_bit;expected=z3.Concat(z3.Extract(255,32,HEADER),BITS&0x80001f1f);bad.append(z3.And(cond,z3.Or(m.load(z3.BitVecVal(S,64),32)!=expected,m.load(z3.BitVecVal(S+32,64),4)!=(DESC if complex_bit else z3.BitVecVal(0,32)),m.read('x0')!=S,m.read('x1')!=36,m.read('x2')!=((RP&0x0000ffffffffffff)|0x3409000000000000),m.read('x3')!=0)));counts['canonical_header_'+str(complex_bit)]=m.count
 qs.append(('all_canonical_header_and_first_hash_arguments',z3.Or(*bad)))
 FIRST,SECOND=z3.BitVecs('rs_first_hash_return64 rs_second_hash_return64',64);m=run('second_hash_arguments',0xfffffe000bcc42c0,0xfffffe000bcc42d0,[('x0',FIRST),('x20',HP)]);n=run('stored_tag',0xfffffe000bcc42d4,0xfffffe000bcc42dc,[('x0',SECOND),('x19',R)]);qs.append(('all_hash_return_and_tag_words',z3.Or(m.read('x0')!=HP,m.read('x1')!=68,m.read('x2')!=FIRST,m.read('x3')!=1,cell(n,R+0x38,4)!=z3.Extract(63,32,SECOND))))
 TAG=z3.BitVec('rs_existing_tag32',32);m=run('tag_verifier',0xfffffe000bcc2364,0xfffffe000bcc2370,[('x0',SECOND),('x19',R)],[(R+0x38,4,TAG)]);qs.append(('all_tag_comparison_words',m.condition('eq')!=(TAG==z3.Extract(63,32,SECOND))))
 OLD=z3.BitVec('rs_destination_counter32',32);m=run('destination_reference',0xfffffe000bcc72b8,0xfffffe000bcc72c4,[('x20',R)],[(R+4,4,OLD)]);qs.append(('all_destination_counter_words',z3.Or(m.read('x0')!=R+4,m.read('w8')!=OLD,cell(m,R+4,4)!=OLD-1)))
 FLAGS=z3.BitVec('rs_thread_flags16',16);m=run('effective_option_rewrite',0xfffffe000bcc7074,0xfffffe000bcc7084,[('x21',O),('w8',z3.ZeroExt(16,FLAGS)),('x23',R)]);qs.append(('all_rewritten_option_and_thread_flag_words',z3.Or(m.read('x21')!=((O&0xfffffffffffeffff)|0x10),cell(m,R+0xc8,2)!=(FLAGS&0xfbff))))
 return qs,counts
if __name__=='__main__':
 qs,counts=obligations();rows=[]
 for name,q in qs:
  a=ROOT/('kernel_reply_send_'+name+'_original.smt2');b=ROOT/('kernel_reply_send_'+name+'.smt2');s=z3.Solver();s.add(q);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));answer=str(s.check());assert answer=='unsat',(name,answer,s.model()if answer=='sat'else s.reason_unknown());b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer});print(name,answer,flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_reply_send_source.json','daemon_arena_lifetime_symbolic.py','lskd_values_symbolic.py']},'proofs':rows,'source_lift_counts':counts,'native_target_executed':False,'native_MAC_or_PAC_executed':False,'full_goal_complete':False};(ROOT/'kernel_reply_send_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
