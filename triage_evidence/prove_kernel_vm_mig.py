#!/usr/bin/env python3
"""Original local selector/hash/stub/reply/dispatch ABI proof obligations.
Valid disjoint fixed cells and explicit API return models are premises.
O(source/BV/___ DAGs + solver resources) time/space; no native IPC or PAC.
"""
import json
import z3
from daemon_receive_tools import ROOT
from daemon_output_base_dispatch import CS
from daemon_arena_lifetime_symbolic import LifetimeFlags
from lskd_values_symbolic import mem,cell
from capture_daemon_record720 import sha
from kernel_vm_mig_tools import ROUTINES,STUB,NDR
def obligations():
 source=json.loads((ROOT/'kernel_vm_mig_source.json').read_text());qs=[];counts={}
 def raw(a,n):
  for f in source['functions']:
   p=int(f['start'],16);b=bytes.fromhex(f['bytes'])
   if p<=a and a+n<=p+len(b):return b[a-p:a-p+n]
  raise AssertionError(hex(a))
 class Local(LifetimeFlags):
  def run(self,label):
   span=next(x for x in self.c['spans']if x['label']==label);old=self.c
   for i in CS.disasm(bytes.fromhex(span['bytes_hex']),int(span['start'],16)):
    if i.mnemonic=='umull':
     a,b=[self.read(i.reg_name(o.reg))for o in i.operands[1:]];self.write(i.reg_name(i.operands[0].reg),z3.ZeroExt(32,a)*z3.ZeroExt(32,b));self.count+=1
    elif i.mnemonic=='msub':
     a,b,c=[self.read(i.reg_name(o.reg))for o in i.operands[1:]];self.write(i.reg_name(i.operands[0].reg),c-a*b);self.count+=1
    else:self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one')
   self.c=old
 def run(name,a,z,seeds=(),memory=()):
  m=Local({'spans':[{'label':name,'start':hex(a),'bytes_hex':raw(a,z-a).hex()}]})
  for r,v in seeds:m.seed(r,v)
  for at,n,v in memory:mem(m,at,n,v)
  m.negative,m.equal,m.carry,m.overflow=[z3.Bool('kmig_'+name+'_'+f)for f in ['N','Z','C','V']];m.run(name);counts[name]=m.count;return m
 MID=z3.BitVec('kmig_message_id32',32);H,R,B,E,S=0x6500001000,0x6500004000,0x6500005000,0x6500008000,0x65000f0000
 m=run('selector_range',0xfffffe000bd8b340,0xfffffe000bd8b350,[('x0',H)],[(H+28,4,MID)]);inside=z3.And(z3.UGE(MID,4800),z3.ULT(MID,4830));qs.append(('all_selector_message_ids',m.condition('hs')!=inside))
 m=run('selector_offset',0xfffffe000bd8b35c,0xfffffe000bd8b370,[('x8',z3.ZeroExt(32,MID))]);offset=m.read('x8');expected=z3.ZeroExt(32,MID-4800)*32+8;qs.append(('all_in_range_selector_offsets',z3.And(inside,z3.Or(offset!=expected,m.read('x10')!=ROUTINES,offset!=z3.SignExt(32,z3.Extract(31,0,offset))))))
 m=run('hash_remainder',0xfffffe000bcf4364,0xfffffe000bcf4374,[('w13',MID),('w9',0x7f218557),('w10',1031)]);quot=z3.LShR(z3.ZeroExt(32,MID)*0x7f218557,41);qs.append(('all_source_hash_remainder_words',z3.Or(m.read('w14')!=(MID-z3.Extract(31,0,quot)*1031),m.read('w13')!=MID+1)))
 N=z3.Int('kmig_hash_input_integer');Q=(N*0x7f218557)/(1<<41);qs.append(('all_u32_hash_quotient_bounds',z3.And(N>=0,N<(1<<32),z3.Or(Q*1031>N,N>=(Q+1)*1031))))
 PORT,OUT=z3.BitVecs('kmig_port_object64 kmig_output_body64',64);m=run('port_sentinel',0xfffffe000bd8b1b4,0xfffffe000bd8b1c4,[('x0',H),('x4',OUT)],[(H+8,8,PORT)]);qs.append(('all_port_sentinel_words',z3.Or(m.condition('hs')!=z3.And(PORT!=0,PORT!=((1<<64)-1)),m.read('x20')!=OUT)))
 MAP,A,Z,RET=z3.BitVecs('kmig_converted_map64 kmig_address64 kmig_size64 kmig_VM_return64',64);m=run('VM_arguments',0xfffffe000bd8b1cc,0xfffffe000bd8b1d8,[('x1',H+32),('x19',MAP)],[(H+40,8,A),(H+48,8,Z)]);qs.append(('all_VM_argument_bits',z3.Or(m.read('x0')!=MAP,m.read('x1')!=A,m.read('x2')!=Z)))
 m=run('result_and_release',0xfffffe000bd8b1dc,0xfffffe000bd8b1e4,[('x0',RET),('x20',B),('x19',MAP)]);n=run('success_NDR',0xfffffe000bd8b1e8,0xfffffe000bd8b1f4,[('x20',B)],[(NDR,8,0x100000000)]);qs.append(('all_VM_results_and_release_arguments',z3.Or(cell(m,B+8,4)!=z3.Extract(31,0,RET),m.read('x0')!=MAP,cell(n,B,8)!=0x100000000)))
 m=run('bad_arguments_reply',0xfffffe000bd8b204,0xfffffe000bd8b218,[('x3',R)],[(NDR,8,0x100000000)]);qs.append(('bad_header_reply_fields',z3.Or(cell(m,R+40,4)!=0xfffffed0,cell(m,R+32,8)!=0x100000000)))
 BITS=z3.BitVec('kmig_in_bits32',32);LOCAL=z3.BitVec('kmig_in_reply_object64',64);m=run('reply_header',0xfffffe000bcf4760,0xfffffe000bcf4798,[('x16',R),('x8',H),('x23',NDR&~4095)],[(H,4,BITS),(H+16,8,LOCAL),(H+28,4,MID),(NDR,8,0x100000000)]);qs.append(('all_reply_header_field_bits',z3.Or(cell(m,R,4)!=(z3.LShR(BITS,8)&31),cell(m,R+4,4)!=44,cell(m,R+8,8)!=LOCAL,cell(m,R+16,8)!=0,cell(m,R+24,4)!=0,cell(m,R+28,4)!=MID+100,cell(m,R+32,8)!=0x100000000,cell(m,R+40,4)!=0)))
 INHEAD,INBODY,TRAILER,OUTHEAD,OUTBODY=z3.BitVecs('kmig_InHead64 kmig_InBody64 kmig_trailer64 kmig_OutHead64 kmig_OutBody64',64);m=run('dispatch_call',0xfffffe000bcf4814,0xfffffe000bcf4830,[('x24',E),('x22',INHEAD),('x26',INBODY),('x27',TRAILER),('x25',OUTBODY),('sp',S)],[(E+8,8,STUB),(S+32,8,OUTHEAD)]);qs.append(('all_five_stub_argument_words',z3.Or(m.read('x8')!=STUB,m.read('x17')!=0x3a83,*[m.read('x'+str(i))!=v for i,v in enumerate([INHEAD,INBODY,TRAILER,OUTHEAD,OUTBODY])])) )
 return qs,counts
if __name__=='__main__':
 qs,counts=obligations();rows=[]
 for name,q in qs:
  a=ROOT/('kernel_vm_mig_'+name+'_original.smt2');b=ROOT/('kernel_vm_mig_'+name+'.smt2');s=z3.Solver();s.add(q);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));answer=str(s.check());assert answer=='unsat',(name,answer,s.reason_unknown());b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer});print(name,answer,flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_vm_mig_source.json','daemon_arena_lifetime_symbolic.py','lskd_values_symbolic.py']},'proofs':rows,'source_lift_counts':counts,'native_target_executed':False,'full_goal_complete':False};(ROOT/'kernel_vm_mig_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
