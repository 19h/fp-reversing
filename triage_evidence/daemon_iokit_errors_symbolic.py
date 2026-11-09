#!/usr/bin/env python3
"""Original A64 caller codecs, shared status partitions and result obligations.
u32/u64 modular arithmetic, signed status predicates explicit. O(I) DAG time
and space plus30 s/query; selected phases, original tables and aligned records.
"""
import z3
from daemon_iokit_sync_symbolic import SyncLift
from lskd_values_symbolic import part,mem,cell
def queries(c):
 qs=[];counts={};phases={};R,F,H,A,B=z3.BitVecs('error_record64 error_frame64 error_helper_SP64 error_controller_A64 error_controller_B64',64);S,K=z3.BitVecs('error_status32 error_shared_key32',32);r=z3.Extract(31,0,R);ENC=S^0x8b3dc651;MASK=0x8b3dc651;M=0xa5cd4cf;T=0x73d046208eaed1a6
 def run(n,a,z,seeds=(),memory=()):
  v=SyncLift(part(c,n,a,z))
  for reg,val in seeds:v.seed(reg,val)
  for at,size,val in memory:mem(v,at,size,val)
  v.run(n);counts[n]=v.count;phases[n]=v;return v
 for n,a,z in [('main_caller_prekey',0x10062fb84,0x10062fbb0),('matching_caller_prekey',0x100318ce0,0x100318d10),('open_caller_prekey',0x1004bdbbc,0x1004bdbec)]:
  v=run(n,a,z,[('x29',R+0x78)]);qs.append((n,z3.And(R&7==0,v.read('w9')!=(r^0x8515cfbd))))
 v=run('adapter_prekey',0x100422ab0,0x100422abc,[('x0',R)]);qs.append(('adapter_prekey',v.read('w8')!=(r^0x8515cfbd)))
 def packing(n,a,z,seeds):
  v=run(n,a,z,[('sp',F),('x29',R+0x78),*seeds]);qs.append((n,z3.Or(cell(v,R,8)!=F+0x60,cell(v,R+8,4)!=ENC-K,cell(v,R+12,4)!=K+0x952a)))
 v=run('main_status_mask',0x10062fb78,0x10062fb84,[('w0',S)]);qs.append(('main_status_mask',v.read('w8')!=((S&MASK)<<1)))
 packing('main_record_pack',0x10062fbbc,0x10062fbec,[('w0',S),('w9',K),('w8',(S&MASK)<<1),('w26',0x5784),('w28',0x597a)])
 v=run('matching_phase_mask',0x100318cc0,0x100318ce0,[('w25',0x597a),('w0',S)]);qs.append(('matching_phase_mask',z3.Or(v.read('w26')!=0x5784,v.read('w8')!=((S&MASK)<<1))))
 packing('matching_record_pack',0x100318d1c,0x100318d48,[('w9',K),('w25',0x597a),('w0',S),('w8',(S&MASK)<<1)])
 first=run('open_status_save_prefix',0x100478bb4,0x100478be0,[('w0',S),('x26',0x9376)])
 v=run('open_status_save',0x100478c10,0x100478c14,[('w8',first.read('w8')),('w9',first.read('w9'))]);qs.append(('open_status_save',v.read('w27')!=S+0x6c3d1923))
 v=run('open_encoded_status',0x1004bdb24,0x1004bdbbc,[('w25',0xab5b),('w27',S+0x6c3d1923)]);qs.append(('open_encoded_status',z3.Or(v.read('w8')!=ENC,v.read('w21')!=0x4ef4,v.read('w26')!=0x5784)))
 packing('open_record_pack',0x1004bdbf8,0x1004bdc14,[('w9',K),('w8',ENC),('w21',0x4ef4)])
 v=run('adapter_record_unpack',0x100422ac8,0x100422ad8,[('x0',R),('w10',K)],[(R+8,4,ENC-K),(R+12,4,0x952a+K)]);qs.append(('adapter_record_unpack',z3.Or(v.read('w8')!=ENC,v.read('w11')!=0x952a+K)))
 unpack=v
 v=run('adapter_first_gate',0x100422ad8,0x100422b64,[('w8',ENC),('w11',0x952a+K),('w10',K),('w13',unpack.read('w13'))]);qs.append(('adapter_first_gate',z3.Or(v.read('w8')!=ENC,v.read('w10')!=0x6c14,v.read('w11')!=0x94e0,v.read('w16')!=0x952a,v.read('w13')!=z3.If(S<100,z3.BitVecVal(0x21da,32),z3.BitVecVal(0,32)))))
 v=run('status_nonpositive_gate',0x10011959c,0x10011962c,[('w8',ENC),('w11',0x94e0)]);qs.append(('status_nonpositive_gate',v.read('w12')!=z3.If(S<=0,z3.BitVecVal(0x952a,32),z3.BitVecVal(0x94e0,32))))
 v=run('positive_status_formula',0x1002cb160,0x1002cb244,[('w8',ENC),('w11',0x94e0)]);qs.append(('positive_status_formula',z3.And(S>=1,S<=99,z3.Or(v.read('w11')!=0x1e25,v.read('w10')!=((-42600-S)^MASK)))))
 qs.append(('positive_formula_prior_equivalence',z3.And(S>=1,S<=99,((-42600-S)^MASK)!=((S+0x67)^0x74c29fae))))
 v=run('negative_or_large_lt100',0x1001ddc64,0x1001ddd0c,[('w8',ENC),('w10',0x6c14)]);qs.append(('negative_or_large_lt100',z3.Or(v.read('w10')!=z3.If(S<100,z3.BitVecVal(0x6c4c,32),z3.BitVecVal(0x6c14,32)),v.read('w11')!=0x1e29,v.read('w12')!=0x6c4c)))
 v=run('status_lt256',0x100202e14,0x100202ea0,[('w8',ENC),('w12',0x6c4c)]);qs.append(('status_lt256',z3.Or(v.read('w10')!=z3.If(S<256,z3.BitVecVal(0x8201,32),z3.BitVecVal(0x6c4c,32)),v.read('w11')!=0x1e29)))
 v=run('status_lt_neg42000',0x1000d44ac,0x1000d454c,[('w8',ENC),('w11',0x1e29)]);qs.append(('status_lt_neg42000',z3.Or(v.read('w11')!=z3.If(S<-42000,z3.BitVecVal(0x3d3a,32),z3.BitVecVal(0x1e29,32)),v.read('w10')!=0x1e25,v.read('w12')!=0x1e25)))
 v=run('status_lt_neg49998',0x10003b414,0x10003b498,[('w8',ENC),('w10',0x1e25)]);qs.append(('status_lt_neg49998',v.read('w11')!=z3.If(S<-49998,z3.BitVecVal(0x1e29,32),z3.BitVecVal(0x1e25,32))))
 O,V=z3.BitVec('error_output64',64),z3.BitVec('error_value32',32)
 v=run('status_destination_publication',0x10013b168,0x10013b174,[('x0',R),('w10',V),('sp',H)],[(R,8,O)]);qs.append(('status_destination_publication',z3.Or(cell(v,O,4)!=V,v.read('sp')!=H+0x10)))
 v=run('adapter_controller_updates',0x100422a64,0x100422ab0,[('sp',H)],[(0x1010c52d8,8,A),(0x1010c4670,8,B)]);D=A+B+(H+8);qs.append(('adapter_controller_updates',z3.Or(cell(v,0x1010c52d8,8)!=((D*M)^T),cell(v,0x1010c4670,8)!=((D^T)*M))))
 default=run('status_default_word',0x10004e440,0x10004e448);qs.append(('status_default_word',default.read('w10')!=(z3.BitVecVal(-42600,32)^MASK)))
 alternate=run('status_lt256_default_word',0x100202ea4,0x100202eac);qs.append(('status_lt256_default_word',alternate.read('w10')!=default.read('w10')))
 passthrough=run('status_passthrough_word',0x10003b49c,0x10003b4a4,[('x10',0x1e25),('x8',z3.ZeroExt(32,ENC))]);qs.append(('status_passthrough_word',passthrough.read('w10')!=ENC))
 first=phases['adapter_first_gate'];selector=run('adapter_first_selector',0x100422b98,0x100422b9c,[('w13',first.read('w13')),('w16',first.read('w16'))]);qs.append(('adapter_first_selector',selector.read('w13')!=z3.If(S<100,z3.BitVecVal(0xb4f0,32),z3.BitVecVal(0x952a,32))))
 low=z3.If(phases['status_lt_neg42000'].read('w11')==0x3d3a,z3.If(phases['status_lt_neg49998'].read('w11')==0x1e25,passthrough.read('w10'),default.read('w10')),default.read('w10'))
 other=z3.If(phases['negative_or_large_lt100'].read('w10')==0x6c14,z3.If(phases['status_lt256'].read('w10')==0x8201,alternate.read('w10'),low),low)
 result=z3.If(selector.read('w13')==0xb4f0,z3.If(phases['status_nonpositive_gate'].read('w12')==0x94e0,phases['positive_status_formula'].read('w10'),other),other)
 decoded=z3.If(z3.And(S>=1,S<=99),-42600-S,z3.If(z3.And(S>=-49998,S<=-42001),S,z3.BitVecVal(-42600,32)))
 qs.append(('composed_all_u32_status_formula',result!=(decoded^MASK)))
 output=result^MASK
 qs.append(('decoded_output_negative_interval',z3.Or(output<-49998,output>-42001)))
 repeated=z3.If(z3.And(output>=1,output<=99),-42600-output,z3.If(z3.And(output>=-49998,output<=-42001),output,z3.BitVecVal(-42600,32)))
 qs.append(('decoded_normalizer_idempotence',repeated!=output))
 return qs,counts
