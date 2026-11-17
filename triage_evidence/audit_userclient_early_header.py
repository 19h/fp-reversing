#!/usr/bin/env python3
"""Independent input/phase oracles and arbitrary-byte original-source proofs.
O(C*(V+E+M)+I+256R+query DAG) work/space; SMT 30 s/query limit.
"""
import json
from collections import Counter
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG
from kext_port_tools import ROOT
from kernel_native_reader import Kernel
from verify_daemon_reader_record_payloads_publication import read,sha
from lskd_values_symbolic import Lift as OriginalLift,resize,mem,cell
from audit_userclient_entry_execution import cut,proof
from replay_userclient_early_header import Replay,PRIVATE
import recover_userclient_early_header as R

class Lift(OriginalLift):
 def condition(self,c):
  n,z,carry,overflow=self.flags
  return {'eq':z,'ne':z3.Not(z),'hi':z3.And(carry,z3.Not(z)),'hs':carry,'lo':z3.Not(carry),'ls':z3.Or(z3.Not(carry),z),'ge':n==overflow,'lt':n!=overflow}[c]
 def arithmetic_flags(self,a,b,add):
  n=a.size();v=a+b if add else a-b
  return [z3.Extract(n-1,n-1,v)==1,v==0,z3.ULT(v,a)if add else z3.UGE(a,b),z3.Extract(n-1,n-1,(~(a^b)if add else(a^b))&(a^v))==1]
 def run(self,label):
  row=next(s for s in self.c['spans']if s['label']==label);raw=bytes.fromhex(row['bytes_hex']);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;ins=list(cs.disasm(raw,int(row['start'],16)));assert len(ins)*4==len(raw)
  for i in ins:
   self.pc=i.address;m=i.mnemonic;o=i.operands
   if m in ['cmp','cmn','ccmp']:
    n=self.width(i.reg_name(o[0].reg));a=self.operand(i,o[0],n);b=self.operand(i,o[1],n);flags=self.arithmetic_flags(a,b,m=='cmn')
    if m=='ccmp':
     cond=self.condition(i.op_str.rsplit(',',1)[1].strip());flags=[z3.If(cond,v,z3.BoolVal(bool(o[2].imm&(1<<j))))for v,j in zip(flags,[3,2,1,0])]
    self.flags=flags;self.count+=1
   elif m=='cset':self.write(i.reg_name(o[0].reg),z3.If(self.condition(i.op_str.rsplit(',',1)[1].strip()),resize(1,32),resize(0,32)));self.count+=1
   elif m=='tst':
    n=self.width(i.reg_name(o[0].reg));v=self.operand(i,o[0],n)&self.operand(i,o[1],n);self.flags=[z3.Extract(n-1,n-1,v)==1,v==0,z3.BoolVal(False),z3.BoolVal(False)];self.count+=1
   elif m in ['lsl','lsr']and o[2].type==ARM64_OP_REG:
    n=self.width(i.reg_name(o[0].reg));a=self.operand(i,o[1],n);shift=self.operand(i,o[2],n)&(n-1);self.write(i.reg_name(o[0].reg),a<<shift if m=='lsl'else z3.LShR(a,shift));self.count+=1
   else:self.c={'spans':[{'label':'word','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('word')
  return self
class Bytes(Lift):
 def __init__(self,c,values):super().__init__(c);self.octets=values;self.byte_addresses=[]
 def load(self,a,n):
  if n!=1:return super().load(a,n)
  j=len(self.byte_addresses);assert j<len(self.octets);self.byte_addresses.append(a);return self.octets[j]
def obligations(e):
 out=[];I,c,S,C,H=z3.BitVecs('EH_input64 EH_cursor64 EH_workspace64 EH_typed64 EH_object64',64);N,L,D=z3.BitVecs('EH_extent32 EH_length32 EH_tag32',32);U=z3.BitVec('EH_type16',16);Q=z3.BitVec('EH_payload64',64)
 def lift(a,z,values=None):return (Lift if values is None else Bytes)(cut(e,'one',(a,z))[0],*(()if values is None else(values,)))
 def seeds(v,items):
  for reg,val in items:v.seed(reg,val)
 def octets(v,n):return [z3.Extract(n*8-1-8*j,n*8-8-8*j,v)for j in range(n)]
 v=lift(0xfffffe000a660dcc,0xfffffe000a660e4c,octets(L,4));seeds(v,[('x9',c+6),('x10',I),('x8',c)]);v.run('one');out.append(proof('raw_length_BE32_and_candidate',v,z3.Or(v.read('w12')!=(L^0x652d5642),v.read('x9')!=c+10+z3.ZeroExt(32,L),v.read('x11')!=c+10,*[a!=I+c+6+j for j,a in enumerate(v.byte_addresses)])))
 v=lift(0xfffffe000a660e4c,0xfffffe000a660e84);seeds(v,[('x9',c+10+z3.ZeroExt(32,L)),('x15',z3.ZeroExt(32,N)-0x31ae0066),('w13',0x7c6)]);v.run('one');out.append(proof('body_extent_unsigned_dispatch',v,v.read('w15')!=z3.If(z3.ULE(c+10+z3.ZeroExt(32,L),z3.ZeroExt(32,N)),resize(0x7c6,32),resize(0x82d,32)),[z3.ULT(c,z3.ZeroExt(32,N))]))
 header=[z3.ULT(c,z3.ZeroExt(32,N)),z3.ULE(c+10,z3.ZeroExt(32,N))]
 v=lift(0xfffffe000a660e98,0xfffffe000a660f7c,octets(D,4));seeds(v,[('w13',0x7c6),('x8',c),('x14',0x886a1ca3),('x10',I)]);v.run('one');out.append(proof('raw_tag_BE32_and_addresses',v,z3.Or(v.read('w19')!=(D^0x31ae0066),*[a!=I+c+j for j,a in enumerate(v.byte_addresses)]),header))
 witness_c=1<<62;witness_i=0x1000;actual=z3.simplify(z3.substitute(v.byte_addresses[0],(c,resize(witness_c,64)),(I,resize(witness_i,64)))).as_long();expected=(witness_i+witness_c)&((1<<64)-1);assert actual!=expected
 out[-1]['excluded_cursor_counterexample']={'cursor64':hex(witness_c),'input_base64':hex(witness_i),'original_first_address64':hex(actual),'linear_first_address64':hex(expected),'source_extent_invariant_satisfied':False}
 v=lift(0xfffffe000a660f7c,0xfffffe000a661004,octets(U,2));seeds(v,[('x8',c),('x10',I),('w16',0x54835624),('w12',L^0x652d5642)]);v.run('one');out.append(proof('raw_type_BE16_and_length_domain',v,z3.Or(z3.Extract(15,0,v.read('w8'))!=(U^0xa2e3),v.read('w24')!=(L^0x31ae0066),*[a!=I+c+4+j for j,a in enumerate(v.byte_addresses)]),header))
 v=lift(0xfffffe000a661084,0xfffffe000a661138,octets(D,4));seeds(v,[('x11',c+10),('w12',0x386),('x10',I),('w0',0x54835624),('x4',S)]);v.run('one');out.append(proof('u32_payload_BE32_and_encoded_store',v,z3.Or(cell(v,S+4,4)!=(D^0x31ae0066),*[a!=I+c+10+j for j,a in enumerate(v.byte_addresses)]),header+[z3.ULE(c+10+len(v.byte_addresses),z3.ZeroExt(32,N))]))
 v=lift(0xfffffe000a6619bc,0xfffffe000a661b44,octets(Q,8));seeds(v,[('x11',c+10),('w10',0x386),('x12',I),('x4',S)]);v.run('one');out.append(proof('u64_payload_BE64_and_encoded_store',v,z3.Or(cell(v,S+0xc60,8)!=(Q^0x8f98c6acce5848ca),*[a!=I+c+10+j for j,a in enumerate(v.byte_addresses)]),header+[z3.ULE(c+10+len(v.byte_addresses),z3.ZeroExt(32,N))]))
 v=lift(0xfffffe000a6618fc,0xfffffe000a66190c);seeds(v,[('x2',C),('x11',c+10)]);mem(v,C+0x670,8,I);v.run('one');v.c=cut(e,'one',(0xfffffe000a661914,0xfffffe000a66191c))[0];seeds(v,[('x4',S),('x9',c+10+z3.ZeroExt(32,L))]);v.run('one');out.append(proof('span_pointer_and_cursor_publication',v,z3.Or(cell(v,C+0x690,8)!=I+c+10,cell(v,S+0xa10,8)!=c+10+z3.ZeroExt(32,L)),[(I^(I+c+10))&0xffc0000000000000==0]))
 v=lift(0xfffffe000a66191c,0xfffffe000a66193c);seeds(v,[('w10',0x1c2),('w12',0x386),('w13',D^0x652d5642)]);v.run('one');out.append(proof('span_zero_tag_early_success_index',v,v.read('w9')!=z3.If(D==0,resize(0x5a1,32),resize(0x386,32))))
 T=z3.BitVec('EH_packed_type16',16);V=z3.BitVec('EH_encoded_scalar32',32);A,B,K=z3.BitVecs('EH_encoded_scalar64 EH_span64 EH_callback64',64)
 v=lift(0xfffffe000a6614b4,0xfffffe000a6614d4);seeds(v,[('x2',C),('x4',S),('x10',K),('x25',H),('w19',D^0x31ae0066),('w8',T),('w24',L^0x31ae0066),('w26',V),('x12',A),('x9',B)]);v.run('one');out.append(proof('early_node_metadata_pack',v,z3.Or(cell(v,C+0x260,8)!=K,cell(v,C+0x20,8)!=H,cell(v,S+0x1d0,4)!=(D^0x31ae0066),cell(v,S+0x1b2,2)!=T,cell(v,S+0x94,4)!=(L^0x31ae0066),cell(v,S+0x110,4)!=V,cell(v,S+0xad0,8)!=A,cell(v,C+0x168,8)!=B),[z3.ULE(C,resize(2**64-0x1001,64)),z3.ULE(S,resize(2**64-0x4001,64)),z3.Or(z3.ULE(C+0x1000,S),z3.ULE(S+0x4000,C))]))
 v=lift(0xfffffe000a661514,0xfffffe000a661590);seeds(v,[('w3',0x886a1ca3),('w10',0x7795e642),('w13',0x63d),('w24',L^0x31ae0066),('w30',0x31ae0066)]);v.run('one');out.append(proof('node_extent_u32_add_ten_gate',v,v.read('w8')!=z3.If(z3.ULE(L,resize(0xfffffff5,32)),resize(0xce0,32),resize(0x63d,32))))
 return out

def prefix(r,parent):
 j=r['input']['header_parent_case_index']
 if j is None:return False
 p=parent['cases'][j];n=len(p['source_visits'])
 for key in ['entry_PC','entry_SP','entry_registers31','entry_NZCV','entry_Q_registers32','frame_base_SP','extra_initial_globals','probe_entries']:assert r[key]==p[key]
 for key in ['source_visits','source_frames']:assert r[key][:n]==p[key]
 for key in ['source_reads','source_writes','logical_edges','API_models']:assert [q for q in r[key]if q['source_visit_index']<n]==p[key]
 f=r['source_frames'][n]if len(r['source_frames'])>n else r['boundary']
 for key in ['SP','registers31','NZCV']:assert f[key]==p['boundary'][key]
 return True

def oracle(r,v):
 c=r['input'];name=c['profile'];i=c['inputs8'][0];s=PRIVATE+0x8000;t=PRIVATE+0xc000;h=PRIVATE+0xe000;n=c['inputs8'][1]&0xffffffff;d,u,l=c['wire_tag32'],c['wire_type16'],c['wire_length32'];data=bytes.fromhex(c['input_fixture_hex'])
 def val(a,z):assert all(j in v.known for j in range(a,a+z));return int.from_bytes(v.at(a,z),'little')
 assert r['unknown_read']is None and r['boundary']['kind']=='before_unmodeled_call'and len(r['API_models'])==3 and r['model_memory_writes']==0 and r['initial_input_bytes_declared']==len(data)
 assert val(h,8)==val(h+8,8)==0 and val(t+0xb0,8)==h and not any(j in v.known for j in range(s+0x20,s+0x24))
 reads=[q for q in r['source_reads']if i<=int(q['address'],16)<i+64];offsets=[int(q['address'],16)-i for q in reads];want=[]if name=='short_header'else[6,7,8,9]if name=='body_too_long'else[6,7,8,9,0,1,2,3,4,5]
 if name=='u32_payload':want+=list(range(10,14))
 if name in ['u64_payload','u64_payload_high32_size']:want+=list(range(10,18))
 assert offsets==want and all(q['size_bytes']==1 and q['bytes_hex']==data[a:a+1].hex()for q,a in zip(reads,offsets))
 node=name in ['blob_tag_one','blob_payload','u32_payload','u64_payload','u64_payload_high32_size'];success=name in ['blob_zero_tag','blob_unconsumed_suffix'];cursor=10+l if node or success else 0;assert val(s+0xa10,8)==cursor
 if node:
  assert r['boundary']['pc']=='0xfffffe000a661664'and r['unexecuted_call']['target']=='0xfffffe000c4ba154'and r['unexecuted_call']['arguments8'][0]=='0xfffffe000847b4a0'
  scalar32=int.from_bytes(data[10:14],'big')if name=='u32_payload'else 0;scalar64=int.from_bytes(data[10:18],'big')if name.startswith('u64_payload')else 0;span=i+10 if name.startswith('blob')else 0
  for a,z,want in [(t+0x20,8,h),(t+0x260,8,0xfffffe000a661ba0),(s+0x1d0,4,d^0x31ae0066),(s+0x1b2,2,u^0xa2e3),(s+0x94,4,l^0x31ae0066),(s+0x110,4,scalar32^0x31ae0066),(s+0xad0,8,scalar64^0x8f98c6acce5848ca),(t+0x168,8,span)]:assert val(a,z)==want
  assert val(t+0x418,8)==0
 else:
  assert r['boundary']['pc']=='0xfffffe000a6605c4'and r['unexecuted_call']['target']=='0xfffffe000c4ba368'and r['unexecuted_call']['arguments8'][:2]==['0xfffffe000847bde0',hex(h)]
  assert val(s+0xc94,4)==(0x31ae0066 if success else 0xce515bb8);cleanup=t+(0x418 if success else 0x3d0);assert val(cleanup,8)==h and int(r['boundary']['registers31'][19],16)==cleanup
 return {'profile':name,'source_visits':len(r['source_visits']),'input_offsets_read':offsets,'input_bytes_read':len(reads),'committed_cursor64':cursor,'parser_success_selected':success,'node_request_selected':node,'marker_defined_bytes':0,'all_checks_pass':True}

def audit(e=None):
 e=e if e is not None else json.loads(read(ROOT/(R.P+'_checks.json')));k=Kernel();assert e['source']==R.source(k,e['cases']);parent=json.loads(read(ROOT/'userclient_fpttlv_entry_checks.json'));totals=Counter();rows=[];matched=0
 for r in e['cases']:
  v=Replay(k,r);totals.update(v.run());matched+=prefix(r,parent);rows.append(oracle(r,v))
 assert matched==48 and sum(q['node_request_selected']for q in rows)==30 and sum(q['parser_success_selected']for q in rows)==12 and sum(q['input_bytes_read']for q in rows)==744
 from probe_userclient_early_header import Entry,cases
 case=next(c for c in cases()if c['profile']=='blob_tag_one');negatives=[]
 for pc in [0xfffffe000a660df0,0xfffffe000a6614c0]:
  mutation={'pc':pc};b=Entry(case,mutation);r=b.run();v=Replay(k,r,mutation);counts=v.run()
  try:oracle(r,v)
  except AssertionError:rejected=True
  else:rejected=False
  assert rejected;negatives.append({'mutated_PC':hex(pc),'original_word_hex':k.read(pc,4).hex(),'replacement_word_hex':'1f2003d5','boundary':r['boundary'],'independent_checks':counts,'normal_oracle_rejected':True,'undefined_value_consumed':False})
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'replay_sha256':sha(ROOT/'replay_userclient_early_header.py'),'dependencies':e['dependencies'],'source_sha256':e['source_sha256'],'kernel_collection_sha256':k.sha256,'scope':e['scope'],'verified_counts':e['verified_counts'],'independent_totals':dict(totals),'matched_parent_prefixes':matched,'cases':rows,'source_proofs':obligations(e),'negative_source_controls':negatives,'all_checks_pass':True,**{n:False for n in R.FALSE}}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps({'independent':a['independent_totals'],'queries':len(a['source_proofs']),'lifted':sum(p['lifted_instruction_instances']for p in a['source_proofs']),'controls':len(a['negative_source_controls'])}),flush=True)
