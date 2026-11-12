#!/usr/bin/env python3
"""Independent byte epochs, source-lift equations and interface joins.

O(receipt bytes+V+E+256R) time/space, plus 30 s/query. Native target operations,
native IPC, uninitialized values and pending allocator effects are excluded.
"""
import json,struct
from collections import Counter
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from lskd_values_symbolic import Lift,part,mem,cell,resize
from recover_kext_cold_init import pointer
from kext_port_tools import ROOT,IMAGE,POOL,TABLE,qword,selected
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_versioned_core_preparation as R

class Select(Lift):
 def run(self,label):
  original=self.c;row=next(s for s in self.c['spans']if s['label']==label);dc=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);dc.detail=True
  for i in dc.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   self.pc=i.address
   if i.mnemonic=='csel':
    assert i.op_str.rsplit(',',1)[1].strip()=='eq';self.write(i.reg_name(i.operands[0].reg),z3.If(self.equal,self.read(i.reg_name(i.operands[1].reg)),self.read(i.reg_name(i.operands[2].reg))));self.count+=1;continue
   self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one')
  self.c=original;return self

def proofs(regions):
 c={'spans':regions};qs=[];counts={};F=0x51010000;B=z3.BitVec('prep_working_base64',64);C=B+32;N=z3.BitVec('prep_count32',32)
 def run(name,a,z,seeds=(),memory=(),typ=Lift):
  v=typ(part(c,name,a,z))
  for r,x in seeds:v.seed(r,x)
  for a,n,x in memory:mem(v,a,n,x)
  v.run(name);counts[name]=v.count;return v
 dk=run('common_decoder_key',0xfffffe000a6173b4,0xfffffe000a6173e8,[('x23',C)])
 ck=run('common_caller_key',0xfffffe000a5a61b4,0xfffffe000a5a61fc,[('sp',F)],[(F+0xd8,8,C)])
 qs.append(('common_address_key_agreement',ck.read('w9')!=dk.read('w13')))
 # The preceding source-derived equality qualifies this shared-key composition.
 key=ck.read('w9');A,D=z3.BitVecs('prep_auxiliary64 prep_inputB64',64)
 v=run('common_caller_record',0xfffffe000a5a6160,0xfffffe000a5a623c,[('sp',F),('x29',F+0x250),('x21',B),('x27',B+16),('x23',D),('w12',2),('w22',0x3da4b356),('w30',0xc25b517a),('w8',N<<1)],[(F+0x1b8,4,N),(F+0xd8,8,C),(F+0xe8,8,A),(F+0xe0,8,A+4096),(F+0xf0,8,B+192),(F+0xf8,8,B+16320)])
 normalized=z3.simplify(cell(v,C+16,4)-key)
 if not z3.is_bv_value(normalized):
  probe=z3.Solver();probe.add(B==0);assert probe.check()==z3.sat;normalized=probe.model().eval(normalized,model_completion=True)
 qs.append(('common_record_count_and_fields',z3.Or(cell(v,C+64,4)^key!=N+0x5bed6383,cell(v,C,8)!=D,cell(v,C+8,8)!=B,cell(v,C+24,8)!=A,cell(v,C+32,8)!=B+16,cell(v,C+48,8)!=D,cell(v,C+56,8)!=A+4096,cell(v,C+72,8)!=B+192,cell(v,C+80,8)!=B+16320)))
 op=normalized.as_long();qs.append(('common_normalized_operation',cell(v,C+16,4)-key!=op))
 v=run('common_count_normalizer',0xfffffe000a617494,0xfffffe000a6174b8,[('sp',F),('w25',N+0x5bed6383)])
 qs.append(('common_count_normalizer',v.read('w10')!=N))
 ok=run('optional_caller_key',0xfffffe000a5a5d44,0xfffffe000a5a5d80,[('sp',F)],[(F+0xd8,8,C)])
 od=run('optional_decoder_key',0xfffffe000a5b4424,0xfffffe000a5b4458,[('x0',C),('w17',0xc69a7e73)])
 qs.append(('optional_address_key_agreement',ok.read('w9')!=od.read('w11')))
 v=run('optional_caller_record',0xfffffe000a5a5d80,0xfffffe000a5a5dc4,[('sp',F),('x0',C),('w9',ok.read('w9')),('w22',0x3da4b356)],[(F+0xe8,8,A),(F+0xf8,8,B+16320),(F+0xe0,8,A+4096),(F+0x128,8,B+128),(F+0xf0,8,B+192)])
 qs.append(('optional_normalized_fields',z3.Or(cell(v,C+48,4)+ok.read('w9')!=0x938,cell(v,C+52,2)^resize(ok.read('w9'),16)!=0x6019,cell(v,C,8)!=A,cell(v,C+16,8)!=A+4096,cell(v,C+24,8)!=B+16320,cell(v,C+32,8)!=B+192,cell(v,C+40,8)!=B+128)))
 v=run('mode2_fixed_span',0xfffffe000a5a5e30,0xfffffe000a5a5ec0,[('sp',F),('x29',F+0x250),('w30',0xc25b517a)],[(F+0x128,8,B+128),(F+0x1a4,4,0x3da4b356)])
 fixed=bytes.fromhex('19296018ebe32481f2d5fe6dec30ed8e');qs.append(('mode2_fixed_span',z3.Or(*[cell(v,B+128+j,1)!=b for j,b in enumerate(fixed)])))
 symbols=[z3.BitVec('prep_copy_byte'+str(j),8)for j in range(16)]
 v=run('mode2_fixed_span_copy',0xfffffe000a5a605c,0xfffffe000a5a60e8,[('sp',F),('x21',B),('w30',0xc25b517a),('w22',0x3da4b356)],[(B+128+j,1,x)for j,x in enumerate(symbols)]+[(F+0x128,8,B+128)])
 qs.append(('mode2_fixed_span_copy',z3.Or(*[cell(v,B+j,1)!=x for j,x in enumerate(symbols)])))
 I=z3.BitVec('prep_reverse_counter64',64)
 v=run('static_loop_control',0xfffffe000a5a5cf8,0xfffffe000a5a5d08,[('x13',I),('w4',0xfb),('w9',0x570)])
 qs.append(('static_loop_control',v.read('w17')!=z3.If(I==0,z3.BitVecVal(0x58b,32),z3.BitVecVal(0x570,32))))
 V,T1,T2,T3=z3.BitVecs('prep_payload32 prep_tableA32 prep_tableB32 prep_tableC32',32)
 v=run('first_byte_projection',0xfffffe000a617694,0xfffffe000a6176ac,[('w17',V),('w2',T1),('w3',T2),('w4',-3*resize(I,32)),('w16',11),('w1',T3),('x21',D),('x9',I)])
 qs.append(('first_byte_projection',cell(v,D+I,1)!=resize(V^T1^T2^(-3*resize(I,32))^11^T3,8)))
 v=run('last_byte_projection',0xfffffe000a617cc8,0xfffffe000a617ce4,[('w4',resize(I,32)&15),('w15',-77),('w1',V),('w2',T1),('w0',T2),('w17',T3),('w16',0xd0),('x5',D),('x10',I)])
 qs.append(('last_byte_projection',cell(v,D+I,1)!=resize(V^((resize(I,32)&15)*-77)^T1^T2^T3^0xd0,8)))
 S=z3.BitVec('prep_final_guard32',32)
 v=run('common_result_store',0xfffffe000a617d00,0xfffffe000a617d28,[('sp',F),('w8',S)],[(F+0x100,8,C)],Select)
 qs.append(('common_result_store',cell(v,C+40,4)!=z3.If(S==0x67de9af5,z3.BitVecVal(0x31ae0066,32),z3.BitVecVal(0xce515bbe,32))))
 out=[]
 for label,q in qs:
  s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));assert s.check()==z3.unsat,label;out.append({'label':label,'query':s.to_smt2(),'result':'unsat'})
 return out,counts,hex(op)

def final_bytes(row):
 state={};known=set();pattern=row['configuration']['pattern'];counts=Counter()
 for a,h in row['initial_cells'].items():
  for j,b in enumerate(bytes.fromhex(h),int(a,16)):state[j]=b;known.add(j)
 for e in row['source_writes']:
  for j,b in enumerate(bytes.fromhex(e['after_hex']),int(e['address'],16)):state[j]=b;known.add(j)
 for key in ['final_workspace','final_auxiliary','final_processed_input','count_cell_at_boundary']:
  snap=row[key];a=int(snap['address'],16);n=snap['size_bytes'];assert bytes(state.get(j,pattern)for j in range(a,a+n)).hex()==snap['bytes_hex']and bytes(int(j in known)for j in range(a,a+n)).hex()==snap['known_mask_hex'];counts['final_snapshot_bytes']+=n
 return counts

def frame_census(k):
 from capstone.arm64 import ARM64_OP_MEM,ARM64_OP_REG,ARM64_OP_IMM
 from recover_carrier_control import span
 row=span(k,0xfffffe000a5a5494,0xfffffe000a5a729c);dc=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);dc.detail=True;stores=[];aliases=[];visited=0
 for ins in dc.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
  visited+=1;ops=ins.operands
  if ins.mnemonic in ['str','stur','strb','sturb','strh','sturh','stp']:
   o=ops[-1]
   if o.type==ARM64_OP_MEM and ins.reg_name(o.mem.base)in ['sp','fp','x29']and not o.mem.index:
    off=o.mem.disp+(0x250 if ins.reg_name(o.mem.base)in ['fp','x29']else 0);reg=ins.reg_name(ops[0].reg);n=(1 if ins.mnemonic.endswith('b')else 2 if ins.mnemonic.endswith('h')else 4 if reg.startswith('w')else 16 if reg.startswith('q')else 8)*(2 if ins.mnemonic=='stp'else 1)
    if off<0x134 and off+n>0x130:stores.append(hex(ins.address))
  if ins.mnemonic in ['add','sub']and len(ops)==3 and ops[1].type==ARM64_OP_REG and ops[2].type==ARM64_OP_IMM and ins.reg_name(ops[1].reg)in ['sp','fp','x29']:
   off=(0x250 if ins.reg_name(ops[1].reg)in ['fp','x29']else 0)+(ops[2].imm<<ops[2].shift.value)*(1 if ins.mnemonic=='add'else -1)
   if off==0x130:aliases.append(hex(ins.address))
 assert not stores and not aliases
 row.pop('instructions');row.update(instruction_words_checked=visited,direct_SP_FP_store_overlap=stores,direct_SP_FP_pointer_producers=aliases,computed_alias_writers_excluded=True,native_uninitialized_read_proved=False);return row

def build():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));k=R.Kernel();qs,lifts,op=proofs(e['source_regions']);counts=Counter();joins=[];slots=set();alltransfers=0
 for row in e['cases']:
  counts.update(final_bytes(row));mode=row['configuration']['mode32'];D=R.Parent.P+0x1200;ps=row['source_payload'];reads=[x for x in row['source_reads']if D<=int(x['address'],16)<D+16];writes=[x for x in row['source_writes']if D<=int(x['address'],16)<D+16]
  for ev in row['source_reads']:
   a=int(ev['address'],16)
   if ev['size_bytes']==8 and POOL<=a<POOL+0xc000 and int.from_bytes(bytes.fromhex(ev['bytes_hex']),'little')>>48==0xffff:slots.add(a)
  for edge in row['source_transfers']:
   a=int(edge['matched_source_pointer_read'],16);p=pointer(k,a);assert int(p['target'],16)==int(edge['target'],16)and p['authenticated']and int(p['diversity'],16)==int(edge['modifier'],16);alltransfers+=1
  if mode==2:
   assert len(reads)==len(writes)==48 and row['boundary']['kind']=='before_undefined_frame_word_read'and row['boundary']['known_bytes']==0
   first=[x for x in writes if x['pc']=='0xfffffe000a6176a8'];last=[x for x in writes if x['pc']=='0xfffffe000a617ce0'];assert len(first)==len(last)==16 and [int(x['address'],16)-D for x in first]==[int(x['address'],16)-D for x in last]==list(range(15,-1,-1))
   middle=[x for x in writes if x not in first+last];assert len(middle)==16 and {int(x['address'],16)-D for x in middle}==set(range(16))
   before=next(x for x in row['source_checkpoints']if x['pc']=='0xfffffe000a5a6294');after=next(x for x in row['source_checkpoints']if x['pc']=='0xfffffe000a5a6298');assert before['SP']==after['SP']and before['registers31'][19:30]==after['registers31'][19:30]
   result=next(x for x in row['source_writes']if x['pc']=='0xfffffe000a617d24');assert result['after_hex']=='6600ae31';counts['complete_block_helper_returns']+=1
  else:assert not reads and not writes and row['boundary']['pc']=='0xfffffe000a5b4e00'and row['boundary']['target']=='0xfffffe000c4ba60c'and int(row['boundary']['registers31'][0],16)==47
  joins.append({'daemon_case_index':ps['daemon_case_index'],'guest_epoch':row['configuration']['epoch'],'operand_profile':ps['operand_profile'],'mode32':mode,'inputB_initial_hex':ps['processed16_hex'],'inputB_final_hex':row['final_processed_input']['bytes_hex'],'payload_read_events':len(reads),'payload_write_events':len(writes),'boundary':row['boundary']})
 rules=[]
 for name,l,r,key,add in [('conditional_helper',qword(POOL+0xc08)-8,qword(POOL+0x158)-4,5,0xf01),('block_helper',qword(POOL+0xf50)-4,qword(POOL+0xf20)-4,0x93,0xe8d)]:
  x=selected(l,r,key,add);x.update(label=name,left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex(),original_pointer=pointer(k,int(x['slot'],16)));rules.append(x)
 records=[pointer(k,a)for a in sorted(slots)]
 for p in records:assert int(p['target'],16)==qword(int(p['slot'],16))
 for rule in rules:assert k.read(int(rule['left'],16),256).hex()==rule['left256_hex']and k.read(int(rule['right'],16),256).hex()==rule['right256_hex']
 from resolve_kernel_collection_interfaces import commands
 segments=[]
 for at,cmd,n in commands(IMAGE.data,0):
  if cmd!=0x19:continue
  va,vm,off,sz=struct.unpack_from('<4Q',IMAGE.data,at+24)
  if va<=0xfffffe000ccceaf4<0xfffffe000ccceafc<=va+vm:segments.append({'name':IMAGE.data[at+8:at+24].split(b'\0')[0].decode(),'address':hex(va),'virtual_size_bytes':vm,'file_size_bytes':sz})
 assert segments==[{'name':'__DATA','address':'0xfffffe000ccc2a20','virtual_size_bytes':0xc118,'file_size_bytes':0x8000}]
 return {'scope':__doc__,'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'generator_sha256':sha(ROOT/('recover_'+R.P+'.py')),'source_proofs':qs,'source_lift_counts':lifts,'normalized_common_operation':op,'selected_bank_rules':rules,'original_pointer_records':records,'frame_word_census':frame_census(k),'kernel_only_cell':{'address':'0xfffffe000ccceaf4','original8_hex':k.read(0xfffffe000ccceaf4,8).hex(),'normalized_file_backed':False,'normalized_segment':segments[0],'native_runtime_value_known':False},'exact_symbols':k.symbols([0xfffffe000c4ba60c]),'interface_joins':joins,'verified_counts':{'source_queries_unsat':len(qs),'source_lift_instructions':sum(lifts.values()),'bank_rules':len(rules),'bank_inputs':len(rules)*256,'original_pointer_records':len(slots),'authenticated_transfers_checked':alltransfers,**counts},'native_target_executed':False,'model_memory_writes':0,'all_checks_pass':True,'full_goal_complete':False}

if __name__=='__main__':
 obj=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(obj,indent=2)+'\n');print(json.dumps(obj['verified_counts']),flush=True)
