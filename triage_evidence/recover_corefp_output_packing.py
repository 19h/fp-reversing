#!/usr/bin/env python3
"""Partial source lift of private output packing and byte-transfer contracts.

All non-result register/stack/read interfaces are captured premises.
O(C*(V*J+P*F+R)+N*659+N*16*256) time/space; 30 s/SMT query.
No native target/API/IPC or IDB operation; no source PC or records patched.
"""
import json,z3,struct
from pathlib import Path
from collections import Counter
from capstone.arm64_const import *
import audit_corefp_workspace_consumers as A
C=A.C;ROOT=A.ROOT;SHA=A.SHA;W=A.W
from verify_daemon_reader_record_payloads_publication import read
START=0x1bb5a8;END=0x1bbff4;S=C.Pointers();INS=list(C.CS.disasm(S.read(START,END-START),START));M64=(1<<64)-1
parent=json.loads(read(ROOT/'corefp_workspace_consumers_checks.json'));forms=json.loads(read(ROOT/'corefp_workspace_audit.json'))['workspace_oracles']
def vars_in(e):
 out={};seen=set()
 def walk(x):
  if x.get_id()in seen:return
  seen.add(x.get_id())
  if z3.is_const(x)and x.decl().kind()==z3.Z3_OP_UNINTERPRETED:out[str(x)]=x
  for c in x.children():walk(c)
 walk(e);return out

def lift(block):
 form=next(f for f in forms if f['label']==block['label']);q2=int(form['second_xor_u32'],16);frame=block['entry']['CPU'];regs={j:z3.BitVecVal(int(v,16),64)for j,v in enumerate(frame['X31'])};sp=int(frame['SP'],16)
 stack={sp+j:z3.BitVecVal(b,8)for j,b in enumerate(bytes.fromhex(block['entry']['stack1312_hex']))};g=[z3.BitVec('g'+str(j),8)for j in range(16)];proofs=[];luts=[];outputs=[];modeled_reads=[];ri=0
 def store(a,n,v):
  for j in range(n):stack[a+j]=z3.Extract(8*j+7,8*j,v)
 for j in range(144,160):
  loc=parent['source_model']['final_destinations']['q'+str(j)];v=(z3.ZeroExt(24,g[j-144])<<8)^0x65^q2
  if 'register'in loc:regs[loc['register']]=z3.ZeroExt(32,v)
  else:store(sp+loc['stack_offset'],4,v)
 def rr(name):
  name={'fp':'x29','lr':'x30'}.get(name,name)
  if name=='sp':return z3.BitVecVal(sp,64)
  if name in ['wzr','xzr']:return z3.BitVecVal(0,32 if name[0]=='w'else 64)
  v=regs[int(name[1:])];return z3.Extract(31,0,v)if name[0]=='w'else v
 def put(name,v):
  name={'fp':'x29','lr':'x30'}.get(name,name)
  regs[int(name[1:])]=z3.ZeroExt(32,z3.simplify(v))if name[0]=='w'else z3.simplify(v)
 def operand(i,o,bits):
  v=rr(i.reg_name(o.reg))if o.type==1 else z3.BitVecVal(o.imm,bits)
  if o.ext:
   if o.ext==ARM64_EXT_UXTB:v=z3.ZeroExt(bits-8,z3.Extract(7,0,v))
   elif o.ext==ARM64_EXT_UXTW:v=z3.ZeroExt(bits-32,z3.Extract(31,0,v))
   elif o.ext==ARM64_EXT_SXTW:v=z3.SignExt(bits-32,z3.Extract(31,0,v))
   else:raise AssertionError(o.ext)
  if v.size()!=bits:assert v.size()==32 and bits==64;v=z3.ZeroExt(32,v)
  if o.shift.type:
   k=o.shift.value
   if o.shift.type==ARM64_SFT_LSL:v=v<<k
   elif o.shift.type==ARM64_SFT_LSR:v=z3.LShR(v,k)
   else:assert o.shift.type==ARM64_SFT_ROR;v=z3.RotateRight(v,k)
  return v
 def address(i,o):
  v=rr(i.reg_name(o.mem.base))+o.mem.disp
  if o.mem.index:
   w=rr(i.reg_name(o.mem.index));w=z3.SignExt(32,w)if o.ext==ARM64_EXT_SXTW else z3.ZeroExt(32,w)if w.size()==32 else w
   v+=w<<o.shift.value
  return z3.simplify(v)
 def mux(values,index):
  if len(values)==1:return z3.BitVecVal(values[0],8)
  half=len(values)//2;bit=half.bit_length()-1
  return z3.If(z3.Extract(bit,bit,index)==0,mux(values[:half],index),mux(values[half:],index))
 def _load(a,n,i):
  nonlocal ri
  a=z3.simplify(a)
  observed=block['reads'][ri];ri+=1;assert observed['visit']==block['entry']['source_visit']+(i.address-START)//4 and observed['size_B']==n
  if z3.is_bv_value(a):
   at=a.as_long();assert at==int(observed['address'],16)
   if all(at+j in stack for j in range(n)):return z3.simplify(z3.Concat(*[stack[at+j]for j in reversed(range(n))]))if n>1 else stack[at]
   return z3.BitVecVal(int.from_bytes(bytes.fromhex(observed['bytes_hex']),'little'),n*8)
  assert n==1,(hex(i.address),str(a))
  terms=a.children()if a.decl().kind()==z3.Z3_OP_BADD else [a];base=sum(x.as_long()for x in terms if z3.is_bv_value(x))&M64
  index=z3.simplify(z3.Extract(7,0,a-base));q=z3.Solver();q.set(timeout=30000);q.add(a!=z3.BitVecVal(base,64)+z3.ZeroExt(56,index));assert q.check()==z3.unsat,(hex(i.address),str(a))
  raw=S.read(base-C.BASE,256);actual_index=int(observed['address'],16)-base;assert 0<=actual_index<256 and raw[actual_index:actual_index+1].hex()==observed['bytes_hex']
  luts.append({'pc':hex(i.address),'base':hex(base-C.BASE),'bytes_hex':raw.hex()});proofs.append({'label':'byte_table_address_'+hex(i.address),'query':q.to_smt2(),'result':'unsat'})
  return z3.simplify(mux(list(raw),index))
 def load(a,n,i):
  value=_load(a,n,i);modeled_reads.append({'index':ri-1,'address':a,'value':value});return value
 for i in INS:
  m=i.mnemonic;o=i.operands;name=i.reg_name(o[0].reg);bits=32 if name.startswith('w')else 64
  if m in ['ldr','ldur','ldrb']:
   n=1 if m=='ldrb'else bits//8;v=load(address(i,o[1]),n,i);put(name,z3.ZeroExt(bits-v.size(),v));continue
  if m=='ldp':
   a=address(i,o[2]);assert z3.is_bv_value(a);v=load(a,8,i);put(name,v);put(i.reg_name(o[1].reg),load(a+8,8,i));continue
  if m in ['str','strb']:
   a=address(i,o[1]);assert z3.is_bv_value(a),(hex(i.address),str(a));n=1 if m=='strb'else bits//8;v=z3.Extract(n*8-1,0,rr(name));store(a.as_long(),n,v)
   if m=='strb':outputs.append({'pc':i.address,'address':a.as_long(),'value':z3.simplify(v)})
   continue
  if m=='mov':put(name,operand(i,o[1],bits));continue
  if m=='movk':
   k=o[1].shift.value;put(name,(rr(name)&z3.BitVecVal(((1<<bits)-1)^(65535<<k),bits))|z3.BitVecVal(o[1].imm<<k,bits));continue
  if m=='adrp':put(name,z3.BitVecVal(C.BASE+o[1].imm,64));continue
  if m=='ubfx':put(name,z3.ZeroExt(bits-o[3].imm,z3.Extract(o[2].imm+o[3].imm-1,o[2].imm,operand(i,o[1],bits))));continue
  if m=='ubfiz':put(name,(operand(i,o[1],bits)&((1<<o[3].imm)-1))<<o[2].imm);continue
  if m=='extr':
   a,b=operand(i,o[1],bits),operand(i,o[2],bits);put(name,z3.Extract(bits-1,0,z3.LShR(z3.Concat(a,b),o[3].imm)));continue
  assert m in ['eor','sub','and','lsl','lsr','add','mul','orn','orr'],m
  a,b=operand(i,o[1],bits),operand(i,o[2],bits)
  v={'eor':lambda:a^b,'sub':lambda:a-b,'and':lambda:a&b,'lsl':lambda:a<<(b&(bits-1)),'lsr':lambda:z3.LShR(a,b&(bits-1)),
    'add':lambda:a+b,'mul':lambda:a*b,'orn':lambda:a|~b,'orr':lambda:a|b}[m]();put(name,v)
 assert ri==len(block['reads'])and len(outputs)==16
 return g,outputs,luts,proofs,regs,stack,modeled_reads

COLS=[0xbc,0x44,0x35,0x7d,0xda,0xcc,0xbf,0xff]
PERM=[9,7,1,5,15,10,13,12,3,11,0,4,14,6,2,8]
WORD_SLOTS=[0x1e0,0x1e4,0x1e8,0x1f0,0x1f4,0x2e4,0x204,0x208,0x364,0x3ec,0x3f0,0x3f4]
PINS={'corefp_workspace_checks.json':'fc31687bcb81fb5611bccd1e928efdce657767a84218f6d91e47a027d69076b6',
 'corefp_workspace_audit.json':'9e1d67b6d637f17b18d8653e23d12400581e20afb7d2e6e4d4fa27faa246ba07',
 'corefp_workspace_consumers_checks.json':'5f976ce1950bfcea57f1852576bd61d4e62f92f3fd3efb7cd0005624f18779ea',
 'corefp_workspace_consumers_audit.json':'adb5603bc9624068bd09c45981d628e8997079c349309648429bb5bd9e5c9a19'}


def h8(x):
    v=0
    for j,c in enumerate(COLS):
        if x>>j&1:v^=c
    return v


def h_expr(x):
    v=z3.BitVecVal(0,8)
    for j,c in enumerate(COLS):v^=z3.If(z3.Extract(j,j,x)==0,z3.BitVecVal(0,8),z3.BitVecVal(c,8))
    return v


def gap_census():
    ins=list(C.CS.disasm(S.read(0x1bad9c,2060),0x1bad9c));written=set();stores=[]
    for i in ins:
        for r in i.regs_access()[1]:written.add(i.reg_name(r))
        if i.mnemonic.startswith('st'):stores.append({'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str})
        assert i.mnemonic not in ['bl','blr','braa','br','ret']and not i.mnemonic.startswith('b.')
    assert len(ins)==515 and not written&{'x6','w6','x14','w14','x15','w15','x17','w17','sp','fp','x29'}
    assert stores==[{'pc':'0x1bb0d0','bytes_hex':S.read(0x1bb0d0,4).hex(),'instruction':'str x26, [sp, #0x318]'}]
    assert all(not(0x318<loc['stack_offset']+4 and 0x320>loc['stack_offset'])for loc in parent['source_model']['final_destinations'].values()if 'stack_offset'in loc)
    return {'start':'0x1bad9c','end':'0x1bb5a8','source_B':2060,'instructions':515,'written_registers':sorted(written),'stores':stores,
      'source_bytes_hex':S.read(0x1bad9c,2060).hex(),'result_registers_and_slots_preserved':True}


def origin(p,at,address,n):
    writes=[w for w in p['writes']if w['visit']<at and int(w['address'],16)<address+n and int(w['address'],16)+w['size_B']>address]
    out=[]
    for j in range(n):
        row=next(w for w in reversed(writes)if int(w['address'],16)<=address+j<int(w['address'],16)+w['size_B'])
        if row not in out:out.append(row)
    return [{'pc':p['visits'][w['visit']]['pc'],**w}for w in out]


def snap(r,index):
    row=A.capture(r);dst=C.addresses(r.p['configuration'])[1]+16*index
    return {**row,'output_base':hex(dst),'output16_hex':r.ram(dst,16).hex()}


class Capture(A.Replay):
    def __init__(self,*args):super().__init__(*args);self.packing=[]
    def code(self,u,pc,n,d):
        self.flush()
        if pc==C.BASE+START:self.packing.append({'entry':snap(self,len(self.packing))})
        if pc==C.BASE+END:self.packing[-1]['end']=snap(self,len(self.packing)-1)
        return super().code(u,pc,n,d)


def transfer(block,actual_g):
    g,out,luts,proofs,regs,stack,reads=lift(block);out=sorted(out,key=lambda r:r['address']);base=int(block['entry']['output_base'],16)
    assert [r['address']for r in out]==list(range(base,base+16))
    def evaluate(expr,values):return z3.simplify(z3.substitute(expr,*[(v,z3.BitVecVal(values.get(str(v),0),8))for v in g])).as_long()
    actual={str(v):b for v,b in zip(g,actual_g)};bias=[];rows=[]
    for j,row in enumerate(out):
        zero=evaluate(row['value'],{});bias.append(zero);name='g'+str(PERM[j])
        values=[evaluate(row['value'],{name:i})for i in range(256)];assert values==[h8(i)^zero for i in range(256)]
        candidate=h_expr(g[PERM[j]])^zero;q=z3.Solver();q.set(timeout=30000);q.add(row['value']!=candidate);assert q.check()==z3.unsat
        proofs.append({'label':'output_byte_'+str(j),'query':q.to_smt2(),'result':'unsat'})
        assert evaluate(row['value'],actual)==bytes.fromhex(block['end']['output16_hex'])[j]
        rows.append({'output_index':j,'source_g_index':PERM[j],'store_pc':hex(row['pc']),'bias_u8':zero,'byte_cases_checked':256})
    assert [hex(evaluate(regs[j],actual))for j in range(31)]==block['end']['CPU']['X31']
    sp=int(block['entry']['stack_base'],16);assert bytes(evaluate(stack[sp+j],actual)for j in range(1312)).hex()==block['end']['stack1312_hex']
    for x in reads:
        old=block['reads'][x['index']];assert evaluate(x['address'],actual)==int(old['address'],16)
        assert evaluate(x['value'],actual)==int.from_bytes(bytes.fromhex(old['bytes_hex']),'little')
    assert len(proofs)==32 and len(reads)==102 and len(luts)==16
    return {'label':block['label'],'block_index':block['block_index'],'bias16_hex':bytes(bias).hex(),'byte_mappings':rows,
      'symbolic_tables':luts,'proofs':proofs,'byte_cases_checked':4096,'source_reads_checked':102,'all_GPRs_and_stack_match':True,
      'universal_scope':'arbitrary sixteen canonical u8 result values; all other captured input/read interfaces fixed'}


def inverse_proof():
    values=[h8(i)for i in range(256)];assert len(set(values))==256;inv=[0]*256
    for i,v in enumerate(values):inv[v]=i
    cols=[inv[1<<j]for j in range(8)];x=z3.BitVec('inverse_H_x8',8);y=h_expr(x);v=z3.BitVecVal(0,8)
    for j,c in enumerate(cols):v^=z3.If(z3.Extract(j,j,y)==0,z3.BitVecVal(0,8),z3.BitVecVal(c,8))
    q=z3.Solver();q.set(timeout=30000);q.add(v!=x);assert q.check()==z3.unsat
    return {'label':'common_affine_inverse8','query':q.to_smt2(),'result':'unsat','inverse_columns_u8':cols,'complete_values_checked':256}


def main():
    pinned={}
    for n,h in PINS.items():
        raw=read(ROOT/n).encode();assert SHA(raw)==h;pinned[n]=json.loads(raw)
    e=pinned['corefp_workspace_checks.json'];a=pinned['corefp_workspace_consumers_audit.json'];consumer=pinned['corefp_workspace_consumers_checks.json']
    blocks=[];models=[];totals=Counter();n=0
    for p in e['profiles']:
        r=Capture(p,e['source_spans'],S);totals.update(r.run())
        for ordinal,b in enumerate(r.packing):
            lo,hi=b['entry']['source_visit'],b['end']['source_visit'];assert hi-lo==659
            assert [int(v['pc'],16)for v in p['visits'][lo:hi]]==list(range(START,END,4))
            assert r.blocks[ordinal]['end']==consumer['blocks'][n]['end']
            b.update({'label':p['configuration']['label'],'block_index':ordinal,'reads':[x for x in p['reads']if lo<=x['visit']<hi],
              'writes':[x for x in p['writes']if lo<=x['visit']<hi]})
            sp=int(b['entry']['stack_base'],16);output=[]
            for w in b['writes']:
                if w['size_B']!=1:continue
                rr=next(x for x in b['reads']if x['visit']==w['visit']-1 and x['size_B']==8)
                address=int(rr['address'],16);assert sp<=address<sp+1312 and int.from_bytes(bytes.fromhex(rr['bytes_hex']),'little')==int(w['address'],16)
                output.append({'output_index':int(w['address'],16)-int(b['entry']['output_base'],16),'store_pc':p['visits'][w['visit']]['pc'],
                  'pointer_load_pc':p['visits'][rr['visit']]['pc'],'stack_slot_offset':address-sp,'reaching_stores':origin(p,rr['visit'],address,8)})
            b['output_pointer_origins']=sorted(output,key=lambda x:x['output_index']);b['initial_word_origins']=[{'stack_slot_offset':off,
              'value_u32':int.from_bytes(bytes.fromhex(b['entry']['stack1312_hex'])[off:off+4],'little'),'reaching_stores':origin(p,lo,sp+off,4)}for off in WORD_SLOTS]
            actual=bytes.fromhex(a['block_oracles'][n]['canonical_final16_hex']);models.append(transfer(b,actual));blocks.append(b);n+=1
        print(json.dumps({'captured':p['configuration']['label'],'blocks':len(r.packing)}),flush=True)
    assert n==8
    dep=['audit_corefp_workspace_consumers.py','audit_corefp_workspace.py','audit_corefp_pool_transform.py','audit_corefp_pool_caller.py',
      'audit_corefp_pool_allocator.py','audit_corefp_lookup_initialization.py','audit_fpsd1201_predicates.py']
    counts={'profiles':6,'blocks':8,'packing_instructions':659,'packing_source_B':2636,'regional_visits':5272,'regional_reads':816,'regional_writes':136,
      'output_bytes':128,'source_table_reads':128,'complete_byte_cases':32768,'new_queries_unsat':257,'gap_instructions':515,'gap_source_B':2060}
    out={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':C.THIN_SHA,'parent_pins':PINS,
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in dep},'source_bytes_hex':S.read(START,END-START).hex(),
      'instructions':[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in INS],
      'gap_census':gap_census(),'common_H_columns_u8':COLS,'common_output_permutation':PERM,'common_inverse_proof':inverse_proof(),
      'blocks':blocks,'transfer_models':models,'replay_totals':dict(totals),'verified_counts':counts,
      'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'new_live_IDA_claim':False,'source_context_initializer_established':False,
      'general_preparation_contract_established':False,'whole_transform_algorithm':'unknown','full_goal_complete':False}
    (ROOT/'corefp_output_packing_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
