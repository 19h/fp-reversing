#!/usr/bin/env python3
"""Source-lifted private workspace consumer and canonical substitution network.

O(B+C*(V*J+P*F+R)) time/space; 150000 visits/profile; 30 s/SMT query.
Original source and retained private fixtures only; no target/API/IPC or IDB access.
"""
import json,struct
from pathlib import Path
from hashlib import sha256
from collections import Counter
import z3
from unicorn import arm64_const as A
import audit_corefp_workspace as W
from verify_daemon_reader_record_payloads_publication import read
C=W.C;ROOT=W.ROOT;SHA=lambda b:sha256(b).hexdigest();START=0x1ba0c0;END=0x1bad9c
PARENT_CHECKS_SHA='fc31687bcb81fb5611bccd1e928efdce657767a84218f6d91e47a027d69076b6'
PARENT_AUDIT_SHA='9e1d67b6d637f17b18d8653e23d12400581e20afb7d2e6e4d4fa27faa246ba07'


def source_model(S):
    proofs=[]
    def prove(label,claim):
        q=z3.Solver();q.set(timeout=30000);q.add(z3.Not(claim));assert q.check()==z3.unsat,label
        proofs.append({'label':label,'query':q.to_smt2(),'result':'unsat'})
    aa,bb,cc,kk,ll,ss=z3.BitVecs('ring_a64 ring_b64 ring_c64 ring_k64 ring_l64 ring_s64',64)
    for label,claim in [
      ('ring_associative',(aa+bb)+cc==aa+(bb+cc)),
      ('ring_negation',aa+(-aa)==0),
      ('ring_shift_distribution',((aa+bb)<<(ss&63))==((aa<<(ss&63))+(bb<<(ss&63)))),
      ('ring_shift_negation',((-aa)<<(ss&63))==-(aa<<(ss&63))),
      ('ring_coefficient_combination',aa*kk+aa*ll==aa*(kk+ll))]:prove(label,claim)
    regs={j:z3.BitVec('u'+str(j),64)for j in range(31)};sp=z3.BitVec('SP',64);regs[29]=sp+0x520
    regs_initial=regs.copy()
    B=[z3.BitVec('B1',64),z3.BitVec('B2',64)];mem={0x428:B[0],0x430:B[1]};loads=[];stores=[];cond=None;asserts=[]
    def ring(v):
     terms={};atoms={};mod=(1<<64)-1
     def walk(e,k):
      if z3.is_bv_value(e):terms['const']=(terms.get('const',0)+k*e.as_long())&mod;return
      kind=e.decl().kind()
      if kind==z3.Z3_OP_BADD:
       for c in e.children():walk(c,k)
       return
      if kind==z3.Z3_OP_BNEG:walk(e.arg(0),-k);return
      if kind==z3.Z3_OP_BSUB:walk(e.arg(0),k);walk(e.arg(1),-k);return
      if kind==z3.Z3_OP_BSHL and z3.is_bv_value(e.arg(1)):walk(e.arg(0),k*(1<<e.arg(1).as_long()));return
      if kind==z3.Z3_OP_BMUL:
       if z3.is_bv_value(e.arg(0)):walk(e.arg(1),k*e.arg(0).as_long());return
       if z3.is_bv_value(e.arg(1)):walk(e.arg(0),k*e.arg(1).as_long());return
      e=z3.simplify(e)
      if z3.is_bv_value(e):terms['const']=(terms.get('const',0)+k*e.as_long())&mod;return
      key=e.sexpr();terms[key]=(terms.get(key,0)+k)&mod;atoms[key]=e
     walk(v,1);out=z3.BitVecVal(terms.get('const',0),64)
     for key,k in terms.items():
      if key!='const'and k:out+=(atoms[key]<<(k.bit_length()-1))if k&(k-1)==0 else atoms[key]*k
     return out

    def rr(n):
     n={'fp':'x29','lr':'x30'}.get(n,n)
     if n in ['wzr','xzr']:return z3.BitVecVal(0,32 if n[0]=='w'else 64)
     if n=='sp':return sp
     v=regs[int(n[1:])];return z3.Extract(31,0,v)if n[0]=='w'else v
    def put(n,v):regs[int(n[1:])]=z3.ZeroExt(32,z3.simplify(v))if n[0]=='w'else ring(v)
    def val(i,o,bits):
     v=rr(i.reg_name(o.reg))if o.type==1 else z3.BitVecVal(o.imm,bits)
     if v.size()!=bits:
      from capstone.arm64_const import ARM64_EXT_UXTW
      assert v.size()==32 and bits==64 and o.ext==ARM64_EXT_UXTW
      v=z3.ZeroExt(32,v)
     if o.shift.type:
      from capstone.arm64_const import ARM64_SFT_LSL,ARM64_SFT_LSR,ARM64_SFT_ROR
      v={ARM64_SFT_LSL:lambda:v<<o.shift.value,ARM64_SFT_LSR:lambda:z3.LShR(v,o.shift.value),ARM64_SFT_ROR:lambda:z3.RotateRight(v,o.shift.value)}[o.shift.type]()
     return v
    def addr(i,o):
     v=rr(i.reg_name(o.mem.base))+o.mem.disp
     if o.mem.index:
      v2=rr(i.reg_name(o.mem.index));v2=z3.ZeroExt(32,v2)if v2.size()==32 else v2
      v+=v2<<o.shift.value
     return ring(v)
    def stackoff(a):
     d=z3.simplify(a-sp)
     return d.as_long()if z3.is_bv_value(d)else None
    for ins in C.CS.disasm(S.read(START,END-START),START):
     m=ins.mnemonic;o=ins.operands;n=ins.reg_name(o[0].reg);bits=32 if n.startswith('w')else 64
     if ins.address==0x1ba1f8:shift_word=rr('w15')
     if ins.address==0x1ba320:before_special=rr('w4')
     if m in ['ldr','ldur']:
      a=addr(ins,o[1]);off=stackoff(a)
      if off is not None:
       if off not in mem:mem[off]=z3.BitVec('s'+hex(off)[2:],bits)
       put(n,mem[off]);continue
      j=len(loads);b=B[0 if j<144 else 1];delta=z3.simplify(ring(a-b));idx=z3.simplify(z3.Extract(9,2,delta));claim=delta==(z3.ZeroExt(56,idx)<<2)
      prove('lookup_address_'+str(j),claim)
      if j==15:
       lhs=z3.ZeroExt(1,z3.Extract(4,0,mem[0x1fc]))+z3.ZeroExt(1,z3.Extract(4,0,mem[0x1a0]))
       desired=z3.Extract(31,24,shift_word);prove('split_shift_extract24',z3.Implies(lhs==24,idx==desired));idx=desired
      loads.append({'pc':ins.address,'index':idx,'dest':n});put(n,z3.BitVec('q'+str(j),32));continue
     if m in ['str','stur']:
      a=addr(ins,o[1]);off=stackoff(a);assert off is not None,(hex(ins.address),str(a));mem[off]=rr(n);stores.append((ins.address,off,rr(n)));continue
     if m=='ubfx':put(n,z3.ZeroExt(bits-o[3].imm,z3.Extract(o[2].imm+o[3].imm-1,o[2].imm,val(ins,o[1],bits))));continue
     if m=='neg':put(n,-val(ins,o[1],bits));continue
     if m=='mov':put(n,val(ins,o[1],bits));continue
     if m=='movk':
      shift=o[1].shift.value;v=(rr(n)&z3.BitVecVal(((1<<bits)-1)^ (65535<<shift),bits))|z3.BitVecVal(o[1].imm<<shift,bits);put(n,v);continue
     if m=='cmp':a,b=val(ins,o[0],bits),val(ins,o[1],bits);cond={'lo':z3.ULT(a,b)};continue
     if m=='tst':cond={'ne':(val(ins,o[0],bits)&val(ins,o[1],bits))!=0};continue
     if m=='cset':assert ins.op_str.endswith(', lo');put(n,z3.If(cond['lo'],z3.BitVecVal(1,bits),z3.BitVecVal(0,bits)));continue
     if m=='cneg':assert ins.op_str.endswith(', ne');v=val(ins,o[1],bits);put(n,z3.If(cond['ne'],-v,v));continue
     assert m in ['and','eor','orr','add','lsl','lsr','ror'],(hex(ins.address),m)
     a,b=val(ins,o[1],bits),val(ins,o[2],bits)
     v={'and':lambda:a&b,'eor':lambda:a^b,'orr':lambda:a|b,'add':lambda:a+b,'lsl':lambda:a<<(b&(bits-1)),
     'lsr':lambda:z3.LShR(a,b&(bits-1)),'ror':lambda:z3.RotateRight(a,o[2].imm)}[m]()
     put(n,v)
     if ins.address==0x1ba34c:
      wanted=before_special^mem[0x1d0]^z3.RotateRight(z3.BitVec('q23',32),24)
      prove('conditional_xor_word',rr('w11')==wanted)
      put('w11',wanted)

    def linear(e):
     e=z3.simplify(e)
     if e.decl().kind()==z3.Z3_OP_BXOR:
      rows=[]
      for c in e.children():rows+=linear(c)
      return rows
     assert e.decl().kind()==z3.Z3_OP_EXTRACT,str(e)
     hi,lo=e.params();v=e.arg(0);assert hi==lo+7 and lo%8==0 and z3.is_const(v)and v.decl().kind()==z3.Z3_OP_UNINTERPRETED,str(e)
     return [(str(v),lo//8)]
    from collections import defaultdict,Counter
    groups=defaultdict(list);depth=[]
    for j,l in enumerate(loads):
     terms=linear(l['index']);qs=[int(n[1:])for n,b in terms if n.startswith('q')]
     depth.append(0 if not qs else 1+max(depth[k]for k in qs))
     if qs:groups[tuple(sorted(qs))].append((j,terms))
    net=[]
    for qs,rows in groups.items():
     assert len(rows)==4 and len(qs)==4,(qs,rows)
     specs=[];mapping=[]
     for j,terms in rows:
      selected=next(b for n,b in terms if n=='q'+str(qs[0]));spec=sorted((n,(b-selected)%4)for n,b in terms)
      specs.append(spec);mapping.append((j,selected))
     assert all(s==specs[0]for s in specs),(qs,specs)
     assert sorted(b for j,b in mapping)==[0,1,2,3]
     net.append({'layer':depth[rows[0][0]],'word_terms':specs[0],'lookups':mapping})

    lookup_map={}
    for serial,node in enumerate(net):
        expr=z3.BitVecVal(0,32)
        for name,rotation in node['word_terms']:
            v=z3.BitVec(name,32)if name[0]!='u'else z3.Extract(31,0,z3.BitVec(name,64))
            expr^=z3.RotateRight(v,8*rotation)
        for j,byte in node['lookups']:
            prove('network_index_'+str(j),loads[j]['index']==z3.Extract(8*byte+7,8*byte,expr))
            lookup_map[j]={'word_node':serial,'byte':byte}
    for j,l in enumerate(loads):
        if j not in lookup_map:
            terms=linear(l['index']);assert len(terms)==1 and terms[0][0]in ['u8','u13','u14','u16']
            name,byte=terms[0];lookup_map[j]={'input_register':int(name[1:]),'byte':byte}
            prove('network_index_'+str(j),l['index']==z3.Extract(8*byte+7,8*byte,regs_initial[int(name[1:])]))
    for off,b in zip([0x428,0x430],B):prove('restored_pointer_'+hex(off),ring(mem[off]-b)==0)
    prove('stack_status',mem[0x360]==z3.If(z3.ULT(z3.BitVec('s3f8',32),0x44506381),z3.BitVecVal(1,32),z3.BitVecVal(0,32)))
    final={}
    for pc,off,v in stores:
        if 0x324<=off<=0x35c:
            v=z3.simplify(v);assert z3.is_const(v)and str(v).startswith('q');final[str(v)]={'stack_offset':off,'source_pc':hex(pc)}
    for reg in [6,14,15,17]:
        v=z3.simplify(rr('w'+str(reg)));assert z3.is_const(v)and str(v).startswith('q');final[str(v)]={'register':reg}
    assert sorted(map(lambda n:int(n[1:]),final))==list(range(144,160))
    assert Counter(depth)==Counter({i:16 for i in range(10)})and len(net)==36
    return {'proofs':proofs,'instructions':[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}
      for i in C.CS.disasm(S.read(START,END-START),START)],'source_bytes_hex':S.read(START,END-START).hex(),
      'word_nodes':net,'lookups':[{'id':j,'pc':hex(l['pc']),'layer':depth[j],'destination_register':l['dest'],**lookup_map[j]}for j,l in enumerate(loads)],
      'final_destinations':final,'premises':{'frame_pointer_minus_SP_B':0x520,'masked_split_shift_sum':24,'nonalias_stack_table_interfaces':True},
      'source_instruction_count':(END-START)//4,'source_B':END-START,'lookup_count':160,'mixed_word_nodes':36,'substitution_layers':10}


def phase_proofs(forms):
    out=[];seen=set()
    def xor(xs):
        v=z3.BitVecVal(0,32)
        for x in xs:v^=x
        return v
    for f in forms:
        mask=int(f['mask_u32'],16);r=f['rotate_per_byte'];b=int(f['index_xor_u8'],16);k=int(f['first_xor_u32'],16);q2=int(f['second_xor_u32'],16)
        params=(mask,r,b,k,q2)
        if params in seen:continue
        seen.add(params);assert mask&0x80808080==0
        def rot(x,n):return z3.Concat(*[z3.RotateLeft(z3.Extract(8*j+7,8*j,x),n)for j in reversed(range(4))])
        def t(x):return rot(x^((x&mask)<<1),r)
        def inverse(x):
            y=rot(x,-r);v=y
            for _ in range(31):v=y^((v&mask)<<1)
            return v
        xs=z3.BitVecs('canonical_x0 canonical_x1 canonical_x2 canonical_x3',32);key=z3.BitVec('encoded_key32',32);word=z3.BitVec('encoded_word32',32)
        ksum=xor([z3.RotateRight(z3.BitVecVal(k,32),8*j)for j in range(4)]);bias=b*0x01010101
        lhs=inverse(xor([z3.RotateRight(t(x)^k,8*j)for j,x in enumerate(xs)])^key^bias)
        rhs=xor([z3.RotateRight(x,8*j)for j,x in enumerate(xs)])^inverse(key^ksum^bias)
        clauses=[lhs==rhs,inverse(t(word))==word]
        for j in range(4):
            y=z3.RotateRight(z3.Extract(8*j+7,8*j,word)^b,r);v=y
            for _ in range(7):v=y^((v&(mask&255))<<1)
            clauses.append(z3.Extract(8*j+7,8*j,inverse(word^bias))==v)
        g=z3.BitVec('final_substitution8',8);encoded=(z3.ZeroExt(24,g)<<8)^0x65^q2
        clauses.append(z3.Extract(15,8,encoded^q2^0x65)==g)
        solver=z3.Solver();solver.set(timeout=30000);solver.add(z3.Not(z3.And(*clauses)));assert solver.check()==z3.unsat
        out.append({'label':'canonical_phase_'+str(len(out)),'parameters':list(params),'query':solver.to_smt2(),'result':'unsat'})
    assert len(out)==5;return out


def snap(r):
    cpu=C.frame(r.u);sp=int(cpu['SP'],16)
    return {'CPU':cpu,'stack_base':hex(sp),'stack1312_hex':r.ram(sp,1312).hex(),'source_visit':r.v}


class Capture(W.Replay):
    def __init__(self,*args):super().__init__(*args);self.blocks=[]
    def code(self,u,pc,n,d):
        self.flush()
        if pc==C.BASE+START:self.blocks.append({'entry':snap(self)})
        if pc==C.BASE+END:
            assert self.blocks and 'end'not in self.blocks[-1];self.blocks[-1]['end']=snap(self)
        return super().code(u,pc,n,d)


def main():
    raw=read(ROOT/'corefp_workspace_checks.json').encode();assert SHA(raw)==PARENT_CHECKS_SHA;e=json.loads(raw)
    raw=read(ROOT/'corefp_workspace_audit.json').encode();assert SHA(raw)==PARENT_AUDIT_SHA;parent=json.loads(raw)
    s=C.Pointers();model=source_model(s);canonical=phase_proofs(parent['workspace_oracles']);blocks=[];totals=Counter()
    for p,form in zip(e['profiles'],e['workspace_constructions']):
        run=Capture(p,e['source_spans'],s);totals.update(run.run());W.T.oracle(p,run);W.workspace_oracle(p,run,s,form);W.preparation_oracle(p,run,s)
        for ordinal,block in enumerate(run.blocks):
            lo,hi=block['entry']['source_visit'],block['end']['source_visit'];assert hi-lo==823
            assert [int(v['pc'],16)for v in p['visits'][lo:hi]]==list(range(START,END,4))
            block.update({'label':p['configuration']['label'],'block_index':ordinal,
              'reads':[r for r in p['reads']if lo<=r['visit']<hi],'writes':[w for w in p['writes']if lo<=w['visit']<hi]})
            blocks.append(block)
        assert len(run.blocks)==p['configuration']['length_u32']//16
        print(json.dumps({'captured':p['configuration']['label'],'blocks':len(run.blocks)}),flush=True)
    assert len(blocks)==8
    deps=['audit_corefp_workspace.py','audit_corefp_pool_transform.py','audit_corefp_pool_caller.py','audit_corefp_pool_allocator.py',
      'audit_corefp_lookup_initialization.py','audit_fpsd1201_predicates.py']
    result={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':C.THIN_SHA,
      'parent_checks_sha256':PARENT_CHECKS_SHA,'parent_audit_sha256':PARENT_AUDIT_SHA,'dependencies':{n:SHA(read(ROOT/n).encode())for n in deps},
      'source_model':model,'canonical_phase_proofs':canonical,'blocks':blocks,'replay_totals':dict(totals),
      'verified_counts':{'profiles':6,'blocks':8,'source_instructions':823,'source_B':3292,'regional_visits':6584,'table_reads':1280,'mixed_word_nodes':36,
        'regional_writes':120,'new_queries_unsat':len(model['proofs'])+len(canonical)},
      'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'new_live_IDA_claim':False,
      'source_context_initializer_established':False,'whole_transform_algorithm':'unknown','full_goal_complete':False}
    (ROOT/'corefp_workspace_consumers_checks.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result['verified_counts']),flush=True)


if __name__=='__main__':main()
