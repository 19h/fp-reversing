#!/usr/bin/env python3
"""First-block late-preparation transfer, with the earlier phase frozen.

Partial source lift with explicit typed reads and one retained PAC interface.
A canonical-result cut quantifies sixteen independent g bytes; this is an
interface composition, not an original-instruction patch or native admission.
O(C*(V*J+P*F+R)+N*3590+N*16*256) time/space; 30 s/SMT query.
No native target/API/IPC or IDB operation.
"""
import json,struct,z3
from pathlib import Path
from collections import Counter
from capstone.arm64_const import *
import recover_corefp_output_packing as F
from verify_daemon_reader_record_payloads_publication import read
A=F.A;W=F.W;C=F.C;ROOT=F.ROOT;SHA=F.SHA;S=C.Pointers()
START=0x1b87dc;END=0x1bbff4;CUT=0x1bad9c;INS=list(C.CS.disasm(S.read(START,END-START),START));M64=(1<<64)-1
WORD_SLOTS=[0x3f0,0x284,0x364,0x3f4];WORD_STORES=[0x1b8a64,0x1b8ab8,0x1b8b0c,0x1b8b4c]
INVERSE_COLUMNS=[39,102,194,204,148,117,192,238]
PINS={**F.PINS,'corefp_output_packing_checks.json':'8dfc45f135b908cf15c4ccc09744d758881ee27fdd84cdb87760fa55703fd7ac',
 'corefp_output_packing_audit.json':'7a98b7fd8afff9080684a1c2a75fb548cf2a6fb8d8e86bdd23123cec42dbe1b7'}


def snap(r):
    row=A.capture(r);dst=C.addresses(r.p['configuration'])[1]
    return {**row,'output_base':hex(dst),'output16_hex':r.ram(dst,16).hex()}


class Capture(A.Replay):
    def __init__(self,*args):super().__init__(*args);self.late={}
    def code(self,u,pc,n,d):
        self.flush()
        if pc==C.BASE+START:assert not self.late;self.late['entry']=snap(self)
        if pc==C.BASE+0x1b8b50:
            sp=int(C.frame(u)['SP'],16);self.late['prepared_words_u32']=[int.from_bytes(self.ram(sp+off,4),'little')for off in WORD_SLOTS]
        if pc==C.BASE+END and 'end'not in self.late:self.late['end']=snap(self)
        return super().code(u,pc,n,d)


def lift(block):
    frame=block['entry']['CPU'];regs={j:z3.BitVecVal(int(v,16),64)for j,v in enumerate(frame['X31'])};sp=int(frame['SP'],16)
    stack={sp+j:z3.BitVecVal(b,8)for j,b in enumerate(bytes.fromhex(block['entry']['stack1312_hex']))}
    p=[z3.BitVec('late_p'+str(j),8)for j in range(16)];g=[z3.BitVec('late_g'+str(j),8)for j in range(16)];proofs=[];luts=[];outputs=[];modeled_reads=[];modeled_writes=[];word_exprs=[];ri=0;cut_values=[]
    flags={k:z3.BoolVal(bool(int(frame['NZCV'],16)&(1<<bit)))for k,bit in [('N',31),('Z',30),('C',29),('V',28)]}
    for j,v in enumerate(p):stack[sp+0x498+j]=v
    dst=int(block['entry']['output_base'],16)
    for j,v in enumerate(bytes.fromhex(block['entry']['output16_hex'])):stack[dst+j]=z3.BitVecVal(v,8)
    def prove(label,claim):
        q=z3.Solver();q.set(timeout=30000);q.add(z3.Not(claim));assert q.check()==z3.unsat,label
        proofs.append({'label':label,'query':q.to_smt2(),'result':'unsat'})
    def store(at,n,v):
        for j in range(n):stack[at+j]=z3.Extract(8*j+7,8*j,v)
    def rr(name):
        name={'fp':'x29','lr':'x30'}.get(name,name)
        if name=='sp':return z3.BitVecVal(sp,64)
        if name in ['wzr','xzr']:return z3.BitVecVal(0,32 if name[0]=='w'else 64)
        v=regs[int(name[1:])];return z3.Extract(31,0,v)if name[0]=='w'else v
    def put(name,v):
        name={'fp':'x29','lr':'x30'}.get(name,name);assert name not in ['sp','wsp']
        regs[int(name[1:])]=z3.ZeroExt(32,z3.simplify(v))if name[0]=='w'else z3.simplify(v)
    def operand(i,o,bits):
        v=rr(i.reg_name(o.reg))if o.type==1 else z3.BitVecVal(o.imm,bits)
        if o.ext:
            if o.ext==ARM64_EXT_UXTB:v=z3.ZeroExt(bits-8,z3.Extract(7,0,v))
            elif o.ext==ARM64_EXT_UXTW:v=z3.ZeroExt(bits-32,z3.Extract(31,0,v))
            else:assert o.ext==ARM64_EXT_SXTW;v=z3.SignExt(bits-32,z3.Extract(31,0,v))
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
    def load(at,n,i):
        nonlocal ri
        at=z3.simplify(at);old=block['reads'][ri];assert old['visit']==block['entry']['source_visit']+(i.address-START)//4 and old['size_B']==n
        if z3.is_bv_value(at):
            a=at.as_long();assert a==int(old['address'],16)
            v=z3.simplify(z3.Concat(*[stack[a+j]for j in reversed(range(n))]))if n>1 and all(a+j in stack for j in range(n))else stack[a]if n==1 and a in stack else z3.BitVecVal(int.from_bytes(bytes.fromhex(old['bytes_hex']),'little'),8*n)
        else:
            assert n==1,(hex(i.address),str(at))
            terms=at.children()if at.decl().kind()==z3.Z3_OP_BADD else [at];constants=[x.as_long()for x in terms if z3.is_bv_value(x)]
            if constants:base=sum(constants)&M64
            else:
                high=z3.simplify(at&z3.BitVecVal(M64^255,64));assert z3.is_bv_value(high),(hex(i.address),str(at));base=high.as_long()
            index=z3.simplify(z3.Extract(7,0,at-base));prove('late_byte_address_'+hex(i.address),at==z3.BitVecVal(base,64)+z3.ZeroExt(56,index))
            raw=S.read(base-C.BASE,256);actual_index=int(old['address'],16)-base;assert 0<=actual_index<256 and raw[actual_index:actual_index+1].hex()==old['bytes_hex']
            luts.append({'pc':hex(i.address),'base':hex(base-C.BASE),'bytes_hex':raw.hex()});v=z3.simplify(mux(list(raw),index))
        modeled_reads.append({'index':ri,'address':at,'value':v});ri+=1;return v
    def canonical_cut():
        form=next(f for f in F.forms if f['label']==block['label']);q=int(form['second_xor_u32'],16)
        for j in range(16):
            loc=F.parent['source_model']['final_destinations']['q'+str(j+144)]
            v=z3.Extract(31,0,regs[loc['register']])if 'register'in loc else z3.Concat(*[stack[sp+loc['stack_offset']+k]for k in [3,2,1,0]])
            actual=(block['actual_canonical_g16'][j]<<8)^0x65^q;prove('late_consumer_preserved_q'+str(j+144),v==actual);cut_values.append(hex(actual))
            free=(z3.ZeroExt(24,g[j])<<8)^0x65^q
            if 'register'in loc:regs[loc['register']]=z3.ZeroExt(32,free)
            else:store(sp+loc['stack_offset'],4,free)
    def hinv(x):
        v=z3.BitVecVal(0,8)
        for k,c in enumerate(INVERSE_COLUMNS):v^=z3.If(z3.Extract(k,k,x)==0,z3.BitVecVal(0,8),z3.BitVecVal(c,8))
        return v
    for i in INS:
        if i.address==0x1b8b50:
            word_exprs=[z3.Concat(*[stack[sp+off+k]for k in [3,2,1,0]])for off in WORD_SLOTS]
            for j,w in enumerate(word_exprs):prove('late_preparation_word_'+str(j),w==(z3.Concat(*[hinv(p[j*4+k])for k in range(4)])^(0xab if j==1 else 0)))
        if i.address==CUT:canonical_cut()
        m=i.mnemonic;o=i.operands;name=i.reg_name(o[0].reg);bits=32 if name.startswith('w')else 64
        if m in ['ldr','ldur','ldrb','ldurb']:
            n=1 if m in ['ldrb','ldurb']else bits//8;v=load(address(i,o[1]),n,i);put(name,z3.ZeroExt(bits-v.size(),v));continue
        if m=='ldp':
            at=address(i,o[2]);n=bits//8;put(name,load(at,n,i));put(i.reg_name(o[1].reg),load(at+n,n,i));continue
        if m in ['str','stur','strb']:
            at=address(i,o[1]);assert z3.is_bv_value(at),(hex(i.address),str(at));n=1 if m=='strb'else bits//8;v=z3.Extract(n*8-1,0,rr(name));a=at.as_long()
            assert sp<=a and a+n<=sp+1312 or dst<=a and a+n<=dst+16
            before=z3.Concat(*[stack[a+k]for k in reversed(range(n))])if n>1 else stack[a]
            modeled_writes.append({'pc':i.address,'address':a,'size_B':n,'before':before,'after':v});store(a,n,v)
            if m=='strb':outputs.append({'pc':i.address,'address':at.as_long(),'value':z3.simplify(v)})
            continue
        if m=='braa':
            assert i.address==0x1b9b34;prove('late_PAC_target',rr('x8')==C.BASE+0x1b9b38);prove('late_PAC_modifier',rr('x17')==0x1410);continue
        if m=='mov':put(name,operand(i,o[1],bits));continue
        if m=='movk':
            k=o[1].shift.value;put(name,(rr(name)&z3.BitVecVal(((1<<bits)-1)^(65535<<k),bits))|z3.BitVecVal(o[1].imm<<k,bits));continue
        if m=='adrp':put(name,z3.BitVecVal(C.BASE+o[1].imm,64));continue
        if m=='ubfx':put(name,z3.ZeroExt(bits-o[3].imm,z3.Extract(o[2].imm+o[3].imm-1,o[2].imm,operand(i,o[1],bits))));continue
        if m=='ubfiz':put(name,(operand(i,o[1],bits)&((1<<o[3].imm)-1))<<o[2].imm);continue
        if m in ['bfi','bfxil']:
            shift,width=o[2].imm,o[3].imm
            if m=='bfi':v=(rr(name)&~z3.BitVecVal(((1<<width)-1)<<shift,bits))|((operand(i,o[1],bits)&((1<<width)-1))<<shift)
            else:v=(rr(name)&~z3.BitVecVal((1<<width)-1,bits))|(z3.LShR(operand(i,o[1],bits),shift)&((1<<width)-1))
            put(name,v);continue
        if m=='extr':
            a,b=operand(i,o[1],bits),operand(i,o[2],bits);put(name,z3.Extract(bits-1,0,z3.LShR(z3.Concat(a,b),o[3].imm)));continue
        if m in ['mvn','neg']:put(name,~operand(i,o[1],bits)if m=='mvn'else-operand(i,o[1],bits));continue
        if m in ['cmp','tst']:
            a,b=operand(i,o[0],bits),operand(i,o[1],bits);v=a-b if m=='cmp'else a&b
            flags={'N':z3.Extract(bits-1,bits-1,v)==1,'Z':v==0,'C':z3.UGE(a,b)if m=='cmp'else z3.BoolVal(False),
              'V':z3.Extract(bits-1,bits-1,(a^b)&(a^v))==1 if m=='cmp'else z3.BoolVal(False)};continue
        if m=='cset':assert i.op_str.endswith(', lo');put(name,z3.If(flags['C'],z3.BitVecVal(0,bits),z3.BitVecVal(1,bits)));continue
        if m=='cneg':assert i.op_str.endswith(', ne');v=operand(i,o[1],bits);put(name,z3.If(flags['Z'],v,-v));continue
        assert m in ['eor','sub','and','lsl','lsr','add','mul','orn','orr','bic','ror'],m
        a,b=operand(i,o[1],bits),operand(i,o[2],bits)
        v={'eor':lambda:a^b,'sub':lambda:a-b,'and':lambda:a&b,'lsl':lambda:a<<(b&(bits-1)),'lsr':lambda:z3.LShR(a,b&(bits-1)),
          'add':lambda:a+b,'mul':lambda:a*b,'orn':lambda:a|~b,'orr':lambda:a|b,'bic':lambda:a&~b,'ror':lambda:z3.RotateRight(a,b)}[m]();put(name,v)
    assert ri==len(block['reads'])and len(outputs)==16 and len(cut_values)==16
    assert len(word_exprs)==4 and len(modeled_writes)==len(block['writes'])
    return p,g,outputs,luts,proofs,regs,stack,modeled_reads,flags,modeled_writes,word_exprs


def transfer(block):
    p,g,outputs,luts,proofs,regs,stack,reads,flags,writes,words=lift(block);outputs=sorted(outputs,key=lambda x:x['address']);dst=int(block['entry']['output_base'],16)
    assert [o['address']for o in outputs]==list(range(dst,dst+16))
    def evaluate(e,pv,gv):return z3.simplify(z3.substitute(e,*[(v,z3.BitVecVal(b,8))for v,b in zip(p+g,list(pv)+list(gv))])).as_long()
    actual_p=bytes.fromhex(block['entry']['stack1312_hex'])[0x498:0x4a8];actual_g=block['actual_canonical_g16'];zeros=bytes(16);constant=[]
    for j,row in enumerate(outputs):
        c=evaluate(row['value'],zeros,zeros);constant.append(c);candidate=F.h_expr(g[F.PERM[j]])^p[j]^c
        q=z3.Solver();q.set(timeout=30000);q.add(row['value']!=candidate);assert q.check()==z3.unsat,(block['label'],j)
        proofs.append({'label':'late_joint_output_'+str(j),'query':q.to_smt2(),'result':'unsat'})
        assert evaluate(row['value'],actual_p,actual_g)==bytes.fromhex(block['end']['output16_hex'])[j]
    assert [hex(evaluate(regs[j],actual_p,actual_g))for j in range(31)]==block['end']['CPU']['X31']
    sp=int(block['entry']['stack_base'],16);assert bytes(evaluate(stack[sp+j],actual_p,actual_g)for j in range(1312)).hex()==block['end']['stack1312_hex']
    nzcv=0
    for name,bit in [('N',31),('Z',30),('C',29),('V',28)]:
        v=z3.simplify(z3.substitute(flags[name],*[(x,z3.BitVecVal(b,8))for x,b in zip(p+g,list(actual_p)+list(actual_g))]));assert z3.is_true(v)or z3.is_false(v)
        if z3.is_true(v):nzcv|=1<<bit
    assert hex(nzcv)==block['end']['CPU']['NZCV']
    for row in reads:
        old=block['reads'][row['index']];assert evaluate(row['address'],actual_p,actual_g)==int(old['address'],16)
        assert evaluate(row['value'],actual_p,actual_g)==int.from_bytes(bytes.fromhex(old['bytes_hex']),'little')
    for row,old in zip(writes,block['writes']):
        assert old['visit']==block['entry']['source_visit']+(row['pc']-START)//4 and row['address']==int(old['address'],16)and row['size_B']==old['size_B']
        for key,oldkey in [('before','before_hex'),('after','after_hex')]:assert evaluate(row[key],actual_p,actual_g)==int.from_bytes(bytes.fromhex(old[oldkey]),'little')
    assert [evaluate(w,actual_p,actual_g)for w in words]==block['prepared_words_u32']
    assert len(proofs)==70 and len(luts)==32 and len(reads)==636 and len(writes)==158
    return {'label':block['label'],'actual_prepared16_hex':actual_p.hex(),'constant16_hex':bytes(constant).hex(),'symbolic_tables':luts,'proofs':proofs,
      'all_GPRs_flags_stack_reads_writes_match':True,'source_reads_checked':636,'source_writes_checked':158,
      'universal_scope':'sixteen free late prepared u8 bytes and sixteen independent canonical-result u8 bytes; earlier entry/read premises fixed; explicit result-interface cut'}


def main():
    pinned={}
    for name,h in PINS.items():
        raw=read(ROOT/name).encode();assert SHA(raw)==h;pinned[name]=json.loads(raw)
    parent=pinned['corefp_workspace_checks.json'];ca=pinned['corefp_workspace_consumers_audit.json'];packing=pinned['corefp_output_packing_checks.json']
    for span in parent['source_spans']:assert span==S.function(int(span['start'],16))
    blocks=[];models=[];totals=Counter();index=0
    for p in parent['profiles']:
        r=Capture(p,parent['source_spans'],S);totals.update(r.run());b=r.late;lo,hi=b['entry']['source_visit'],b['end']['source_visit']
        assert hi-lo==3590 and [int(v['pc'],16)for v in p['visits'][lo:hi]]==list(range(START,END,4))
        assert b['end']==packing['blocks'][index]['end']
        b.update({'label':p['configuration']['label'],'actual_canonical_g16':list(bytes.fromhex(ca['block_oracles'][index]['canonical_final16_hex'])),
          'reads':[x for x in p['reads']if lo<=x['visit']<hi],'writes':[x for x in p['writes']if lo<=x['visit']<hi],
          'PAC_models':[x for x in p['PAC_models']if lo<=x['visit']<hi]})
        assert len(b['PAC_models'])==1 and b['PAC_models'][0]['pc']=='0x1b9b34'
        models.append(transfer(b));blocks.append(b);index+=p['configuration']['length_u32']//16
        print(json.dumps({'captured':b['label'],'queries_unsat':len(models[-1]['proofs'])}),flush=True)
    assert len(blocks)==6 and index==8 and all(m['constant16_hex']==models[0]['constant16_hex']for m in models)
    dependencies=['recover_corefp_output_packing.py','audit_corefp_output_packing.py',*pinned['corefp_output_packing_checks.json']['dependencies']]
    counts={'profiles':6,'first_blocks':6,'source_instructions':3590,'source_B':14360,'regional_visits':21540,'regional_reads':3816,'regional_writes':948,
      'late_prepared_reads':96,'expanded_byte_tables':192,'preparation_words':24,'consumer_results_preserved':96,'output_bytes':96,'new_queries_unsat':420,'regional_PAC_models':6}
    out={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':C.THIN_SHA,'parent_pins':PINS,
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in dependencies},'source_bytes_hex':S.read(START,END-START).hex(),
      'instructions':[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in INS],
      'word_slots':WORD_SLOTS,'word_store_PCs':list(map(hex,WORD_STORES)),'inverse_H_columns_u8':INVERSE_COLUMNS,
      'blocks':blocks,'transfer_models':models,'replay_totals':dict(totals),'verified_counts':counts,
      'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'new_live_IDA_claim':False,'source_context_initializer_established':False,
      'general_raw_preparation_contract_established':False,'general_second_block_contract_established':False,'whole_transform_algorithm':'unknown','full_goal_complete':False}
    (ROOT/'corefp_late_preparation_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
