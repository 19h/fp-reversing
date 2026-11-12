#!/usr/bin/env python3
"""Independent late-preparation interpreter, replay and finite component tests.

Does not import the new producer. O(C*(B+V*J+P*F+R)+N*16*256*3590)
time; bounded private maps; 30 s/SMT query. Each component execution has
one declared PAC model. No native target/API/IPC or IDB operation.
"""
import copy,json,struct
from pathlib import Path
from hashlib import sha256
from collections import Counter
from capstone.arm64_const import ARM64_EXT_UXTW,ARM64_EXT_UXTB,ARM64_EXT_SXTW,ARM64_SFT_LSL,ARM64_SFT_LSR,ARM64_SFT_ROR
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as U
import z3
import audit_corefp_output_packing as F
from verify_daemon_reader_record_payloads_publication import read
A=F.A;W=F.W;C=F.C;ROOT=F.ROOT;SHA=F.SHA;M32=(1<<32)-1;START=0x1b87dc;END=0x1bbff4
COLS=[188,68,53,125,218,204,191,255];PERM=[9,7,1,5,15,10,13,12,3,11,0,4,14,6,2,8]
INVERSE=[39,102,194,204,148,117,192,238];WORD_SLOTS=[0x3f0,0x284,0x364,0x3f4]
CONSTANT=bytes.fromhex('405d850bd17f414f2d5b9ae4907df42b')


def ror(x,n,bits=32):
    n%=bits;return ((x>>n)|(x<<((bits-n)%bits)))&((1<<bits)-1)


def source_interpret(block,instructions,tables):
    cpu=copy.deepcopy(block['entry']['CPU']);reg=[int(v,16)for v in cpu['X31']];sp=int(cpu['SP'],16);nzcv=int(cpu['NZCV'],16)
    stack=bytearray.fromhex(block['entry']['stack1312_hex']);reads=[];writes=[];lo=block['entry']['source_visit']
    outbase=int(block['entry']['output_base'],16);out=bytearray.fromhex(block['entry']['output16_hex']);memory={}
    for row in block['reads']:
        address=int(row['address'],16)
        if sp<=address<sp+1312:continue
        for j,b in enumerate(bytes.fromhex(row['bytes_hex'])):
            assert memory.get(address+j,b)==b;memory[address+j]=b
    for base,raw in tables.items():
        for j,b in enumerate(raw):
            assert memory.get(base+j,b)==b;memory[base+j]=b
    def name(n):return {'fp':'x29','lr':'x30'}.get(n,n)
    def rr(n):
        n=name(n)
        if n in ['xzr','wzr']:return 0
        if n=='sp':return sp
        return reg[int(n[1:])]&((1<<(32 if n[0]=='w'else 64))-1)
    def put(n,v):
        n=name(n);assert n not in ['sp','wsp'];reg[int(n[1:])]=v&((1<<(32 if n[0]=='w'else 64))-1)
    def value(i,o,bits):
        v=rr(i.reg_name(o.reg))if o.type==1 else o.imm
        if o.ext:
            if o.ext==ARM64_EXT_UXTB:v&=255
            elif o.ext==ARM64_EXT_UXTW:v&=M32
            else:
                assert o.ext==ARM64_EXT_SXTW;v&=M32
                if v&(1<<31):v-=1<<32
        if o.shift.type:
            shift=o.shift.value
            if o.shift.type==ARM64_SFT_LSL:v<<=shift
            elif o.shift.type==ARM64_SFT_LSR:v>>=shift
            else:assert o.shift.type==ARM64_SFT_ROR;v=ror(v,shift,bits)
        return v&((1<<bits)-1)
    def address(i,o):
        a=rr(i.reg_name(o.mem.base))+o.mem.disp
        if o.mem.index:
            v=rr(i.reg_name(o.mem.index))
            if o.ext==ARM64_EXT_SXTW and v&(1<<31):v-=1<<32
            a+=v<<o.shift.value
        return a&((1<<64)-1)
    def fetch(a,n):
        if sp<=a and a+n<=sp+len(stack):return bytes(stack[a-sp:a-sp+n])
        if outbase<=a and a+n<=outbase+16:return bytes(out[a-outbase:a-outbase+n])
        assert all(a+j in memory for j in range(n)),('unbacked_source_interface',hex(a),n)
        return bytes(memory[a+j]for j in range(n))
    for serial,i in enumerate(instructions):
        if i.address==0x1b8b50:assert [int.from_bytes(stack[off:off+4],'little')for off in WORD_SLOTS]==block['prepared_words_u32']
        m=i.mnemonic;o=i.operands;n=i.reg_name(o[0].reg);bits=32 if n.startswith('w')else 64;mask=(1<<bits)-1
        if m in ['ldr','ldur','ldrb','ldurb']:
            a=address(i,o[1]);b=fetch(a,1 if m in ['ldrb','ldurb']else bits//8);reads.append({'visit':lo+serial,'address':hex(a),'size_B':len(b),'bytes_hex':b.hex()});put(n,int.from_bytes(b,'little'));continue
        if m=='ldp':
            a=address(i,o[2]);width=bits//8
            for j,d in enumerate([n,i.reg_name(o[1].reg)]):
                b=fetch(a+width*j,width);reads.append({'visit':lo+serial,'address':hex(a+width*j),'size_B':width,'bytes_hex':b.hex()});put(d,int.from_bytes(b,'little'))
            continue
        if m in ['str','stur','strb']:
            a=address(i,o[1]);nbytes=1 if m=='strb'else bits//8;b=(rr(n)&((1<<(nbytes*8))-1)).to_bytes(nbytes,'little');before=fetch(a,len(b))
            if sp<=a and a+len(b)<=sp+len(stack):stack[a-sp:a-sp+len(b)]=b
            else:assert outbase<=a and a+len(b)<=outbase+16;out[a-outbase:a-outbase+len(b)]=b
            writes.append({'visit':lo+serial,'address':hex(a),'size_B':len(b),'before_hex':before.hex(),'after_hex':b.hex()});continue
        if m=='ubfx':put(n,(value(i,o[1],bits)>>o[2].imm)&((1<<o[3].imm)-1));continue
        if m=='ubfiz':put(n,(value(i,o[1],bits)&((1<<o[3].imm)-1))<<o[2].imm);continue
        if m=='braa':
            assert i.address==0x1b9b34 and rr('x8')==C.BASE+0x1b9b38 and rr('x17')==0x1410;continue
        if m in ['bfi','bfxil']:
            shift,width=o[2].imm,o[3].imm;source=value(i,o[1],bits)
            if m=='bfi':v=(rr(n)&~(((1<<width)-1)<<shift))|((source&((1<<width)-1))<<shift)
            else:v=(rr(n)&~((1<<width)-1))|((source>>shift)&((1<<width)-1))
            put(n,v);continue
        if m=='mvn':put(n,~value(i,o[1],bits));continue
        if m=='extr':
            a,b=value(i,o[1],bits),value(i,o[2],bits);put(n,(b>>o[3].imm)|(a<<(bits-o[3].imm)));continue
        if m=='adrp':put(n,C.BASE+o[1].imm);continue
        if m=='mov':put(n,value(i,o[1],bits));continue
        if m=='movk':
            shift=o[1].shift.value;put(n,(rr(n)&~(65535<<shift))|(o[1].imm<<shift));continue
        if m=='neg':put(n,-value(i,o[1],bits));continue
        if m=='cmp':
            a,b=value(i,o[0],bits),value(i,o[1],bits);v=(a-b)&mask
            nzcv=((v>>(bits-1))<<31)|(int(v==0)<<30)|(int(a>=b)<<29)|(int(bool(((a^b)&(a^v))>>(bits-1)))<<28);continue
        if m=='tst':
            v=value(i,o[0],bits)&value(i,o[1],bits);nzcv=((v>>(bits-1))<<31)|(int(v==0)<<30);continue
        if m=='cset':assert i.op_str.endswith(', lo');put(n,int(not(nzcv&(1<<29))));continue
        if m=='cneg':
            assert i.op_str.endswith(', ne');v=value(i,o[1],bits);put(n,-v if not(nzcv&(1<<30))else v);continue
        a,b=value(i,o[1],bits),value(i,o[2],bits)
        if m=='bic':v=a&~b
        elif m=='and':v=a&b
        elif m=='eor':v=a^b
        elif m=='orr':v=a|b
        elif m=='add':v=a+b
        elif m=='sub':v=a-b
        elif m=='mul':v=a*b
        elif m=='orn':v=a|(~b)
        elif m=='lsl':v=a<<(b&(bits-1))
        elif m=='lsr':v=a>>(b&(bits-1))
        else:assert m=='ror';v=ror(a,b,bits)
        put(n,v)
    cpu.update({'X31':[hex(v)for v in reg],'PC':hex(C.BASE+END),'NZCV':hex(nzcv)})
    assert cpu==block['end']['CPU']and stack.hex()==block['end']['stack1312_hex']
    assert out.hex()==block['end']['output16_hex']
    assert reads==block['reads']and writes==block['writes']and len(instructions)==3590 and len(reads)==636 and len(writes)==158
    return {'instructions':len(instructions),'reads':len(reads),'writes':len(writes),'stack_final_B':len(stack),'all_CPU_fields_match':True}


def linear(x,cols):
    v=0
    for k,c in enumerate(cols):
        if x>>k&1:v^=c
    return v


def prep_words(p):
    return [int.from_bytes(bytes(linear(x,INVERSE)for x in p[j*4:j*4+4]),'big')^(0xab if j==1 else 0)for j in range(4)]


def output(p,g):return bytes(linear(g[PERM[j]],COLS)^p[j]^CONSTANT[j]for j in range(16))


def snap(r):
    row=A.capture(r);dst=C.addresses(r.p['configuration'])[1]
    return {**row,'output_base':hex(dst),'output16_hex':r.ram(dst,16).hex()}


class Replay(F.Replay):
    def __init__(self,*args):super().__init__(*args);self.late={}
    def code(self,u,pc,n,d):
        self.flush()
        if pc==C.BASE+START:assert not self.late;self.late['entry']=snap(self)
        if pc==C.BASE+0x1b8b50:
            sp=int(C.frame(u)['SP'],16);self.late['prepared_words_u32']=[int.from_bytes(self.ram(sp+off,4),'little')for off in WORD_SLOTS]
        if pc==C.BASE+END and 'end'not in self.late:self.late['end']=snap(self)
        return super().code(u,pc,n,d)


def machine_cases(p,block,model,s):
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);mapped=set()
    for row in p['initial_RAM']:
        at=int(row['address'],16);u.mem_map(at,4096);u.mem_write(at,C.unpack(row['payload']));mapped.add(at)
    def write(at,b):
        for page in range(at&~4095,(at+len(b)+4095)&~4095,4096):
            if page not in mapped:u.mem_map(page,4096);u.mem_write(page,C.initial_page(s,page));mapped.add(page)
        u.mem_write(at,b)
    sp=int(block['entry']['CPU']['SP'],16);dst=int(block['entry']['output_base'],16);stack=bytes.fromhex(block['entry']['stack1312_hex']);before=bytes.fromhex(block['entry']['output16_hex']);fixed={}
    for r in block['reads']:
        at=int(r['address'],16)
        if sp<=at and at+r['size_B']<=sp+1312:continue
        for j,b in enumerate(bytes.fromhex(r['bytes_hex'])):assert fixed.get(at+j,b)==b;fixed[at+j]=b
    for at,b in fixed.items():write(at,bytes([b]))
    for row in model['symbolic_tables']:
        at=C.BASE+int(row['base'],16);raw=bytes.fromhex(row['bytes_hex']);assert raw==s.read(int(row['base'],16),256)
        assert all(fixed.get(at+j,b)==b for j,b in enumerate(raw));write(at,raw)
    write(C.BASE+START,s.read(START,END-START));write(sp,stack);write(dst,before);C.restore(u,block['entry']['CPU'])
    assert bytes(u.mem_read(C.BASE+START,END-START))==s.read(START,END-START)
    state={'p':stack[0x498:0x4a8],'PAC':0,'word_checkpoints':0}
    def pac(uc,pc,n,d):
        assert pc==C.BASE+0x1b9b34 and uc.reg_read(U.UC_ARM64_REG_X8)==C.BASE+0x1b9b38 and uc.reg_read(U.UC_ARM64_REG_X17)==0x1410
        state['PAC']+=1;uc.reg_write(U.UC_ARM64_REG_PC,C.BASE+0x1b9b38)
    def words(uc,pc,n,d):
        assert [int.from_bytes(uc.mem_read(sp+off,4),'little')for off in WORD_SLOTS]==prep_words(state['p']);state['word_checkpoints']+=1
    u.hook_add(UC_HOOK_CODE,pac,begin=C.BASE+0x1b9b34,end=C.BASE+0x1b9b34)
    u.hook_add(UC_HOOK_CODE,words,begin=C.BASE+0x1b8b50,end=C.BASE+0x1b8b50)
    context=u.context_save();u.emu_start(C.BASE+START,C.BASE+END,count=3591)
    assert C.frame(u)==block['end']['CPU']and bytes(u.mem_read(sp,1312)).hex()==block['end']['stack1312_hex']and bytes(u.mem_read(dst,16)).hex()==block['end']['output16_hex']
    assert state['PAC']==state['word_checkpoints']==1
    state['PAC']=state['word_checkpoints']=0;digest=sha256();cases=0;g=block['actual_canonical_g16']
    for varied in range(16):
        for value in range(256):
            u.context_restore(context);prepared=bytearray(16);prepared[varied]=value;state['p']=bytes(prepared)
            ram=bytearray(stack);ram[0x498:0x4a8]=prepared;write(sp,bytes(ram));write(dst,before)
            u.emu_start(C.BASE+START,C.BASE+END,count=3591);assert u.reg_read(U.UC_ARM64_REG_PC)==C.BASE+END
            got=bytes(u.mem_read(dst,16));assert got==output(prepared,g),(block['label'],varied,value,got.hex())
            digest.update(got);cases+=1
    assert cases==state['PAC']==state['word_checkpoints']==4096
    return {'label':block['label'],'actual_frame_cases':1,'finite_cases':cases,'finite_source_visits':cases*3590,'finite_emulated_instructions':cases*3589,
      'finite_PAC_models':cases,'finite_preparation_words_checked':cases*4,'finite_output_B':cases*16,'ordered_outputs_sha256':digest.hexdigest(),
      'source_bytes_preserved':True,'scope':'first-block component entry; one late prepared byte varied, other fifteen zero; earlier phase/read premises fixed; one declared PAC interface per run'}


def main():
    raw=read(ROOT/'corefp_late_preparation_checks.json').encode();e=json.loads(raw);checks_sha=SHA(raw)
    assert e['generator_sha256']==SHA((ROOT/'recover_corefp_late_preparation.py').read_bytes())and e['thin_sha256']==C.THIN_SHA
    pinned={}
    for name,h in e['parent_pins'].items():
        raw=read(ROOT/name).encode();assert SHA(raw)==h;pinned[name]=json.loads(raw)
    assert len(pinned)==6
    for name,h in e['dependencies'].items():assert SHA(read(ROOT/name).encode())==h
    parent=pinned['corefp_workspace_checks.json'];pa=pinned['corefp_workspace_audit.json'];ce=pinned['corefp_workspace_consumers_checks.json'];ca=pinned['corefp_workspace_consumers_audit.json'];pe=pinned['corefp_output_packing_checks.json']
    s=C.Pointers()
    for span in parent['source_spans']:assert span==s.function(int(span['start'],16))
    instructions=list(C.CS.disasm(s.read(START,END-START),START));assert len(instructions)==3590 and e['source_bytes_hex']==s.read(START,END-START).hex()
    assert e['instructions']==[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in instructions]
    controls=[i for i in instructions if any(i.group(g)for g in [1,2,3])];assert [(hex(i.address),i.mnemonic,i.op_str)for i in controls]==[('0x1b9b34','braa','x8, x17')]
    assert e['inverse_H_columns_u8']==INVERSE and e['word_slots']==WORD_SLOTS and e['word_store_PCs']==['0x1b8a64','0x1b8ab8','0x1b8b0c','0x1b8b4c']
    assert sorted(linear(x,INVERSE)for x in range(256))==list(range(256))and all(linear(linear(x,INVERSE),COLS)==x for x in range(256))
    new=[p for m in e['transfer_models']for p in m['proofs']]
    frozen=[pe['common_inverse_proof']]+[p for m in pe['transfer_models']for p in m['proofs']]+ce['source_model']['proofs']+ce['canonical_phase_proofs']+pa['source_checks']['proofs']+[p for f in pa['frozen_source_checks']for p in f['proofs']]
    assert len(new)==420 and len(frozen)==620
    for p in new+frozen:
        assert p['result']=='unsat';q=z3.Solver();q.set(timeout=30000);q.from_string(p['query']);assert q.check()==z3.unsat,p['label']
    totals=Counter();interpreters=[];machines=[];oracles=[];index=0
    for ordinal,(p,construction,form,b,m)in enumerate(zip(parent['profiles'],parent['workspace_constructions'],pa['workspace_oracles'],e['blocks'],e['transfer_models'])):
        totals.update(A.initial_checks(p,s));r=Replay(p,parent['source_spans'],s);totals.update(r.run());W.T.oracle(p,r)
        assert W.workspace_oracle(p,r,s,construction)==form;W.preparation_oracle(p,r,s)
        assert r.late=={k:b[k]for k in ['entry','end','prepared_words_u32']}and r.packing[0]['end']==b['end']and b['end']==pe['blocks'][index]['end']
        lo,hi=b['entry']['source_visit'],b['end']['source_visit'];assert hi-lo==3590 and [int(v['pc'],16)for v in p['visits'][lo:hi]]==list(range(START,END,4))
        for key in ['reads','writes','PAC_models']:assert b[key]==[x for x in p[key]if lo<=x['visit']<hi]
        assert b['label']==m['label']==p['configuration']['label']and b['actual_canonical_g16']==list(bytes.fromhex(ca['block_oracles'][index]['canonical_final16_hex']))
        prepared=bytes.fromhex(b['entry']['stack1312_hex'])[0x498:0x4a8];assert prepared.hex()==m['actual_prepared16_hex']and prep_words(prepared)==b['prepared_words_u32']
        assert m['constant16_hex']==CONSTANT.hex()and output(prepared,b['actual_canonical_g16']).hex()==b['end']['output16_hex']
        late=[x for x in b['reads']if int(b['entry']['stack_base'],16)+0x498<=int(x['address'],16)<int(b['entry']['stack_base'],16)+0x4a8]
        assert len(late)==16 and {int(x['address'],16)-int(b['entry']['stack_base'],16)-0x498 for x in late}==set(range(16))and all(x['size_B']==1 for x in late)
        assert len(m['proofs'])==70 and len(m['symbolic_tables'])==32
        tables={C.BASE+int(row['base'],16):bytes.fromhex(row['bytes_hex'])for row in m['symbolic_tables']};assert all(raw==s.read(at-C.BASE,256)for at,raw in tables.items())
        interpreters.append(source_interpret(b,instructions,tables));machines.append(machine_cases(p,b,m,s))
        oracles.append({'label':b['label'],'prepared16_hex':prepared.hex(),'prepared_words_u32':prep_words(prepared),'late_reads_checked':16,'canonical_results_unchanged':16,'actual_output16_hex':output(prepared,b['actual_canonical_g16']).hex()})
        index+=p['configuration']['length_u32']//16;print(json.dumps({'audited':b['label'],'finite_cases':sum(x['finite_cases']for x in machines)}),flush=True)
    assert len(oracles)==6 and index==8 and dict(totals)==ca['result']['independent_replay']and e['replay_totals']=={k:v for k,v in totals.items()if not k.startswith('initial_')}
    counts={'profiles':6,'first_blocks':6,'source_instructions':3590,'source_B':14360,'regional_visits':21540,'regional_reads':3816,'regional_writes':948,
      'late_prepared_reads':96,'expanded_byte_tables':192,'preparation_words':24,'consumer_results_preserved':96,'output_bytes':96,'new_queries_unsat':420,'regional_PAC_models':6};assert e['verified_counts']==counts
    result={'verified_counts':counts,'independent_replay':dict(totals),'independent_interpreter':dict(sum((Counter({k:v for k,v in row.items()if type(v)is int})for row in interpreters),Counter())),
      **{k:sum(row[k]for row in machines)for k in ['finite_cases','finite_source_visits','finite_emulated_instructions','finite_PAC_models','finite_preparation_words_checked','finite_output_B']},
      'actual_machine_frames':6,'complete_inverse_values_checked':256,'frozen_queries_unsat':620,'total_queries_unsat':1040,'constant_across_six_domains':True,'all_checks_pass':True,'native_target_executed':False}
    out={'result':result,'checks_sha256':checks_sha,'auditor_sha256':SHA(Path(__file__).read_bytes()),'generator_sha256':e['generator_sha256'],'parent_pins':e['parent_pins'],'dependencies':e['dependencies'],
      'interpreter_oracles':interpreters,'machine_oracles':machines,'component_oracles':oracles,'fresh_replay_completed':True,'process_exit_code':0,
      'native_API_executed':False,'IDB_mutated':False,'new_live_IDA_claim':False,'source_context_initializer_established':False,'general_raw_preparation_contract_established':False,
      'general_second_block_contract_established':False,'whole_transform_algorithm':'unknown','full_goal_complete':False}
    (ROOT/'corefp_late_preparation_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
