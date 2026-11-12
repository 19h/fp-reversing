#!/usr/bin/env python3
"""Independent concrete source interpreter, replay and canonical consumer oracle.

Does not import the new producer. O(C*(B+V*J+P*F+R)+823*N+256) time/space;
150000 visits/profile and 30 s/SMT query. No native target/API/IPC or IDB access.
"""
import copy,json,struct
from pathlib import Path
from hashlib import sha256
from collections import Counter
import z3
from capstone.arm64_const import ARM64_EXT_UXTW,ARM64_SFT_LSL,ARM64_SFT_LSR,ARM64_SFT_ROR
import audit_corefp_workspace as W
from verify_daemon_reader_record_payloads_publication import read
C=W.C;ROOT=W.ROOT;SHA=lambda b:sha256(b).hexdigest();START=0x1ba0c0;END=0x1bad9c;M32=(1<<32)-1
PARENT_CHECKS_SHA='fc31687bcb81fb5611bccd1e928efdce657767a84218f6d91e47a027d69076b6'
PARENT_AUDIT_SHA='9e1d67b6d637f17b18d8653e23d12400581e20afb7d2e6e4d4fa27faa246ba07'
COLS=[0x0c87f872,0x109f32bf,0x55294a32,0xa6bac3d7,0x80b55471,0xc4596bd6,0xb175e165,0xdac764f9]


def ror(x,n,bits=32):
    n%=bits;return ((x>>n)|(x<<((bits-n)%bits)))&((1<<bits)-1)


def capture(r):
    cpu=C.frame(r.u);sp=int(cpu['SP'],16)
    return {'CPU':cpu,'stack_base':hex(sp),'stack1312_hex':r.ram(sp,1312).hex(),'source_visit':r.v}


class Replay(W.Replay):
    def __init__(self,*args):super().__init__(*args);self.blocks=[]
    def code(self,u,pc,n,d):
        self.flush()
        if pc==C.BASE+START:self.blocks.append({'entry':capture(self)})
        if pc==C.BASE+END:self.blocks[-1]['end']=capture(self)
        return super().code(u,pc,n,d)


def source_interpret(block,instructions,tables):
    cpu=copy.deepcopy(block['entry']['CPU']);reg=[int(v,16)for v in cpu['X31']];sp=int(cpu['SP'],16);nzcv=int(cpu['NZCV'],16)
    stack=bytearray.fromhex(block['entry']['stack1312_hex']);reads=[];writes=[];lo=block['entry']['source_visit']
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
        if o.type==1 and i.reg_name(o.reg).startswith('w')and bits==64:assert o.ext==ARM64_EXT_UXTW;v&=M32
        if o.shift.type:
            shift=o.shift.value
            if o.shift.type==ARM64_SFT_LSL:v<<=shift
            elif o.shift.type==ARM64_SFT_LSR:v>>=shift
            else:assert o.shift.type==ARM64_SFT_ROR;v=ror(v,shift,bits)
        return v&((1<<bits)-1)
    def address(i,o):
        a=rr(i.reg_name(o.mem.base))+o.mem.disp
        if o.mem.index:a+=rr(i.reg_name(o.mem.index))<<o.shift.value
        return a&((1<<64)-1)
    def fetch(a,n):
        if sp<=a and a+n<=sp+len(stack):return bytes(stack[a-sp:a-sp+n])
        for base,raw in tables.items():
            if base<=a and a+n<=base+len(raw):return raw[a-base:a-base+n]
        raise AssertionError(('unbacked_source_interface',hex(a),n))
    for serial,i in enumerate(instructions):
        m=i.mnemonic;o=i.operands;n=i.reg_name(o[0].reg);bits=32 if n.startswith('w')else 64;mask=(1<<bits)-1
        if m in ['ldr','ldur']:
            a=address(i,o[1]);b=fetch(a,bits//8);reads.append({'visit':lo+serial,'address':hex(a),'size_B':len(b),'bytes_hex':b.hex()});put(n,int.from_bytes(b,'little'));continue
        if m in ['str','stur']:
            a=address(i,o[1]);assert sp<=a and a+bits//8<=sp+len(stack)
            b=(rr(n)&mask).to_bytes(bits//8,'little');before=fetch(a,len(b));stack[a-sp:a-sp+len(b)]=b
            writes.append({'visit':lo+serial,'address':hex(a),'size_B':len(b),'before_hex':before.hex(),'after_hex':b.hex()});continue
        if m=='ubfx':put(n,(value(i,o[1],bits)>>o[2].imm)&((1<<o[3].imm)-1));continue
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
        if m=='and':v=a&b
        elif m=='eor':v=a^b
        elif m=='orr':v=a|b
        elif m=='add':v=a+b
        elif m=='lsl':v=a<<(b&(bits-1))
        elif m=='lsr':v=a>>(b&(bits-1))
        else:assert m=='ror';v=ror(a,b,bits)
        put(n,v)
    cpu.update({'X31':[hex(v)for v in reg],'PC':hex(C.BASE+END),'NZCV':hex(nzcv)})
    assert cpu==block['end']['CPU']and stack.hex()==block['end']['stack1312_hex']
    assert reads==block['reads']and writes==block['writes']and len(instructions)==823 and len(reads)==204 and len(writes)==15
    return {'instructions':len(instructions),'reads':len(reads),'writes':len(writes),'stack_final_B':len(stack),'all_CPU_fields_match':True}


def canonical_oracle(block,model,form,s):
    rawstack=bytes.fromhex(block['entry']['stack1312_hex']);cpu=block['entry']['CPU'];u=[int(x,16)&M32 for x in cpu['X31']]
    stack=lambda off:int.from_bytes(rawstack[off:off+4],'little');assert int(cpu['X31'][29],16)-int(cpu['SP'],16)==0x520
    assert (stack(0x1fc)&31)+(stack(0x1a0)&31)==24
    mask=int(form['mask_u32'],16);r=form['rotate_per_byte'];b=int(form['index_xor_u8'],16);k=int(form['first_xor_u32'],16);q2=int(form['second_xor_u32'],16)
    assert mask&0x80808080==0
    def phi(x):return (x^((x&mask)<<1))&M32
    def rotate_lanes(x,shift):return sum(ror((x>>(8*j))&255,-shift,8)<<(8*j)for j in range(4))
    def t(x):return rotate_lanes(phi(x),r)
    def inverse(x):
        y=rotate_lanes(x,-r);v=y
        for _ in range(31):v=(y^((v&mask)<<1))&M32
        return v
    def expand(x):
        v=0x1fc44805
        for j,col in enumerate(COLS):
            if x>>j&1:v^=col
        return v
    t16=struct.unpack('<256H',s.read(0x1af3fc0,512));t32=struct.unpack('<256I',s.read(0x166f4e0,1024));g=[t16[i^0xce]>>8 for i in range(256)]
    f=[((t32[i^0x8c]+(i^0x9a7cd460)+0x80551819)&M32)^0x71ad47f5 for i in range(256)]
    assert len(set(g))==256 and all(v&255==0x65 for v in t16)and f==[expand(x)for x in g]
    first,second=bytearray(1024),bytearray(1024)
    for i in range(256):
        index=(t(i)&255)^b;struct.pack_into('<I',first,4*index,t(f[i])^k);struct.pack_into('<I',second,4*index,(g[i]<<8)^0x65^q2)
    ptrs=[int.from_bytes(rawstack[off:off+8],'little')for off in [0x428,0x430]];assert ptrs==[0x64002f60,0x64002b34]
    tables=dict(zip(ptrs,map(bytes,[first,second])));actual=[x for x in block['reads']if any(base<=int(x['address'],16)<base+1024 for base in ptrs)]
    assert len(actual)==160
    nodes=model['word_nodes'];lookups=model['lookups'];assert [x['id']for x in lookups]==list(range(160))and len(nodes)==36
    canonical={};indices={};words={};offsets={};repb=b*0x01010101;ksum=0
    for rot in range(4):ksum^=ror(k,8*rot)
    for layer in range(10):
        for serial,node in enumerate(nodes):
            if node['layer']!=layer:continue
            terms=node['word_terms'];qs=[(int(n[1:]),rot)for n,rot in terms if n.startswith('q')]
            assert len(qs)==4 and {rot for j,rot in qs}==set(range(4))
            encodedkey=0
            for name,rotation in terms:
                if name[0]=='q':continue
                value=u[int(name[1:])]if name[0]=='u'else stack(int(name[1:],16));encodedkey^=ror(value,rotation*8)
            key=inverse(encodedkey^ksum^repb);offsets[serial]=key;word=key
            for j,rotation in qs:assert j in canonical;word^=ror(canonical[j],rotation*8)
            words[serial]=word
        for row in lookups:
            if row['layer']!=layer:continue
            j=row['id'];byte=row['byte'];word=inverse(u[row['input_register']]^repb)if 'input_register'in row else words[row['word_node']]
            index=(word>>(byte*8))&255;indices[j]=index;canonical[j]=expand(g[index])if layer<9 else g[index]
    assert len(offsets)==36 and len(indices)==160 and {x['layer']for x in nodes}==set(range(1,10))
    for j,(row,observed)in enumerate(zip(lookups,actual)):
        assert hex(int(block['entry']['source_visit'])+int(row['pc'],16)//4-START//4)==hex(observed['visit'])
        index=(t(indices[j])&255)^b;expected=t(canonical[j])^k if row['layer']<9 else (canonical[j]<<8)^0x65^q2
        assert observed['size_B']==4 and int(observed['address'],16)==ptrs[int(row['layer']==9)]+4*index and observed['bytes_hex']==struct.pack('<I',expected).hex()
    endstack=bytes.fromhex(block['end']['stack1312_hex']);endcpu=block['end']['CPU'];final=[]
    for j in range(144,160):
        loc=model['final_destinations']['q'+str(j)];value=(canonical[j]<<8)^0x65^q2
        got=int(endcpu['X31'][loc['register']],16)if 'register'in loc else int.from_bytes(endstack[loc['stack_offset']:loc['stack_offset']+4],'little')
        assert got==value;final.append(canonical[j])
    assert all(rawstack[off:off+8]==endstack[off:off+8]for off in [0x428,0x430])
    assert int.from_bytes(endstack[0x360:0x364],'little')==int(stack(0x3f8)<0x44506381)
    result={'label':block['label'],'block_index':block['block_index'],'table_reads_checked':160,'mixed_words_checked':36,'final_destinations_checked':16,
      'canonical_inputs_u32':[hex(inverse(u[j]^repb))for j in [8,13,14,16]],'canonical_round_offsets_u32':[hex(offsets[j])for j in range(36)],
      'canonical_final16_hex':bytes(final).hex(),'source_shift_pair_u32':[stack(0x1fc),stack(0x1a0)],'workspace_pointers_restored':True,
      'stack_status_u32':int(stack(0x3f8)<0x44506381),'canonical_G_sha256':SHA(bytes(g)),'whole_transform_algorithm':'unknown'}
    return result,tables


def initial_checks(p,s):
    c=p['configuration'];assert c==W.config(c['label']);ov=W.overlay(c)
    assert p['declared_overlay']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in ov]
    cpu={'X31':[hex(((j+1)*0x123456789abcdef)&((1<<64)-1))for j in range(31)],'Q32':[hex(int.from_bytes(bytes([j])*16,'little'))for j in range(32)],
      'SP':hex(C.SP),'PC':hex(C.BASE+C.ENTRY),'NZCV':'0x60000000','FPCR':'0x0','FPSR':'0x0','CPACR_EL1':'0x300000'}
    cpu['X31'][0]=hex(C.REC);cpu['X31'][1]=hex(C.OUT);cpu['X31'][30]=hex(C.DONE);assert p['initial_CPU']==cpu
    for row in p['initial_RAM']:
        a=int(row['address'],16);b=bytearray(4096)if a in [C.ARENA,C.ARENA+4096,W.T.CTX]else bytearray(C.initial_page(s,a))
        for addr,raw in ov:
            lo=max(a,addr);hi=min(a+4096,addr+len(raw))
            if lo<hi:b[lo-a:hi-a]=raw[lo-addr:hi-addr]
        assert C.unpack(row['payload'])==b
    return {'initial_CPU_frames_checked':1,'initial_RAM_B_checked':4096*len(p['initial_RAM'])}


def main():
    raw=read(ROOT/'corefp_workspace_consumers_checks.json').encode();checks_sha=SHA(raw);e=json.loads(raw)
    assert e['generator_sha256']==SHA((ROOT/'recover_corefp_workspace_consumers.py').read_bytes())and e['thin_sha256']==C.THIN_SHA
    raw=read(ROOT/'corefp_workspace_checks.json').encode();assert SHA(raw)==PARENT_CHECKS_SHA;parent=json.loads(raw)
    raw=read(ROOT/'corefp_workspace_audit.json').encode();assert SHA(raw)==PARENT_AUDIT_SHA;parent_audit=json.loads(raw)
    assert e['parent_checks_sha256']==PARENT_CHECKS_SHA and e['parent_audit_sha256']==PARENT_AUDIT_SHA
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    s=C.Pointers()
    for span in parent['source_spans']:assert span==s.function(int(span['start'],16))
    model=e['source_model'];instructions=list(C.CS.disasm(s.read(START,END-START),START));assert model['source_bytes_hex']==s.read(START,END-START).hex()
    assert model['instructions']==[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in instructions]
    assert len(instructions)==model['source_instruction_count']==823 and model['source_B']==3292 and model['lookup_count']==160 and model['mixed_word_nodes']==36 and model['substitution_layers']==10
    assert all(len(n['lookups'])==4 for n in model['word_nodes'])and Counter(l['layer']for l in model['lookups'])==Counter({j:16 for j in range(10)})
    assert model['lookups'][15]['layer']==1 and model['lookups'][16]['layer']==0
    assert model['premises']=={'frame_pointer_minus_SP_B':0x520,'masked_split_shift_sum':24,'nonalias_stack_table_interfaces':True}
    proof_rows=model['proofs']+e['canonical_phase_proofs'];frozen=parent_audit['source_checks']['proofs']+[p for f in parent_audit['frozen_source_checks']for p in f['proofs']]
    assert len(model['proofs'])==330 and len(e['canonical_phase_proofs'])==5 and len(frozen)==28
    for p in proof_rows+frozen:
        assert p['result']=='unsat';solver=z3.Solver();solver.set(timeout=30000);solver.from_string(p['query']);assert solver.check()==z3.unsat,p['label']
    totals=Counter();block_rows=[];interpret_rows=[];forms=[];ordinal=0
    for p,construction,form in zip(parent['profiles'],parent['workspace_constructions'],parent_audit['workspace_oracles']):
        totals.update(initial_checks(p,s));r=Replay(p,parent['source_spans'],s);totals.update(r.run());W.T.oracle(p,r)
        assert W.workspace_oracle(p,r,s,construction)==form;W.preparation_oracle(p,r,s);forms.append(form)
        assert len(r.blocks)==p['configuration']['length_u32']//16
        for j,block in enumerate(r.blocks):
            assert block['entry']==e['blocks'][ordinal]['entry']and block['end']==e['blocks'][ordinal]['end']
            lo,hi=block['entry']['source_visit'],block['end']['source_visit'];assert hi-lo==823
            block.update({'label':p['configuration']['label'],'block_index':j,'reads':[x for x in p['reads']if lo<=x['visit']<hi],
              'writes':[x for x in p['writes']if lo<=x['visit']<hi]});assert block==e['blocks'][ordinal]
            oracle,tables=canonical_oracle(block,model,form,s);block_rows.append(oracle);interpret_rows.append(source_interpret(block,instructions,tables));ordinal+=1
        print(json.dumps({'checked':p['configuration']['label'],'blocks':len(r.blocks)}),flush=True)
    assert ordinal==len(e['blocks'])==8
    assert all(totals[k]==v for k,v in e['replay_totals'].items())and dict(totals)==parent_audit['result']['independent_replay']
    offsets=[r['canonical_round_offsets_u32']for r in block_rows];assert all(v==offsets[0]for v in offsets)
    first=[r for r in block_rows if r['block_index']==0];second=[r for r in block_rows if r['block_index']==1]
    assert len(first)==6 and len(second)==2
    assert all(r['canonical_inputs_u32']==first[0]['canonical_inputs_u32']and r['canonical_final16_hex']==first[0]['canonical_final16_hex']for r in first)
    assert all(r['canonical_inputs_u32']==second[0]['canonical_inputs_u32']and r['canonical_final16_hex']==second[0]['canonical_final16_hex']for r in second)
    packed=struct.pack('<36I',*[int(v,16)for v in offsets[0]])
    counts={'profiles':6,'blocks':8,'source_instructions':823,'source_B':3292,'regional_visits':6584,'table_reads':1280,'mixed_word_nodes':36,
      'regional_writes':120,'new_queries_unsat':335};assert e['verified_counts']==counts
    result={'verified_counts':counts,'independent_replay':dict(totals),'independent_interpreter':dict(sum((Counter({k:v for k,v in r.items()if type(v)is int})for r in interpret_rows),Counter())),
      'canonical_word_instances_checked':288,'canonical_final_destinations_checked':128,'frozen_queries_unsat':28,'total_queries_unsat':363,
      'canonical_offset_B':144,'canonical_offset_sha256':SHA(packed),'constant_offsets_across_retained_blocks':True,
      'canonical_first_block_invariance_profiles':6,'canonical_second_block_invariance_profiles':2,'all_checks_pass':True,'native_target_executed':False}
    out={'result':result,'checks_sha256':checks_sha,'auditor_sha256':SHA(Path(__file__).read_bytes()),'generator_sha256':e['generator_sha256'],
      'parent_checks_sha256':PARENT_CHECKS_SHA,'parent_audit_sha256':PARENT_AUDIT_SHA,'dependencies':e['dependencies'],'block_oracles':block_rows,
      'interpreter_oracles':interpret_rows,'fresh_replay_completed':True,'process_exit_code':0,'source_proof_scope':'source lift with explicit typed loads, modular address normalization and split-shift premise',
      'native_API_executed':False,'IDB_mutated':False,'new_live_IDA_claim':False,'source_context_initializer_established':False,
      'whole_transform_algorithm':'unknown','native_key_schedule_established':False,'full_goal_complete':False}
    (ROOT/'corefp_workspace_consumers_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
