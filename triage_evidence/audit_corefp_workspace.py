#!/usr/bin/env python3
"""Independent caller replay and source-lifted workspace representations.

Does not import the new producer. O(C*(B+P*F+V*J+R)+256^2) time/space;
150000 visits/profile and 30 s/query. No native target/API/IPC or IDB operation.
"""
import json,struct,copy
from pathlib import Path
from hashlib import sha256
from collections import Counter
import z3
from unicorn import arm64_const as A
import audit_corefp_pool_transform as T
from verify_daemon_reader_record_payloads_publication import read
ROOT=T.ROOT;C=T.C;SHA=lambda b:sha256(b).hexdigest();PREPSRC=C.HEAP+768;PREP=0x62017f68;M=(1<<32)-1
COLUMNS=[0x0c87f872,0x109f32bf,0x55294a32,0xa6bac3d7,0x80b55471,0xc4596bd6,0xb175e165,0xdac764f9]
AFFINE=0x1fc44805


def config(label):
    cases={'separate_ramp16':{},'separate_zero16':{'preparation_kind':'zero'},'separate_flip16':{'preparation_kind':'flip'},
      'separate_ramp32':{'length_u32':32},'separate_zero32':{'length_u32':32,'preparation_kind':'zero'},'separate_clobber':{'clobber_callers':True}}
    return {'label':label,'length_u32':16,'selector_u8':1,'empty_holder':True,'malloc_success':True,'context_kind':'ramp','context_offset_u32':0,
      'preparation_kind':'ramp',**cases[label]}


def prep(c):
    b=bytearray(16)if c['preparation_kind']=='zero'else bytearray(range(16))
    if c['preparation_kind']=='flip':b[0]=128
    return bytes(b)


def overlay(c):return T.overlay(c)+[(C.REC+16,struct.pack('<Q',PREPSRC)),(PREPSRC,prep(c))]


class Replay(T.Replay):
    def __init__(self,*args):super().__init__(*args);self.constructor=[]
    def code(self,u,pc,n,d):
        if pc==C.BASE+0x1b69c4:
            fp=u.reg_read(A.UC_ARM64_REG_X29);sp=u.reg_read(A.UC_ARM64_REG_SP)
            self.constructor.append({'CPU':C.frame(u),'stack_u32':dict(zip(['left8','affine32','xor_first','xor_second'],
              [int.from_bytes(self.ram(a,4),'little')for a in [fp-200,sp+1040,sp+1024,sp+1016]]))})
        return super().code(u,pc,n,d)


def rol8(x,n):n&=7;return ((x<<n)|(x>>((8-n)&7)))&255
def rolbytes(x,n):return sum(rol8((x>>(8*j))&255,n)<<(8*j)for j in range(4))
def phi(x,m,bits):return (x^((x&m)<<1))&((1<<bits)-1)
def invphi(y,m,bits):
    x=y
    for _ in range(bits-1):x=(y^((x&m)<<1))&((1<<bits)-1)
    return x

def expand(x):
    out=AFFINE
    for j,col in enumerate(COLUMNS):
        if (x>>j)&1:out^=col
    return out


def workspace_oracle(p,r,s,form):
    rows=r.constructor;assert len(rows)==256 and [int(x['CPU']['X31'][13],16)for x in rows]==list(range(256))
    fields=[0,3,6,7,9,10,11,14,15,16,19,20,21,22,23,24,25,26,27,28,30]
    initial={str(j):rows[0]['CPU']['X31'][j]for j in fields};stack=rows[0]['stack_u32']
    assert all({str(j):x['CPU']['X31'][j]for j in fields}==initial and x['stack_u32']==stack for x in rows)
    assert initial==form['invariant_registers_u64']and stack==form['stack_u32']and form['counter_values']==list(range(256))
    v=lambda j:int(initial[str(j)],16)&M
    assert [v(j)for j in [11,14,15,16,26,30]]==[0x9a7cd460,0xce,0x8c,0x7631365f,0x80551819,0x71ad47f5]
    assert int(initial['3'],16)==C.BASE+0x166f4e0 and int(initial['9'],16)==C.BASE+0x1af3fc0
    t32=struct.unpack('<256I',s.read(0x166f4e0,1024));t16=struct.unpack('<256H',s.read(0x1af3fc0,512))
    assert form['table32']=={'address':'0x166f4e0','bytes_hex':s.read(0x166f4e0,1024).hex()}and form['table16']=={'address':'0x1af3fc0','bytes_hex':s.read(0x1af3fc0,512).hex()}
    g=[t16[i^0xce]>>8 for i in range(256)];assert len(set(g))==256 and all((w&255)==0x65 for w in t16)
    canonical=[((t32[i^0x8c]+(i^0x9a7cd460)+0x80551819)&M)^0x71ad47f5 for i in range(256)]
    assert [expand(x)for x in g]==canonical
    left=stack['left8'];mask=stack['affine32'];bias=v(10)&255;k1=stack['xor_first']^v(21)^v(16);k2=stack['xor_second']^v(22)^v(0)
    assert left==v(25)and mask==v(23)and 0<=left<8
    indices=[rol8(phi(i,mask&255,8),left)^bias for i in range(256)];assert len(set(indices))==256
    expected=[bytearray(1024),bytearray(1024)]
    for i,j in enumerate(indices):
        struct.pack_into('<I',expected[0],j*4,rolbytes(phi(expand(g[i]),mask,32),left)^k1)
        struct.pack_into('<I',expected[1],j*4,(g[i]<<8)^0x65^k2)
    before=next(x for x in p['points']if x['label']=='cleanup_entry');arena=bytes.fromhex(before['arena8192_hex'])
    for j,off in enumerate([3936,2868]):assert arena[off:off+1024]==expected[j]
    for j,pc in enumerate(['0x1b6a38','0x1b6a50']):
        actual=[w for w in p['writes']if p['visits'][w['visit']]['pc']==pc];assert actual==form[['first_writes','second_writes'][j]]and len(actual)==256
        base=C.ARENA+[3936,2868][j]
        for i,w in enumerate(actual):assert w['size_B']==4 and int(w['address'],16)==base+4*indices[i]and w['after_hex']==expected[j][4*indices[i]:4*indices[i]+4].hex()
    return {'label':p['configuration']['label'],'source_loop_iterations':256,'workspace_words_checked':512,'source_table_B':1536,
      'canonical_permutation_hex':bytes(g).hex(),'affine_offset_u32':hex(AFFINE),'affine_columns_u32':list(map(hex,COLUMNS)),
      'mask_u32':hex(mask),'rotate_per_byte':left,'index_xor_u8':hex(bias),'first_xor_u32':hex(k1),'second_xor_u32':hex(k2),
      'workspace_sha256':[SHA(b)for b in expected],'source_parameters':{'registers_u64':initial,'stack_u32':stack}}


def preparation_oracle(p,r,s):
    arrays=[s.read(a,16)for a in [0x1ab4186,0x1ba8a54,0x18b1ec1]]
    mask=bytes(((i*0x5f)^arrays[0][i]^arrays[1][i]^arrays[2][i]^0x64)&255 for i in range(16))
    c=p['configuration'];want=bytes(a^b for a,b in zip(prep(c),mask));assert r.ram(PREP,16)==want and r.ram(PREPSRC,16)==prep(c)
    stores=[w for w in p['writes']if p['visits'][w['visit']]['pc']=='0x1afd34'];assert len(stores)==16
    assert [int(w['address'],16)for w in stores]==list(range(PREP+15,PREP-1,-1))and all(w['size_B']==1 and w['after_hex']==want[int(w['address'],16)-PREP:int(w['address'],16)-PREP+1].hex()for w in stores)
    for pc,base in [('0x1afcf8',0x1ab4186),('0x1afd0c',0x1ba8a54),('0x1afd24',0x18b1ec1)]:
        rr=[x for x in p['reads']if p['visits'][x['visit']]['pc']==pc];assert [int(x['address'],16)for x in rr]==list(range(C.BASE+base+15,C.BASE+base-1,-1))
    for i in range(16):
        for x in range(256):assert (x^(i*95)^arrays[0][i]^arrays[1][i]^arrays[2][i]^100)&255==x^mask[i]
    return {'mask16_hex':mask.hex(),'input16_hex':prep(c).hex(),'prepared16_hex':want.hex(),'byte_cases_checked':4096,'input_pointer':hex(PREPSRC),'prepared_pointer':hex(PREP)}


def source_proofs(s,forms):
    proofs=[]
    def prove(label,claim,**extra):
        q=z3.Solver();q.set(timeout=30000);q.add(z3.Not(claim));assert q.check()==z3.unsat,label
        proofs.append({'label':label,'query':q.to_smt2(),'result':'unsat',**extra})
    initial={j:z3.BitVec('X'+str(j)+'_64',64)for j in range(31)};regs=initial.copy();sp=z3.BitVec('SP64',64)
    params={n:z3.BitVec(n+'_32',32)for n in ['left8','affine32','xor_first','xor_second']};table32=z3.BitVec('table32_word',32);table16=z3.BitVec('table16_word',16)
    loads={};stores=[];count=0
    def rr(name):
        name={'fp':'x29','lr':'x30'}.get(name,name)
        if name in ['xzr','wzr']:return z3.BitVecVal(0,32 if name[0]=='w'else 64)
        if name=='sp':return sp
        v=regs[int(name[1:])];return z3.Extract(31,0,v)if name[0]=='w'else v
    def put(name,value):regs[int(name[1:])]=z3.ZeroExt(32,value)if name[0]=='w'else value
    def operand(i,o,bits):
        v=rr(i.reg_name(o.reg))if o.type==1 else z3.BitVecVal(o.imm,bits)
        if o.shift.type:
            from capstone.arm64_const import ARM64_SFT_LSL
            assert o.shift.type==ARM64_SFT_LSL;v=v<<o.shift.value
        return v
    def address(i,o):
        v=rr(i.reg_name(o.mem.base))+o.mem.disp
        if o.mem.index:
            index=rr(i.reg_name(o.mem.index));index=z3.ZeroExt(32,index)if index.size()==32 else index
            v+=index<<o.shift.value
        return v
    value_at={0x1b69d8:params['left8'],0x1b69e8:table32,0x1b69fc:params['affine32'],0x1b6a18:params['xor_first'],
      0x1b6a3c:z3.ZeroExt(16,table16),0x1b6a40:params['xor_second']}
    instructions=[]
    for i in C.CS.disasm(s.read(0x1b69c4,144),0x1b69c4):
        count+=1;instructions.append({'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str});m=i.mnemonic;o=i.operands;n=i.reg_name(o[0].reg)
        bits=32 if n[0]=='w'else 64
        if m in ['ldr','ldur','ldrh']:
            loads[i.address]=address(i,o[1]);put(n,value_at[i.address]);continue
        if m=='str':stores.append((address(i,o[1]),rr(n)));continue
        if m=='ubfiz':put(n,(operand(i,o[1],bits)&((1<<o[3].imm)-1))<<o[2].imm);continue
        assert m in ['and','eor','orr','add','lsl','lsr'],m
        a,b=operand(i,o[1],bits),operand(i,o[2],bits)
        v={'and':lambda:a&b,'eor':lambda:a^b,'orr':lambda:a|b,'add':lambda:a+b,'lsl':lambda:a<<(b&(bits-1)),
          'lsr':lambda:z3.LShR(a,b&(bits-1))}[m]();put(n,v)
    assert count==36 and len(stores)==2 and len(loads)==6
    w=lambda j:z3.Extract(31,0,initial[j]);i=w(13);v=i^((i&w(23))<<1)
    index=z3.Extract(7,0,(v<<(params['left8']&31))|z3.LShR(v&w(27)&255,w(28)&31))^z3.Extract(7,0,w(10))
    index64=z3.ZeroExt(56,index);z=(table32+(i^w(11))+w(26))^w(30);z=z^((z&params['affine32'])<<1)
    first=((z&w(20))<<(w(25)&31))+z3.LShR(z&w(24),w(19)&31);first^=params['xor_first']^w(21)^w(16)
    second=z3.ZeroExt(16,table16)^params['xor_second']^w(22)^w(0)
    prove('source_table_load_addresses',z3.And(loads[0x1b69e8]==initial[3]+(z3.ZeroExt(32,i^w(15))<<2),
      loads[0x1b6a3c]==initial[9]+(z3.ZeroExt(32,i^w(14))<<1)),source_instructions_lifted=count)
    prove('source_first_workspace_store',z3.And(stores[0][0]==initial[7]+(index64<<2),stores[0][1]==first),source_instructions_lifted=count)
    prove('source_second_workspace_store',z3.And(stores[1][0]==initial[6]+(index64<<2),stores[1][1]==second),source_instructions_lifted=count)
    for j in set(range(31))-{2,4,5,17}:assert z3.eq(regs[j],initial[j])
    phases={}
    for f in forms:
        p=f['source_parameters'];reg=lambda j:int(p['registers_u64'][str(j)],16)&M;t=p['stack_u32'];r=t['left8']
        key=tuple([reg(j)for j in [10,23,25,27,28,20,24,19]]+[r]);phases[key]=p
    for serial,(key,p)in enumerate(phases.items()):
        v=lambda j:int(p['registers_u64'][str(j)],16)&M;r=p['stack_u32']['left8'];byte=z3.BitVec('byte_phase_'+str(serial),8);word=z3.BitVec('word_phase_'+str(serial),32)
        b=z3.ZeroExt(24,byte);b=b^((b&v(23))<<1)
        actual=z3.Extract(7,0,(b<<r)|z3.LShR(b&v(27)&255,v(28)&31))^(v(10)&255)
        wanted=z3.RotateLeft(byte^((byte&(v(23)&255))<<1),r)^(v(10)&255)
        prove('phase_'+str(serial)+'_index_normalization',actual==wanted,parameters=p)
        actual=((word&v(20))<<(v(25)&31))+z3.LShR(word&v(24),v(19)&31)
        wanted=z3.Concat(*[z3.RotateLeft(z3.Extract(8*j+7,8*j,word),r)for j in reversed(range(4))])
        prove('phase_'+str(serial)+'_word_rotation',actual==wanted,parameters=p)
    for bits in [8,32]:
        x=z3.BitVec('x_'+str(bits),bits);m=z3.BitVec('mask_'+str(bits),bits);y=x^((x&m)<<1);inverse=y
        for _ in range(bits-1):inverse=y^((inverse&m)<<1)
        prove('triangular_affine_inverse_'+str(bits),inverse==x)
    byte=z3.BitVec('preparation_input8',8);index=z3.BitVec('preparation_index32',32);aa,bb,cc=z3.BitVecs('prep_A8 prep_B8 prep_C8',8)
    state={5:z3.ZeroExt(24,byte),17:index,16:z3.BitVecVal(95,32),2:z3.BitVecVal(100,32)}
    for pc in [0x1afcd8,0x1afcdc,0x1afcfc,0x1afd10,0x1afd28,0x1afd2c]:
        if pc==0x1afcfc:state[7]=z3.ZeroExt(24,aa)
        if pc==0x1afd10:state[7]=z3.ZeroExt(24,bb)
        if pc==0x1afd28:state[6]=z3.ZeroExt(24,cc)
        ins=next(C.CS.disasm(s.read(pc,4),pc));assert ins.mnemonic in ['eor','mul'];args=[int(ins.reg_name(o.reg)[1:])for o in ins.operands];d,a,b=args
        state[d]=state[a]^state[b]if ins.mnemonic=='eor'else state[a]*state[b]
    prove('preparation_byte_data_slice',z3.Extract(7,0,state[5])==byte^z3.Extract(7,0,index*95)^aa^bb^cc^100)
    return {'proofs':proofs,'source_constructor_instructions':instructions,'constructor_instruction_count':count,'phase_classes':len(phases)}

FIPS_SBOX_HEX='637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16'
FIPS_PDF_B=1184436


def reference_checks(g):
    def multiply(a,b):
        out=0
        for _ in range(8):
            if b&1:out^=a
            a=((a<<1)^(0x11b if a&128 else 0))&255;b>>=1
        return out
    generated=[]
    for x in range(256):
        base=x;power=254;value=1
        while power:
            if power&1:value=multiply(value,base)
            base=multiply(base,base);power>>=1
        generated.append(value^rol8(value,1)^rol8(value,2)^rol8(value,3)^rol8(value,4)^0x63)
    assert bytes(generated).hex()==FIPS_SBOX_HEX
    inverse=[0]*256
    for i,v in enumerate(generated):inverse[v]=i
    counterexamples=[];matches=[]
    for name,reference in [('FIPS197_SBOX',generated),('FIPS197_inverse_SBOX',inverse)]:
        for delta in range(256):
            mapping={reference[i^delta]:g[i]for i in range(256)};constant=mapping[0];cols=[mapping[1<<j]^constant for j in range(8)]
            first=None
            for i in range(256):
                x=reference[i^delta];pred=constant
                for j in range(8):
                    if x>>j&1:pred^=cols[j]
                if pred!=g[i]:first={'counterexample_i':i,'expected_G':g[i],'affine_prediction':pred};break
            row={'reference':name,'input_xor':delta,'unique_affine_constant':constant,'unique_affine_columns':cols}
            (matches if first is None else counterexamples).append({**row,**(first or {})})
    hist=Counter();maximum=0
    for delta in range(1,256):
        row=Counter(g[x]^g[x^delta]for x in range(256));hist.update(row.values());maximum=max(maximum,max(row.values()))
    assert maximum==4 and dict(hist)=={2:32130,4:255}
    return {'reference':{'title':'FIPS 197-upd1, Advanced Encryption Standard','DOI':'10.6028/NIST.FIPS.197-upd1',
      'URL':'https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf','PDF_sha256':'62c86eb567f13edb8f71826e985da870b04ef6381634f303cdb16e84d47becd1',
      'PDF_B':FIPS_PDF_B,'official_table':'Table 4, printed page 14; PDF page index 21','table256_hex':FIPS_SBOX_HEX,'generated_values_checked':256,
      'PDF_freshly_fetched_by_this_auditor':False},'candidate_family':'G(i) = output_affine(reference(i XOR delta)); forward/inverse reference; all u8 delta',
      'family_members':512,'matches':matches,'counterexamples':counterexamples,'general_affine_input_equivalence_tested':False,
      'differential_pairs_checked':255*256,'nonzero_differential_histogram':dict(hist),'maximum_nonzero_differential_count':maximum}


def main():
    e=json.loads(read(ROOT/'corefp_workspace_checks.json'));s=C.Pointers();assert e['generator_sha256']==SHA((ROOT/'recover_corefp_workspace.py').read_bytes())and e['thin_sha256']==C.THIN_SHA
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    assert e['base_declared_inputs']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in C.declared_inputs()]
    for span in e['source_spans']:assert span==s.function(int(span['start'],16))
    totals=Counter();oracles=[];forms=[];preparations=[]
    for p,form in zip(e['profiles'],e['workspace_constructions']):
        c=p['configuration'];assert c==config(c['label']);ov=overlay(c);assert p['declared_overlay']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in ov]
        cpu={'X31':[hex(((j+1)*0x123456789abcdef)&((1<<64)-1))for j in range(31)],'Q32':[hex(int.from_bytes(bytes([j])*16,'little'))for j in range(32)],
          'SP':hex(C.SP),'PC':hex(C.BASE+C.ENTRY),'NZCV':'0x60000000','FPCR':'0x0','FPSR':'0x0','CPACR_EL1':'0x300000'}
        cpu['X31'][0]=hex(C.REC);cpu['X31'][1]=hex(C.OUT);cpu['X31'][30]=hex(C.DONE);assert p['initial_CPU']==cpu;totals['initial_CPU_frames_checked']+=1
        for row in p['initial_RAM']:
            a=int(row['address'],16);b=bytearray(4096)if a in [C.ARENA,C.ARENA+4096,T.CTX]else bytearray(C.initial_page(s,a))
            for addr,raw in ov:
                lo=max(a,addr);hi=min(a+4096,addr+len(raw))
                if lo<hi:b[lo-a:hi-a]=raw[lo-addr:hi-addr]
            assert C.unpack(row['payload'])==b;totals['initial_RAM_B_checked']+=4096
        r=Replay(p,e['source_spans'],s);totals.update(r.run());oracles.append(T.oracle(p,r));forms.append(workspace_oracle(p,r,s,form));preparations.append(preparation_oracle(p,r,s))
        print(json.dumps({'checked':c['label']}),flush=True)
    source=source_proofs(s,forms);g=bytes.fromhex(forms[0]['canonical_permutation_hex']);reference=reference_checks(g)
    assert all(f['canonical_permutation_hex']==g.hex()for f in forms)
    by={o['label']:o for o in oracles};xor=lambda a,b:bytes(x^y for x,y in zip(bytes.fromhex(a),bytes.fromhex(b)))
    assert xor(by['separate_ramp16']['output_hex'],by['separate_zero16']['output_hex'])==bytes(range(16))
    assert xor(by['separate_ramp32']['output_hex'],by['separate_zero32']['output_hex'])==bytes(range(16))+bytes(16)
    assert by['separate_ramp16']['output_hex']==by['separate_clobber']['output_hex']=='732780382ca3157581b95dc50e78053a'
    assert xor(by['separate_ramp16']['output_hex'],by['separate_flip16']['output_hex'])==b'\x80'+bytes(15)
    frozen=[T.source_checks(s),C.source_checks(s),C.pool_source(s)];sdk=C.sdk_checks()
    counts={'profiles':len(e['profiles']),**{k:sum(len(p[k])for p in e['profiles'])for k in ['visits','reads','writes','PAC_models','models','points','allocations','child_entries']}}
    assert counts==e['verified_counts']and len(forms)==len(e['profiles'])==6
    result={'verified_counts':counts,'independent_replay':dict(totals),'source_B_checked':59120,'source_spans':3,
      'workspace_words_checked':sum(f['workspace_words_checked']for f in forms),'source_constructor_instructions':36,'phase_classes':source['phase_classes'],
      'new_queries_unsat':len(source['proofs']),'frozen_queries_unsat':sum(len(f['proofs'])for f in frozen),'preparation_byte_cases_checked':preparations[0]['byte_cases_checked'],
      'canonical_permutation_B':256,'canonical_expansion_B':37,'reference_family_members':512,'reference_family_matches':len(reference['matches']),
      'differential_pairs_checked':65280,'SDK_compile_exit':sdk['exit_code'],'all_checks_pass':True,'native_target_executed':False}
    deps=['audit_corefp_pool_transform.py','audit_corefp_pool_caller.py','audit_corefp_pool_allocator.py','audit_corefp_lookup_initialization.py','audit_fpsd1201_predicates.py']
    out={'result':result,'checks_sha256':SHA(read(ROOT/'corefp_workspace_checks.json').encode()),'auditor_sha256':SHA(Path(__file__).read_bytes()),
      'dependencies':e['dependencies'],'frozen_auditor_dependencies':{n:SHA(read(ROOT/n).encode())for n in deps},'oracles':oracles,'workspace_oracles':forms,
      'preparation_oracles':preparations,'source_checks':source,'frozen_source_checks':frozen,'reference_comparison':reference,'SDK_assertions':sdk,
      'fresh_replay_completed':True,'process_exit_code':0,'native_API_executed':False,'IDB_mutated':False,'new_live_IDA_claim':False,
      'source_context_initializer_established':False,'whole_transform_algorithm':'unknown','full_goal_complete':False}
    (ROOT/'corefp_workspace_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
