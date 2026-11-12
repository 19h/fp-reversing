#!/usr/bin/env python3
"""Independent output-packing interpreter, original-byte tests and whole replay.

Does not import the new producer. Scalar and finite component tests retain
captured input/read premises; no native target/API/IPC or IDB operation.
O(C*(B+V*J+P*F+R)+N*16*256*659) time; bounded private maps and 30 s/SMT query.
"""
import copy,json,struct
from pathlib import Path
from hashlib import sha256
from collections import Counter
from capstone.arm64_const import ARM64_EXT_UXTW,ARM64_EXT_UXTB,ARM64_EXT_SXTW,ARM64_SFT_LSL,ARM64_SFT_LSR,ARM64_SFT_ROR
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM
from unicorn import arm64_const as U
import z3
import audit_corefp_workspace_consumers as A
from verify_daemon_reader_record_payloads_publication import read
C=A.C;W=A.W;ROOT=A.ROOT;SHA=A.SHA;M32=(1<<32)-1;START=0x1bb5a8;END=0x1bbff4
COLS=[188,68,53,125,218,204,191,255];PERM=[9,7,1,5,15,10,13,12,3,11,0,4,14,6,2,8]


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
        m=i.mnemonic;o=i.operands;n=i.reg_name(o[0].reg);bits=32 if n.startswith('w')else 64;mask=(1<<bits)-1
        if m in ['ldr','ldur','ldrb']:
            a=address(i,o[1]);b=fetch(a,1 if m=='ldrb'else bits//8);reads.append({'visit':lo+serial,'address':hex(a),'size_B':len(b),'bytes_hex':b.hex()});put(n,int.from_bytes(b,'little'));continue
        if m=='ldp':
            a=address(i,o[2])
            for j,d in enumerate([n,i.reg_name(o[1].reg)]):
                b=fetch(a+8*j,8);reads.append({'visit':lo+serial,'address':hex(a+8*j),'size_B':8,'bytes_hex':b.hex()});put(d,int.from_bytes(b,'little'))
            continue
        if m in ['str','stur','strb']:
            a=address(i,o[1]);nbytes=1 if m=='strb'else bits//8;b=(rr(n)&((1<<(nbytes*8))-1)).to_bytes(nbytes,'little');before=fetch(a,len(b))
            if sp<=a and a+len(b)<=sp+len(stack):stack[a-sp:a-sp+len(b)]=b
            else:assert outbase<=a and a+len(b)<=outbase+16;out[a-outbase:a-outbase+len(b)]=b
            writes.append({'visit':lo+serial,'address':hex(a),'size_B':len(b),'before_hex':before.hex(),'after_hex':b.hex()});continue
        if m=='ubfx':put(n,(value(i,o[1],bits)>>o[2].imm)&((1<<o[3].imm)-1));continue
        if m=='ubfiz':put(n,(value(i,o[1],bits)&((1<<o[3].imm)-1))<<o[2].imm);continue
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
        if m=='and':v=a&b
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
    assert reads==block['reads']and writes==block['writes']and len(instructions)==659 and len(reads)==102 and len(writes)==17
    return {'instructions':len(instructions),'reads':len(reads),'writes':len(writes),'stack_final_B':len(stack),'all_CPU_fields_match':True}


def h8(x):
    v=0
    for k,c in enumerate(COLS):
        if x>>k&1:v^=c
    return v


def snap(r,j):
    row=A.capture(r);dst=C.addresses(r.p['configuration'])[1]+16*j
    return {**row,'output_base':hex(dst),'output16_hex':r.ram(dst,16).hex()}


class Replay(A.Replay):
    def __init__(self,*args):super().__init__(*args);self.packing=[]
    def code(self,u,pc,n,d):
        self.flush()
        if pc==C.BASE+START:self.packing.append({'entry':snap(self,len(self.packing))})
        if pc==C.BASE+END:self.packing[-1]['end']=snap(self,len(self.packing)-1)
        return super().code(u,pc,n,d)


def check_origins(p,block):
    sp=int(block['entry']['stack_base'],16);lo=block['entry']['source_visit'];dst=int(block['entry']['output_base'],16)
    def check(rows,visit,address,n):
        expected=[]
        for byte in range(address,address+n):
            candidates=[w for w in p['writes']if w['visit']<visit and int(w['address'],16)<=byte<int(w['address'],16)+w['size_B']]
            assert candidates;last=max(candidates,key=lambda w:w['visit'])
            if last not in expected:expected.append(last)
        assert rows==[{'pc':p['visits'][w['visit']]['pc'],**w}for w in expected]
        return sum(w['size_B']for w in expected)
    assert len(block['initial_word_origins'])==12 and len(block['output_pointer_origins'])==16
    for row in block['initial_word_origins']:
        off=row['stack_slot_offset'];assert row['value_u32']==int.from_bytes(bytes.fromhex(block['entry']['stack1312_hex'])[off:off+4],'little')
        check(row['reaching_stores'],lo,sp+off,4)
    for j,row in enumerate(block['output_pointer_origins']):
        assert row['output_index']==j
        w=next(w for w in block['writes']if int(w['address'],16)==dst+j)
        rr=next(r for r in block['reads']if r['visit']==w['visit']-1)
        assert row['store_pc']==p['visits'][w['visit']]['pc']and row['pointer_load_pc']==p['visits'][rr['visit']]['pc']
        assert int(rr['address'],16)==sp+row['stack_slot_offset']and rr['size_B']==8 and int.from_bytes(bytes.fromhex(rr['bytes_hex']),'little')==dst+j
        check(row['reaching_stores'],rr['visit'],int(rr['address'],16),8)
    return {'scalar_fields':12,'output_pointer_slots':16,'provenance':'last reaching writes only'}


def machine_cases(p,block,model,destinations,form,s):
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);mapped=set()
    for row in p['initial_RAM']:
        at=int(row['address'],16);u.mem_map(at,4096);u.mem_write(at,C.unpack(row['payload']));mapped.add(at)
    def write(at,b):
        for page in range(at&~4095,(at+len(b)+4095)&~4095,4096):
            if page not in mapped:u.mem_map(page,4096);u.mem_write(page,C.initial_page(s,page));mapped.add(page)
        u.mem_write(at,b)
    sp=int(block['entry']['CPU']['SP'],16);dst=int(block['entry']['output_base'],16);stack=bytes.fromhex(block['entry']['stack1312_hex']);before=bytes.fromhex(block['entry']['output16_hex'])
    fixed={}
    for r in block['reads']:
        at=int(r['address'],16)
        if sp<=at and at+r['size_B']<=sp+1312:continue
        for j,b in enumerate(bytes.fromhex(r['bytes_hex'])):
            assert fixed.get(at+j,b)==b;fixed[at+j]=b
    for at,b in fixed.items():write(at,bytes([b]))
    for row in model['symbolic_tables']:
        at=C.BASE+int(row['base'],16);raw=bytes.fromhex(row['bytes_hex']);assert raw==s.read(int(row['base'],16),256)
        assert all(fixed.get(at+j,b)==b for j,b in enumerate(raw));write(at,raw)
    write(C.BASE+START,s.read(START,END-START))
    write(sp,stack);write(dst,before);C.restore(u,block['entry']['CPU'])
    assert bytes(u.mem_read(C.BASE+START,END-START))==s.read(START,END-START)
    u.emu_start(C.BASE+START,C.BASE+END,count=660)
    assert C.frame(u)==block['end']['CPU']and bytes(u.mem_read(sp,1312)).hex()==block['end']['stack1312_hex']and bytes(u.mem_read(dst,16)).hex()==block['end']['output16_hex']
    C.restore(u,block['entry']['CPU']);zero=bytearray(stack);q=int(form['second_xor_u32'],16)
    for j in range(16):
        loc=destinations['q'+str(144+j)];v=0x65^q
        if 'register'in loc:u.reg_write(getattr(U,'UC_ARM64_REG_X'+str(loc['register'])),v)
        else:struct.pack_into('<I',zero,loc['stack_offset'],v)
    context=u.context_save();bias=bytes.fromhex(model['bias16_hex']);digest=sha256();cases=0
    for varied in range(16):
        loc=destinations['q'+str(144+varied)]
        for value in range(256):
            u.context_restore(context);write(sp,bytes(zero));write(dst,before);encoded=(value<<8)^0x65^q
            if 'register'in loc:u.reg_write(getattr(U,'UC_ARM64_REG_X'+str(loc['register'])),encoded)
            else:write(sp+loc['stack_offset'],struct.pack('<I',encoded))
            u.emu_start(C.BASE+START,C.BASE+END,count=660)
            assert u.reg_read(U.UC_ARM64_REG_PC)==C.BASE+END
            got=bytes(u.mem_read(dst,16));expected=bytes(h8(value if PERM[j]==varied else 0)^bias[j]for j in range(16))
            assert got==expected,(block['label'],block['block_index'],varied,value,got.hex(),expected.hex())
            digest.update(got);cases+=1
    assert cases==4096
    return {'label':block['label'],'block_index':block['block_index'],'actual_frame_cases':1,'finite_cases':cases,'finite_instructions':cases*659,
      'finite_output_B':cases*16,'ordered_outputs_sha256':digest.hexdigest(),'source_bytes_preserved':True,
      'scope':'component entry: one free canonical byte at a time, other fifteen zero; captured non-result CPU/stack/read premises'}


def main():
    raw=read(ROOT/'corefp_output_packing_checks.json').encode();e=json.loads(raw);checks_sha=SHA(raw)
    assert e['generator_sha256']==SHA((ROOT/'recover_corefp_output_packing.py').read_bytes())and e['thin_sha256']==C.THIN_SHA
    pinned={}
    for name,h in e['parent_pins'].items():
        raw=read(ROOT/name).encode();assert SHA(raw)==h;pinned[name]=json.loads(raw)
    assert len(pinned)==4
    for name,h in e['dependencies'].items():assert SHA(read(ROOT/name).encode())==h
    parent=pinned['corefp_workspace_checks.json'];pa=pinned['corefp_workspace_audit.json'];ce=pinned['corefp_workspace_consumers_checks.json'];ca=pinned['corefp_workspace_consumers_audit.json']
    s=C.Pointers();instructions=list(C.CS.disasm(s.read(START,END-START),START))
    assert e['source_bytes_hex']==s.read(START,END-START).hex()
    assert e['instructions']==[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in instructions]
    assert len(instructions)==659 and all(not any(i.group(g)for g in [1,2,3])for i in instructions)
    gap=e['gap_census'];gapins=list(C.CS.disasm(s.read(0x1bad9c,2060),0x1bad9c));assert len(gapins)==515
    assert gap['source_bytes_hex']==s.read(0x1bad9c,2060).hex()
    written={i.reg_name(r)for i in gapins for r in i.regs_access()[1]};assert sorted(written)==gap['written_registers']and not written&{'x6','w6','x14','w14','x15','w15','x17','w17','sp','fp','x29'}
    assert [i.address for i in gapins if i.mnemonic.startswith('st')]==[0x1bb0d0]
    assert next(i.op_str for i in gapins if i.address==0x1bb0d0)=='x26, [sp, #0x318]'
    assert all(not any(i.group(g)for g in [1,2,3])for i in gapins)
    assert e['common_H_columns_u8']==COLS and e['common_output_permutation']==PERM and sorted(PERM)==list(range(16))
    hv=[h8(x)for x in range(256)];assert sorted(hv)==list(range(256));inverse=[hv.index(1<<j)for j in range(8)]
    assert inverse==e['common_inverse_proof']['inverse_columns_u8']
    new=[e['common_inverse_proof']]+[p for m in e['transfer_models']for p in m['proofs']]
    frozen=ce['source_model']['proofs']+ce['canonical_phase_proofs']+pa['source_checks']['proofs']+[p for f in pa['frozen_source_checks']for p in f['proofs']]
    assert len(new)==257 and len(frozen)==363
    for p in new+frozen:
        assert p['result']=='unsat';q=z3.Solver();q.set(timeout=30000);q.from_string(p['query']);assert q.check()==z3.unsat,p['label']
    totals=Counter();interpreters=[];machine=[];origins=[];n=0;destinations=ce['source_model']['final_destinations']
    for p,construction,form in zip(parent['profiles'],parent['workspace_constructions'],pa['workspace_oracles']):
        totals.update(A.initial_checks(p,s));r=Replay(p,parent['source_spans'],s);totals.update(r.run());W.T.oracle(p,r)
        assert W.workspace_oracle(p,r,s,construction)==form;W.preparation_oracle(p,r,s)
        for j,block in enumerate(r.packing):
            expected=e['blocks'][n];model=e['transfer_models'][n]
            assert block['entry']==expected['entry']and block['end']==expected['end']and r.blocks[j]['end']==ce['blocks'][n]['end']
            lo,hi=block['entry']['source_visit'],block['end']['source_visit'];assert hi-lo==659
            assert [int(v['pc'],16)for v in p['visits'][lo:hi]]==list(range(START,END,4))
            assert expected['reads']==[x for x in p['reads']if lo<=x['visit']<hi]and expected['writes']==[x for x in p['writes']if lo<=x['visit']<hi]
            assert expected['label']==model['label']==p['configuration']['label']and expected['block_index']==model['block_index']==j
            actual=bytes.fromhex(ca['block_oracles'][n]['canonical_final16_hex']);q=int(form['second_xor_u32'],16);stack=bytes.fromhex(expected['entry']['stack1312_hex'])
            for k in range(16):
                loc=destinations['q'+str(144+k)]
                if 'register'in loc:got=int(expected['entry']['CPU']['X31'][loc['register']],16)
                else:
                    off=loc['stack_offset'];assert not(0x318<off+4 and off<0x320);got=int.from_bytes(stack[off:off+4],'little')
                assert got==(actual[k]<<8)^0x65^q
            bias=bytes.fromhex(model['bias16_hex']);assert len(bias)==16 and bytes(h8(actual[PERM[k]])^bias[k]for k in range(16)).hex()==expected['end']['output16_hex']
            assert len(model['byte_mappings'])==16 and len(model['symbolic_tables'])==16
            for k,row in enumerate(model['byte_mappings']):assert row['output_index']==k and row['source_g_index']==PERM[k]and row['bias_u8']==bias[k]and row['byte_cases_checked']==256
            tables={C.BASE+int(row['base'],16):bytes.fromhex(row['bytes_hex'])for row in model['symbolic_tables']}
            assert all(raw==s.read(base-C.BASE,256)for base,raw in tables.items())
            interpreters.append(source_interpret(expected,instructions,tables));origins.append(check_origins(p,expected));machine.append(machine_cases(p,expected,model,destinations,form,s));n+=1
        print(json.dumps({'audited':p['configuration']['label'],'blocks':len(r.packing),'finite_cases':sum(m['finite_cases']for m in machine)}),flush=True)
    assert n==8 and dict(totals)==ca['result']['independent_replay']and e['replay_totals']=={k:v for k,v in totals.items()if not k.startswith('initial_')}
    counts={'profiles':6,'blocks':8,'packing_instructions':659,'packing_source_B':2636,'regional_visits':5272,'regional_reads':816,'regional_writes':136,'output_bytes':128,
      'source_table_reads':128,'complete_byte_cases':32768,'new_queries_unsat':257,'gap_instructions':515,'gap_source_B':2060};assert e['verified_counts']==counts
    biases=[bytes.fromhex(m['bias16_hex'])for m in e['transfer_models']]
    assert biases[0]==biases[3]==biases[7]and biases[4]==biases[6]and bytes(a^b for a,b in zip(biases[0],biases[1]))==bytes(range(16))
    assert bytes(a^b for a,b in zip(biases[0],biases[2]))==bytes([128])+bytes(15)
    result={'verified_counts':counts,'independent_replay':dict(totals),'independent_interpreter':dict(sum((Counter({k:v for k,v in row.items()if type(v)is int})for row in interpreters),Counter())),
      'finite_machine_cases':sum(m['finite_cases']for m in machine),'finite_machine_instructions':sum(m['finite_instructions']for m in machine),
      'finite_machine_output_B':sum(m['finite_output_B']for m in machine),'actual_machine_frames':8,'gap_result_values_checked':128,'scalar_field_origins_checked':96,
      'output_pointer_origins_checked':128,'H_complete_cases':256,'frozen_queries_unsat':363,'total_queries_unsat':620,'all_checks_pass':True,'native_target_executed':False}
    out={'result':result,'checks_sha256':checks_sha,'auditor_sha256':SHA(Path(__file__).read_bytes()),'generator_sha256':e['generator_sha256'],'parent_pins':e['parent_pins'],
      'dependencies':e['dependencies'],'interpreter_oracles':interpreters,'machine_oracles':machine,'origin_oracles':origins,'fresh_replay_completed':True,'process_exit_code':0,
      'native_API_executed':False,'IDB_mutated':False,'new_live_IDA_claim':False,'source_context_initializer_established':False,'general_preparation_contract_established':False,
      'whole_transform_algorithm':'unknown','full_goal_complete':False}
    (ROOT/'corefp_output_packing_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
