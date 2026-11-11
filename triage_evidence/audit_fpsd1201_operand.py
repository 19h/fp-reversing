#!/usr/bin/env python3
"""Independent operand-prefix replay, descriptor oracle and source proofs.

Never imports the new producer. Frozen CPU/journal mechanics are extended
with independently reconstructed patches, a bit recurrence and modular inverse
oracle. O(I+C*(B+F+V+P*J+R)) time, O(I+B+F+C*(V+J+P+R)) space;
solver cost separate. No native operation or whole-parent execution.
"""
import json,struct
from collections import Counter
from pathlib import Path
from hashlib import sha256
import z3
from capstone.arm64 import ARM64_OP_IMM,ARM64_SFT_LSL,ARM64_SFT_LSR
from unicorn import arm64_const as A
from audit_fpsd1201_import import Replay as ImportReplay,reference_and_source,CS,ROOT,CONTEXT,OWNER,SP,FP,HALT,RAM
from audit_fpsd1201_record import Replay as RecordReplay,source_and_proofs,unpack,RECORD,OUT
from verify_daemon_reader_record_payloads_publication import read

K=0x1ac70ef2;MASK=(1<<32)-1;MASK64=(1<<64)-1;PAYLOAD=OWNER+0x3000
SHA=lambda b:sha256(b).hexdigest()


class Replay(ImportReplay):
    def __init__(self,p,old,code,banks,D):
        super().__init__(p,old,code[:5],banks,D);self.oi=0;self.next_bit=1
        self.u.mem_map(0x14f8000,0x3000)
        for r in code[5:]:
            a=int(r['start'],16);b=bytes.fromhex(r['bytes_hex']);self.u.mem_write(a,b);self.ranges.append((a,a+len(b)))
    def operand_point(self,pc):
        self.flush();point=self.p['operand_points'][self.oi];self.oi+=1
        if pc==0x14fac64:
            self.operand_record=self.reg(0);self.operand_output=self.reg(1);self.caller_sp=self.u.reg_read(A.UC_ARM64_REG_SP)
            expected=[]
            if self.c['backed']:
                n=self.c['operand_u32'];expected=[(CONTEXT+0x290,struct.pack('<IIQ',1,0x4b0cf050+int(n!=0),PAYLOAD)),(PAYLOAD,(n^K).to_bytes(4,'little')),(self.operand_output,self.c['second_seed_u64'].to_bytes(8,'little'))]
            actual=[]
            for a,b in expected:actual.append({'address':hex(a),'before_hex':self.ram(a,len(b)).hex(),'after_hex':b.hex()});self.u.mem_write(a,b)
            assert actual==self.p['operand_controls'];self.seed=int.from_bytes(self.ram(self.operand_output,8),'little')
        self.frame(point['CPU']);r=self.operand_record;raw=self.ram(r,32);pair=int.from_bytes(raw[8:16],'little');pv=self.ram(pair,24)
        first=int.from_bytes(pv[:8],'little');second=int.from_bytes(pv[8:16],'little');imported=int(self.p['import_points'][-1]['descriptor_pointer'],16)
        d1=self.ram(first,16);d2=self.ram(second,16);di=self.ram(imported,16);limb=self.ram(int.from_bytes(d1[8:],'little'),4)
        actual={'pc':hex(pc),'record_pointer':hex(r),'record32_hex':raw.hex(),'pair_pointer':hex(pair),'pair24_hex':pv.hex(),
          'context_descriptor16_hex':self.ram(CONTEXT+0x290,16).hex(),'output_cell_pointer':hex(self.operand_output),'output_cell_u64':hex(int.from_bytes(self.ram(self.operand_output,8),'little')),
          'first_descriptor16_hex':d1.hex(),'second_descriptor16_hex':d2.hex(),'first_limb_hex':limb.hex(),'import_descriptor_pointer':hex(imported),'import_descriptor16_hex':di.hex()}
        assert actual=={k:v for k,v in point.items()if k!='CPU'}
        assert int.from_bytes(self.ram(self.operand_output,8),'little')==self.seed
        if pc==0x14fac64:
            p=r&MASK;m=((p^0x5f8c1ee6)*0x2a03d31f)&MASK;assert int.from_bytes(raw[:4],'little')^m==0xb9d0
            assert int.from_bytes(raw[16:24],'little')==CONTEXT+0x290
            assert(first,second,imported)==(self.caller_sp+0xa0,self.caller_sp+0x80,self.caller_sp+0x90)
            assert d1==struct.pack('<IIQ',130,0x4b0cf050,self.caller_sp+0x3d0)
            assert d2==struct.pack('<IIQ',130,0x4b0cf050,self.caller_sp+0x5d8)
            assert di==struct.pack('<IIQ',64,0x4b0cf070,self.caller_sp+0x2d0)
            self.first=first;self.second=second;self.imported=imported;self.pair=pair;self.d2=d2;self.di=di
        if pc in [0x14f8d28,0x14f8e50]:
            value=int.from_bytes(self.ram(self.reg(1),8),'little');assert value==((self.seed-144)&MASK64 if pc==0x14f8d28 else self.seed)
            self.stats['second_cursor_checkpoints_checked']+=1
        if pc==0x14f9030:
            if self.next_bit==1:self.q=self.c['operand_u32'];self.candidate=1
            assert self.reg(20)==self.next_bit and (self.reg(24)^K)&MASK==self.q and self.reg(1)==self.candidate
            take=(self.q>>1)&1;self.q=((self.q>>1)+(self.c['operand_u32']if take else 0))&MASK
            if take:self.candidate=(self.candidate+(1<<self.next_bit))&MASK
            self.next_bit+=1;self.stats['source_recurrence_steps_checked']+=1
        if pc==0x14f9208:assert self.next_bit==32 and self.reg(20)==32 and self.reg(1)==self.candidate
        if pc==0x14f9258:
            coefficient=int.from_bytes(pv[16:20],'little');n=self.c['operand_u32'];assert coefficient==(-self.candidate)&MASK
            if n&1:
                assert coefficient==(-pow(n,-1,1<<32))&MASK and (n*coefficient)&MASK==MASK;self.stats['odd_inverse_oracles_checked']+=1
            else:assert (n*coefficient)&MASK!=MASK;self.stats['even_noninverse_controls_checked']+=1
            self.coefficient=coefficient
        if pc==0x14f932c:
            a=self.reg(0);v=self.ram(a,24);m=((((a&MASK)^0x2fbc3a3b)^0xf6a89466)*0x08c5d407)&MASK
            assert int.from_bytes(v[:4],'little')^m==0xed31
            assert int.from_bytes(v[8:16],'little')==self.first
            scalar=(int.from_bytes(v[16:20],'little')^m)+0xf369ff3c;assert scalar&MASK==1
        if pc==0x14f9330:
            assert d1==struct.pack('<IIQ',130,0x4b0cf051,self.caller_sp+0x3d0)and int.from_bytes(limb,'little')==1^K
            assert int.from_bytes(pv[16:20],'little')==self.coefficient;self.stats['selected_scalar_one_initializers_checked']+=1
        assert d2==self.d2 and di==self.di
        self.stats['operand_CPU_points_checked']+=1
    def hook(self,u,pc,n,data):
        self.flush()
        if pc in [0x17bbb8,0x981758]:self.import_point(pc)
        if pc in [0x14fac64,0x14f8d28,0x14f8e50,0x14f9030,0x14f9208,0x14f9258,0x14f932c,0x14f9330]:self.operand_point(pc)
        if(pc==0x14f8edc and not self.c['backed'])or pc==0x14f9408:
            self.frame(self.p['terminal']);e=self.p['frontier'];self.stop='callee_boundary'if self.c['backed']else'unbacked_context_payload'
            expected={'pc':hex(pc),'instruction_executed':False}
            if self.c['backed']:
                target=self.reg(8);mod=self.reg(17);slot=int(e['original_slot'],16);row=self.D[slot]
                assert row['target']==hex(target)and row['diversity']==hex(mod)and row['key']=='IA'and not row['address_diversity']
                assert any(r['address']==hex(slot)and r['size_B']==8 for r in self.p['source_reads'][:self.r]);self.used.add(slot)
                expected.update({'target':hex(target),'modifier':hex(mod),'original_slot':hex(slot),'argument_record24_hex':self.ram(self.reg(0),24).hex()})
                assert self.next_bit==32
            else:
                assert self.reg(10)==0xa5a5a5a5a5a5a5a5;expected.update({'read_address':hex(self.reg(10)),'read_size_B':4})
            assert e==expected;u.emu_stop();return
        RecordReplay.hook(self,u,pc,n,data)
    def run(self):
        self.u.emu_start(0x8f3448,0x8f34f8,count=10000);self.flush();self.frame(self.p['constructor_terminal'])
        assert self.ram(RECORD,80).hex()==self.p['record80_before_controls_hex'];expected=[]
        if self.c['control']=='null_auxiliary':expected=[(RECORD+0x28,b'\0'*8)]
        else:assert self.c['control']=='as_staged'
        patches=[]
        for a,b in expected:patches.append({'address':hex(a),'before_hex':self.ram(a,len(b)).hex(),'after_hex':b.hex()});self.u.mem_write(a,b)
        assert patches==self.p['record_controls']and self.ram(RECORD,80).hex()==self.p['record80_after_controls_hex']
        self.phase='nested';self.setreg(0,RECORD);self.setreg(1,OUT);self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_PC,0x981c38);self.frame(self.p['nested_entry'])
        self.u.emu_start(0x981c38,0,count=50000);self.flush();assert self.stop==self.p['stop_reason']
        assert(self.v,self.r,self.w,self.pi,self.ci,self.oi,self.ii)==tuple(len(self.p[k])for k in ['source_visits','source_reads','source_writes','PAC_models','CPU_points','operand_points','import_points'])
        assert self.ii==2 and self.p['used_original_pointer_rows']==[self.D[a]for a in sorted(self.used)]
        for row in self.p['used_original_pointer_rows']:
            if row['bind']:assert row['import']['name']=='___stack_chk_guard';continue
            w=int(row['word'],16);target=w&MASK if w>>63 else(w&((1<<43)-1))|(((w>>43)&255)<<56);assert target==int(row['target'],16)
            if w>>63:assert(w>>49&3,w>>32&65535,w>>48&1)==(0,int(row['diversity'],16),row['address_diversity'])
            self.stats['original_pointer_profile_associations_checked']+=1
        assert int.from_bytes(self.ram(OUT,8),'little')==self.c['seed_u64']and int.from_bytes(self.ram(RECORD+0x30,4),'little')==0xa5a5a5a5
        assert self.p['final_delta_cell_u64']==hex(self.c['seed_u64'])and self.p['final_status_u32']=='0xa5a5a5a5'
        for key in ['source_reads','source_writes']:assert not any(int(e['address'],16)<OWNER+0x900 and OWNER+0x880<int(e['address'],16)+e['size_B']for e in self.p[key])
        assert self.ram(OWNER+0x880,128)==b'\xa5'*128 and len(self.p['final_RAM'])==3
        for row,(a,n)in zip(self.p['final_RAM'],RAM):assert row['address']==hex(a)and unpack(row['payload'])==self.ram(a,n);self.stats['complete_final_RAM_bytes_checked']+=n
        assert not self.p['native_effects'];self.stats.update({'original_visits_checked':self.v,'original_reads_checked':self.r,'original_writes_checked':self.w,'PAC_models_checked':self.pi})
        return self.stats


def lift_details(ins,regs,a,b):
    out=dict(regs);bv=lambda v:z3.BitVecVal(v,32)
    def operand(i,o):
        v=bv(o.imm)if o.type==ARM64_OP_IMM else out[i.reg_name(o.reg)]
        if o.shift.type:
            assert o.shift.type in [ARM64_SFT_LSL,ARM64_SFT_LSR]
            v=v<<o.shift.value if o.shift.type==ARM64_SFT_LSL else z3.LShR(v,o.shift.value)
        return v
    for address in range(a,b,4):
        i=ins[address];ops=i.operands;d=i.reg_name(ops[0].reg);m=i.mnemonic;assert d.startswith('w')
        if m=='mov':out[d]=operand(i,ops[1]);continue
        if m=='movk':
            shift=ops[1].shift.value;out[d]=(out[d]&bv(~(0xffff<<shift)))|operand(i,ops[1]);continue
        x,y=operand(i,ops[1]),operand(i,ops[2])
        if m in ['lsl','lsr']and ops[2].type!=ARM64_OP_IMM:y=y&bv(31)
        if m=='eor':v=x^y
        elif m=='orr':v=x|y
        elif m=='and':v=x&y
        elif m=='add':v=x+y
        elif m=='sub':v=x-y
        elif m=='mul':v=x*y
        elif m=='lsl':v=x<<y
        elif m=='lsr':v=z3.LShR(x,y)
        else:raise AssertionError(m)
        out[d]=v
    return out


def source_checks(e,old,banks,D):
    att=json.loads(read(ROOT/'fpsd1201_operand_ida_readback.json'));assert not att['IDB_mutated']and not att['native_target_executed']
    assert att['input_sha256']=='68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f'
    assert e['code_spans'][:5]==old['code_spans']
    starts=json.loads(read(ROOT/'corefp_library_inventory.json'))['compiler_function_starts'];raw=(ROOT.parent/'CoreFP').read_bytes();assert SHA(raw)==att['input_sha256']
    for j in range(struct.unpack_from('>I',raw,4)[0]):
        cpu,sub,off,n,_=struct.unpack_from('>5I',raw,8+20*j)
        if(cpu,sub)==(0x100000c,0x80000002):thin=raw[off:off+n];break
    segments=[];at=32
    for j in range(struct.unpack_from('<I',thin,16)[0]):
        cmd,n=struct.unpack_from('<II',thin,at)
        if cmd==0x19:
            _,vm,vs,fo,fs=struct.unpack_from('<16s4Q',thin,at+8);segments.append((vm,fo,fs))
        at+=n
    expected=[('0x14fac64','0x14fae60',508,'29b4fcbd317b4dc019411c97cc76b7b744409dddac46871af3a3998cb9d7da69'),('0x14f8d28','0x14fac64',7996,'c9061adae45d6ed11fe2300ca6b6b745ab02d1af00927544a8f7b5e47797fef1')]
    for j,(a,b,n,h)in enumerate(expected):
        r=att['spans'][j];data=bytes.fromhex(r['bytes_hex']);assert(r['start'],r['end_exclusive'],r['size_B'])==(a,b,n)
        assert len(data)==n and SHA(data)==r['sha256']==r['original_sha256']==h and r['current_equals_IDA_original_bytes']
        assert starts[starts.index(a)+1]==b
        address=int(a,16);vm,fo,fs=next(s for s in segments if s[0]<=address<address+n<=s[0]+s[2]);assert thin[fo+address-vm:fo+address-vm+n]==data
        assert e['code_spans'][j+5]=={**r,'role':'operand_wrapper'if j==0 else'operand_child'}
    assert len(att['spans'])==2 and e['reference_file_check']=={**old['reference_file_check'],'code_bytes_checked':13852}
    ins={i.address:i for r in e['code_spans']for i in CS.disasm(bytes.fromhex(r['bytes_hex']),int(r['start'],16))}
    exact={0x14fad54:('ldr','x21, [x19]'),0x14fadb8:('sub','x2, x21, #0x90'),0x14fadbc:('str','x2, [x20]'),
      0x14fae38:('blraa','x8, x17'),0x14fae3c:('ldr','w8, [x20]'),0x14fae40:('sub','w8, w8, w21'),
      0x14fae44:('ubfiz','x8, x8, #4, #0x10'),0x14fae48:('str','x8, [x19]'),0x14f8e44:('ldr','x10, [x1]'),
      0x14f8e48:('add','x10, x10, #0x90'),0x14f8e4c:('str','x10, [x1]'),0x14f8ea4:('ldr','w22, [x14, #4]'),
      0x14f8ed8:('ldr','x10, [x14, #8]'),0x14f8edc:('ldr','w24, [x10]'),0x14f900c:('cmp','w20, #0x20'),
      0x14f9010:('cset','w17, ne'),0x14f9014:('mul','w17, w17, w5'),0x14f9018:('eor','w17, w17, w21'),
      0x14f9048:('cmp','w17, w24'),0x14f904c:('cset','w17, ne'),0x14f9050:('orr','w17, w30, w17, lsl #2'),
      0x14f91e8:('mov','w23, #1'),0x14f91ec:('lsl','w25, w23, w20'),0x14f91f0:('add','w1, w25, w1'),
      0x14f924c:('neg','w9, w1'),0x14f9254:('str','w9, [x10, #0x10]'),0x14f932c:('blraa','x8, x17')}
    for a,pair in exact.items():assert(ins[a].mnemonic,ins[a].op_str)==pair
    for proof in e['proofs']:
        s=z3.Solver();s.set(timeout=60000);s.add(z3.parse_smt2_string(proof['query']));result=str(s.check());assert result==proof['result']=='unsat',(proof['label'],result,s.reason_unknown())
    bv=lambda x:z3.BitVecVal(x,32);n,q,v,k=z3.BitVecs('audit_n audit_q audit_v audit_k',32)
    r=lift_details(ins,{'w24':n^bv(K),'w30':bv(0x8f3b)},0x14f8ee0,0x14f8f40);r=lift_details(ins,r,0x14f8f94,0x14f8fec)
    r.update({'w24':q^bv(K),'w30':bv(0x8f3b),'w8':bv(0x4a2d180),'w20':k,'w1':v});r=lift_details(ins,r,0x14f9030,0x14f9048)
    claims=[r['w25']==(z3.LShR(q,1)^bv(K)),(r['w17']==r['w24'])==(z3.Extract(1,1,q)==1)]
    r=lift_details(ins,r,0x14f9064,0x14f91f8);claims.extend([z3.Extract(8*j+7,8*j,r['w25'])==z3.Extract(8*j+7,8*j,(z3.LShR(q,1)+n)^bv(K))for j in range(4)]);claims.extend([z3.Implies(z3.And(z3.UGT(k,0),z3.ULT(k,32)),r['w1']==v+(bv(1)<<k))])
    r=lift_details(ins,{'w21':bv(0xb960),'w20':k,'w0':bv(0xbabf),'w2':bv(37),'w3':bv(0x246d),'w4':bv(0x1237)},0x14f8ff4,0x14f900c)
    claims.append(z3.And(r['w20']==k+1,r['w30']==0x8f3b));s64=z3.BitVec('audit_seed64',64);claims.append((s64+z3.BitVecVal(-144,64))+144==s64)
    p=z3.BitVec('audit_product',32)
    for bit in range(1,32):
        take=z3.Extract(1,1,q)==1;pn=p+z3.If(take,n<<bit,bv(0));qn=z3.LShR(q,1)+z3.If(take,n,bv(0))
        assumptions=z3.And(z3.Extract(0,0,n)==1,z3.Extract(bit-1,0,p)==1,z3.Extract(32-bit,0,q)==z3.Extract(31,bit-1,p))
        conclusion=z3.And(z3.Extract(bit,0,pn)==1,z3.Extract(31-bit,0,qn)==z3.Extract(31,bit,pn))
        claims.append(z3.Implies(assumptions,conclusion))
    for claim in claims:
        s=z3.Solver();s.set(timeout=60000);s.add(z3.Not(claim));assert s.check()==z3.unsat
    expected_banks=[(0x1ac19c0,0x1c78040,0x78,0x2e),(0x1ac19c0,0x1c78040,0x27,0x18),(0x1ac19c0,0x1c78040,0x20,0x94),(0x174f320,0x18ac370,0xe4,0xec),(0x18ac070,0x1ac18c0,0x8c,0xa3)]
    assert e['bindings']['exhaustive_banks']==[{'first':hex(a),'second':hex(b),'key':hex(k),'constant':hex(v),'inputs':256}for a,b,k,v in expected_banks]
    for a,b,k,v in expected_banks:assert all(x^banks[b][banks[a][x]^k]==v for x in range(256))
    roles=[('wrapper_stateA',0x1d101c8,-4,0x1d33698),('wrapper_stateB',0x1d120a8,0,0x1d37f68),('wrapper_cursor_meta',0x1d11650,-4,0x1d332a0),('wrapper_table',0x1d108e8,-4,0x1c81940),('child_stateA',0x1d07638,-4,0x1d43800),('child_stateB',0x1d120a8,0,0x1d37f68),('child_table',0x1d108e8,-4,0x1c81940),('outer_wrapper',0x1d05948,0,0x14fac64),('nested_child',0x1d04c30,0,0x14f8d28),('loop_entry',0x1cde7c0,0,0x14f9030),('loop_add',0x1cc9318,0,0x14f9064),('loop_skip',0x1cc9338,0,0x14f8ff4),('loop_exit',0x1cde440,0,0x14f9208),('scalar_initializer',0x1d039d8,0,0x181b00),('next_helper',0x1d03860,0,0x5a600c)]
    expected_rows=[]
    for role,a,bias,target in roles:
        assert int(D[a]['target'],16)+bias==target
        expected_rows.append({'role':role,'slot':hex(a),'bias':bias,'effective_target':hex(target),'original':D[a]})
    assert e['bindings']['selected_bindings']==expected_rows
    return {'fresh_IDA_spans':2,'fresh_IDA_bytes':8504,'compiler_bounded_bodies':2,'original_file_new_code_bytes':8504,
      'original_file_total_selected_code_bytes':13852,'exact_source_instructions_checked':len(exact),'retained_queries_unsat':len(e['proofs']),
      'independent_local_queries_unsat':len(claims),'exhaustive_bank_inputs':1280,'selected_binding_roles':15,'source_lifters_use_distinct_operand_decoders':True}


def main():
    e=json.loads(read(ROOT/'fpsd1201_operand_checks.json'));old=json.loads(read(ROOT/'fpsd1201_import_checks.json'));record=json.loads(read(ROOT/'fpsd1201_record_checks.json'))
    for name,h in e['dependencies'].items():assert SHA(read(ROOT/name).encode())==h
    assert e['generator_sha256']==SHA((ROOT/'recover_fpsd1201_operand.py').read_bytes())and e['IDA_readback_sha256']==SHA(read(ROOT/'fpsd1201_operand_ida_readback.json').encode())
    banks,D,prior=source_and_proofs(record);D2,prior_import=reference_and_source(old,record);assert D==D2
    source=source_checks(e,old,banks,D);ps=e['profiles'];assert len(ps)==36 and sum(p['configuration']['backed']for p in ps)==28
    expected=[1,3,5,7,17,65537,0xffffffff,0x80000001,0xa5a5a5a5,0x7fffffff];value=0x12345678
    for j in range(14):value=(value*1664525+1013904223)&MASK;expected.append(value|1)
    expected.extend([0,2,0x80000000,0xfffffffe]);assert[p['configuration']['operand_u32']for p in ps if p['configuration']['backed']]==expected
    base=[p['configuration']for p in record['profiles']if p['configuration']['control']in ['as_staged','null_auxiliary']]
    for j,p in enumerate(ps):
        c=p['configuration'];b=base[j if j<8 else(j-8)%8]
        for key in ['control','seed_u64','global1_u64','global2_u64','global3_u64','global4_u64']:assert c[key]==b[key]
        assert c['mode']=='nested'and c['backed']==(j>=8)
        if j>=8:assert c['second_seed_u64']==[0,1,MASK64,0x0123456789abcdef][(j-8)%4]
    totals=Counter()
    for p in ps:totals.update(Replay(p,record,e['code_spans'],banks,D).run())
    assert not any(e[k]for k in ['whole_parent_replayed','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    targets=sorted({p['frontier'].get('target')for p in ps if p['configuration']['backed']})
    result={'source':source,'pinned_predecessor_source':prior,'pinned_import_source':prior_import,'fresh_replay':dict(totals),
      'profiles':36,'unbacked_context_frontiers':8,'backed_operand_prefixes':28,'next_callee_targets':targets,'candidate_inline128_reads_or_writes':0,
      'whole_parent_replayed':False,'complete_operand_child_return_established':False,'native_target_executed':False,'full_goal_complete':False,'all_checks_pass':True}
    receipt={'result':result,'dependencies':e['dependencies'],'checks_sha256':SHA(read(ROOT/'fpsd1201_operand_checks.json').encode()),
      'IDA_readback_sha256':e['IDA_readback_sha256'],'auditor_sha256':SHA(Path(__file__).read_bytes()),'fresh_replay_completed':True,'process_exit_code':0,'native_target_executed':False}
    (ROOT/'fpsd1201_operand_audit.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
