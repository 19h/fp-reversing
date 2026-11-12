#!/usr/bin/env python3
"""Independent original-byte replay and auxiliary/consumer integer oracles.

Does not import the new producer. Reconstructs controls, maps fresh RAM/CPU,
checks every journal item and CPU frame, then checks numerical contracts.
Time O(I+C*(B+F+V+P*J+R)); space O(I+B+F+C*(V+J+P+R)); SMT separate.
"""
import json,struct
from pathlib import Path
from hashlib import sha256
from collections import Counter
import unicorn as uc
from unicorn import arm64_const as A
import z3
from audit_fpsd1201_record import Replay as Core,unpack,ROOT,RAM,CS,OWNER,FP,SP,HALT,RECORD,OUT
from audit_fpsd1201_product import sources as prior_sources
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();M=0xffffffff;BASE=0x4b0cf050;K=0x1ac70ef2
LENGTH=0x59f4e8;BIT=0x57af24;IR=FP+0x100;DESC=OWNER+0x800;PAYLOAD=OWNER+0x1000
ENTRIES={LENGTH:0x59f704,BIT:0x57b090};EXITS={v:k for k,v in ENTRIES.items()}
PRIOR_AUDIT_SHA='219fd7b1a149580151b1fe9475f25652cf2990e526c7ce872d3bf53bec57ca7e'


def value(view):
    d=bytes.fromhex(view['descriptor16_hex']);count=(int.from_bytes(d[4:8],'little')-BASE)&M;count=count-(1<<32)if count>>31 else count
    assert abs(count)<=130;raw=bytes.fromhex(view['active_payload_hex']);assert len(raw)==4*abs(count)
    n=sum((int.from_bytes(raw[4*j:4*j+4],'little')^K)<<(32*j)for j in range(abs(count)))
    return -n if count<0 else n


class Replay(Core):
    def __init__(self,p,prior,outer,code,banks,D):
        self.p=p;self.c=p['configuration'];self.D=D;self.v=self.r=self.w=self.pi=self.ci=0;self.hi=self.oi=0
        self.phase='auxiliary_'+self.c['mode'];self.pending=[];self.stats=Counter();self.used=set();self.stack=[];self.indices=[];self.summary={}
        self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.ranges=[(int(r['start'],16),int(r['start'],16)+len(bytes.fromhex(r['bytes_hex'])))for r in code];pages=set()
        for a,b in self.ranges+[(a,a+len(b))for a,b in banks.items()]+[(a,a+n)for a,n in RAM]+[(0x1c80000,0x1d20000),(HALT,HALT+4096)]:pages.update(range(a&~4095,(b+4095)&~4095,4096))
        for a in sorted(pages):self.u.mem_map(a,4096)
        for row in code:self.u.mem_write(int(row['start'],16),bytes.fromhex(row['bytes_hex']))
        for a,b in banks.items():self.u.mem_write(a,b)
        for a,row in D.items():
            if 0x1c80000<=a<a+8<=0x1d20000 and not row['bind']:self.u.mem_write(a,int(row['target'],16).to_bytes(8,'little'))
        self.u.mem_write(0x1d1c578,(0x1d43300).to_bytes(8,'little'));self.u.reg_write(A.UC_ARM64_REG_CPACR_EL1,3<<20)
        for row,(a,n)in zip(prior['final_RAM'],RAM):
            b=unpack(row['payload']);assert row['address']==hex(a)and len(b)==n;self.u.mem_write(a,b);self.stats['restored_RAM_bytes_checked']+=n
        f=prior['terminal'];assert f['pc']=='0x11425bc'
        for j,v in enumerate(f['registers31']):self.setreg(j,int(v,16))
        for name,key in [('SP','sp'),('PC','pc'),('NZCV','NZCV')]:self.u.reg_write(getattr(A,'UC_ARM64_REG_'+name),int(f[key],16))
        for j,v in enumerate(f['Q32']):self.u.reg_write(A.UC_ARM64_REG_Q0+j,int(v,16))
        self.outer=outer['consumer_points'][0];self.orp=int(self.outer['record_pointer'],16);self.oc=int(self.outer['caller_cursor_pointer'],16);self.cc=int(outer['consumer_points'][3]['child_cursor_pointer'],16);self.seed=prior['configuration']['seed_u64']
        controls=[]
        def patch(a,b):controls.append({'address':hex(a),'before_hex':self.ram(a,len(b)).hex(),'after_hex':b.hex()});self.u.mem_write(a,b)
        def descriptor(d,ptr,v,sign,leading,special=None):
            count=sign*((v.bit_length()+31)//32+leading)if special is None else special
            patch(d,struct.pack('<IIQ',130,(BASE+count)&M,0 if special is not None else ptr))
            if special is None:
                for j in range(abs(count)):patch(ptr+4*j,(((v>>(32*j))&M)^K).to_bytes(4,'little'))
        c=self.c
        if c['mode']in ['retained','exponent']:
            self.entry=0x11425bc;j=p['checkpoint_pointer_load']['prior_read_index'];r=prior['source_reads'][j];v=prior['source_visits'][r['visit']]
            assert p['checkpoint_pointer_load']=={'prior_read_index':j,'read':r,'source_visit':v}
            assert(r['address'],r['size_B'],r['bytes_hex'])==('0x1d037a8',8,LENGTH.to_bytes(8,'little').hex())and self.ram(int(v['pc'],16),4).hex()==v['bytes_hex']
            self.stats['checkpoint_reaching_loads_checked']+=1
            if c['mode']=='exponent':descriptor(int.from_bytes(self.ram(self.reg(0)+8,8),'little'),OWNER+0x3400,int(c['exponent_hex'],16),1,0)
        else:
            assert c['mode']in ['length','bit']and p['checkpoint_pointer_load']is None
            descriptor(DESC,PAYLOAD,int(c['value_hex'],16),c['sign'],c['leading_zero_limbs'],c.get('special_count'))
            if c['mode']=='length':
                mask=((IR^0x1766cddd)*0xb7a7bfff)&M;patch(IR,struct.pack('<IIQ',(0x951a-mask)&M,0xa5a5a5a5,DESC));self.entry=LENGTH
            else:
                mask=((IR^0x542fbf9b)*0x4386951d)&M;encoded=((c['index_i32']-0x02a682df)*pow(0xef42366d,-1,1<<32))&M
                patch(IR,struct.pack('<IIIIQ',0xa5a5a5a5,encoded^mask,(0x6873-mask)&M,0xa5a5a5a5,DESC));self.entry=BIT
            self.setreg(0,IR);self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_SP,SP);self.u.reg_write(A.UC_ARM64_REG_PC,self.entry)
        assert controls==p['operand_controls'];self.frame(p['initial'])
        if c['mode']in ['retained','exponent']:
            raw=self.ram(self.orp,48);self.input_before=self.desc(int.from_bytes(raw[32:40],'little'));self.modulus_before=self.desc(int.from_bytes(raw[40:48],'little'))
        for row,(a,n)in zip(p['initial_RAM'],RAM):assert row['address']==hex(a)and unpack(row['payload'])==self.ram(a,n);self.stats['initial_RAM_bytes_checked']+=n
        self.u.hook_add(uc.UC_HOOK_CODE,self.hook);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.readhook);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.writehook)
    def desc(self,a):
        raw=self.ram(a,16);count=(int.from_bytes(raw[4:8],'little')-BASE)&M;count=count-(1<<32)if count>>31 else count;ptr=int.from_bytes(raw[8:],'little')
        valid=abs(count)<=130 and any(lo<=ptr<=ptr+4*abs(count)<=lo+n for lo,n in RAM)
        payload=''if count==0 else self.ram(ptr,4*abs(count)).hex()if valid else None
        return {'address':hex(a),'descriptor16_hex':raw.hex(),'active_payload_hex':payload}
    def helper(self,pc):
        if pc in ENTRIES:entry,r=pc,self.reg(0);before=None
        else:entry,r,before=self.stack.pop();assert EXITS[pc]==entry
        e=self.p['helper_points'][self.hi];self.hi+=1;self.frame(e['CPU']);raw=self.ram(r,24)
        d=self.desc(int.from_bytes(raw[8:16]if entry==LENGTH else raw[16:24],'little'))
        assert {k:v for k,v in e.items()if k!='CPU'}=={'pc':hex(pc),'entry':hex(entry),'record_pointer':hex(r),'record24_hex':raw.hex(),'descriptor':d}
        if pc in ENTRIES:
            self.stack.append((entry,r,e));word=lambda off:int.from_bytes(raw[off:off+4],'little')
            if entry==LENGTH:assert(word(0)+((r^0x1766cddd)*0xb7a7bfff))&M==0x951a
            else:
                h=((r^0x542fbf9b)*0x4386951d)&M;assert(word(8)+h)&M==0x6873
                idx=(((word(4)^h)*0xef42366d)+0x02a682df)&M;idx=idx-(1<<32)if idx>>31 else idx;self.indices.append(abs(idx))
        else:
            assert before['descriptor']==e['descriptor']and before['CPU']['sp']==e['CPU']['sp'];old=bytes.fromhex(before['record24_hex'])
            descraw=bytes.fromhex(d['descriptor16_hex']);count=(int.from_bytes(descraw[4:8],'little')-BASE)&M
            if count==0x80000000:expected=0;self.stats['signed_minimum_count_zero_results']+=1
            elif entry==LENGTH:expected=abs(value(d)).bit_length()
            else:
                h=((r^0x542fbf9b)*0x4386951d)&M;index=(((int.from_bytes(old[4:8],'little')^h)*0xef42366d)+0x02a682df)&M;index=index-(1<<32)if index>>31 else index
                expected=(abs(value(d))>>abs(index))&1 if abs(index)<4160 else 0
            if entry==LENGTH:
                assert raw==old[:4]+((0x4fe66f44+expected)&M).to_bytes(4,'little')+old[8:];self.stats['bit_length_oracles_checked']+=1
            else:
                assert raw==(0xc0a17a28|expected).to_bytes(4,'little')+old[4:];self.stats['bit_selection_oracles_checked']+=1
            if self.c['mode']in ['length','bit']:
                assert self.reg(30)==HALT;self.stats['isolated_helper_returns_checked']+=1
        self.stats['helper_points_checked']+=1
    def consumer(self,pc):
        e=self.p['consumer_points'][self.oi];self.oi+=1;self.frame(e['CPU']);raw=self.ram(self.orp,48);ptr=lambda j:int.from_bytes(raw[j:j+8],'little')
        actual={'pc':hex(pc),'record48_hex':raw.hex(),'output':self.desc(ptr(8)),'input':self.desc(ptr(32)),'modulus':self.desc(ptr(40)),
          'wrapper_cursor_u64':hex(int.from_bytes(self.ram(self.oc,8),'little')),'child_cursor_u64':hex(int.from_bytes(self.ram(self.cc,8),'little'))}
        assert actual=={k:v for k,v in e.items()if k!='CPU'}
        assert e['input']==self.input_before and e['modulus']==self.modulus_before
        if pc==0x1142874:
            exponent=int(self.c['exponent_hex'],16)if self.c['mode']=='exponent'else 65537;n=value(e['modulus']);b=value(e['input']);out=value(e['output'])
            assert self.indices==list(reversed(range(exponent.bit_length())))
            calls=[int(q['pc'],16)for q in self.p['PAC_models'][:self.pi]if q['kind']=='blraa'and int(q['pc'],16)in [0x11429e4,0x1142ac8,0x1142be4]]
            expected=[]
            for index in reversed(range(exponent.bit_length())):
                expected.extend([0x11429e4,0x1142ac8])
                if exponent>>index&1:expected.append(0x1142be4)
            assert calls==expected
            self.stats['consumer_loop_call_sequences_checked']+=1;self.stats['consumer_loop_squares_checked']+=exponent.bit_length();self.stats['consumer_loop_products_checked']+=exponent.bit_count()
            if n&1:assert out==pow(b,exponent,n);self.stats['modular_exponentiation_oracles_checked']+=1
            else:self.stats['even_consumer_controls_checked']+=1
            s=int(self.outer['caller_cursor_u64'],16);assert int(e['child_cursor_u64'],16)==s
            self.summary={'modulus_hex':hex(n),'input_hex':hex(b),'exponent_hex':hex(exponent),'result_hex':hex(out),'pow_oracle_matches':out==pow(b,exponent,n)if n&1 else None,'bit_queries':len(self.indices)}
            self.stats['complete_consumer_child_returns_checked']+=1
        if pc==0x1142e2c:assert e['wrapper_cursor_u64']=='0x0';self.stats['complete_consumer_wrapper_returns_checked']+=1
        if pc==0x9819c8:self.stats['consumer_caller_resumes_checked']+=1
    def hook(self,u,pc,n,data):
        self.flush()
        if pc==0x1142700:
            r=self.reg(0);raw=self.ram(r,24);h=(((r^0x2fbc3a3b)^0xf6a89466)*0x08c5d407)&M
            assert int.from_bytes(raw[:4],'little')^h==0xed31
            assert ((int.from_bytes(raw[16:20],'little')^h)+0xf369ff3c)&M==1
            self.scalar_descriptor=int.from_bytes(raw[8:16],'little')
        if pc==0x1142704:
            assert value(self.desc(self.scalar_descriptor))==1;self.stats['final_scalar_one_initializers_checked']+=1
        if pc in ENTRIES or pc in EXITS:self.helper(pc)
        if pc in [0x1142874,0x1142e2c,0x9819c8]:self.consumer(pc)
        if pc==0x59f650 and self.c['mode']=='retained'and self.stack[-1][2]['descriptor']['active_payload_hex']is None:
            self.frame(self.p['terminal']);assert self.p['frontier']=={'pc':hex(pc),'read_address':hex((self.reg(4)+4*self.reg(9))&((1<<64)-1)),'size_B':4,'instruction_executed':False}
            assert self.p['frontier']['read_address']=='0xa5a5a5a710087af5';self.stop='unbacked_auxiliary_payload';u.emu_stop();self.stats['bounded_unbacked_payload_frontiers_checked']+=1;return
        if pc==0x981bc8:
            self.frame(self.p['terminal']);assert(self.reg(8),self.reg(17))==(0x32f628,0xa77e);slot=0x1d03d10;row=self.D[slot]
            assert(row['target'],row['diversity'],row['key'],row['address_diversity'])==('0x32f628','0xa77e','IA',0)
            assert any(r['address']==hex(slot)and r['size_B']==8 and r['bytes_hex']==(0x32f628).to_bytes(8,'little').hex()for r in self.p['source_reads'][:self.r])
            assert self.p['frontier']=={'pc':hex(pc),'target':'0x32f628','modifier':'0xa77e','original_slot':hex(slot),'instruction':'blraa x8, x17','instruction_executed':False,'argument_record80_hex':self.ram(self.reg(0),80).hex()}
            self.used.add(slot);self.stop='unretained_callee';u.emu_stop();return
        if pc==0x11425bc and self.v==0:
            assert self.p['source_visits'][0]=={'phase':self.phase,'pc':hex(pc),'bytes_hex':self.ram(pc,4).hex(),'instruction':'blraa x8, x17'};self.v+=1
            e=self.p['PAC_models'][self.pi];self.pi+=1;self.frame(e['before']);assert e=={'pc':hex(pc),'kind':'blraa','before':self.p['initial'],'target':hex(LENGTH),'modifier':'0x7c9f','original_slot':'0x1d037a8'}
            row=self.D[0x1d037a8];assert(row['target'],row['diversity'],row['key'],row['address_diversity'])==(hex(LENGTH),'0x7c9f','IA',0)
            assert(self.reg(8),self.reg(17))==(LENGTH,0x7c9f);self.used.add(0x1d037a8);self.setreg(30,pc+4);u.reg_write(A.UC_ARM64_REG_PC,LENGTH);return
        Core.hook(self,u,pc,n,data)
    def run(self):
        self.u.emu_start(self.entry,0,count=500000);self.flush();assert self.stop==self.p['stop_reason']
        assert(self.v,self.r,self.w,self.pi,self.ci)==tuple(len(self.p[k])for k in ['source_visits','source_reads','source_writes','PAC_models','CPU_points'])
        assert self.hi==len(self.p['helper_points'])and self.oi==len(self.p['consumer_points'])and len(self.stack)==(self.stop=='unbacked_auxiliary_payload')
        assert self.p['used_original_pointer_rows']==[self.D[a]for a in sorted(self.used)]
        for row in self.p['used_original_pointer_rows']:
            if row['bind']:assert row['import']['name']=='___stack_chk_guard';continue
            word=int(row['word'],16);target=word&M if word>>63 else(word&((1<<43)-1))|(((word>>43)&255)<<56)
            assert target==int(row['target'],16)
            if word>>63:assert word>>49&3==0 and word>>32&65535==int(row['diversity'],16)and word>>48&1==row['address_diversity']
            self.stats['original_pointer_profile_associations_checked']+=1
        for row,(a,n)in zip(self.p['final_RAM'],RAM):assert row['address']==hex(a)and unpack(row['payload'])==self.ram(a,n);self.stats['final_RAM_bytes_checked']+=n
        assert not self.p['native_effects']
        if self.c['mode']in ['retained','exponent']:
            assert int.from_bytes(self.ram(OUT,8),'little')==int(self.p['final_delta_cell_u64'],16)==self.seed
            assert int.from_bytes(self.ram(RECORD+0x30,4),'little')==int(self.p['final_status_u32'],16)==0xa5a5a5a5
            for name in ['source_reads','source_writes']:assert not any(int(r['address'],16)<OWNER+0x900 and OWNER+0x880<int(r['address'],16)+r['size_B']for r in self.p[name])
            assert self.ram(OWNER+0x880,128)==b'\xa5'*128
            if self.oi:
                writes=[w for w in self.p['source_writes']if int(w['address'],16)<self.oc+8 and self.oc<int(w['address'],16)+w['size_B']]
                assert len(writes)==1 and writes[0]['address']==hex(self.oc)and writes[0]['size_B']==8 and writes[0]['after_hex']=='00'*8
                assert self.p['source_visits'][writes[0]['visit']]['pc']=='0x1142e18';self.stats['consumer_stack_emission_stores_checked']+=1
        elif 'special_count'in self.c:
            payload_pc='0x59f650'if self.c['mode']=='length'else'0x57b060'
            assert not any(v['pc']==payload_pc for v in self.p['source_visits']);self.stats['null_payload_no_reads_checked']+=1
        self.stats.update({'original_visits_checked':self.v,'original_reads_checked':self.r,'original_writes_checked':self.w,'PAC_models_checked':self.pi})
        return self.stats,self.summary


def source(e,old,consumer):
    banks,D,prefix=prior_sources(old,consumer);assert e['code_spans'][:23]==old['code_spans']
    att=json.loads(read(ROOT/'fpsd1201_auxiliary_ida_readback.json'));assert not att['IDB_mutated']and not att['native_target_executed']and len(att['spans'])==2
    raw=(ROOT.parent/'CoreFP').read_bytes();assert SHA(raw)==att['input_sha256']=='68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f'
    slices=[struct.unpack_from('>5I',raw,8+20*j)for j in range(struct.unpack_from('>I',raw,4)[0])];_,_,off,n,_=next(s for s in slices if s[:2]==(0x100000c,0x80000002));thin=raw[off:off+n]
    assert SHA(thin)=='8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c';at=32;segments=[]
    for j in range(struct.unpack_from('<I',thin,16)[0]):
        cmd,n=struct.unpack_from('<II',thin,at)
        if cmd==0x19:
            _,vm,vs,fo,fs=struct.unpack_from('<16s4Q',thin,at+8);segments.append((vm,fo,fs))
        at+=n
    starts=json.loads(read(ROOT/'corefp_library_inventory.json'))['compiler_function_starts'];expected=[(LENGTH,0x59f708,544,'627b3f0378862c135727ac1a933069521fa34c42a862b0c06039f416674ea696'),(BIT,0x57b094,368,'f16a2c599874d5252c9286c2ac1a20d1db082bb8ae9ce703970e449ae91f9289')]
    for j,(a,end,n,h)in enumerate(expected):
        row=att['spans'][j];b=bytes.fromhex(row['bytes_hex']);vm,fo,fs=next(s for s in segments if s[0]<=a<a+n<=s[0]+s[2])
        assert thin[fo+a-vm:fo+a-vm+n]==b and len(b)==n and SHA(b)==row['sha256']==row['original_sha256']==h
        assert row['start']==hex(a)and row['end_exclusive']==hex(end)and row['size_B']==n and row['current_equals_IDA_original_bytes']and starts[starts.index(hex(a))+1]==hex(end)
        assert e['code_spans'][23+j]=={**row,'role':['magnitude_bit_length','magnitude_bit_selection'][j]}
    ins={i.address:(i.mnemonic,i.op_str)for row in e['code_spans']for i in CS.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16))}
    exact={0x59f578:('madd','w16, w9, w11, w12'),0x59f590:('ldr','w9, [x11, #4]'),0x59f5a4:('cneg','w9, w9, mi'),0x59f61c:('cmp','w9, #1'),0x59f650:('ldr','w17, [x4, x9, lsl #2]'),0x59f6fc:('str','w8, [x0, #4]'),0x59f704:('ret',''),
      0x57afc4:('csel','w10, w12, w10, pl'),0x57afec:('cmp','w12, w1'),0x57aff0:('cset','w1, lt'),0x57b060:('ldr','w9, [x9, w12, uxtw #2]'),0x57b070:('lsr','w9, w9, w10'),0x57b088:('str','w8, [x0]'),0x57b090:('ret',''),
      0x1142874:('retab',''),0x1142e2c:('retab',''),0x981bc8:('blraa','x8, x17')}
    for a,want in exact.items():assert ins[a]==want,(hex(a),ins[a])
    p,x=z3.BitVecs('independent_aux_pointer independent_aux_index',32)
    claims=[((2*(p&0x11f97c13)-p+0x6e0683ec)^0x79604e31)*0xb7a7bfff==(p^0x1766cddd)*0xb7a7bfff,
      ((x-0x02a682df)*pow(0xef42366d,-1,1<<32))*0xef42366d+0x02a682df==x,0xfd597d21-x==-(x+0x02a682df)]
    assert len(e['proofs'])==len(claims)==3
    for proof,claim in zip(e['proofs'],claims):
        q=z3.Solver();q.set(timeout=60000);q.add(z3.parse_smt2_string(proof['query']));assert proof['result']=='unsat'and q.check()==z3.unsat
        q=z3.Solver();q.set(timeout=60000);q.add(z3.Not(claim));assert q.check()==z3.unsat
    return banks,D,{'fresh_IDA_spans':2,'fresh_IDA_bytes':912,'compiler_bounded_bodies':2,'total_selected_code_bytes':40412,'original_fixup_words_checked':len(D),'compiler_starts_checked':len(starts),'retained_queries_unsat':3,'independent_queries_unsat':3,'exact_source_instructions_checked':len(exact),'universal_consumer_algorithm_proof':False}


def main():
    e=json.loads(read(ROOT/'fpsd1201_auxiliary_checks.json'));old=json.loads(read(ROOT/'fpsd1201_product_checks.json'));consumer=json.loads(read(ROOT/'fpsd1201_consumer_checks.json'))
    receipt=json.loads(read(ROOT/'fpsd1201_product_audit.json'));assert SHA(read(ROOT/'fpsd1201_product_audit.json').encode())==PRIOR_AUDIT_SHA and receipt['fresh_replay_completed']and receipt['result']['all_checks_pass']
    assert receipt['checks_sha256']==SHA(read(ROOT/'fpsd1201_product_checks.json').encode())and receipt['auditor_sha256']==SHA((ROOT/'audit_fpsd1201_product.py').read_bytes())
    assert e['generator_sha256']==SHA((ROOT/'recover_fpsd1201_auxiliary.py').read_bytes())and e['IDA_readback_sha256']==SHA(read(ROOT/'fpsd1201_auxiliary_ida_readback.json').encode())
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    expected=[{'mode':'retained','prior_index':12+j}for j in range(12)]
    expected.extend({'mode':'exponent','prior_index':20,'exponent_hex':hex(v)}for v in [0,1,2,3,17,65537,0x80000001,0xffffffff])
    expected.extend({'mode':'exponent','prior_index':21,'exponent_hex':hex(v)}for v in [0,2,17,65537])
    for v in [0,1,2,3,65537,0xffffffff,1<<32,(1<<33)+3,(1<<127)+1,(1<<2047)+1]:
        for sign in ([1]if v==0 else[1,-1]):
            for leading in [0,2]:expected.append({'mode':'length','prior_index':12,'value_hex':hex(v),'sign':sign,'leading_zero_limbs':leading})
    for v in [0,1,65537,(1<<31)+3,(1<<32)+5,(1<<127)+1]:
        for sign in [1,-1]:
            for index in [0,1,16,31,32,63,127,128,-1,-32,-128,-0x80000000]:expected.append({'mode':'bit','prior_index':12,'value_hex':hex(v),'sign':sign,'index_i32':index,'leading_zero_limbs':0})
    for mode in ['length','bit']:
        for count in [0,-0x80000000]:expected.append({'mode':mode,'prior_index':12,'value_hex':'0x0','sign':1,'leading_zero_limbs':0,'special_count':count,'index_i32':0})
    assert len(expected)==len(e['profiles'])==210 and [p['configuration']for p in e['profiles']]==expected
    banks,D,src=source(e,old,consumer);total=Counter();summaries=[];modes=Counter()
    for j,p in enumerate(e['profiles']):
        index=p['prior_profile_index'];assert index==p['configuration']['prior_index']and 12<=index<24
        replay=Replay(p,old['profiles'][index],consumer['profiles'][index-12],e['code_spans'],banks,D);stats,summary=replay.run();total.update(stats);summaries.append(summary);modes[p['configuration']['mode']]+=1
        if j<24 or j%24==0:print(json.dumps({'profile':j,'mode':p['configuration']['mode'],'visits':stats['original_visits_checked'],'summary':summary}),flush=True)
    result={'source':src,'fresh_replay':dict(total),'profiles':len(e['profiles']),'modes':dict(modes),'profile_summaries':summaries,'prior_replay_receipt_sha256':PRIOR_AUDIT_SHA,'prefix_instructions_rerun':0,
      'next_callee_targets':['0x32f628'],'nested_candidate_inline128_reads_or_writes':0,'whole_parent_replayed':False,'native_target_executed':False,'full_goal_complete':False,'all_checks_pass':True}
    assert not any(e[k]for k in ['whole_parent_replayed','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    out={'result':result,'dependencies':e['dependencies'],'checks_sha256':SHA(read(ROOT/'fpsd1201_auxiliary_checks.json').encode()),'IDA_readback_sha256':e['IDA_readback_sha256'],
      'auditor_sha256':SHA(Path(__file__).read_bytes()),'fresh_replay_completed':True,'process_exit_code':0,'native_target_executed':False}
    (ROOT/'fpsd1201_auxiliary_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({**result,'profile_summaries':'retained in receipt'}),flush=True)


if __name__=='__main__':main()
