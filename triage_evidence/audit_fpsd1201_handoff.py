#!/usr/bin/env python3
"""Independent original-byte replay and retained-result serialization audit.

Does not import the new producer. Reconstruct every binding from declared
configuration; compare all CPU/read/write/RAM/PAC observations and byte oracles.
O(B+F+C*(V+J+R)) time/space; SMT separate. No target or API is executed.
"""
import json,struct
from pathlib import Path
from collections import Counter
from hashlib import sha256
import unicorn as uc
from unicorn import arm64_const as A
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
from audit_fpsd1201_caller import Replay as Frozen,unpack
from verify_daemon_reader_record_payloads_publication import read

ROOT=Path(__file__).resolve().parent;SHA=lambda b:sha256(b).hexdigest()
CS=Cs(CS_ARCH_ARM64,CS_MODE_ARM);CS.detail=True
SP=0x71008000;FP=0x7100c000;P=0x73000000;G=0x74000000;B=0x76000000;T=0x1c81940
RAM=[(0x71000000,65536),(P,16384),(0x1d33000,69632),(G,4096),(B,4096),(0x1d1c000,4096)]
SLOTS=[0x1cbf7c0,0x1cde068,0x1cac848,0x1cac960,0x1cf2d98,0x1cf2df8,0x1d03f08]


class Replay(Frozen):
    def __init__(self,p,old,spans,D):
        self.p=p;self.c=p['configuration'];self.D=D;self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM)
        self.v=self.r=self.w=self.pac=self.point=0;self.pending=[];self.stats=Counter();self.old=old
        pages=sorted({a&~4095 for a in SLOTS}|{0x18ac000,0x1ac1000})
        for a,n in [(0x8e8000,86016),(0x8000,4096)]+[(a,4096)for a in pages]+RAM:self.u.mem_map(a,n)
        for row in spans:self.u.mem_write(int(row['start'],16),bytes.fromhex(row['bytes_hex']))
        for a in SLOTS:self.u.mem_write(a,int(D[a]['target'],16).to_bytes(8,'little'))
        for a,n in RAM:self.u.mem_write(a,b'\xa5'*n)
        assert len(old['final_RAM'])==3
        for row,(a,n)in zip(old['final_RAM'],RAM):
            raw=unpack(row['payload']);assert row['address']==hex(a)and len(raw)==n;self.u.mem_write(a,raw)
        self.input128=self.ram(P+0x880,128);self.context128=self.ram(P+0x2000,128)
        f=old['terminal']
        for j,v in enumerate(f['registers31']):self.setreg(j,int(v,16))
        for name,key in [('SP','sp'),('PC','pc'),('NZCV','NZCV')]:self.u.reg_write(getattr(A,'UC_ARM64_REG_'+name),int(f[key],16))
        for j,v in enumerate(f['Q32']):self.u.reg_write(A.UC_ARM64_REG_Q0+j,int(v,16))
        self.u.reg_write(A.UC_ARM64_REG_CPACR_EL1,3<<20)
        assert p['restored']==f and f['pc']=='0x7f000000'and f['sp']==hex(SP);self.frame(p['restored']);self.checkram(p['restored_RAM'],'restored_RAM_bytes_checked')
        assert [self.reg(j)for j in [20,22,23,29]]==[0x55e1,0x7bd0,0x3de80,FP]
        assert self.ram(SP+0x1b8,8)==(P+0x880).to_bytes(8,'little')and self.ram(SP+0x978,8)==bytes(8)
        rb=[{'register':'X'+str(j),'before':hex(self.reg(j)),'after':hex(v)}for j,v in [(19,T),(25,P+0x900)]];assert p['register_bindings']==rb
        self.setreg(19,T);self.setreg(25,P+0x900);patches=[]
        def patch(a,raw,why):
            patches.append({'address':hex(a),'before_hex':self.ram(a,len(raw)).hex(),'after_hex':raw.hex(),'reason':why});self.u.mem_write(a,raw)
        c=self.c
        cells={0x1a8:(P+0x900,8),0x1f0:(P+0x2000,8),0x258:(P,8),0x4c0:(G,8),0x4b8:(G+4,8),0x3a8:(0x18ac270,8),0x3a0:(0x1ac1ac0,8),0x4e8:(0x6800+c['prior_index'],4)}
        for off,(v,n)in cells.items():patch(SP+off,v.to_bytes(n,'little'),'declared_parent_binding')
        patch(P+0x168,c['scalar_u32'].to_bytes(4,'little'),'declared_scalar')
        patch(G,struct.pack('<II',0x12345678,0xabcdef01^c['scalar_u32']),'declared_bank_mix')
        patch(B+256,bytes.fromhex('0000000001000000'),'declared_NDR_data');patch(B+512,bytes.fromhex('b39a4e0cf582617d'),'declared_guard_data')
        patch(0x1d1c570,(B+256).to_bytes(8,'little'),'declared_imported_data_pointer');patch(0x1d1c578,(B+512).to_bytes(8,'little'),'declared_imported_data_pointer')
        if c['root_override_u32']is not None:patch(FP-136,c['root_override_u32'].to_bytes(4,'little'),'negative_root_marker_control')
        assert p['operand_controls']==patches;self.stats['explicit_memory_bindings_checked']+=len(patches)
        assert self.ram(P+0x880,128)==self.input128 and self.ram(P+0x2000,128)==self.context128
        self.u.reg_write(A.UC_ARM64_REG_PC,0x8f3564);self.frame(p['initial']);self.checkram(p['initial_RAM'],'initial_RAM_bytes_checked')
        self.u.hook_add(uc.UC_HOOK_CODE,self.hook);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.readhook);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.writehook)
    def checkram(self,rows,label):
        assert len(rows)==len(RAM)
        for row,(a,n)in zip(rows,RAM):assert row['address']==hex(a)and unpack(row['payload'])==self.ram(a,n);self.stats[label]+=n
    def writehook(self,u,ac,a,n,v,d):
        assert any(lo<=a<a+n<=lo+m for lo,m in RAM)
        e=self.p['source_writes'][self.w];self.w+=1
        assert {k:e[k]for k in ['visit','address','size_B','before_hex']}=={'visit':self.v-1,'address':hex(a),'size_B':n,'before_hex':self.ram(a,n).hex()};self.pending.append(e)
    def hook(self,u,pc,n,d):
        self.flush()
        if pc in [0x8f3664,0x8f389c,0x8db0]:self.frame(self.p['terminal']);self.done=True;u.emu_stop();return
        raw=self.ram(pc,4);i=next(CS.disasm(raw,pc));assert self.p['source_visits'][self.v]=={'pc':hex(pc),'bytes_hex':raw.hex(),'instruction':i.mnemonic+' '+i.op_str};self.v+=1
        if pc in [0x8f3594,0x8f35c8,0x8f363c,0x8f3658,0x8f3838,0x8d40]:
            e=self.p['CPU_points'][self.point];self.point+=1;assert e['pc']==hex(pc);self.frame(e['CPU'])
            if pc==0x8f3838:
                assert [self.reg(j)for j in [0,1,2,8,17]]==[0x6800+self.c['prior_index'],self.c['scalar_u32'],P+0x880,0x8d40,0x8390]
                assert u.reg_read(A.UC_ARM64_REG_SP)==SP;self.stats['builder_argument_frames_checked']+=1
        if i.mnemonic in ['pacibsp','braa','blraa']:
            e=self.p['PAC_models'][self.pac];self.pac+=1;assert e['pc']==hex(pc);self.frame(e['before'])
            if i.mnemonic=='pacibsp':assert e['kind']=='PACIBSP_private_noop';u.reg_write(A.UC_ARM64_REG_PC,pc+4)
            else:
                assert pc in [0x8f35c8,0x8f35f8,0x8f3658,0x8f3838]
                rn={0x8f35c8:10,0x8f35f8:9,0x8f3658:8,0x8f3838:8}[pc];target=self.reg(rn);mod=self.reg(17);a=int(e['original_slot'],16);r=self.D[a]
                assert a in SLOTS and e['target']==hex(target)and e['modifier']==hex(mod)and e['kind']==i.mnemonic
                assert r['key']=='IA'and not r['address_diversity']and int(r['target'],16)==target and int(r['diversity'],16)==mod
                assert self.ram(a,8)==target.to_bytes(8,'little')
                if i.mnemonic=='blraa':self.setreg(30,pc+4)
                u.reg_write(A.UC_ARM64_REG_PC,target)
    def run(self):
        self.u.emu_start(0x8f3564,0,count=3000);self.flush();assert self.done
        assert [self.v,self.r,self.w,self.pac,self.point]==[len(self.p[k])for k in ['source_visits','source_reads','source_writes','PAC_models','CPU_points']]
        c=self.c;success=c['root_override_u32']is None;called=success and c['scalar_u32']>=2
        assert self.p['terminal']['pc']==('0x8db0'if called else'0x8f389c'if success else'0x8f3664')
        assert self.ram(P+0x880,128)==self.input128 and self.p['candidate128_hex']==self.input128.hex()
        assert self.ram(P+0x2000,128)==self.context128
        assert self.ram(SP+0x1b8,8)==(P+0x880).to_bytes(8,'little')and self.ram(SP+0x4e8,4)==(0x6800+c['prior_index']).to_bytes(4,'little')
        for e in self.p['source_writes']:
            a=int(e['address'],16);n=e['size_B'];assert a+n<=P+0x880 or a>=P+0x900
        visits=self.p['source_visits'];reads=lambda pc:[r for r in self.p['source_reads']if visits[r['visit']]['pc']==pc]
        writes=lambda pc:[w for w in self.p['source_writes']if visits[w['visit']]['pc']==pc]
        status=reads('0x8f3594');assert len(status)==1 and status[0]['address']==hex(FP-136)
        expected_marker=0xba1df9db if success else c['root_override_u32'];assert int.from_bytes(bytes.fromhex(status[0]['bytes_hex']),'little')==expected_marker
        branches=[e for e in self.p['PAC_models']if e['pc']=='0x8f35c8'];assert len(branches)==1 and branches[0]['original_slot']==('0x1cde068'if success else'0x1cbf7c0')
        r,w=reads('0x8f35d0'),writes('0x8f35e0');assert len(r)==len(w)==(128 if success else 0)
        for j,(rr,ww)in enumerate(zip(r,w)):
            k=127-j;assert rr['address']==hex(P+0x2000+k)and rr['size_B']==1 and rr['bytes_hex']==self.context128[k:k+1].hex()
            assert ww['address']==hex(P+0x900+k)and ww['size_B']==1 and int(ww['after_hex'],16)==(self.context128[k]^0xba);self.stats['XOR_byte_oracles_checked']+=1
        if success:assert self.ram(P+0x900,128)==bytes(x^0xba for x in self.context128)
        assert self.p['xor128_hex']==self.ram(P+0x900,128).hex()
        if called:
            assert self.u.reg_read(A.UC_ARM64_REG_SP)==SP-208
            assert self.ram(SP-208+40,128)==self.input128 and self.p['serialized128_hex']==self.input128.hex()
            assert self.p['serialized_scalar_u32']==c['scalar_u32']==int.from_bytes(self.ram(SP-208+36,4),'little')
            rs=[r for r in self.p['source_reads']if visits[r['visit']]['pc']in ['0x8d6c','0x8d78','0x8d84','0x8d90']]
            assert len(rs)==16 and all(r['size_B']==8 for r in rs)
            assert sorted(int(r['address'],16)for r in rs)==[P+0x880+8*j for j in range(16)]
            for r in rs:
                k=int(r['address'],16)-(P+0x880);assert r['bytes_hex']==self.input128[k:k+8].hex()
            ws=[w for w in self.p['source_writes']if visits[w['visit']]['pc']in ['0x8d70','0x8d74','0x8d7c','0x8d80','0x8d88','0x8d8c','0x8d94','0x8dac']]
            assert len(ws)==16 and all(w['size_B']==8 for w in ws)
            assert sorted(int(w['address'],16)for w in ws)==[SP-208+40+8*j for j in range(16)]
            for w in ws:
                k=int(w['address'],16)-(SP-208+40);assert w['after_hex']==self.input128[k:k+8].hex()
            self.stats['serialized_payload_bytes_checked']+=128;self.stats['pre_import_serializations_checked']+=1
            self.stats['short_export_still_staged_controls']+=self.c['prior_index']in [16,17]
        else:assert self.p['serialized128_hex']is None and self.p['serialized_scalar_u32']is None
        assert not any(v['pc']in ['0x8db0','0x8e04']for v in visits)and not self.p['first_import_call_executed']and not self.p['native_effects']
        self.checkram(self.p['final_RAM'],'final_RAM_bytes_checked')
        self.stats.update({'original_visits_checked':self.v,'original_reads_checked':self.r,'original_writes_checked':self.w,'PAC_models_checked':self.pac,'CPU_points_checked':self.point,'candidate_preservation_profiles_checked':1})
        return self.stats


def source(e,D):
    raw=(ROOT.parent/'CoreFP').read_bytes();assert SHA(raw)==e['reference_universal_sha256']=='68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f'
    slices=[struct.unpack_from('>5I',raw,8+20*j)for j in range(struct.unpack_from('>I',raw,4)[0])]
    _,_,off,n,_=next(s for s in slices if s[:2]==(0x100000c,0x80000002));thin=raw[off:off+n]
    assert SHA(thin)==e['reference_arm64e_sha256']=='8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c'
    pos=32;segments=[]
    for _ in range(struct.unpack_from('<I',thin,16)[0]):
        cmd,n=struct.unpack_from('<II',thin,pos)
        if cmd==0x19:_,vm,vs,fo,fs=struct.unpack_from('<16s4Q',thin,pos+8);segments.append((vm,fo,fs))
        pos+=n
    def get(a,n):
        vm,fo,fs=next(s for s in segments if s[0]<=a<a+n<=s[0]+s[2]);return thin[fo+a-vm:fo+a-vm+n]
    spans=e['code_spans'];att=json.loads(read(ROOT/'fpsd1201_caller_ida_readback.json'))
    parent=next(r for r in att['spans']if r['role']=='parent')
    assert parent['sha256']=='4e0ebb4383ce0f3d074358e851dd1bdfff67e77d675e0cfa9e73b4a03ff9a94e'and parent['size_B']==85464
    assert spans[:-1]==[r for r in att['spans']if r['role']in ['parent','call_bank']]
    client=next(r for r in json.loads(read(ROOT/'corefp_mach_request_profiles.json'))['original_functions']if r['start']=='0x8d40')
    assert spans[-1]=={'start':client['start'],'bytes_hex':client['bytes'],'role':'request1201_builder'}
    for row in spans:
        b=bytes.fromhex(row['bytes_hex']);assert get(int(row['start'],16),len(b))==b
        if 'sha256'in row:assert SHA(b)==row['sha256']
    for a,r in D.items():assert get(a,8)==int(r['word'],16).to_bytes(8,'little')
    assert e['pointer_rows']==[D[a]for a in SLOTS]
    for a in SLOTS:
        r=D[a];word=int.from_bytes(get(a,8),'little')
        assert r['pointer_format']==12 and r['authenticated']and not r['bind']and r['chain_membership_verified']
        assert word&0xffffffff==int(r['target'],16)and (word>>32)&0xffff==int(r['diversity'],16)and (word>>48)&1==0 and (word>>49)&3==0
    L=get(0x18ac270,256);R=get(0x1ac1ac0,256);assert all((x^R[L[x]^0xc8])==0xc0 for x in range(256))
    ins={i.address:i for row in spans if row['role']in ['parent','request1201_builder']for i in CS.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16))}
    exact={0x8e83ec:('sub','x19, x8, #4'),0x8f3430:('ldr','x25, [sp, #0x1a8]'),0x8f3450:('lsl','w23, w22, #3'),
      0x8f3560:('blraa','x8, x17'),0x8f3564:('ldr','x13, [sp, #0x1f0]'),0x8f3588:('ldr','x9, [sp, #0x978]'),
      0x8f3590:('mov','sp, x8'),0x8f3594:('ldur','w9, [x29, #-0x88]'),0x8f3598:('cmp','w9, w3'),
      0x8f35a8:('eor','w10, w23, w10'),0x8f35bc:('ldr','x10, [x19, w8, sxtw #3]'),0x8f35c8:('braa','x10, x17'),
      0x8f35d0:('ldrb','w9, [x13, x8]'),0x8f35e0:('strb','w9, [x25, x8]'),0x8f3638:('ldr','w1, [x25, #0x168]'),
      0x8f363c:('cmp','w1, #2'),0x8f3640:('cset','w9, lo'),0x8f3658:('braa','x8, x17'),
      0x8f3810:('ldr','w0, [sp, #0x4e8]'),0x8f382c:('ldr','x2, [sp, #0x1b8]'),0x8f3838:('blraa','x8, x17'),
      0x8d44:('sub','sp, sp, #0xd0'),0x8da8:('str','w1, [sp, #0x24]'),0x8db0:('bl','#0x15d1934'),0x8e04:('bl','#0x15d18e4')}
    for pc,want in exact.items():assert(ins[pc].mnemonic,ins[pc].op_str)==want,(hex(pc),str(ins[pc]))
    x19writes=[{'pc':hex(i.address),'instruction':i.mnemonic+' '+i.op_str}for i in ins.values()if 0x8e81c8<=i.address<0x8fcfa0 and any(i.reg_name(r)in ['x19','w19']for r in i.regs_access()[1])]
    assert x19writes==[{'pc':'0x8e83ec','instruction':'sub x19, x8, #4'},{'pc':'0x8fc42c','instruction':'ldp x20, x19, [sp, #0x40]'}]
    imports=json.loads(read(ROOT/'corefp_import_calls.json'))['stubs']
    assert next(r for r in imports if r['address']=='0x15d1934')['pointer']['import']['name']=='_mig_get_reply_port'
    assert next(r for r in imports if r['address']=='0x15d18e4')['pointer']['import']['name']=='_mach_msg'
    m,n=z3.BitVecs('independent_handoff_marker independent_handoff_scalar',32)
    claims=[((z3.If(m==0xba1df9db,z3.BitVecVal(1,32),z3.BitVecVal(0,32))*(0x3de80^0x31db5))^0x7bd0)==z3.If(m==0xba1df9db,z3.BitVecVal(0xb8e5,32),z3.BitVecVal(0x7bd0,32)),
      (z3.BitVecVal(0xe28b,32)^z3.If(z3.ULT(n,2),z3.BitVecVal(28,32),z3.BitVecVal(0,32)))==z3.If(z3.UGE(n,2),z3.BitVecVal(0xe28b,32),z3.BitVecVal(0xe297,32))]
    for q,claim in zip(e['proofs'],claims):
        s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_string(q['query']));assert q['result']=='unsat'and s.check()==z3.unsat
        s=z3.Solver();s.set(timeout=30000);s.add(z3.Not(claim));assert s.check()==z3.unsat
    assert len(e['proofs'])==2
    return {'source_bytes_checked':sum(len(bytes.fromhex(r['bytes_hex']))for r in spans),'original_fixup_words_checked':len(D),
      'exact_source_instructions_checked':len(exact),'request_bank_cases_checked':256,'parent_X19_writers':x19writes,'retained_queries_unsat':2,'independent_queries_unsat':2}


def main():
    e=json.loads(read(ROOT/'fpsd1201_handoff_checks.json'));assert e['generator_sha256']==SHA((ROOT/'recover_fpsd1201_handoff.py').read_bytes())
    for name,h in e['dependencies'].items():assert SHA(read(ROOT/name).encode())==h
    old_raw=read(ROOT/'fpsd1201_export_checks.json');prior_raw=read(ROOT/'fpsd1201_export_audit.json')
    assert SHA(old_raw.encode())=='e69211620dde7b07114a314849f0f786852d8fb75c146e45bd8fa557293a906b'
    assert SHA(prior_raw.encode())=='d55c04ca84d34b0d6ae04f1d4e45a8eb72e4fdb43e0ab64e68d9a5465a9ab8da'
    old=json.loads(old_raw);prior=json.loads(prior_raw)
    assert prior['fresh_replay_completed']and prior['process_exit_code']==0 and prior['result']['all_checks_pass']
    assert prior['checks_sha256']==SHA(old_raw.encode())and prior['auditor_sha256']==SHA((ROOT/'audit_fpsd1201_export.py').read_bytes())
    expected=[{'prior_index':j,'scalar_u32':2,'root_override_u32':None}for j in range(18)]
    expected.extend({'prior_index':0,'scalar_u32':n,'root_override_u32':None}for n in [0,1,3,0x80000000,0xffffffff])
    expected.extend({'prior_index':0,'scalar_u32':2,'root_override_u32':n}for n in [0,0x45e2a205,0xba1df9da,0xffffffff])
    assert [p['configuration']for p in e['profiles']]==expected
    D={int(r['address'],16):r for r in json.loads(read(ROOT/'corefp_fixups_inventory.json'))['fixups']};src=source(e,D);total=Counter()
    for j,p in enumerate(e['profiles']):
        total.update(Replay(p,old['profiles'][p['configuration']['prior_index']],e['code_spans'],D).run())
        print(json.dumps({'profile':j,'terminal':p['terminal']['pc']}),flush=True)
    assert e['prefix_instructions_rerun']==0 and not any(e[k]for k in ['whole_parent_replayed','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    counts={'profiles':27,**{k:sum(len(p[k])for p in e['profiles'])for k in ['source_visits','source_reads','source_writes','PAC_models','CPU_points']},
      'builder_pre_import_stops':21,'scalar_skip_stops':2,'root_mismatch_stops':4,'original_pointer_rows':7,'local_queries_unsat':2}
    assert e['verified_counts']==counts
    result={'source':src,'fresh_replay':dict(total),'verified_counts':counts,'prefix_instructions_rerun':0,'explicit_parent_bindings_required':True,
      'whole_parent_replayed':False,'native_port_or_endpoint_identity_established':False,'native_target_executed':False,'full_goal_complete':False,'all_checks_pass':True}
    out={'result':result,'checks_sha256':SHA(read(ROOT/'fpsd1201_handoff_checks.json').encode()),'dependencies':e['dependencies'],
      'auditor_sha256':SHA(Path(__file__).read_bytes()),'fresh_replay_completed':True,'process_exit_code':0,'native_target_executed':False}
    (ROOT/'fpsd1201_handoff_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
