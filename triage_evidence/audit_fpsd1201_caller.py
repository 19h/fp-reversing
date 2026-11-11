#!/usr/bin/env python3
"""Independent source, private fragment and conditional frame audit.

Does not import the new producer. Rebuilds inputs, replays original bytes,
compares every retained CPU/read/write/RAM event and checks independent oracles.
O(B+F+C*(V+R)+256*K) time/space; SMT cost separate; no native effects.
"""
import base64,json,re,struct,zlib
from collections import Counter
from hashlib import sha256
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as A
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
import z3
from verify_daemon_reader_record_payloads_publication import read

ROOT=Path(__file__).resolve().parent
SHA=lambda b:sha256(b).hexdigest()
CS=Cs(CS_ARCH_ARM64,CS_MODE_ARM);CS.detail=True
T=0x1c81940;STACK=0x71000000;INPUT=0x72000000;OWNER=0x73000000;GLOBAL=0x74000000
RAM=[(STACK,65536),(INPUT,4096),(OWNER,8192),(GLOBAL,4096)]


def unpack(p):
    b=zlib.decompress(base64.b64decode(p['zlib_base64']));assert len(b)==p['size_bytes']and SHA(b)==p['sha256'];return b


class Replay:
    def __init__(self,p,att,D):
        self.p=p;self.c=p['configuration'];self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.D=D
        self.v=self.r=self.w=self.pac=0;self.pending=[];self.stats=Counter()
        for a,n in [(0x8e8000,0x15000),(0x18ac000,4096),(0x1ac1000,4096),
          (0x1cac000,4096),(0x1cf2000,4096),(0x1d03000,4096)]+RAM:self.u.mem_map(a,n)
        for row in att['spans']:
            if row['role']in ['parent','call_bank']:self.u.mem_write(int(row['start'],16),bytes.fromhex(row['bytes_hex']))
        for a in [0x1cac848,0x1cac960,0x1cf2d98,0x1cf2df8,0x1d03f08]:self.u.mem_write(a,int(D[a]['target'],16).to_bytes(8,'little'))
        for a,n in RAM:self.u.mem_write(a,b'\xa5'*n)
        c=self.c;sp=STACK+0x8000
        self.u.mem_write(INPUT,bytes((j+c['pattern_shift'])&255 for j in range(128)))
        self.u.mem_write(OWNER+0x168,c['scalar_u32'].to_bytes(4,'little'))
        self.u.mem_write(GLOBAL,struct.pack('<II',c['global_a_u32'],c['global_b_u32']))
        cells={0x258:(OWNER,8),0x4c0:(GLOBAL,8),0x4b8:(GLOBAL+4,8),0x3a8:(0x18ac270,8),
          0x3a0:(0x1ac1ac0,8),0x4e8:(c['destination_u32'],4),0x1b8:(OWNER+0x880,8),0x5c8:(0x1234567812345678,8)}
        for off,(value,n)in cells.items():self.u.mem_write(sp+off,value.to_bytes(n,'little'))
        for j in range(31):self.setreg(j,((j+1)*0x123456789abcdef)&((1<<64)-1))
        for j,value in {3:0xba1df9db,7:0x68001f0b,8:128,11:0x8b,12:0x3e5,13:INPUT,19:T,
          20:0x55e1,25:OWNER+0x900,26:c['global_x26_u64']}.items():self.setreg(j,value)
        self.u.reg_write(A.UC_ARM64_REG_SP,sp);self.u.reg_write(A.UC_ARM64_REG_PC,0x8f35cc)
        self.u.reg_write(A.UC_ARM64_REG_NZCV,0);self.u.reg_write(A.UC_ARM64_REG_CPACR_EL1,3<<20)
        for j in range(32):self.u.reg_write(A.UC_ARM64_REG_Q0+j,int.from_bytes(bytes([j])*16,'little'))
        self.frame(p['initial']);assert len(p['initial_RAM'])==len(RAM)
        for row,(a,n)in zip(p['initial_RAM'],RAM):assert row['address']==hex(a)and unpack(row['payload'])==self.ram(a,n)
        self.u.hook_add(uc.UC_HOOK_CODE,self.hook);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.readhook);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.writehook)
    def reg(self,j):return self.u.reg_read(getattr(A,'UC_ARM64_REG_X'+str(j)))
    def setreg(self,j,v):self.u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),v)
    def ram(self,a,n):return bytes(self.u.mem_read(a,n))
    def frame(self,f):
        assert f=={'pc':hex(self.u.reg_read(A.UC_ARM64_REG_PC)),'sp':hex(self.u.reg_read(A.UC_ARM64_REG_SP)),
          'registers31':[hex(self.reg(j))for j in range(31)],'NZCV':hex(self.u.reg_read(A.UC_ARM64_REG_NZCV)),
          'Q32':[hex(self.u.reg_read(A.UC_ARM64_REG_Q0+j))for j in range(32)]};self.stats['complete_CPU_frames_checked']+=1
    def flush(self):
        for e in self.pending:assert self.ram(int(e['address'],16),e['size_B']).hex()==e['after_hex']
        self.pending=[]
    def readhook(self,u,access,a,n,value,data):
        e={'visit':self.v-1,'address':hex(a),'size_B':n,'bytes_hex':self.ram(a,n).hex()};assert self.p['source_reads'][self.r]==e;self.r+=1
    def writehook(self,u,access,a,n,value,data):
        assert any(lo<=a<a+n<=lo+m for lo,m in RAM)
        e=self.p['source_writes'][self.w];self.w+=1
        assert {k:e[k]for k in ['visit','address','size_B','before_hex']}=={'visit':self.v-1,'address':hex(a),'size_B':n,'before_hex':self.ram(a,n).hex()};self.pending.append(e)
    def hook(self,u,pc,n,data):
        self.flush()
        if pc in [0x8f3838,0x8f389c]:self.frame(self.p['terminal']);self.done=True;u.emu_stop();return
        raw=self.ram(pc,4);i=next(CS.disasm(raw,pc))
        assert self.p['source_visits'][self.v]=={'pc':hex(pc),'bytes_hex':raw.hex(),'instruction':i.mnemonic+' '+i.op_str};self.v+=1
        if i.mnemonic=='braa':
            assert pc in [0x8f35f8,0x8f3658]
            e=self.p['PAC_models'][self.pac];self.pac+=1;self.frame(e['before'])
            target=self.reg(9 if pc==0x8f35f8 else 8);mod=self.reg(17);a=int(e['original_slot'],16);r=self.D[a]
            assert e['pc']==hex(pc)and e['target']==hex(target)and e['modifier']==hex(mod)
            assert int(r['target'],16)==target and int(r['diversity'],16)==mod and r['key']=='IA'and not r['address_diversity']
            assert int.from_bytes(self.ram(a,8),'little')==target
            u.reg_write(A.UC_ARM64_REG_PC,target)
    def run(self):
        self.u.emu_start(0x8f35cc,0,count=3000);self.flush();assert self.done
        assert self.v==len(self.p['source_visits'])and self.r==len(self.p['source_reads'])and self.w==len(self.p['source_writes'])and self.pac==len(self.p['PAC_models'])
        c=self.c;called=c['scalar_u32']>=2
        assert self.u.reg_read(A.UC_ARM64_REG_PC)==(0x8f3838 if called else 0x8f389c)
        assert self.reg(1)==c['scalar_u32']and self.u.reg_read(A.UC_ARM64_REG_SP)==STACK+0x8000
        if called:assert [self.reg(j)for j in [0,2,8,17]]==[c['destination_u32'],OWNER+0x880,0x8d40,0x8390]
        want=bytes(((j+c['pattern_shift'])&255)^0xba for j in range(128))
        assert self.ram(OWNER+0x900,128)==want and self.p['copied128_hex']==want.hex()
        assert self.ram(OWNER+0x880,128)==b'\xa5'*128
        for row,(a,n)in zip(self.p['final_RAM'],RAM):
            assert row['address']==hex(a)and unpack(row['payload'])==self.ram(a,n);self.stats['complete_final_RAM_bytes_checked']+=n
        assert len(self.p['final_RAM'])==len(RAM)and not self.p['native_effects']
        self.stats.update({'original_visits_checked':self.v,'original_reads_checked':self.r,'original_writes_checked':self.w,'PAC_models_checked':self.pac})
        return self.stats


def source_audit(att,e,D):
    spans=att['spans'];assert len(spans)==30 and sum(r['size_B']for r in spans)==89092
    assert att['input_sha256']=='68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f'
    assert not att['IDB_mutated']and not att['native_target_executed']
    for r in spans:
        b=bytes.fromhex(r['bytes_hex']);assert len(b)==r['size_B']and SHA(b)==r['sha256']
        if r['role']=='IDA_normalized_pointer':assert int.from_bytes(b,'little')==int(D[int(r['start'],16)]['target'],16)
    main=next(r for r in spans if r['role']=='parent');helper=next(r for r in spans if r['role']=='stack_helper')
    old=json.loads(read(ROOT/'corefp_client_paths_contracts.json'))['main_caller']
    assert all(main[k]==old[k]for k in ['start','sha256'])and main['size_B']==old['size_bytes']==85464
    assert main['sha256']=='4e0ebb4383ce0f3d074358e851dd1bdfff67e77d675e0cfa9e73b4a03ff9a94e'
    checks=att['code_and_bank_patch_checks'];assert len(checks)==6
    for c in checks:
        r=next(s for s in spans if s['start']==c['start']);assert c['current_equals_IDA_original_bytes']and c['original_sha256']==r['sha256']and c['size_B']==r['size_B']
    ins={i.address:i for i in CS.disasm(bytes.fromhex(main['bytes_hex']),int(main['start'],16))}
    assert len(ins)==21366
    h={i.address:i for i in CS.disasm(bytes.fromhex(helper['bytes_hex']),int(helper['start'],16))}
    def check(at,mn,ops):assert (ins.get(at)or h[at]).mnemonic==mn and (ins.get(at)or h[at]).op_str==ops
    exact={0x8e83e4:('add','w8, w11, w8, uxtb'),0x8e83e8:('ldr','x8, [x4, w8, uxtw #3]'),0x8e83ec:('sub','x19, x8, #4'),
      0x8e84c0:('adrp','x25, #0x1d09000'),0x8e84c4:('add','x25, x25, #0xf68'),0x8e84cc:('mov','w9, #0xa788'),
      0x8e84d0:('add','x9, x25, x9'),0x8e84d4:('ldr','x9, [x9]'),0x8e84d8:('str','x9, [sp, #0x3a8]'),
      0x8e84ec:('ldr','x10, [x25]'),0x8e84f0:('sub','x10, x10, #8'),0x8e84f4:('str','x10, [sp, #0x3a0]'),
      0x8ea07c:('add','x5, x21, #0x800'),0x8ea090:('str','wzr, [sp, #0x4e8]'),0x8ea09c:('mov','x20, x21'),
      0x8ea108:('add','x9, sp, #0x4e8'),0x8ea10c:('str','x9, [sp, #0x18]'),0x8ea14c:('blraa','x8, x17'),
      0x8ea1b4:('add','x10, x20, #0x880'),0x8ea1b8:('str','x10, [sp, #0x1b8]'),
      0x8ea1bc:('add','x10, x20, #0x900'),0x8ea1c0:('str','x10, [sp, #0x1a8]'),
      0x8f3430:('ldr','x25, [sp, #0x1a8]'),0x8f34d0:('ldr','x8, [sp, #0x1b8]'),0x8f34d4:('stp','x8, x9, [x29, #-0x98]'),
      0x8f35cc:('subs','x8, x8, #1'),0x8f35d0:('ldrb','w9, [x13, x8]'),0x8f35d4:('orn','w10, w11, w9, lsl #1'),
      0x8f35d8:('add','w9, w9, w10'),0x8f35dc:('sub','w9, w9, #0x45'),0x8f35e0:('strb','w9, [x25, x8]'),
      0x8f35e4:('cset','w9, ne'),0x8f35e8:('mul','w9, w9, w12'),0x8f35ec:('eor','w9, w9, w20'),
      0x8f35f0:('ldr','x9, [x19, w9, sxtw #3]'),0x8f35f4:('mov','x17, #0x3c7d'),0x8f35f8:('braa','x9, x17'),
      0x8f35fc:('mov','w8, #-0x53df'),0x8f3600:('add','w8, w20, w8'),0x8f3604:('mov','w9, #0xe089'),0x8f3608:('orr','w8, w8, w9'),
      0x8f3634:('ldr','x25, [sp, #0x258]'),0x8f3638:('ldr','w1, [x25, #0x168]'),0x8f363c:('cmp','w1, #2'),
      0x8f3640:('cset','w9, lo'),0x8f3644:('lsl','w10, w9, #5'),0x8f3648:('sub','w9, w10, w9, lsl #2'),0x8f364c:('eor','w8, w9, w8'),
      0x8f3650:('ldr','x8, [x19, w8, sxtw #3]'),0x8f3654:('mov','x17, #0x1347'),0x8f3658:('braa','x8, x17'),
      0x8f3810:('ldr','w0, [sp, #0x4e8]'),0x8f3824:('add','w8, w8, #0xa8'),0x8f3828:('ldr','x8, [x19, w8, uxtw #3]'),
      0x8f382c:('ldr','x2, [sp, #0x1b8]'),0x8f3834:('mov','x17, #0x8390'),0x8f3838:('blraa','x8, x17'),
      0x8f61c4:('str','w8, [sp, #0x1b8]'),0x981e48:('ldr','w8, [x20]'),0x981e4c:('sub','w8, w8, w21'),
      0x981e50:('ubfiz','x8, x8, #4, #0x10'),0x981e54:('str','x8, [x19]')}
    for at,(mn,ops)in exact.items():check(at,mn,ops)
    # Complete parent census includes prologue/epilogue writeback and all MOV SP sites.
    sp=[{'pc':hex(i.address),'instruction':i.mnemonic+' '+i.op_str}for i in ins.values()if any(i.reg_name(r)=='sp'for r in i.regs_access()[1])]
    assert e['source_census']['SP_writes']==sp and len(sp)==11
    stores=e['source_census']['direct_SP_stores_overlapping_selected_cells']
    assert [(r['pc'],r['size_B'])for r in stores if '0x1b8'in r['overlaps_cells']]==[('0x8ea1b8',8),('0x8f61c4',4)]
    assert [r['pc']for r in stores if '0x4e8'in r['overlaps_cells']]==['0x8ea090']
    for r in stores:assert ins[int(r['pc'],16)].mnemonic+' '+ins[int(r['pc'],16)].op_str==r['instruction']
    independent_stores=[]
    for i in ins.values():
        if not i.mnemonic.startswith('st'):continue
        m=re.search(r'\[sp(?:, #(-?0x[0-9a-f]+))?\]',i.op_str)
        if not m:continue
        off=int(m[1],16)if m[1]else 0;reg=i.op_str.split(',')[0]
        width={'q':16,'d':8,'x':8,'s':4,'w':4,'h':2,'b':1}[reg[0]]
        if i.mnemonic in ['strb','sturb']:width=1
        if i.mnemonic in ['strh','sturh']:width=2
        if i.mnemonic in ['stp','stnp']:width*=2
        cells=[hex(a)for a,n in [(0x1b8,8),(0x1a8,8),(0x1f0,8),(0x258,8),(0x3a0,16),(0x4e8,4)]if off<a+n and a<off+width]
        if cells:independent_stores.append({'pc':hex(i.address),'instruction':i.mnemonic+' '+i.op_str,'offset':off,'size_B':width,'overlaps_cells':cells})
    assert independent_stores==stores
    assert not e['source_census']['indexed_SP_stores_not_resolved']and not e['source_census']['alias_or_callee_stores_exhausted']and not e['source_census']['dynamic_SP_epochs_joined']
    # Original raw format12 words are independently decoded; IDA bytes above are normalized.
    for r in e['pointer_rows']:
        assert r==D[int(r['address'],16)]and r['pointer_format']==12 and not r['bind']
        word=int(r['word'],16);target=word&0xffffffff if word>>63 else(word&((1<<43)-1))|(((word>>43)&255)<<56)
        assert target==int(r['target'],16)
        if word>>63:assert (word>>32)&65535==int(r['diversity'],16)and (word>>48)&1==r['address_diversity']and (word>>49)&3==0 and r['key']=='IA'
    by={int(r['start'],16):bytes.fromhex(r['bytes_hex'])for r in spans if r['role']in ['init_bank','call_bank']}
    expected=[('parent_table',0x18ac070,0x1ac18c0,0x89,0x77),('request1201',0x18ac270,0x1ac1ac0,0xc8,0xc0),('stack_helper',0x18ac270,0x1ac1ac0,0xe7,0x1f)]
    for row,(label,a,b,k,value)in zip(e['banks'],expected):
        v=[j^by[b][by[a][j]^k]for j in range(256)];assert row=={'label':label,'left':hex(a),'right':hex(b),'key_u8':k,'constant_u8':value,'results256':v}and set(v)=={value}
    assert 0x1d05fa0+(0x14b2+0x77)*8==0x1d108e8 and int(D[0x1d108e8]['target'],16)-4==T
    assert int(D[0x1d146f0]['target'],16)==0x18ac270 and int(D[0x1d09f68]['target'],16)-8==0x1ac1ac0
    assert T+(0x10351+0xa8+0xc0)*8==0x1d03f08 and int(D[0x1d03f08]['target'],16)==0x8d40 and D[0x1d03f08]['diversity']=='0x8390'
    assert T+(0x10351+0x193+0x1f)*8==0x1d04158 and D[0x1d04158]['target']=='0x981c38'
    assert T+0x55e1*8==0x1cac848 and T+(0x55e1^0x3e5)*8==0x1cac960
    assert T+0xe28b*8==0x1cf2d98 and T+0xe297*8==0x1cf2df8
    # Reused modifier scan is an inventory, not fourteen proved call edges.
    candidates=[r for r in spans if r['role']=='modifier_candidate'];assert len(candidates)==14
    pcs=[int(r['modifier_pc'],16)for r in candidates];assert [p for p in pcs if 0x8e81c8<=p<0x8fcfa0]==[0x8f3834]
    assert [i.address for i in ins.values()if i.mnemonic=='mov'and i.op_str=='x17, #0x8390']==[0x8f3834]
    for r in candidates:
        at=int(r['start'],16);offset=int(r['modifier_pc'],16)-at;assert bytes.fromhex(r['bytes_hex'])[offset:offset+4]==bytes.fromhex('117290d2')
        if 0x8e81c8<=at<0x8fcfa0:assert bytes.fromhex(r['bytes_hex'])==bytes.fromhex(main['bytes_hex'])[at-0x8e81c8:at-0x8e81c8+r['size_B']]
    # Port output stack argument: builderFP = entrySP - 16, [FP+40] = entrySP+24.
    body=next(r for r in json.loads(read(ROOT/'corefp_mach_request_profiles.json'))['original_functions']if r['start']=='0x8ae0')
    bb=bytes.fromhex(body['bytes']);assert SHA(bb)==body['sha256']
    bi={i.address:i for i in CS.disasm(bb,0x8ae0)}
    for pc,mn,ops in [(0x8ae4,'sub','sp, sp, #0x130'),(0x8af8,'add','x29, sp, #0x120'),(0x8b04,'mov','x21, x5'),
      (0x8c98,'ldp','x10, x8, [x29, #0x20]'),(0x8ca0,'ldr','w13, [sp, #0x38]'),(0x8cf4,'str','w13, [x8]')]:assert (bi[pc].mnemonic,bi[pc].op_str)==(mn,ops)
    return {'exact_source_instructions_checked':len(exact)+6,'parent_instructions_scanned':len(ins),'SP_writes':len(sp),
      'original_pointer_words_decoded':len(e['pointer_rows']),'exhaustive_bank_inputs':768,'fresh_IDA_spans':len(spans),'fresh_IDA_bytes_including_overlap':89092}


def extra_proofs(e,att):
    for p in e['proofs']:
        s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_string(p['query']));assert str(s.check())==p['result']=='unsat'
    # Independent concrete source execution of the four-instruction delta suffix.
    h=next(r for r in att['spans']if r['role']=='stack_helper');code=bytes.fromhex(h['bytes_hex'])[0x981e48-0x981c38:0x981e58-0x981c38]
    u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.mem_map(0x981000,4096);u.mem_map(0x75000000,4096);u.mem_write(0x981e48,code)
    n=0
    for saved in [0,1,0xffffffff,0x1234567800000000]:
        for child in [0,1,65535,65536,0xffffffff]:
            u.mem_write(0x75000000,child.to_bytes(4,'little'));u.reg_write(A.UC_ARM64_REG_X20,0x75000000);u.reg_write(A.UC_ARM64_REG_X19,0x75000008);u.reg_write(A.UC_ARM64_REG_X21,saved)
            u.emu_start(0x981e48,0x981e58)
            assert int.from_bytes(bytes(u.mem_read(0x75000008,8)),'little')==((child-saved)&65535)*16;n+=1
    # Independent full-domain counterexamples, rather than only replaying retained queries.
    v=z3.BitVec('independent_byte',8);a=z3.ZeroExt(24,v)
    s=z3.Solver();s.add(z3.Extract(7,0,a+(z3.BitVecVal(0x8b,32)|~(a<<1))-0x45)!=(v^186));assert s.check()==z3.unsat
    v=z3.BitVec('independent_scalar',32);idx=z3.BitVecVal(((0x55e1-0x53df)|0xe089),32)^z3.If(z3.ULT(v,2),z3.BitVecVal(28,32),z3.BitVecVal(0,32))
    s=z3.Solver();s.add((idx==0xe28b)!=z3.UGE(v,2));assert s.check()==z3.unsat
    return {'retained_queries_unsat':3,'independent_local_queries_unsat':2,'original_delta_suffix_cases':n,'original_delta_suffix_instructions':n*4}


def main():
    e=json.loads(read(ROOT/'fpsd1201_caller_checks.json'));att=json.loads(read(ROOT/'fpsd1201_caller_ida_readback.json'))
    assert e['generator_sha256']==SHA((ROOT/'recover_fpsd1201_caller.py').read_bytes())
    assert e['IDA_readback_sha256']==SHA(read(ROOT/'fpsd1201_caller_ida_readback.json').encode())
    for name,value in e['dependencies'].items():assert SHA(read(ROOT/name).encode())==value
    D={int(r['address'],16):r for r in json.loads(read(ROOT/'corefp_fixups_inventory.json'))['fixups']}
    source=source_audit(att,e,D);proof=extra_proofs(e,att);totals=Counter()
    assert [(p['configuration']['pattern_shift'],p['configuration']['scalar_u32'])for p in e['profiles']]==[(shift,scalar)for shift in [0,128]for scalar in [0,1,2,3,0x80000000,0xffffffff]]
    for p in e['profiles']:totals.update(Replay(p,att,D).run())
    assert e['entry_is_declared_fragment_not_whole_parent']and not any(e[k]for k in ['zero_delta_between_requests_established','native_port_identity_established','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    result={'source':source,'fresh_fragment_replay':dict(totals),'proofs':proof,'profiles':len(e['profiles']),
      'whole_parent_replayed':False,'zero_delta_or_native_endpoint_identity_established':False,'native_target_executed':False,'full_goal_complete':False,'all_checks_pass':True}
    receipt={'result':result,'dependencies':e['dependencies'],'checks_sha256':SHA(read(ROOT/'fpsd1201_caller_checks.json').encode()),
      'IDA_readback_sha256':e['IDA_readback_sha256'],'auditor_sha256':SHA(Path(__file__).read_bytes()),
      'fresh_replay_completed':True,'process_exit_code':0,'native_target_executed':False}
    (ROOT/'fpsd1201_caller_audit.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(result))


if __name__=='__main__':main()
