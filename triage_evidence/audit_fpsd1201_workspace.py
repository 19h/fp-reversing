#!/usr/bin/env python3
"""Independent context-producer/gate replay, exact fields and cross-image prefix.

Never imports the new producer. Original bytes, all events, complete CPU/RAM,
explicit gap controls, record fields and sealed daemon witnesses are checked.
O(I+B+F+C*(V+J+R)) time/space; SMT separate; no target/API execution.
"""
import base64,gc,json,struct,zlib
from pathlib import Path
from hashlib import sha256
from collections import Counter
import unicorn as uc
from unicorn import arm64_const as A
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
import z3
from audit_fpsd1201_caller import Replay as Frozen,unpack
from verify_daemon_reader_record_payloads_publication import read

ROOT=Path(__file__).resolve().parent;SHA=lambda b:sha256(b).hexdigest()
CS=Cs(CS_ARCH_ARM64,CS_MODE_ARM);CS.detail=True
SP=0x71008000;FP=0x7100c000;P=0x73000000;T=0x1c81940;G=0x1d43500
RAM=[(0x71000000,65536),(P,16384),(0x1d33000,69632)]


class Replay(Frozen):
    def __init__(self,p,parent,D,prior=None):
        self.p=p;self.c=p['configuration'];self.D=D;self.phase=self.c['kind'];self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM)
        self.v=self.r=self.w=self.pac=0;self.pending=[];self.stats=Counter()
        for a,n in [(0x8e8000,86016),(0x1c80000,655360)]+RAM:self.u.mem_map(a,n)
        self.u.mem_write(int(parent['start'],16),bytes.fromhex(parent['bytes_hex']))
        for a,r in D.items():
            if 0x1c80000<=a<a+8<=0x1d20000 and not r['bind']:self.u.mem_write(a,int(r['target'],16).to_bytes(8,'little'))
        for a,n in RAM:self.u.mem_write(a,b'\xa5'*n)
        for j in range(31):self.setreg(j,((j+1)*0x13579bdf02468ace)&((1<<64)-1))
        c=self.c
        for j,v in {19:T,20:P,12:(c['phase_u32']-0x8094)&0xffffffff,16:c['cursor_u64'],29:FP}.items():self.setreg(j,v)
        self.u.reg_write(A.UC_ARM64_REG_SP,SP);self.u.reg_write(A.UC_ARM64_REG_NZCV,0);self.u.reg_write(A.UC_ARM64_REG_CPACR_EL1,3<<20)
        for j in range(32):self.u.reg_write(A.UC_ARM64_REG_Q0+j,int.from_bytes(bytes([j])*16,'little'))
        controls=[]
        if prior is not None:
            assert c['phase_u32']==0xc1f7 and prior['configuration']=={'kind':'constructor','phase_u32':0xc1f7,'cursor_u64':c['cursor_u64']}
            for row,(a,n)in zip(prior['final_RAM'],RAM):assert row['address']==hex(a);self.u.mem_write(a,unpack(row['payload']))
            f=prior['terminal']
            for j,v in enumerate(f['registers31']):self.setreg(j,int(v,16))
            for name,key in [('SP','sp'),('PC','pc'),('NZCV','NZCV')]:self.u.reg_write(getattr(A,'UC_ARM64_REG_'+name),int(f[key],16))
            for j,v in enumerate(f['Q32']):self.u.reg_write(A.UC_ARM64_REG_Q0+j,int(v,16))
            r=p['restored_constructor'];assert r['CPU']==f;self.frame(r['CPU']);self.checkram(r['RAM'],'restored_constructor_RAM_bytes_checked')
            controls.append({'register':'X23','before':hex(self.reg(23)),'after':'0xc1f7','reason':'declared_control_after_unexecuted_gap'});self.setreg(23,0xc1f7)
            def patch(a,raw,why):
                controls.append({'address':hex(a),'before_hex':self.ram(a,len(raw)).hex(),'after_hex':raw.hex(),'reason':why});self.u.mem_write(a,raw)
            patch(SP+2148,c['status_u32'].to_bytes(4,'little'),'declared_pre_helper_status')
            patch(SP+920,G.to_bytes(8,'little'),'declared_cursor_seed_pointer');patch(G,bytes.fromhex('f0debc9a78563412'),'declared_cursor_seed')
        else:assert p['restored_constructor']is None
        assert p['gap_controls']==controls
        self.entry=0x8ea19c if self.phase=='constructor'else 0x8f33dc
        self.u.reg_write(A.UC_ARM64_REG_PC,self.entry);self.frame(p['initial']);self.checkram(p['initial_RAM'],'initial_RAM_bytes_checked')
        self.u.hook_add(uc.UC_HOOK_CODE,self.hook);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.readhook);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.writehook)
    def checkram(self,rows,label):
        assert len(rows)==3
        for row,(a,n)in zip(rows,RAM):assert row['address']==hex(a)and unpack(row['payload'])==self.ram(a,n);self.stats[label]+=n
    def readhook(self,u,ac,a,n,v,d):
        e={'phase':self.phase,'visit':self.v-1,'address':hex(a),'size_B':n,'bytes_hex':self.ram(a,n).hex()};assert self.p['source_reads'][self.r]==e;self.r+=1
    def writehook(self,u,ac,a,n,v,d):
        assert any(lo<=a<a+n<=lo+m for lo,m in RAM)
        e=self.p['source_writes'][self.w];self.w+=1
        assert {k:e[k]for k in ['phase','visit','address','size_B','before_hex']}=={'phase':self.phase,'visit':self.v-1,'address':hex(a),'size_B':n,'before_hex':self.ram(a,n).hex()};self.pending.append(e)
    def hook(self,u,pc,n,d):
        self.flush()
        if pc in ([0x8ea48c,0x8ed4c0]if self.phase=='constructor'else[0x8f34f8,0x8f3664]):self.frame(self.p['terminal']);self.done=True;u.emu_stop();return
        raw=self.ram(pc,4);i=next(CS.disasm(raw,pc));assert self.p['source_visits'][self.v]=={'phase':self.phase,'pc':hex(pc),'bytes_hex':raw.hex(),'instruction':i.mnemonic+' '+i.op_str};self.v+=1
        if i.mnemonic=='braa':
            e=self.p['PAC_models'][self.pac];self.pac+=1;self.frame(e['before']);a=int(e['original_slot'],16);r=self.D[a]
            rn={0x8ea24c:12,0x8f33f0:8,0x8f3444:8}[pc];target=self.reg(rn);mod=self.reg(17)
            assert e['pc']==hex(pc)and e['kind']=='braa'and e['target']==hex(target)and e['modifier']==hex(mod)
            assert r['key']=='IA'and not r['address_diversity']and int(r['target'],16)==target and int(r['diversity'],16)==mod and self.ram(a,8)==target.to_bytes(8,'little')
            u.reg_write(A.UC_ARM64_REG_PC,target)
    def run(self):
        self.u.emu_start(self.entry,0,count=1000);self.flush();assert self.done
        assert [self.v,self.r,self.w,self.pac]==[len(self.p[k])for k in ['source_visits','source_reads','source_writes','PAC_models']]
        c=self.c;C=SP+2464+c['cursor_u64'];assert self.p['context_pointer']==hex(C)
        assert self.ram(C,128)==bytes.fromhex('006664706300000001')+b'\xa5'*119 and self.p['context128_hex']==self.ram(C,128).hex()
        for off,value in {440:P+2176,424:P+2304,464:C+128,496:C,2112:C+1776,2104:C+9,1976:C+9}.items():assert self.ram(SP+off,8)==value.to_bytes(8,'little')
        delta=1872 if c['phase_u32']==0xc1f7 else 17081
        assert int.from_bytes(self.ram(SP+1480,8),'little')==c['cursor_u64']+delta
        assert self.p['cursor_after_u64']==hex(c['cursor_u64']+delta)
        if c['kind']=='constructor':
            assert self.p['terminal']['pc']==('0x8ea48c'if c['phase_u32']==0xc1f7 else'0x8ed4c0')
            ws=[w for w in self.p['source_writes']if C<=int(w['address'],16)<C+128]
            assert [(w['address'],w['size_B'],w['after_hex'])for w in ws]==[(hex(C),8,'0066647063000000'),(hex(C+8),1,'01')]
            self.stats['source_prefix_store_bytes_checked']+=9;self.stats['context_pointer_producers_checked']+=1
        else:
            yes=c['status_u32']==0xba1df9db;assert self.p['terminal']['pc']==('0x8f34f8'if yes else'0x8f3664')
            assert len(self.p['gap_controls'])==4
            if yes:
                R=FP-184;h=((((2*(R&0x55860eb0)-R+0x2a79f14c)&0xffffffff)^0x84f565d4)*0x9e8a2055)&0xffffffff
                b=bytearray(b'\xa5'*80)
                for off,value in {0:0,16:SP+1476,24:C+656,32:P+2176,40:C+928,56:C,64:0}.items():struct.pack_into('<Q',b,off,value)
                struct.pack_into('<I',b,8,h^0x5a617ac0);struct.pack_into('<I',b,72,(h+0x9265)&0xffffffff)
                assert self.ram(R,80)==b and self.ram(SP+1476,4)==(128).to_bytes(4,'little')and self.ram(SP+2424,8)==bytes.fromhex('f0debc9a78563412')
                assert [self.reg(j)for j in [12,20,21,22,23,25]]==[C,0x55e1,0x5ba0,0x7bd0,0x3de80,P+2304]
                self.stats['complete_record_stagings_checked']+=1;self.stats['record_bytes_checked']+=80
            else:assert self.ram(FP-184,80)==b'\xa5'*80
        assert self.p['record80_hex']==self.ram(FP-184,80).hex();self.checkram(self.p['final_RAM'],'final_RAM_bytes_checked')
        for row in self.p['used_original_pointer_rows']:assert row==self.D[int(row['address'],16)]
        assert not self.p['intervening_parent_gap_executed']and not self.p['native_effects']
        self.stats.update({'original_visits_checked':self.v,'original_reads_checked':self.r,'original_writes_checked':self.w,'PAC_models_checked':self.pac,'context_prefix_preservation_profiles_checked':1})
        return self.stats


def source(e,D):
    raw=(ROOT.parent/'CoreFP').read_bytes();assert SHA(raw)=='68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f'
    fat=[struct.unpack_from('>5I',raw,8+20*j)for j in range(struct.unpack_from('>I',raw,4)[0])]
    _,_,off,n,_=next(s for s in fat if s[:2]==(0x100000c,0x80000002));thin=raw[off:off+n];assert SHA(thin)=='8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c'
    pos=32;segments=[]
    for _ in range(struct.unpack_from('<I',thin,16)[0]):
        cmd,n=struct.unpack_from('<II',thin,pos)
        if cmd==0x19:_,vm,vs,fo,fs=struct.unpack_from('<16s4Q',thin,pos+8);segments.append((vm,fo,fs))
        pos+=n
    def get(a,n):
        vm,fo,fs=next(s for s in segments if s[0]<=a<a+n<=s[0]+s[2]);return thin[fo+a-vm:fo+a-vm+n]
    p=e['parent_source'];assert p==next(r for r in json.loads(read(ROOT/'fpsd1201_caller_ida_readback.json'))['spans']if r['role']=='parent')
    b=bytes.fromhex(p['bytes_hex']);assert len(b)==85464 and SHA(b)==p['sha256']=='4e0ebb4383ce0f3d074358e851dd1bdfff67e77d675e0cfa9e73b4a03ff9a94e'and get(0x8e81c8,len(b))==b
    for a,r in D.items():assert get(a,8)==int(r['word'],16).to_bytes(8,'little')
    ins={i.address:i for i in CS.disasm(b,0x8e81c8)}
    exact={0x8ea178:('ldr','x16, [sp, #0x5c8]'),0x8ea1b8:('str','x10, [sp, #0x1b8]'),0x8ea1c0:('str','x10, [sp, #0x1a8]'),
      0x8ea1dc:('add','x10, sp, #0x9a0'),0x8ea1e0:('add','x13, x10, x16'),0x8ea1e8:('str','x10, [sp, #0x1d0]'),
      0x8ea1f8:('str','x10, [x13]'),0x8ea200:('strb','w10, [x13, #8]'),0x8ea208:('str','x13, [sp, #0x1f0]'),0x8ea210:('str','x10, [sp, #0x840]'),
      0x8ea220:('str','x10, [sp, #0x5c8]'),0x8ea24c:('braa','x12, x17'),0x8f33e4:('ldr','w9, [sp, #0x864]'),
      0x8f33f8:('eor','w22, w23, w8'),0x8f3410:('cmp','w9, w8'),0x8f3430:('ldr','x25, [sp, #0x1a8]'),0x8f343c:('ldr','x12, [sp, #0x1f0]'),
      0x8f4ce8:('str','x8, [sp, #0x230]'),0x8f4cec:('and','x9, x8, #0xff'),0x8f4cf0:('str','x9, [sp, #0x1f0]')}
    for pc,want in exact.items():assert(ins[pc].mnemonic,ins[pc].op_str)==want
    stores=[]
    for i in ins.values():
        if i.mnemonic not in ['str','stur']:continue
        if any(o.type==3 and i.reg_name(o.mem.base)=='sp'and not o.mem.index and o.mem.disp==0x1f0 for o in i.operands):stores.append(hex(i.address))
    assert stores==['0x8ea208','0x8f4cf0']
    s,sp,o,j,k=z3.BitVecs('audit_cursor audit_sp audit_owner audit_j audit_k',64);m=z3.BitVec('audit_saved_status',32)
    claims=[s+z3.BitVecVal(0xc516-0xbdc6,64)==s+1872,(sp+2464+s+128)-(sp+2464+s)==128,
      (sp+2464+s+1776)-(sp+2464+s)==1776,
      ((z3.If(m==0xba1df9db,z3.BitVecVal(1,32),z3.BitVecVal(0,32))*0xfe33)^0x7bd0)==z3.If(m==0xba1df9db,z3.BitVecVal(0x85e3,32),z3.BitVecVal(0x7bd0,32)),
      z3.Implies(z3.And(z3.ULT(j,128),z3.ULT(k,128)),o+2176+j!=o+2304+k),z3.ULE(s&255,255)]
    assert len(e['proofs'])==len(claims)==6
    for proof,claim in zip(e['proofs'],claims):
        q=z3.Solver();q.set(timeout=30000);q.add(z3.parse_smt2_string(proof['query']));assert proof['result']=='unsat'and q.check()==z3.unsat
        q=z3.Solver();q.set(timeout=30000);q.add(z3.Not(claim));assert q.check()==z3.unsat
    q=z3.Solver();q.add(z3.parse_smt2_string(e['wrap_countermodel']['query']));assert q.check()==z3.sat
    x=int(e['wrap_countermodel']['example_cursor_u64'],16);assert((x+1872)&((1<<64)-1))<x
    return {'original_parent_bytes_checked':len(b),'original_fixup_words_checked':len(D),'exact_source_instructions_checked':len(exact),
      'direct_SP_1f0_store_sites':stores,'retained_queries_unsat':6,'independent_queries_unsat':6,'wrap_countermodel_checked':True}


def server(e):
    checks_raw=read(ROOT/'fpsd1200_certificate_checks.json');receipt_raw=read(ROOT/'fpsd1200_certificate_audit.json')
    assert SHA(checks_raw.encode())=='33c9de98eda8d6ef4f3ff2fed8190f6cd3aa3567ca43e35d82d0ab63fb7d866d'
    assert SHA(receipt_raw.encode())=='87faaa02a47c02f6312291945eba4838c5f35101fb96e1fb2e85fdaf56017b7d'
    old=json.loads(checks_raw);a=json.loads(receipt_raw);assert a['checks_sha256']==SHA(checks_raw.encode())and a['fresh_replay_completed']and a['process_exit_code']==0
    assert old['generator_sha256']==SHA((ROOT/'recover_fpsd1200_certificate.py').read_bytes())and a['auditor_sha256']==SHA((ROOT/'audit_fpsd1200_certificate.py').read_bytes())
    assert old['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert a['result']['full_Montgomery_outputs_checked']==251 and a['result']['public_signature_relations']==2
    assert len(e['server_witnesses'])==2;prefixes=[]
    for w,j in zip(e['server_witnesses'],[1,2]):
        packed=old['profiles'][j];raw=zlib.decompress(base64.b64decode(packed['payload_zlib_base64']));r=json.loads(raw)
        assert w['prior_profile_index']==j and w['label']==packed['label']and w['decoded_payload_size_B']==len(raw)and w['decoded_payload_sha256']==SHA(raw)
        calls=r['montgomery_calls'];assert len(calls)==94 and w['call_index']==73 and w['call']==calls[73]
        c=calls[73];assert c['kind']=='product'and c['entry_pc']=='0x10094593c'and c['entry_checkpoint']['pc']==c['entry_pc']
        v=c['entry']['right'];hdr=bytes.fromhex(v['header16_hex']);count=(int.from_bytes(hdr[4:8],'little')-0x693be708)&0xffffffff;assert count==32 and int.from_bytes(hdr[:4],'little')>=count
        active=bytes.fromhex(v['active_limbs_hex']);assert len(active)==128 and v['header_known_mask_hex']=='01'*16 and v['active_known_mask_hex']=='01'*128
        b=b''.join((int.from_bytes(active[k:k+4],'little')^0xada56e3c).to_bytes(4,'big')for k in range(124,-1,-4))
        assert b.hex()==w['representative128_hex']and b[:9].hex()==w['prefix9_hex']=='006664706300000001';prefixes.append(b[:9])
        del r,raw;gc.collect()
    assert prefixes[0]==prefixes[1]
    return {'sealed_predecessor_profiles_checked':2,'representative_bytes_checked':256,'shared_prefix_bytes_per_witness':9,
      'daemon_checks_sha256':SHA(checks_raw.encode()),'daemon_audit_sha256':SHA(receipt_raw.encode()),'daemon_prefix_instructions_rerun':0}


def main():
    e=json.loads(read(ROOT/'fpsd1201_workspace_checks.json'));assert e['generator_sha256']==SHA((ROOT/'recover_fpsd1201_workspace.py').read_bytes())
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    expected=[{'kind':'constructor','phase_u32':p,'cursor_u64':c}for p in [0xc1f7,0xfd60]for c in [0,16,32,256,4096]]
    expected.extend({'kind':'pre_helper_gate','phase_u32':0xc1f7,'cursor_u64':c,'constructor_profile_index':j,'status_u32':s}for j,c in enumerate([0,16,32,256,4096])for s in [0,0xba1df9db,0x45e2a205,0xba1df9da,0xffffffff])
    assert [p['configuration']for p in e['profiles']]==expected
    D={int(r['address'],16):r for r in json.loads(read(ROOT/'corefp_fixups_inventory.json'))['fixups']};src=source(e,D);total=Counter()
    for p in e['profiles']:
        c=p['configuration'];prior=e['profiles'][c['constructor_profile_index']]if c['kind']=='pre_helper_gate'else None
        total.update(Replay(p,e['parent_source'],D,prior).run())
    counts={'profiles':35,'constructor_profiles':10,'pre_helper_gate_profiles':25,'record_staging_stops':5,
      **{k:sum(len(p[k])for p in e['profiles'])for k in ['source_visits','source_reads','source_writes','PAC_models']},'local_queries_unsat':6,'local_wrap_control_sat':1,'server_witnesses':2}
    assert e['verified_counts']==counts;witness=server(e)
    assert not any(e[k]for k in ['whole_parent_replayed','new_IDA_access','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    result={'source':src,'fresh_replay':dict(total),'sealed_daemon_witnesses':witness,'verified_counts':counts,'intervening_parent_gap_executed':False,
      'native_pairing_or_field_semantics_established':False,'native_target_executed':False,'full_goal_complete':False,'all_checks_pass':True}
    a={'result':result,'checks_sha256':SHA(read(ROOT/'fpsd1201_workspace_checks.json').encode()),'dependencies':e['dependencies'],
      'auditor_sha256':SHA(Path(__file__).read_bytes()),'fresh_replay_completed':True,'process_exit_code':0,'native_target_executed':False}
    (ROOT/'fpsd1201_workspace_audit.json').write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
