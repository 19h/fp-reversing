#!/usr/bin/env python3
"""Independent replay of identity-policy evidence, including original libbsm.

Uses the frozen admission event replay, never the identity producer. Additional
library transfer, once callback, cache context and boundary handling are local.
O(C*(B+F+K)+R+256N) time; O(B+F+R) transient space, solver cost separate.
"""
import json,struct,subprocess
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as A
import z3
from audit_fpsd1200_admission import Replay as Parent,SHA,PRIVATE
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,verify_original_fixups,qword,TABLE
from daemon_import_bindings import binding
from bootpolicy_cache_reader import Cache,Dylib
from verify_daemon_reader_record_payloads_publication import read

SLOT=0x1010a0500;STACK=0x70000000;HALT=0x6001000000


class Replay(Parent):
    def __init__(self,row,library):
        super().__init__(row);self.library=library;f=library['function'];self.lo=int(f['start'],16);self.hi=int(f['end'],16)
        self.u.mem_map(self.lo&~4095,4096,uc.UC_PROT_READ|uc.UC_PROT_EXEC);self.u.mem_write(self.lo,bytes.fromhex(f['bytes']))
        self.u.mem_write(SLOT,struct.pack('<Q',self.lo));self.li=0;self.pending_library=None
        self.xi=0;self.xpoints={int(p['pc'],16)for p in row['identity_points']};self.pri=0;self.cri=0;self.wi=0
        self.once=None;self.callback_count=0
        if row['provider_snapshot']is not None:
            self.u.mem_write(PRIVATE+0x9000,bytes.fromhex(row['provider_snapshot']['published_buffer512_hex']))
            self.u.mem_write(0x1010c8268,struct.pack('<Q',PRIVATE+0x9000));self.u.mem_write(0x1010c67d4,struct.pack('<I',255))

    def read_hook(self,u,access,a,n,v,data):
        if PRIVATE+0x9000<=a<a+n<=PRIVATE+0x9200:
            actual={'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'offset_B':a-PRIVATE-0x9000,
              'width_B':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()}
            assert actual==self.row['provider_reads'][self.pri];self.pri+=1
        if a in [0x1010c8268,0x1010c67d4]:
            actual={'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'address':hex(a),'width_B':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()}
            assert actual==self.row['cache_context_reads'][self.cri];self.cri+=1
        assert not STACK+0x6000<=a<STACK+0x6000+756
        return super().read_hook(u,access,a,n,v,data)

    def write_hook(self,u,access,a,n,v,data):
        if 0x100000000<=a<0x102000000:
            actual={'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'address':hex(a),'size':n,'value':hex(v&((1<<(8*n))-1))}
            assert actual==self.row['image_writes'][self.wi];self.wi+=1

    def hook(self,u,pc,n,data):
        if self.pending_library is not None and pc==self.pending_library['return_pc']:
            p=self.pending_library
            assert bytes(u.mem_read(p['pid_output'],4)).hex()==p['output32_after']
            assert [hex(self.reg(j))for j in range(29)]==p['registers_after']
            assert p['output32_after']==bytes.fromhex(p['token32'])[20:24].hex()
            self.pending_library=None;self.li+=1
        if pc in self.xpoints:
            p=self.row['identity_points'][self.xi];self.xi+=1;assert p['pc']==hex(pc)
            assert p['sp']==hex(u.reg_read(A.UC_ARM64_REG_SP))
            if 'registers31'in p:
                assert p['registers31']==[hex(self.reg(j))for j in range(31)]and p['nzcv']==hex(u.reg_read(A.UC_ARM64_REG_NZCV))
            else:assert p['registers']==[hex(self.reg(j))for j in range(29)]
            if 'record24'in p:
                a=int(p['record_address'],16);assert a==u.reg_read(A.UC_ARM64_REG_X29)-0xa8
                assert bytes(u.mem_read(a,24)).hex()==p['record24']
                dst=struct.unpack('<Q',u.mem_read(a,8))[0];assert hex(dst)==p['destination']and bytes(u.mem_read(dst,256)).hex()==p['destination256']
            if 'caller256'in p:
                assert bytes(u.mem_read(int(p['caller_destination'],16),256)).hex()==p['caller256']
                assert bytes(u.mem_read(self.reg(0),32)).hex()==p['input_record32']
        if self.row['stop_reason']=='unmapped_environment_read_guard'and pc==int(self.row['last_pc'],16):
            if pc==0x100625eac:a=self.reg(17)
            elif pc==0x1003c3254:a=self.reg(10)
            else:
                assert pc==0x10058e484;off=self.reg(16)&0xffffffff;off=off-(1<<32)if off>>31 else off;a=(self.reg(13)+off)&((1<<64)-1)
            assert a==0 and self.index==len(self.row['visited']);self.finished=True;u.emu_stop();return
        if pc==HALT+0x100:
            assert self.once is not None;p=self.once
            assert u.reg_read(A.UC_ARM64_REG_SP)==p['sp']-256 and [self.reg(j)for j in range(19,30)]==p['saved19_29']
            u.reg_write(A.UC_ARM64_REG_SP,p['sp']);self.setreg(30,p['return_pc']);self.setreg(0,0)
            u.reg_write(A.UC_ARM64_REG_PC,p['return_pc']);self.once=None;self.callback_count+=1;return
        if self.lo<=pc<self.hi:
            assert self.row['visited'][self.index]==hex(pc);self.index+=1
            raw=bytes(u.mem_read(pc,4));off=pc-self.lo;assert raw==bytes.fromhex(self.library['function']['bytes'])[off:off+4]
            if pc==self.lo:
                p=self.row['library_calls'][self.li];assert self.pending_library is None
                assert p['site']==hex(self.reg(30)-4)and p['return_pc']==self.reg(30)and p['pid_output']==self.reg(6)
                assert p['token32']==bytes(u.mem_read(self.reg(0),32)).hex()and p['output32_before']==bytes(u.mem_read(self.reg(6),4)).hex()
                assert p['registers_before']==[hex(self.reg(j))for j in range(29)]and p['sp']==hex(u.reg_read(A.UC_ARM64_REG_SP))
                assert p['stack_argument0']==bytes(u.mem_read(u.reg_read(A.UC_ARM64_REG_SP),8)).hex()=='00'*8
                self.pending_library=p
            ins=next(CS.disasm(raw,pc))
            if ins.mnemonic in ['pacibsp','paciasp','autibsp','autiasp','bti']:u.reg_write(A.UC_ARM64_REG_PC,pc+4)
            elif ins.mnemonic in ['retab','retaa']:u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
            else:assert not ins.mnemonic.startswith(('pac','aut','xpac'))and ins.mnemonic not in ['svc','hvc','smc','brk']
            return
        if pc in self.imports:
            e=self.import_events[self.ei]
            if 'logical_key'in e:
                a=self.reg(1);ptr=qword(a+16);key=IMAGE.read(ptr,qword(a+24)+1)
                assert key[-1]==0 and key[:-1].decode()==e['logical_key']
            if e.get('callback_invoked'):
                assert e['name']==self.imports[pc]=='libSystem/_pthread_once'and e['site']==hex(self.reg(30)-4)
                assert e['args']==[hex(self.reg(j))for j in range(8)]and e['result']=='0x0';self.ei+=1
                assert self.reg(0)==0x1010b8cd0 and self.reg(1)==0x10040ebd4 and self.once is None
                self.once={'sp':u.reg_read(A.UC_ARM64_REG_SP),'return_pc':self.reg(30),'saved19_29':[self.reg(j)for j in range(19,30)]}
                u.reg_write(A.UC_ARM64_REG_SP,self.once['sp']-256);self.setreg(30,HALT+0x100);u.reg_write(A.UC_ARM64_REG_PC,0x10040ebd4);return
        if 0x100000000<=pc<0x100e2c000:
            i=next(CS.disasm(IMAGE.read(pc,4),pc))
            if i.mnemonic=='paciza':
                assert self.row['visited'][self.index]==hex(pc)and bytes(u.mem_read(pc,4))==IMAGE.read(pc,4);self.index+=1
                u.reg_write(A.UC_ARM64_REG_PC,pc+4);return
        return super().hook(u,pc,n,data)

    def verify(self):
        out=super().run_replay()
        assert self.li==len(self.row['library_calls'])and self.pending_library is None
        assert self.xi==len(self.row['identity_points'])and self.pri==len(self.row['provider_reads'])and self.cri==len(self.row['cache_context_reads'])
        assert self.wi==len(self.row['image_writes'])and self.callback_count==len(self.row['callback_models'])and self.once is None
        for p in self.row['final_image_writes']:assert bytes(self.u.mem_read(int(p['address'],16),p['width_B'])).hex()==p['bytes_hex']
        return out


def audit():
    e=json.loads(read(ROOT/'fpsd1200_identity_checks.json'))
    assert SHA(SOURCE.read_bytes())==e['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert SHA((ROOT/'recover_fpsd1200_identity.py').read_bytes())==e['generator_sha256']
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h,n
    c=Cache();d=Dylib(c,e['library']['logical_name']);f=d.function(d.exports[e['library']['export']]['address'])
    assert (c.uuid,d.uuid,f)==(e['library']['cache_uuid'],e['library']['library_uuid'],e['library']['function'])
    assert f['sha256']=='76ed6c9a5a2b1b51e22d1fd36ca9802e734187970d71868438eb981b52e613e5'
    ins={}
    for r in e['spans']:
        a,z=int(r['start'],16),int(r['end'],16);b=IMAGE.read(a,z-a)
        assert SHA(b)==r['sha256']and b.hex()==r['bytes_hex']
        actual=[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a)]
        assert actual==r['instructions'];ins.update({int(i['ea'],16):i for i in actual})
    for a,m,o in [(0x100581fbc,'stp','x10, x21, [x29, #-0xa8]'),(0x100582090,'ldur','w8, [x29, #-0x94]'),
      (0x10058209c,'cmp','w8, w9'),(0x1005820a4,'eor','w9, w22, w16'),(0x1005820b4,'eor','w8, w8, w25'),
      (0x1003c3240,'and','w10, w13, w10'),(0x1003c324c,'and','x10, x10, #0xfffffffffffffff8'),
      (0x100625e8c,'and','w17, w24, #0xfffffff8'),(0x100625ea4,'and','x17, x17, x11'),
      (0x10058e480,'and','w16, w16, w14'),(0x10058e484,'ldr','x16, [x13, w16, sxtw]')]:
        assert(ins[a]['mnemonic'],ins[a]['operands'])==(m,o),(hex(a),ins.get(a))
    att=json.loads(read(ROOT/'fpsd1200_identity_ida_readback.json'))
    assert att['input_sha256']=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'
    assert att['spans']==[{'start':r['start'],'size_B':int(r['end'],16)-int(r['start'],16),'sha256':r['sha256']}for r in e['spans']]
    for s,t in zip(e['constant_strings'],att['constant_strings'],strict=True):
        a=int(s['address'],16);p=qword(a+16);n=qword(a+24)
        assert IMAGE.read(a,32).hex()==s['original_object32']and qword(a+8)==int(s['flags64'],16)
        assert hex(p)==s['literal_address']==t['literal_address']and n==s['length_B']==t['length_B']
        assert IMAGE.read(p,n+1).hex()==s['literal_hex']==t['literal_hex']and IMAGE.read(p,n).decode()==s['literal']
        obj=bytes.fromhex(t['object32']);assert obj[8:16]==IMAGE.read(a+8,8)and int.from_bytes(obj[16:24],'little')==p and int.from_bytes(obj[24:32],'little')==n
        assert verify_original_fixups([a+16])=={k:v for k,v in s['pointer_binding'].items()if k!='bindings'}
        assert [binding(a)]==s['pointer_binding']['bindings']
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
    for s in e['SDK_context']:
        raw=(sdk/'System/Library/Frameworks/CoreFoundation.framework/Headers'/s['logical_name'].split('/')[-1]).read_bytes()
        assert SHA(raw)==s['sha256']and all(d in raw.decode()for d in s['declarations'])
    for p in e['proofs'].values():
        s=z3.Solver();s.set(timeout=15000);s.from_string(p['query']);assert s.check()==z3.unsat and p['result']=='unsat'
    assert len(e['proofs'])==5
    accesses={int(a,16)for r in e['profiles']for a in r['fixup_reads']};binds={a for a in accesses if FIXUPS[a]['kind'].endswith('bind')}
    assert verify_original_fixups(sorted(accesses-binds))=={k:v for k,v in e['fixups'].items()if k!='bindings'}
    assert [binding(a)for a in sorted(binds)]==e['fixups']['bindings']
    pairs=0
    for p in e['byte_bank_proofs']:
        l,r,k=(int(p[n],16)for n in ['left','right','key']);left,right=IMAGE.read(l,256),IMAGE.read(r,256)
        assert {x^right[left[x]^k]for x in range(256)}=={int(p['constant'],16)}and p['inputs_checked']==256;pairs+=p['observed_uses']
    assert pairs==e['byte_bank_pairs']and sum(len(r['byte_bank_reads'])for r in e['profiles'])==pairs*2+len(e['unpaired_byte_bank_reads'])
    ctx=json.loads(read(ROOT/'daemon_object_initialization_context.json'))
    total=imports=points=guards=callbacks=provider_reads=copies=library_visits=0
    for r in e['profiles']:
        assert not r['reply_completed']and r['reply_status_u32']is None and not r['input_ool_reads']
        token=r['fixture'].get('audit32',bytes(range(32)).hex());assert len(r['library_calls'])==1
        call=r['library_calls'][0];assert call['site']=='0x100581f2c'and call['token32']==token
        assert call['output32_after']==bytes.fromhex(token)[20:24].hex()
        before=[int(x,16)for x in call['registers_before']];assert before[1:6]==[0]*5 and before[6]and before[7]==0
        for cp in r['copies']:assert cp['size_B']==32 and cp['source_hex']==cp['destination_after_hex']==token;copies+=1
        for v in r['events']:
            if 'audit32'in v:assert v['audit32']==token
        at={p['pc']:p for p in r['identity_points']if 'registers31'in p}
        done=at.get('0x100582178')
        if done:
            raw=bytes.fromhex(done['record24']);status=int.from_bytes(raw[20:24],'little')
            assert status in [0x3eb38698,0x3eb2e254,0x3eb2e276]
            rr=[int(x,16)for x in done['registers31']];assert(rr[22],rr[16],rr[25])==(0x55e4,0x5bf6,0x7e48)
            assert rr[10]==qword(TABLE+(0x7e63 if status==0x3eb38698 else 0x7e48)*8)
        if r['provider_snapshot']is not None:
            assert r['provider_snapshot']==ctx['coherent_provider_snapshots'][r['fixture']['provider_case']]
            for p in r['provider_reads']:
                o,n=p['offset_B'],p['width_B'];assert 0<=o and o+n<=512
                assert p['bytes_hex']==bytes.fromhex(r['provider_snapshot']['published_buffer512_hex'])[o:o+n].hex()
        else:assert not r['provider_reads']
        v,i,p=Replay(r,e['library']).verify();total+=v;imports+=i;points+=p
        guards+=r['stop_reason']=='unmapped_environment_read_guard';callbacks+=len(r['callback_models']);provider_reads+=len(r['provider_reads'])
        library_visits+=sum(int(a,16)>=0x200000000 for a in r['visited'])
    labels={r['fixture']['label']:r for r in e['profiles']}
    no,yes=labels['no_provider_reference'],labels['provider_0']
    assert no['initial_request128']==yes['initial_request128']and no['provider_snapshot']is None and yes['provider_snapshot']is not None
    assert no['stop_reason']=='unmapped_environment_read_guard'and yes['stop_reason']=='unmodeled_import_boundary'
    assert len(e['profiles'])==25 and guards==15 and callbacks==4 and library_visits==475
    return {'profiles':25,'original_instruction_visits':total,'daemon_visits':total-library_visits,'library_visits':library_visits,
      'import_events':imports,'admission_checkpoints':points,'identity_checkpoints':sum(len(r['identity_points'])for r in e['profiles']),
      'original_copy_calls':copies,'unmapped_read_guards':guards,'original_once_callbacks':callbacks,'provider_reads':provider_reads,
      'terminal_stack_private_bytes_checked':25*(0x80000+0x10000),'queries_unsat':5,'source_IDA_spans':len(e['spans']),
      'bank_inputs':256*len(e['byte_bank_proofs']),'all_checks_pass':True}


if __name__=='__main__':print(json.dumps(audit()))
