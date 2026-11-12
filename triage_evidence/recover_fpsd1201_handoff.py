#!/usr/bin/env python3
"""Declared parent re-entry joins retained export bytes to pre-import serialization.

Restore receipt-pinned helper returns, explicitly bind absent parent state, and
execute original parent/builder bytes up to the first native import call.
No native API, reply-port model, reply, or arithmetic result is supplied.
Time O(B+F+C*(V+J+R)); space O(B+F+C*(V+J+R)); SMT cost separate.
Whole-parent/native reachability, right ownership and endpoint identity unknown.
"""
import json,struct
from pathlib import Path
from hashlib import sha256
import unicorn as uc
from unicorn import arm64_const as A
import z3
from daemon_receive_tools import ROOT,CS
from probe_daemon_descriptor_source import zipbytes
from recover_fpsd1201_consumer import unpack
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest()
SP=0x71008000;FP=0x7100c000;OWNER=0x73000000;CONTEXT=OWNER+0x2000
GLOBAL=0x74000000;BIND=0x76000000;T=0x1c81940
RAM=[(0x71000000,65536),(OWNER,16384),(0x1d33000,0x11000),(GLOBAL,4096),(BIND,4096),(0x1d1c000,4096)]
SLOTS=[0x1cbf7c0,0x1cde068,0x1cac848,0x1cac960,0x1cf2d98,0x1cf2df8,0x1d03f08]
DEPS=['fpsd1201_export_checks.json','fpsd1201_export_audit.json','fpsd1201_caller_ida_readback.json',
 'corefp_fixups_inventory.json','corefp_mach_request_profiles.json','fpsd1201_caller_checks.json',
 'fpsd1201_caller_audit.json','recover_fpsd1201_consumer.py','daemon_receive_tools.py',
 'probe_daemon_descriptor_source.py','recover_fpsd1201_export.py','audit_fpsd1201_export.py','corefp_import_calls.json']


def sources():
    att=json.loads(read(ROOT/'fpsd1201_caller_ida_readback.json'))
    spans=[r for r in att['spans']if r['role']in ['parent','call_bank']]
    body=next(r for r in json.loads(read(ROOT/'corefp_mach_request_profiles.json'))['original_functions']if r['start']=='0x8d40')
    spans.append({'start':body['start'],'bytes_hex':body['bytes'],'role':'request1201_builder'})
    D={int(r['address'],16):r for r in json.loads(read(ROOT/'corefp_fixups_inventory.json'))['fixups']}
    return spans,D


def configurations():
    yield from ({'prior_index':j,'scalar_u32':2,'root_override_u32':None}for j in range(18))
    yield from ({'prior_index':0,'scalar_u32':n,'root_override_u32':None}for n in [0,1,3,0x80000000,0xffffffff])
    yield from ({'prior_index':0,'scalar_u32':2,'root_override_u32':n}for n in [0,0x45e2a205,0xba1df9da,0xffffffff])


class Execute:
    def __init__(self,c,prior,spans,D):
        self.c=c;self.D=D;self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM)
        self.visits=[];self.reads=[];self.writes=[];self.pending=[];self.pac=[];self.points=[];self.controls=[]
        pages={a&~4095 for a in SLOTS}|{0x18ac000,0x1ac1000}
        for a,n in [(0x8e8000,0x15000),(0x8000,4096)]+[(a,4096)for a in sorted(pages)]+RAM:self.u.mem_map(a,n)
        for row in spans:self.u.mem_write(int(row['start'],16),bytes.fromhex(row['bytes_hex']))
        for a in SLOTS:self.u.mem_write(a,int(D[a]['target'],16).to_bytes(8,'little'))
        for a,n in RAM:self.u.mem_write(a,b'\xa5'*n)
        for row in prior['final_RAM']:self.u.mem_write(int(row['address'],16),unpack(row['payload']))
        f=prior['terminal'];assert f['pc']=='0x7f000000'and f['sp']==hex(SP)
        for j,v in enumerate(f['registers31']):self.setreg(j,int(v,16))
        for key in ['SP','PC','NZCV']:self.u.reg_write(getattr(A,'UC_ARM64_REG_'+key),int(f[key.lower()if key!='NZCV'else key],16))
        for j,v in enumerate(f['Q32']):self.u.reg_write(A.UC_ARM64_REG_Q0+j,int(v,16))
        self.u.reg_write(A.UC_ARM64_REG_CPACR_EL1,3<<20);assert self.frame()==f
        self.restored=self.frame();self.restored_RAM=self.dump()
        self.register_bindings=[]
        for j,v in [(19,T),(25,OWNER+0x900)]:
            self.register_bindings.append({'register':'X'+str(j),'before':hex(self.reg(j)),'after':hex(v)});self.setreg(j,v)
        for off,v,n in [(0x1a8,OWNER+0x900,8),(0x1f0,CONTEXT,8),(0x258,OWNER,8),
          (0x4c0,GLOBAL,8),(0x4b8,GLOBAL+4,8),(0x3a8,0x18ac270,8),(0x3a0,0x1ac1ac0,8),
          (0x4e8,0x6800+c['prior_index'],4)]:self.patch(SP+off,v.to_bytes(n,'little'),'declared_parent_binding')
        self.patch(OWNER+0x168,c['scalar_u32'].to_bytes(4,'little'),'declared_scalar')
        self.patch(GLOBAL,struct.pack('<II',0x12345678,0xabcdef01^c['scalar_u32']),'declared_bank_mix')
        self.patch(BIND+0x100,bytes.fromhex('0000000001000000'),'declared_NDR_data')
        self.patch(BIND+0x200,bytes.fromhex('b39a4e0cf582617d'),'declared_guard_data')
        for a,v in [(0x1d1c570,BIND+0x100),(0x1d1c578,BIND+0x200)]:self.patch(a,v.to_bytes(8,'little'),'declared_imported_data_pointer')
        if c['root_override_u32']is not None:self.patch(FP-0x88,c['root_override_u32'].to_bytes(4,'little'),'negative_root_marker_control')
        self.u.reg_write(A.UC_ARM64_REG_PC,0x8f3564);self.initial=self.frame();self.initial_RAM=self.dump()
        self.u.hook_add(uc.UC_HOOK_CODE,self.hook);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.readhook);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.writehook)
    def reg(self,j):return self.u.reg_read(getattr(A,'UC_ARM64_REG_X'+str(j)))
    def setreg(self,j,v):self.u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),v)
    def ram(self,a,n):return bytes(self.u.mem_read(a,n))
    def frame(self):return {'pc':hex(self.u.reg_read(A.UC_ARM64_REG_PC)),'sp':hex(self.u.reg_read(A.UC_ARM64_REG_SP)),
      'registers31':[hex(self.reg(j))for j in range(31)],'NZCV':hex(self.u.reg_read(A.UC_ARM64_REG_NZCV)),
      'Q32':[hex(self.u.reg_read(A.UC_ARM64_REG_Q0+j))for j in range(32)]}
    def dump(self):return [{'address':hex(a),'payload':zipbytes(self.ram(a,n))}for a,n in RAM]
    def patch(self,a,b,why):
        self.controls.append({'address':hex(a),'before_hex':self.ram(a,len(b)).hex(),'after_hex':b.hex(),'reason':why});self.u.mem_write(a,b)
    def flush(self):
        for w in self.pending:w['after_hex']=self.ram(int(w['address'],16),w['size_B']).hex()
        self.pending=[]
    def readhook(self,u,ac,a,n,v,d):self.reads.append({'visit':len(self.visits)-1,'address':hex(a),'size_B':n,'bytes_hex':self.ram(a,n).hex()})
    def writehook(self,u,ac,a,n,v,d):
        assert any(lo<=a<a+n<=lo+m for lo,m in RAM)
        w={'visit':len(self.visits)-1,'address':hex(a),'size_B':n,'before_hex':self.ram(a,n).hex()};self.writes.append(w);self.pending.append(w)
    def hook(self,u,pc,n,d):
        self.flush()
        if pc in [0x8f3664,0x8f389c,0x8db0]:self.terminal=self.frame();u.emu_stop();return
        assert 0x8e81c8<=pc<0x8fcfa0 or 0x8d40<=pc<0x8ed4
        raw=self.ram(pc,4);i=next(CS.disasm(raw,pc));self.visits.append({'pc':hex(pc),'bytes_hex':raw.hex(),'instruction':i.mnemonic+' '+i.op_str})
        assert len(self.visits)<3000
        if pc in [0x8f3594,0x8f35c8,0x8f363c,0x8f3658,0x8f3838,0x8d40]:self.points.append({'pc':hex(pc),'CPU':self.frame()})
        if i.mnemonic=='pacibsp':self.pac.append({'pc':hex(pc),'kind':'PACIBSP_private_noop','before':self.frame()});u.reg_write(A.UC_ARM64_REG_PC,pc+4)
        elif i.mnemonic in ['braa','blraa']:
            rn=10 if pc==0x8f35c8 else 9 if pc==0x8f35f8 else 8;target=self.reg(rn);mod=self.reg(17)
            a=next(a for a in SLOTS if int(self.D[a]['target'],16)==target and int(self.D[a]['diversity'],16)==mod)
            assert self.D[a]['key']=='IA'and self.D[a]['address_diversity']==0
            self.pac.append({'pc':hex(pc),'kind':i.mnemonic,'target':hex(target),'modifier':hex(mod),'original_slot':hex(a),'before':self.frame()})
            if i.mnemonic=='blraa':self.setreg(30,pc+4)
            u.reg_write(A.UC_ARM64_REG_PC,target)
    def run(self):
        self.u.emu_start(0x8f3564,0,count=3000);self.flush();assert hasattr(self,'terminal')
        called=self.terminal['pc']=='0x8db0';builder_sp=SP-208
        return {'configuration':self.c,'restored':self.restored,'restored_RAM':self.restored_RAM,'register_bindings':self.register_bindings,
          'operand_controls':self.controls,'initial':self.initial,'initial_RAM':self.initial_RAM,'source_visits':self.visits,'source_reads':self.reads,
          'source_writes':self.writes,'PAC_models':self.pac,'CPU_points':self.points,'terminal':self.terminal,'final_RAM':self.dump(),
          'candidate128_hex':self.ram(OWNER+0x880,128).hex(),'xor128_hex':self.ram(OWNER+0x900,128).hex(),
          'serialized128_hex':self.ram(builder_sp+40,128).hex()if called else None,
          'serialized_scalar_u32':int.from_bytes(self.ram(builder_sp+36,4),'little')if called else None,
          'first_import_call_executed':False,'native_effects':False}


def proofs():
    marker=z3.BitVec('parent_root_marker32',32);yes=z3.If(marker==0xba1df9db,z3.BitVecVal(1,32),z3.BitVecVal(0,32))
    idx=(yes*(z3.BitVecVal(0x3de80,32)^0x31db5))^0x7bd0
    n=z3.BitVec('parent_scalar32',32);gate=z3.BitVecVal((0x55e1-0x53df)|0xe089,32)^z3.If(z3.ULT(n,2),z3.BitVecVal(28,32),z3.BitVecVal(0,32))
    claims=[('root_status_partition',idx==z3.If(marker==0xba1df9db,z3.BitVecVal(0xb8e5,32),z3.BitVecVal(0x7bd0,32))),
      ('scalar_partition',gate==z3.If(z3.UGE(n,2),z3.BitVecVal(0xe28b,32),z3.BitVecVal(0xe297,32)))]
    out=[]
    for label,claim in claims:
        s=z3.Solver();s.set(timeout=30000);s.add(z3.Not(claim));assert s.check()==z3.unsat
        out.append({'label':label,'query':s.to_smt2(),'result':'unsat'})
    return out


def main():
    spans,D=sources();old=json.loads(read(ROOT/'fpsd1201_export_checks.json'));profiles=[]
    for c in configurations():
        profiles.append(Execute(c,old['profiles'][c['prior_index']],spans,D).run())
        print(json.dumps({'profile':len(profiles)-1,'terminal':profiles[-1]['terminal']['pc'],'visits':len(profiles[-1]['source_visits'])}),flush=True)
    qs=proofs();counts={'profiles':len(profiles),**{k:sum(len(p[k])for p in profiles)for k in ['source_visits','source_reads','source_writes','PAC_models','CPU_points']},
      'builder_pre_import_stops':sum(p['terminal']['pc']=='0x8db0'for p in profiles),'scalar_skip_stops':sum(p['terminal']['pc']=='0x8f389c'for p in profiles),
      'root_mismatch_stops':sum(p['terminal']['pc']=='0x8f3664'for p in profiles),'original_pointer_rows':len(SLOTS),'local_queries_unsat':len(qs)}
    out={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},
      'code_spans':spans,'pointer_rows':[D[a]for a in SLOTS],'profiles':profiles,'proofs':qs,'verified_counts':counts,
      'reference_universal_sha256':'68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f',
      'reference_arm64e_sha256':'8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c',
      'prefix_instructions_rerun':0,'whole_parent_replayed':False,'native_target_executed':False,'IDB_edit_operations_requested':False,'full_goal_complete':False}
    (ROOT/'fpsd1201_handoff_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
