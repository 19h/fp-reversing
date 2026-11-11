#!/usr/bin/env python3
"""CoreFP1201 parent selection, conditional port/data provenance and frame gaps.

Frozen reference first, read-only IDA bytes for missing body/banks. Selected
loop/gate fragments execute privately; no whole-parent or native IPC executes.
O(B+F+C*V+256*K) time and O(B+F+C*(V+R)) space; SMT cost separate.
"""
import json,struct
from hashlib import sha256
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as A
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
from daemon_receive_tools import ROOT,CS
from probe_daemon_descriptor_source import zipbytes
from verify_daemon_reader_record_payloads_publication import read

T=0x1c81940;STACK=0x71000000;INPUT=0x72000000;OWNER=0x73000000;GLOBAL=0x74000000
RAM=[(STACK,65536),(INPUT,4096),(OWNER,8192),(GLOBAL,4096)]
DEPS=['corefp_fixups_inventory.json','corefp_client_paths_contracts.json',
 'corefp_client_flow_profiles.json','corefp_mach_request_profiles.json',
 'fpsd1201_client_checks.json','daemon_receive_tools.py','probe_daemon_descriptor_source.py']


def digest(b):return sha256(b).hexdigest()


def sources():
    att=json.loads(read(ROOT/'fpsd1201_caller_ida_readback.json'))
    ptrs=json.loads(read(ROOT/'corefp_fixups_inventory.json'))
    return att,{int(r['address'],16):r for r in ptrs['fixups']}


def banks(att):
    at={int(r['start'],16):bytes.fromhex(r['bytes_hex'])for r in att['spans']if r['role']in ['init_bank','call_bank']}
    out=[]
    for label,a,b,key,expected in [('parent_table',0x18ac070,0x1ac18c0,0x89,0x77),
      ('request1201',0x18ac270,0x1ac1ac0,0xc8,0xc0),('stack_helper',0x18ac270,0x1ac1ac0,0xe7,0x1f)]:
        values=[i^at[b][at[a][i]^key]for i in range(256)];assert set(values)=={expected}
        out.append({'label':label,'left':hex(a),'right':hex(b),'key_u8':key,'constant_u8':expected,'results256':values})
    return out


def source_census(att):
    p=next(r for r in att['spans']if r['role']=='parent');b=bytes.fromhex(p['bytes_hex'])
    decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM);decoder.detail=True
    ins=list(decoder.disasm(b,int(p['start'],16)));assert len(ins)*4==len(b)
    sp=[];stores=[];dynamic_stores=[]
    targets=[(0x1b8,8),(0x1a8,8),(0x1f0,8),(0x258,8),(0x3a0,16),(0x4e8,4)]
    for i in ins:
        rr,rw=i.regs_access()
        if 'sp'in [i.reg_name(r)for r in rw]:sp.append({'pc':hex(i.address),'instruction':i.mnemonic+' '+i.op_str})
        if not i.mnemonic.startswith('st'):continue
        for op in i.operands:
            if op.type!=3 or i.reg_name(op.mem.base)!='sp':continue
            if op.mem.index:dynamic_stores.append({'pc':hex(i.address),'instruction':i.mnemonic+' '+i.op_str});continue
            regs=[o for o in i.operands if o.type==1]
            if not regs:continue
            rn=i.reg_name(regs[0].reg)
            width=16 if rn.startswith('q')else 8 if rn.startswith(('x','d'))else 4 if rn.startswith(('w','s'))else 2 if rn.startswith('h')else 1
            if i.mnemonic in ['strb','sturb']:width=1
            if i.mnemonic in ['strh','sturh']:width=2
            n=width*(2 if i.mnemonic in ['stp','stnp']else 1);off=op.mem.disp
            hit=[hex(a)for a,m in targets if off<a+m and a<off+n]
            if hit:stores.append({'pc':hex(i.address),'instruction':i.mnemonic+' '+i.op_str,'offset':off,'size_B':n,'overlaps_cells':hit})
    return {'parent_instructions':len(ins),'SP_writes':sp,'direct_SP_stores_overlapping_selected_cells':stores,
      'indexed_SP_stores_not_resolved':dynamic_stores,'alias_or_callee_stores_exhausted':False,
      'dynamic_SP_epochs_joined':False}


def proofs():
    x=z3.BitVec('byte',8);w=z3.ZeroExt(24,x)
    source=w+(z3.BitVecVal(0x8b,32)|~(w<<1))-0x45
    scalar=z3.BitVec('scalar',32);state=z3.BitVecVal(0x55e1,32)
    index=((state-0x53df)|0xe089)^z3.If(z3.ULT(scalar,2),z3.BitVecVal(28,32),z3.BitVecVal(0,32))
    child=z3.BitVec('child',32);saved=z3.BitVec('saved',64)
    delta=z3.ZeroExt(32,(child-z3.Extract(31,0,saved))&0xffff)<<4
    claims=[('loop_byte',z3.Extract(7,0,source)==(x^0xba)),
      ('gate_all_u32',index==z3.If(z3.ULT(scalar,2),z3.BitVecVal(0xe297,32),z3.BitVecVal(0xe28b,32))),
      ('delta_alignment_and_extent',z3.And((delta&15)==0,z3.ULE(delta,0xffff0),
       (delta==0)==(z3.Extract(15,0,child)==z3.Extract(15,0,saved))))]
    out=[]
    for label,claim in claims:
        s=z3.Solver();s.set(timeout=30000);s.add(z3.Not(claim));result=str(s.check());assert result=='unsat'
        out.append({'label':label,'query':s.sexpr()+'\n(check-sat)\n','result':result,'timeout_ms':30000})
    return out


class Fragment:
    def __init__(self,c,att,fixups):
        self.c=c;self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.visits=[];self.reads=[];self.writes=[];self.pending=[];self.pac=[]
        self.fixups=fixups
        for a,n in [(0x8e8000,0x15000),(0x18ac000,4096),(0x1ac1000,4096),
          (0x1cac000,4096),(0x1cf2000,4096),(0x1d03000,4096)]+RAM:self.u.mem_map(a,n)
        for r in att['spans']:
            if r['role']in ['parent','call_bank']:self.u.mem_write(int(r['start'],16),bytes.fromhex(r['bytes_hex']))
        for a in [0x1cac848,0x1cac960,0x1cf2d98,0x1cf2df8,0x1d03f08]:self.u.mem_write(a,struct.pack('<Q',int(fixups[a]['target'],16)))
        for a,n in RAM:self.u.mem_write(a,b'\xa5'*n)
        self.sp=STACK+0x8000
        payload=bytes((j+c['pattern_shift'])&255 for j in range(128));self.u.mem_write(INPUT,payload)
        self.u.mem_write(OWNER+0x168,struct.pack('<I',c['scalar_u32']))
        self.u.mem_write(GLOBAL,struct.pack('<2I',c['global_a_u32'],c['global_b_u32']))
        for off,value,width in [(0x258,OWNER,8),(0x4c0,GLOBAL,8),(0x4b8,GLOBAL+4,8),
          (0x3a8,0x18ac270,8),(0x3a0,0x1ac1ac0,8),(0x4e8,c['destination_u32'],4),
          (0x1b8,OWNER+0x880,8),(0x5c8,0x1234567812345678,8)]:self.u.mem_write(self.sp+off,value.to_bytes(width,'little'))
        for j in range(31):self.setreg(j,(j+1)*0x123456789abcdef&((1<<64)-1))
        for j,value in [(3,0xba1df9db),(7,0x68001f0b),(8,128),(11,0x8b),(12,0x3e5),
          (13,INPUT),(19,T),(20,0x55e1),(25,OWNER+0x900),(26,c['global_x26_u64'])]:self.setreg(j,value)
        self.u.reg_write(A.UC_ARM64_REG_SP,self.sp);self.u.reg_write(A.UC_ARM64_REG_PC,0x8f35cc)
        self.u.reg_write(A.UC_ARM64_REG_NZCV,0);self.u.reg_write(A.UC_ARM64_REG_CPACR_EL1,3<<20)
        for j in range(32):self.u.reg_write(A.UC_ARM64_REG_Q0+j,int.from_bytes(bytes([j])*16,'little'))
        self.initial=self.frame();self.initial_ram=[{'address':hex(a),'payload':zipbytes(self.ram(a,n))}for a,n in RAM]
        self.u.hook_add(uc.UC_HOOK_CODE,self.hook);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.readhook);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.writehook)
    def reg(self,j):return self.u.reg_read(getattr(A,'UC_ARM64_REG_X'+str(j)))
    def setreg(self,j,v):self.u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),v&((1<<64)-1))
    def ram(self,a,n):return bytes(self.u.mem_read(a,n))
    def frame(self):return {'pc':hex(self.u.reg_read(A.UC_ARM64_REG_PC)),'sp':hex(self.u.reg_read(A.UC_ARM64_REG_SP)),
      'registers31':[hex(self.reg(j))for j in range(31)],'NZCV':hex(self.u.reg_read(A.UC_ARM64_REG_NZCV)),
      'Q32':[hex(self.u.reg_read(A.UC_ARM64_REG_Q0+j))for j in range(32)]}
    def flush(self):
        for w in self.pending:w['after_hex']=self.ram(int(w['address'],16),w['size_B']).hex()
        self.pending=[]
    def readhook(self,u,access,a,n,value,data):self.reads.append({'visit':len(self.visits)-1,'address':hex(a),'size_B':n,'bytes_hex':self.ram(a,n).hex()})
    def writehook(self,u,access,a,n,value,data):
        assert any(lo<=a<a+n<=lo+m for lo,m in RAM)
        w={'visit':len(self.visits)-1,'address':hex(a),'size_B':n,'before_hex':self.ram(a,n).hex()};self.writes.append(w);self.pending.append(w)
    def hook(self,u,pc,n,data):
        self.flush()
        if pc in [0x8f3838,0x8f389c]:self.terminal=self.frame();u.emu_stop();return
        ins=next(CS.disasm(bytes(u.mem_read(pc,4)),pc));self.visits.append({'pc':hex(pc),'bytes_hex':bytes(ins.bytes).hex(),'instruction':ins.mnemonic+' '+ins.op_str})
        assert len(self.visits)<3000
        if ins.mnemonic=='braa':
            assert pc in [0x8f35f8,0x8f3658]
            target=self.reg(9 if pc==0x8f35f8 else 8);modifier=self.reg(17)
            expected=next(a for a in [0x1cac848,0x1cac960,0x1cf2d98,0x1cf2df8]if int(self.fixups[a]['target'],16)==target)
            row=self.fixups[expected];assert int(row['diversity'],16)==modifier and row['key']=='IA'and row['address_diversity']==0
            self.pac.append({'pc':hex(pc),'target':hex(target),'modifier':hex(modifier),'original_slot':hex(expected),'before':self.frame()})
            u.reg_write(A.UC_ARM64_REG_PC,target)
    def run(self):
        self.u.emu_start(0x8f35cc,0,count=3000);self.flush();assert hasattr(self,'terminal')
        return {'configuration':self.c,'initial':self.initial,'initial_RAM':self.initial_ram,'source_visits':self.visits,
          'source_reads':self.reads,'source_writes':self.writes,'PAC_models':self.pac,'terminal':self.terminal,
          'final_RAM':[{'address':hex(a),'payload':zipbytes(self.ram(a,n))}for a,n in RAM],
          'copied128_hex':self.ram(OWNER+0x900,128).hex(),'native_effects':False}


def main():
    att,D=sources();bank=banks(att);census=source_census(att);qs=proofs()
    profiles=[]
    for shift in [0,128]:
        for scalar in [0,1,2,3,0x80000000,0xffffffff]:
            c={'label':'scalar_'+hex(scalar)+'_pattern_'+str(shift),'scalar_u32':scalar,'pattern_shift':shift,
              'global_a_u32':0x12345678^shift,'global_b_u32':0xabcdef01^scalar,
              'global_x26_u64':0x2a3c56842e5d49ec^shift,'destination_u32':0x6800+shift}
            profiles.append(Fragment(c,att,D).run())
    rows=[D[a]for a in [0x1d108e8,0x1d09f68,0x1d146f0,0x1d03f08,0x1d04158,0x1d04218,0x1cac848,0x1cac960,0x1cf2d98,0x1cf2df8]]
    counts={'profiles':len(profiles),'original_visits':sum(len(p['source_visits'])for p in profiles),
      'original_reads':sum(len(p['source_reads'])for p in profiles),'original_writes':sum(len(p['source_writes'])for p in profiles),
      'PAC_models':sum(len(p['PAC_models'])for p in profiles),'banks_exhaustive_256':len(bank),'SMT_unsat':len(qs),
      'source_parent_instructions':census['parent_instructions'],'fresh_IDA_spans':len(att['spans']),
      'fresh_IDA_bytes_including_overlap':sum(r['size_B']for r in att['spans']),'original_pointer_words':len(rows)}
    out={'scope':__doc__,'reference_universal_sha256':att['input_sha256'],
      'reference_arm64e_sha256':'8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c',
      'banks':bank,'pointer_rows':rows,'source_census':census,'proofs':qs,'profiles':profiles,
      'entry_is_declared_fragment_not_whole_parent':True,'zero_delta_between_requests_established':False,
      'native_port_identity_established':False,'dependencies':{n:digest(read(ROOT/n).encode())for n in DEPS},
      'IDA_readback_sha256':digest(read(ROOT/'fpsd1201_caller_ida_readback.json').encode()),
      'generator_sha256':digest(Path(__file__).read_bytes()),'verified_counts':counts,
      'native_target_executed':False,'IDB_edit_operations_requested':False,'full_goal_complete':False}
    (ROOT/'fpsd1201_caller_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts))


if __name__=='__main__':main()
