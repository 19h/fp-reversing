#!/usr/bin/env python3
"""CoreFP1201 source-staged record, nested admission and cursor compensation.

Original constructor fragment, helper, child and selected numeric initializer;
stop before every further unretained callee. Diagnostic record controls and
global/context backing are declared. No protected result or native effect.
O(C*(B+F+V+P*J+R)+256*K) time and O(B+F+C*(V+J+P+R)) space;
P counts modeled PAC sites and J source journal entries. SMT cost separate.
"""
import json,struct
from hashlib import sha256
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
import unicorn as uc
from unicorn import arm64_const as A
import z3
from probe_daemon_descriptor_source import zipbytes
from verify_daemon_reader_record_payloads_publication import read

ROOT=Path(__file__).resolve().parent;CS=Cs(CS_ARCH_ARM64,CS_MODE_ARM);CS.detail=True
STACK=0x71000000;OWNER=0x73000000;CONTEXT=OWNER+0x2000;HALT=0x7f000000
SP=STACK+0x8000;FP=STACK+0xc000;RECORD=FP-0xb8;OUT=SP+0x978
GLOB=0x1d33000;RAM=[(STACK,65536),(OWNER,16384),(GLOB,0x11000)]
DEPS=['fpsd1201_caller_ida_readback.json','fpsd1201_caller_checks.json','fpsd1201_caller_audit.json',
 'corefp_library_inventory.json','corefp_lookup_contracts.json','corefp_fixups_inventory.json','probe_daemon_descriptor_source.py']


def digest(b):return sha256(b).hexdigest()


def sources():
    old=json.loads(read(ROOT/'fpsd1201_caller_ida_readback.json'))
    fresh=json.loads(read(ROOT/'fpsd1201_record_ida_readback.json'))
    p=next(r for r in old['spans']if r['role']=='parent');pb=bytes.fromhex(p['bytes_hex'])
    code=[{'start':'0x8f3448','bytes_hex':pb[0x8f3448-0x8e81c8:0x8f34f8-0x8e81c8].hex(),'role':'constructor_fragment'}]
    code+=[{**r,'role':'helper'}for r in old['spans']if r['role']=='stack_helper']
    code+=[{**r,'role':'child'if r['start']=='0x981104'else'initializer'}for r in fresh['spans']]
    lookup=json.loads(read(ROOT/'corefp_lookup_contracts.json'));bankbytes={}
    for r in lookup['banks']:
        for address,key in [('first_address','first_bytes'),('second_address','second_bytes')]:
            a=int(r[address],16);b=bytes.fromhex(r[key]);assert a not in bankbytes or bankbytes[a]==b;bankbytes[a]=b
    D={int(r['address'],16):r for r in json.loads(read(ROOT/'corefp_fixups_inventory.json'))['fixups']}
    return code,bankbytes,D


def queries():
    p=z3.BitVec('record_low32',32)
    parent=((((p&0x55860eb0)<<1)-p+0x2a79f14c)^0x84f565d4)*0x9e8a2055
    child=(((p&0x4014fca6)|~(p|0x4014fca6))^0x116797c1)*0x9e8a2055
    seed=z3.BitVec('seed',64)
    c=z3.BitVec('decoded_compare_word',32);nonnull=z3.Bool('nonnull_record_fields')
    b=z3.If(z3.And(nonnull,c!=0x5a617a40),z3.BitVecVal(0,32),z3.BitVecVal(1,32))
    state=z3.BitVecVal(0x9265,32);mixed=(state^0x90da)*0x33
    bit=(mixed^b)&1;index=state^(bit|(bit<<1))
    count=z3.BitVec('count_pointer',64);first=z3.BitVec('first_pointer',64);second=z3.BitVec('second_pointer',64)
    valid=z3.And(count!=0,(first|second)!=0)
    mixed2=z3.BitVecVal((0x9265^0x90da)*0x33,32)
    mask=((mixed2+0x3b9972b2)&0xc46631f4)^((mixed2+0xea2f27d8)&0x15d0de7f)^0xa2c0
    index2=mixed2^z3.If(valid,z3.BitVecVal(0,32),mask)
    claims=[('aligned_record_codec',z3.Implies((p&7)==0,parent==child)),
      ('cursor_subtract_add_u64',(seed-0xe0+0xe0)==seed),
      ('first_gate_selected_state',(index==0x9266)==z3.And(nonnull,c!=0x5a617a40)),
      ('second_gate_all_u64_pointers',(index2==0x8c0d)==valid)]
    out=[]
    for label,claim in claims:
        s=z3.Solver();s.set(timeout=30000);s.add(z3.Not(claim));result=str(s.check());assert result=='unsat'
        out.append({'label':label,'query':s.sexpr()+'\n(check-sat)\n','result':result,'timeout_ms':30000})
    return out


class Execution:
    def __init__(self,c,code,banks,D):
        self.c=c;self.D=D;self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM)
        self.visits=[];self.reads=[];self.writes=[];self.pending=[];self.pac=[];self.points=[];self.phase='constructor';self.used=set()
        for a,n in [(0x8f3000,4096),(0x981000,8192),(0x181000,4096),
          (0x174f000,4096),(0x18ac000,4096),(0x1ac1000,4096),(0x1c78000,4096),
          (0x1c80000,0xa0000),(HALT,4096)]+RAM:self.u.mem_map(a,n)
        self.code=code;self.ranges=[]
        for row in code:
            a=int(row['start'],16);b=bytes.fromhex(row['bytes_hex']);self.u.mem_write(a,b);self.ranges.append((a,a+len(b)))
        for a,b in banks.items():self.u.mem_write(a,b)
        for a,row in D.items():
            if 0x1c80000<=a<a+8<=0x1d20000 and not row['bind']:self.u.mem_write(a,int(row['target'],16).to_bytes(8,'little'))
        self.u.mem_write(0x1d1c578,(0x1d43300).to_bytes(8,'little'))
        for a,n in RAM:self.u.mem_write(a,b'\xa5'*n)
        for a,v in [(0x1d356f0,c['global1_u64']),(0x1d37f68,c['global2_u64']),
          (0x1d333e8,c['global3_u64']),(0x1d358c8,c['global4_u64']),
          (0x1d43500,c['seed_u64']),(0x1d43300,0xb39a4e0cf582617d)]:self.u.mem_write(a,v.to_bytes(8,'little'))
        # Raw context metadata is a declared finite fixture, not source-produced.
        self.u.mem_write(CONTEXT+0x294,(0x4b0cf052).to_bytes(4,'little'))
        for off,v in [(0x1b8,OWNER+0x880),(0x398,0x1d43500)]:self.u.mem_write(SP+off,v.to_bytes(8,'little'))
        for j in range(31):self.setreg(j,((j+1)*0x13579bdf02468ace)&((1<<64)-1))
        for j,v in [(12,CONTEXT),(22,0x7bd0),(29,FP)]:self.setreg(j,v)
        self.u.reg_write(A.UC_ARM64_REG_SP,SP);self.u.reg_write(A.UC_ARM64_REG_PC,0x8f3448)
        self.u.reg_write(A.UC_ARM64_REG_NZCV,0);self.u.reg_write(A.UC_ARM64_REG_CPACR_EL1,3<<20)
        for j in range(32):self.u.reg_write(A.UC_ARM64_REG_Q0+j,int.from_bytes(bytes([j])*16,'little'))
        self.initial=self.frame();self.initial_RAM=self.dump()
        self.u.hook_add(uc.UC_HOOK_CODE,self.hook);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.readhook);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.writehook)
    def reg(self,j):return self.u.reg_read(getattr(A,'UC_ARM64_REG_X'+str(j)))
    def setreg(self,j,v):self.u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),v)
    def ram(self,a,n):return bytes(self.u.mem_read(a,n))
    def frame(self):return {'pc':hex(self.u.reg_read(A.UC_ARM64_REG_PC)),'sp':hex(self.u.reg_read(A.UC_ARM64_REG_SP)),
      'registers31':[hex(self.reg(j))for j in range(31)],'NZCV':hex(self.u.reg_read(A.UC_ARM64_REG_NZCV)),
      'Q32':[hex(self.u.reg_read(A.UC_ARM64_REG_Q0+j))for j in range(32)]}
    def dump(self):return [{'address':hex(a),'payload':zipbytes(self.ram(a,n))}for a,n in RAM]
    def flush(self):
        for e in self.pending:e['after_hex']=self.ram(int(e['address'],16),e['size_B']).hex()
        self.pending=[]
    def readhook(self,u,access,a,n,value,data):
        self.reads.append({'phase':self.phase,'visit':len(self.visits)-1,'address':hex(a),'size_B':n,'bytes_hex':self.ram(a,n).hex()})
        if a in self.D:self.used.add(a)
    def writehook(self,u,access,a,n,value,data):
        assert any(lo<=a<a+n<=lo+m for lo,m in RAM)
        e={'phase':self.phase,'visit':len(self.visits)-1,'address':hex(a),'size_B':n,'before_hex':self.ram(a,n).hex()};self.writes.append(e);self.pending.append(e)
    def hook(self,u,pc,n,data):
        self.flush()
        if pc==HALT:self.stop='returned';self.terminal=self.frame();u.emu_stop();return
        assert any(lo<=pc<hi for lo,hi in self.ranges),hex(pc)
        raw=self.ram(pc,4);i=next(CS.disasm(raw,pc));target=modifier=None
        if pc in [0x981104,0x981218,0x981520]:
            point={'pc':hex(pc),'CPU':self.frame()}
            if pc in [0x981104,0x981218]:point.update({'cursor_pointer':hex(self.reg(1)),'cursor_u64':hex(int.from_bytes(self.ram(self.reg(1),8),'little'))})
            else:
                at=self.u.reg_read(A.UC_ARM64_REG_SP)+0x48
                point.update({'descriptor16_address':hex(at),'descriptor16_hex':self.ram(at,16).hex()})
            self.points.append(point)
        if i.mnemonic in ['braa','blraa']:
            regs=[x.strip()for x in i.op_str.split(',')];target=self.u.reg_read(getattr(A,'UC_ARM64_REG_'+regs[0].upper()));modifier=self.u.reg_read(getattr(A,'UC_ARM64_REG_'+regs[1].upper()))
            if i.mnemonic=='blraa'and not any(lo<=target<hi for lo,hi in self.ranges):
                slots=[int(r['address'],16)for r in reversed(self.reads)if int(r['address'],16)in self.D and self.D[int(r['address'],16)].get('target')==hex(target)and self.D[int(r['address'],16)].get('diversity')==hex(modifier)]
                assert slots;self.used.add(slots[0])
                self.stop='unretained_callee';self.terminal=self.frame();self.frontier={'pc':hex(pc),'target':hex(target),'modifier':hex(modifier),'original_slot':hex(slots[0]),'instruction':i.mnemonic+' '+i.op_str,'instruction_executed':False,'argument_record80_hex':self.ram(self.reg(0),80).hex()};u.emu_stop();return
        self.visits.append({'phase':self.phase,'pc':hex(pc),'bytes_hex':raw.hex(),'instruction':i.mnemonic+' '+i.op_str});assert len(self.visits)<10000
        if i.mnemonic in ['pacibsp','retab','braa','blraa']:
            e={'pc':hex(pc),'kind':i.mnemonic,'before':self.frame()}
            if target is not None:
                candidates=[int(r['address'],16)for r in reversed(self.reads)if r['size_B']==8 and int(r['address'],16)in self.D and not self.D[int(r['address'],16)]['bind']and self.D[int(r['address'],16)].get('target')==hex(target)and self.D[int(r['address'],16)].get('diversity')==hex(modifier)]
                assert candidates,(hex(pc),hex(target),hex(modifier));slot=candidates[0];row=self.D[slot];assert row['key']=='IA'and row['address_diversity']==0
                e.update({'target':hex(target),'modifier':hex(modifier),'original_slot':hex(slot)})
                if i.mnemonic=='blraa':self.setreg(30,pc+4)
                u.reg_write(A.UC_ARM64_REG_PC,target)
            elif i.mnemonic=='retab':u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
            else:u.reg_write(A.UC_ARM64_REG_PC,pc+4)
            self.pac.append(e)
    def run(self):
        self.u.emu_start(0x8f3448,0x8f34f8,count=10000);self.flush();assert self.u.reg_read(A.UC_ARM64_REG_PC)==0x8f34f8
        constructor=self.frame();record_before=self.ram(RECORD,80).hex();controls=[]
        def control(a,b):
            controls.append({'address':hex(a),'before_hex':self.ram(a,len(b)).hex(),'after_hex':b.hex()});self.u.mem_write(a,b)
        if self.c['control']=='null_context':control(RECORD+0x38,b'\0'*8)
        elif self.c['control']=='null_count':control(RECORD+0x10,b'\0'*8)
        elif self.c['control']=='null_input':control(RECORD+0x20,b'\0'*8)
        elif self.c['control']=='null_auxiliary':control(RECORD+0x28,b'\0'*8)
        elif self.c['control']=='compare_equal':control(RECORD+8,(int.from_bytes(self.ram(RECORD+8,4),'little')^0x80).to_bytes(4,'little'))
        else:assert self.c['control']=='as_staged'
        record_after=self.ram(RECORD,80).hex();self.phase='nested';self.setreg(0,RECORD);self.setreg(1,OUT);self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_PC,0x981c38)
        entry=self.frame();self.u.emu_start(0x981c38,0,count=10000);self.flush();assert hasattr(self,'stop')
        return {'configuration':self.c,'initial':self.initial,'initial_RAM':self.initial_RAM,
          'constructor_terminal':constructor,'record80_before_controls_hex':record_before,'record_controls':controls,
          'record80_after_controls_hex':record_after,'nested_entry':entry,'source_visits':self.visits,'source_reads':self.reads,
          'source_writes':self.writes,'PAC_models':self.pac,'CPU_points':self.points,'stop_reason':self.stop,'frontier':getattr(self,'frontier',None),
          'terminal':self.terminal,'final_RAM':self.dump(),'final_delta_cell_u64':hex(int.from_bytes(self.ram(OUT,8),'little')),
          'final_status_u32':hex(int.from_bytes(self.ram(RECORD+0x30,4),'little')),
          'used_original_pointer_rows':[self.D[a]for a in sorted(self.used)],'native_effects':False}


def configurations():
    for j,seed in enumerate([0,1,0xffffffffffffffff,0x0123456789abcdef]):
        for control in ['as_staged','null_context','null_count','null_input','compare_equal','null_auxiliary']:
            yield {'label':control+'_seed'+str(j),'seed_u64':seed,'control':control,
              'global1_u64':(j+1)*0x0123456789abcdef,'global2_u64':(j+1)*0x1020304050607080,
              'global3_u64':(j+1)*0x13579bdf2468ace,'global4_u64':(j+1)*0x2468ace13579bdf}


def main():
    code,banks,D=sources();profiles=[Execution(c,code,banks,D).run()for c in configurations()]
    counts={'profiles':len(profiles),'source_visits':sum(len(p['source_visits'])for p in profiles),
      'source_reads':sum(len(p['source_reads'])for p in profiles),'source_writes':sum(len(p['source_writes'])for p in profiles),
      'PAC_models':sum(len(p['PAC_models'])for p in profiles),'completed_rejections':sum(p['stop_reason']=='returned'for p in profiles),
      'callee_frontiers':sum(p['stop_reason']=='unretained_callee'for p in profiles),'fresh_IDA_spans':2,'fresh_IDA_bytes':3368,
      'source_code_bytes_including_constructor':sum(len(bytes.fromhex(r['bytes_hex']))for r in code),'local_queries_unsat':4}
    out={'scope':__doc__,'code_spans':code,'profiles':profiles,'proofs':queries(),'verified_counts':counts,
      'generator_sha256':digest(Path(__file__).read_bytes()),'dependencies':{n:digest(read(ROOT/n).encode())for n in DEPS},
      'IDA_readback_sha256':digest(read(ROOT/'fpsd1201_record_ida_readback.json').encode()),
      'entry_register_and_context_fixtures_are_declared':True,'whole_parent_replayed':False,
      'native_target_executed':False,'IDB_edit_operations_requested':False,'full_goal_complete':False}
    (ROOT/'fpsd1201_record_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts));print(json.dumps([{'case':p['configuration']['label'],'stop':p['stop_reason'],'frontier':p['frontier'],'delta':p['final_delta_cell_u64'],'status':p['final_status_u32']}for p in profiles]))


if __name__=='__main__':main()
