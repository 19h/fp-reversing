#!/usr/bin/env python3
"""CoreFP byte-to-limb import ABI and original nested continuation.

Private original-byte execution only. Isolated record grammars are diagnostic
fixtures; nested cases retain the predecessor's source-staged context. No
protected result, native API or whole-parent reachability is supplied.
O(C*(B+F+V+P*J+R)+256*K) time, O(B+F+C*(V+J+P+R)) space;
retained-read/PAC association costs P*J; solver cost separate.
"""
import json,struct
from hashlib import sha256
from pathlib import Path
import z3
from unicorn import arm64_const as A
from recover_fpsd1201_record import Execution as Previous,sources as prior_sources,configurations as prior_configurations,CS,ROOT,STACK,OWNER,CONTEXT,HALT,SP,FP,RAM
from verify_daemon_reader_record_payloads_publication import read

ENTRY=0x17bbb8;END=0x17c090;IR=FP+0x100;INPUT=OWNER+0x400;DESC=OWNER+0x800;LIMBS=OWNER+0x1000
COUNT_BASE=0x4b0cf050;LIMB_XOR=0x1ac70ef2
DEPS=['recover_fpsd1201_record.py','audit_fpsd1201_record.py','fpsd1201_record_checks.json',
 'fpsd1201_record_audit.json','fpsd1201_record_ida_readback.json','fpsd1201_caller_ida_readback.json',
 'corefp_library_inventory.json','corefp_lookup_contracts.json','corefp_fixups_inventory.json','probe_daemon_descriptor_source.py']


def digest(b):return sha256(b).hexdigest()


def local_reference(code,banks,D):
    raw=(ROOT.parent/'CoreFP').read_bytes();assert digest(raw)=='68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f'
    n=struct.unpack_from('>I',raw,4)[0];assert raw[:4]==bytes.fromhex('cafebabe')
    slices=[struct.unpack_from('>5I',raw,8+20*j)for j in range(n)]
    cpu,sub,off,size,align=next(r for r in slices if r[:2]==(0x100000c,0x80000002));thin=raw[off:off+size]
    assert digest(thin)=='8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c'
    at=32;segments=[];function_blob=None
    for j in range(struct.unpack_from('<I',thin,16)[0]):
        command,length=struct.unpack_from('<II',thin,at)
        if command==0x19:
            name,vm,vs,fo,fs=struct.unpack_from('<16s4Q',thin,at+8);segments.append({'name':name.rstrip(b'\0').decode(),'vm':vm,'vm_size_B':vs,'file_offset':fo,'file_size_B':fs})
        if command==0x26:
            a,n=struct.unpack_from('<II',thin,at+8);function_blob=thin[a:a+n]
        at+=length
    def get(a,n):
        row=next(r for r in segments if r['vm']<=a<a+n<=r['vm']+r['file_size_B']);p=row['file_offset']+a-row['vm'];return thin[p:p+n]
    starts=[];v=0;shift=0;pc=0
    for byte in function_blob:
        v|=(byte&127)<<shift
        if byte&128:shift+=7;continue
        if v==0:break
        pc+=v;starts.append(hex(pc));v=0;shift=0
    assert starts==json.loads(read(ROOT/'corefp_library_inventory.json'))['compiler_function_starts']
    for r in code:assert get(int(r['start'],16),len(bytes.fromhex(r['bytes_hex'])))==bytes.fromhex(r['bytes_hex'])
    parent=next(r for r in json.loads(read(ROOT/'fpsd1201_caller_ida_readback.json'))['spans']if r['role']=='parent')
    parent_bytes=bytes.fromhex(parent['bytes_hex']);assert get(int(parent['start'],16),len(parent_bytes))==parent_bytes
    for a,b in banks.items():assert get(a,len(b))==b
    for a,r in D.items():assert int.from_bytes(get(a,8),'little')==int(r['word'],16)
    return {'logical_reference_name':'CoreFP','universal_sha256':digest(raw),'arm64e_sha256':digest(thin),
      'universal_size_B':len(raw),'selected_slice_offset':off,'selected_slice_size_B':size,'segments':segments,
      'compiler_function_starts_equal':True,'compiler_function_starts_count':len(starts),
      'compiler_function_starts_blob_sha256':digest(function_blob),'all_original_fixup_words_equal':True,
      'original_fixup_words_checked':len(D),'code_bytes_checked':sum(len(bytes.fromhex(r['bytes_hex']))for r in code),
      'earlier_parent_bytes_checked':len(parent_bytes),'earlier_parent_sha256':digest(parent_bytes),
      'bank_bytes_checked':sum(len(b)for b in banks.values()),'native_target_executed':False}


def mask(pointer):return ((~((pointer&0xffffffff)^0x7232c2dc)^0xfd8e9ed9)*0x4ecee2ad)&0xffffffff


class Execute(Previous):
    def __init__(self,c,code,banks,D):
        super().__init__(c,code[:-1],banks,D)
        r=code[-1];b=bytes.fromhex(r['bytes_hex']);self.u.mem_map(0x17b000,8192);self.u.mem_write(ENTRY,b);self.ranges.append((ENTRY,END));self.import_points=[]
        if c['mode']=='isolated':
            self.phase='isolated';self.u.mem_write(INPUT,bytes.fromhex(c['input_hex']))
            self.u.mem_write(DESC,struct.pack('<IIQ',64,COUNT_BASE,LIMBS))
            m=mask(IR);self.u.mem_write(IR,struct.pack('<I',0x66dc^m))
            self.u.mem_write(IR+8,struct.pack('<QQ',0 if c['null_input']else INPUT,DESC))
            self.u.mem_write(IR+0x1c,struct.pack('<I',(0x62b6a411+c['length_u32']-m)&0xffffffff))
            self.setreg(0,IR);self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_PC,ENTRY)
            self.initial=self.frame();self.initial_RAM=self.dump()
    def import_state(self,at,record):
        desc=int.from_bytes(self.ram(record+0x10,8),'little');p=int.from_bytes(self.ram(desc+8,8),'little')
        return {'pc':hex(at),'CPU':self.frame(),'record_pointer':hex(record),'record32_hex':self.ram(record,32).hex(),
          'descriptor_pointer':hex(desc),'descriptor16_hex':self.ram(desc,16).hex(),'limb_pointer':hex(p),'limb256_hex':self.ram(p,256).hex()}
    def hook(self,u,pc,n,data):
        self.flush()
        if pc==ENTRY:
            self.import_record=self.reg(0);self.import_points.append(self.import_state(pc,self.import_record))
        if pc==0x981758:self.import_points.append(self.import_state(pc,self.import_record))
        if pc==HALT:
            if self.c['mode']=='isolated':self.import_points.append(self.import_state(pc,IR))
            self.stop='returned';self.terminal=self.frame();u.emu_stop();return
        assert any(lo<=pc<hi for lo,hi in self.ranges)
        raw=self.ram(pc,4);i=next(CS.disasm(raw,pc));target=modifier=None
        if pc in [0x981104,0x981218,0x981520]:
            point={'pc':hex(pc),'CPU':self.frame()}
            if pc in [0x981104,0x981218]:point.update({'cursor_pointer':hex(self.reg(1)),'cursor_u64':hex(int.from_bytes(self.ram(self.reg(1),8),'little'))})
            else:
                at=self.u.reg_read(A.UC_ARM64_REG_SP)+0x48;point.update({'descriptor16_address':hex(at),'descriptor16_hex':self.ram(at,16).hex()})
            self.points.append(point)
        if i.mnemonic in ['braa','blraa']:
            regs=[r.strip().upper()for r in i.op_str.split(',')];target=u.reg_read(getattr(A,'UC_ARM64_REG_'+regs[0]));modifier=u.reg_read(getattr(A,'UC_ARM64_REG_'+regs[1]))
            if i.mnemonic=='blraa'and not any(lo<=target<hi for lo,hi in self.ranges):
                slots=[int(r['address'],16)for r in reversed(self.reads)if int(r['address'],16)in self.D and self.D[int(r['address'],16)].get('target')==hex(target)and self.D[int(r['address'],16)].get('diversity')==hex(modifier)];assert slots;self.used.add(slots[0])
                self.stop='unretained_callee';self.terminal=self.frame();self.frontier={'pc':hex(pc),'target':hex(target),'modifier':hex(modifier),'original_slot':hex(slots[0]),'instruction':i.mnemonic+' '+i.op_str,'instruction_executed':False,'argument_record80_hex':self.ram(self.reg(0),80).hex()};u.emu_stop();return
        self.visits.append({'phase':self.phase,'pc':hex(pc),'bytes_hex':raw.hex(),'instruction':i.mnemonic+' '+i.op_str});assert len(self.visits)<50000
        if i.mnemonic in ['pacibsp','retab','braa','blraa']:
            e={'pc':hex(pc),'kind':i.mnemonic,'before':self.frame()}
            if target is not None:
                slots=[int(r['address'],16)for r in reversed(self.reads)if r['size_B']==8 and int(r['address'],16)in self.D and self.D[int(r['address'],16)].get('target')==hex(target)and self.D[int(r['address'],16)].get('diversity')==hex(modifier)];assert slots;slot=slots[0];row=self.D[slot];assert row['key']=='IA'and row['address_diversity']==0
                e.update({'target':hex(target),'modifier':hex(modifier),'original_slot':hex(slot)})
                if i.mnemonic=='blraa':self.setreg(30,pc+4)
                u.reg_write(A.UC_ARM64_REG_PC,target)
            else:u.reg_write(A.UC_ARM64_REG_PC,self.reg(30)if i.mnemonic=='retab'else pc+4)
            self.pac.append(e)
    def run(self):
        if self.c['mode']=='nested':p=super().run()
        else:
            self.u.emu_start(ENTRY,0,count=50000);self.flush();assert self.stop=='returned'
            p={'configuration':self.c,'initial':self.initial,'initial_RAM':self.initial_RAM,'source_visits':self.visits,
              'source_reads':self.reads,'source_writes':self.writes,'PAC_models':self.pac,'CPU_points':self.points,
              'terminal':self.terminal,'final_RAM':self.dump(),'stop_reason':self.stop,'frontier':None,
              'used_original_pointer_rows':[self.D[a]for a in sorted(self.used)],'native_effects':False}
        p['import_points']=self.import_points;return p


def configurations():
    base=next(prior_configurations())
    for n in [0,1,2,3,4,5,7,8,15,16,17,31,32,33,127,128,129,255,256]:
        for pattern in ['zero','sequence','one']:
            data=bytes(n)if pattern=='zero'else bytes((j*37+11)&255 for j in range(n))if pattern=='sequence'else(bytes(n-1)+b'\1'if n else b'')
            yield {**base,'label':'isolated_'+str(n)+'_'+pattern,'mode':'isolated','length_u32':n,'input_hex':data.hex(),'null_input':False}
    for n in [257,0xffffffff]:yield {**base,'label':'rejected_'+hex(n),'mode':'isolated','length_u32':n,'input_hex':'','null_input':True}
    yield {**base,'label':'empty_NULL','mode':'isolated','length_u32':0,'input_hex':'','null_input':True}
    for c in prior_configurations():
        if c['control']in ['as_staged','null_auxiliary']:yield {**c,'label':'nested_'+c['label'],'mode':'nested'}


def proofs():
    n=z3.BitVec('length',32);a=n-257;summ=z3.ZeroExt(1,a)+258
    hi=z3.And(z3.Extract(32,32,summ)==1,z3.Extract(31,0,summ)!=0)
    w=z3.BitVec('limb',32);encoded=w-(0x358e1de4&(w<<1))+0x1ac70ef2
    q=[]
    for name,claim in [('length_all_u32',hi==z3.ULE(n,256)),('limb_XOR_all_u32',encoded==(w^0x1ac70ef2))]:
        s=z3.Solver();s.set(timeout=30000);s.add(z3.Not(claim));result=str(s.check());assert result=='unsat';q.append({'label':name,'query':s.sexpr()+'\n(check-sat)\n','result':result,'timeout_ms':30000})
    return q


def main():
    code,banks,D=prior_sources();att=json.loads(read(ROOT/'fpsd1201_import_ida_readback.json'))
    code.append({**att['spans'][0],'role':'byte_importer'});file_check=local_reference(code,banks,D)
    profiles=[Execute(c,code,banks,D).run()for c in configurations()]
    counts={'profiles':len(profiles),'isolated_profiles':sum(p['configuration']['mode']=='isolated'for p in profiles),
      'nested_profiles':sum(p['configuration']['mode']=='nested'for p in profiles),'source_visits':sum(len(p['source_visits'])for p in profiles),
      'source_reads':sum(len(p['source_reads'])for p in profiles),'source_writes':sum(len(p['source_writes'])for p in profiles),
      'PAC_models':sum(len(p['PAC_models'])for p in profiles),'import_CPU_points':sum(len(p['import_points'])for p in profiles),
      'fresh_IDA_spans':1,'fresh_IDA_bytes':1240,'source_code_bytes':5348,'local_queries_unsat':2}
    out={'scope':__doc__,'code_spans':code,'profiles':profiles,'proofs':proofs(),'reference_file_check':file_check,
      'dependencies':{n:digest(read(ROOT/n).encode())for n in DEPS},'generator_sha256':digest(Path(__file__).read_bytes()),
      'IDA_readback_sha256':digest(read(ROOT/'fpsd1201_import_ida_readback.json').encode()),'verified_counts':counts,
      'whole_parent_replayed':False,'native_target_executed':False,'IDB_edit_operations_requested':False,'full_goal_complete':False}
    (ROOT/'fpsd1201_import_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts))


if __name__=='__main__':main()
