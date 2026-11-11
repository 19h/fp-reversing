#!/usr/bin/env python3
"""Independent importer oracle and original nested continuation replay.

Uses the frozen predecessor auditor for CPU/journal mechanics, never the new
producer. Independent initial fixtures, big-endian integer/limb oracles and
source flag queries distinguish importer success from whole-operation success.
O(C*(B+F+V+P*J+R)) time; O(B+F+C*(V+J+P+R)) space; SMT separate.
"""
import json,struct,zlib,base64
from pathlib import Path
from hashlib import sha256
from collections import Counter
import z3
from unicorn import arm64_const as A
from audit_fpsd1201_record import Replay as Previous,source_and_proofs,unpack,CS,STACK,OWNER,CONTEXT,HALT,SP,FP,RAM,ROOT
from verify_daemon_reader_record_payloads_publication import read

ENTRY=0x17bbb8;END=0x17c090;IR=FP+0x100;INPUT=OWNER+0x400;DESC=OWNER+0x800;LIMBS=OWNER+0x1000
COUNT_BASE=0x4b0cf050;LIMB_XOR=0x1ac70ef2;SHA=lambda b:sha256(b).hexdigest()


class Replay(Previous):
    def __init__(self,p,old,code,banks,D):
        # The frozen baseline validates the inherited constructor-entry fixture.
        super().__init__(p if p['configuration']['mode']=='nested'else old['profiles'][0],code[:-1],banks,D)
        self.p=p;self.c=p['configuration'];self.ii=0;self.oracle=None
        self.u.mem_map(0x17b000,8192);r=code[-1];self.u.mem_write(ENTRY,bytes.fromhex(r['bytes_hex']));self.ranges.append((ENTRY,END))
        if self.c['mode']=='isolated':
            c=self.c;self.phase='isolated';self.stats=Counter()
            self.u.mem_write(INPUT,bytes.fromhex(c['input_hex']));self.u.mem_write(DESC,struct.pack('<IIQ',64,COUNT_BASE,LIMBS))
            p32=IR&0xffffffff;m=((~(p32^0x7232c2dc)^0xfd8e9ed9)*0x4ecee2ad)&0xffffffff
            self.u.mem_write(IR,(0x66dc^m).to_bytes(4,'little'));self.u.mem_write(IR+8,struct.pack('<QQ',0 if c['null_input']else INPUT,DESC))
            self.u.mem_write(IR+0x1c,((0x62b6a411+c['length_u32']-m)&0xffffffff).to_bytes(4,'little'))
            self.setreg(0,IR);self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_PC,ENTRY)
            self.frame(p['initial'])
            assert len(p['initial_RAM'])==3
            for row,(a,n)in zip(p['initial_RAM'],RAM):assert row['address']==hex(a)and unpack(row['payload'])==self.ram(a,n)
    def import_point(self,pc):
        point=self.p['import_points'][self.ii];self.ii+=1;self.frame(point['CPU'])
        record=self.reg(0)if pc==ENTRY else self.oracle['record']
        raw=self.ram(record,32);desc=int.from_bytes(raw[16:24],'little');d=self.ram(desc,16);dst=int.from_bytes(d[8:],'little');limbs=self.ram(dst,256)
        assert {k:v for k,v in point.items()if k!='CPU'}=={'pc':hex(pc),'record_pointer':hex(record),'record32_hex':raw.hex(),
          'descriptor_pointer':hex(desc),'descriptor16_hex':d.hex(),'limb_pointer':hex(dst),'limb256_hex':limbs.hex()}
        if pc==ENTRY:
            p=record&0xffffffff;m=((~(p^0x7232c2dc)^0xfd8e9ed9)*0x4ecee2ad)&0xffffffff
            length=(int.from_bytes(raw[28:32],'little')+m-0x62b6a411)&0xffffffff
            assert int.from_bytes(raw[:4],'little')^m==0x66dc
            src=int.from_bytes(raw[8:16],'little');data=self.ram(src,length)if 0<length<=256 else b''
            self.oracle={'record':record,'raw':raw,'desc':desc,'descriptor':d,'dst':dst,'before_limbs':limbs,
              'src':src,'data':data,'length':length,'read_index':self.r,'write_index':self.w}
        else:
            o=self.oracle;n=o['length'];valid=n<=256
            assert int.from_bytes(raw[24:28],'little')==(0xba1df9db if valid else 0x45e2a205)
            assert raw[:24]==o['raw'][:24]and raw[28:]==o['raw'][28:]
            reads=self.p['source_reads'][o['read_index']:self.r]
            byte_reads=[r for r in reads if self.p['source_visits'][r['visit']]['pc']=='0x17bde0']
            assert [(int(r['address'],16),r['size_B'])for r in byte_reads]==[(o['src']+i,1)for i in reversed(range(n))]if valid else not byte_reads
            if valid:
                data=o['data'];value=int.from_bytes(data,'big');count=(value.bit_length()+31)//32
                assert int.from_bytes(d[4:8],'little')==(COUNT_BASE+count)&0xffffffff
                assert d[:4]==o['descriptor'][:4]and d[8:]==o['descriptor'][8:]
                expected=bytearray(o['before_limbs']);written=(n+3)//4
                for j in range(written):expected[j*4:j*4+4]=(((value>>(32*j))&0xffffffff)^LIMB_XOR).to_bytes(4,'little')
                assert limbs==expected
                self.stats['limb_values_checked']+=written;self.stats['input_bytes_checked']+=n
            else:assert d==o['descriptor']and limbs==o['before_limbs']
            self.stats['importer_outcomes_checked']+=1
    def hook(self,u,pc,n,data):
        if pc in [ENTRY,0x981758]or(pc==HALT and self.c['mode']=='isolated'):self.import_point(pc)
        # The inherited auditor's old frontier was before this importer. The
        # new frontier is verified here without claiming that call executes.
        if pc==0x98189c:
            self.flush();e=self.p['frontier'];self.frame(self.p['terminal']);self.stop='unretained_callee'
            assert e=={'pc':'0x98189c','target':'0x14fac64','modifier':'0xb1e','original_slot':'0x1d05948',
              'instruction':'blraa x8, x17','instruction_executed':False,'argument_record80_hex':self.ram(self.reg(0),80).hex()}
            assert self.reg(8)==0x14fac64 and self.reg(17)==0xb1e;self.used.add(0x1d05948);u.emu_stop();return
        super().hook(u,pc,n,data)
    def run(self):
        if self.c['mode']=='nested':result=super().run()
        else:
            self.u.emu_start(ENTRY,0,count=50000);self.flush();assert self.stop=='returned'
            assert self.v==len(self.p['source_visits'])and self.r==len(self.p['source_reads'])and self.w==len(self.p['source_writes'])and self.pi==len(self.p['PAC_models'])and not self.p['CPU_points']
            assert self.u.reg_read(A.UC_ARM64_REG_SP)==SP
            for row,(a,n)in zip(self.p['final_RAM'],RAM):assert row['address']==hex(a)and unpack(row['payload'])==self.ram(a,n);self.stats['complete_final_RAM_bytes_checked']+=n
            assert len(self.p['final_RAM'])==3 and self.p['used_original_pointer_rows']==[self.D[a]for a in sorted(self.used)]
            for r in self.p['used_original_pointer_rows']:
                assert not r['bind'];w=int(r['word'],16);target=w&0xffffffff if w>>63 else(w&((1<<43)-1))|(((w>>43)&255)<<56)
                assert target==int(r['target'],16);self.stats['original_pointer_profile_associations_checked']+=1
            self.stats.update({'original_visits_checked':self.v,'original_reads_checked':self.r,'original_writes_checked':self.w,'PAC_models_checked':self.pi})
            result=self.stats
        assert self.ii==len(self.p['import_points'])==2
        return result


def reference_and_source(e,old):
    att=json.loads(read(ROOT/'fpsd1201_import_ida_readback.json'));r=att['spans'][0]
    assert len(att['spans'])==1 and r['start']=='0x17bbb8'and r['size_B']==1240
    b=bytes.fromhex(r['bytes_hex']);assert SHA(b)==r['sha256']==r['original_sha256']=='43ecb5a423f86b154cf35ba2fe2dc900d91ff003ed7d4e708426d03c797cb93c'
    assert r['current_equals_IDA_original_bytes']and not att['IDB_mutated']and not att['native_target_executed']
    assert e['code_spans'][:-1]==old['code_spans']and e['code_spans'][-1]=={**r,'role':'byte_importer'}
    # Fresh original file verification is independent of the producer reader.
    raw=(ROOT.parent/'CoreFP').read_bytes();assert SHA(raw)==att['input_sha256']=='68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f'
    selected=None
    for j in range(int.from_bytes(raw[4:8],'big')):
        cpu,sub,off,n,align=struct.unpack_from('>IIIII',raw,8+20*j)
        if (cpu,sub)==(0x100000c,0x80000002):selected=raw[off:off+n];break
    assert selected is not None and SHA(selected)=='8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c'
    segments=[];at=32;function_blob=None
    for j in range(struct.unpack_from('<I',selected,16)[0]):
        cmd,n=struct.unpack_from('<II',selected,at)
        if cmd==0x19:
            name,vm,vs,fo,fs=struct.unpack_from('<16s4Q',selected,at+8);segments.append({'name':name.rstrip(b'\0').decode(),'vm':vm,'vm_size_B':vs,'file_offset':fo,'file_size_B':fs})
        if cmd==0x26:
            pos,size=struct.unpack_from('<II',selected,at+8);function_blob=selected[pos:pos+size]
        at+=n
    def source(address,n):
        s=next(s for s in segments if s['vm']<=address<address+n<=s['vm']+s['file_size_B']);p=s['file_offset']+address-s['vm'];return selected[p:p+n]
    D={int(r['address'],16):r for r in json.loads(read(ROOT/'corefp_fixups_inventory.json'))['fixups']}
    for a,r in D.items():assert int.from_bytes(source(a,8),'little')==int(r['word'],16)
    for r in e['code_spans']:assert source(int(r['start'],16),len(bytes.fromhex(r['bytes_hex'])))==bytes.fromhex(r['bytes_hex'])
    parent=next(r for r in json.loads(read(ROOT/'fpsd1201_caller_ida_readback.json'))['spans']if r['role']=='parent')
    parent_bytes=bytes.fromhex(parent['bytes_hex']);assert source(int(parent['start'],16),len(parent_bytes))==parent_bytes
    bankbytes={}
    for bank in json.loads(read(ROOT/'corefp_lookup_contracts.json'))['banks']:
        for ak,bk in [('first_address','first_bytes'),('second_address','second_bytes')]:
            address=int(bank[ak],16);data=bytes.fromhex(bank[bk]);assert source(address,len(data))==data;bankbytes[address]=data
    starts=[];pc=0;acc=0;shift=0
    for v in function_blob:
        acc+=(v&127)<<shift
        if v&128:shift+=7;continue
        if not acc:break
        pc+=acc;starts.append(hex(pc));acc=shift=0
    assert starts==json.loads(read(ROOT/'corefp_library_inventory.json'))['compiler_function_starts']
    assert starts[starts.index(hex(ENTRY))+1]==hex(END)
    f=e['reference_file_check'];assert f['universal_sha256']==SHA(raw)and f['arm64e_sha256']==SHA(selected)and f['universal_size_B']==len(raw)and f['selected_slice_offset']==off and f['selected_slice_size_B']==len(selected)
    assert f['segments']==segments and f['compiler_function_starts_blob_sha256']==SHA(function_blob)
    assert f['original_fixup_words_checked']==len(D)==79512 and f['all_original_fixup_words_equal']and f['compiler_function_starts_equal']and f['compiler_function_starts_count']==len(starts)==1602
    assert f['code_bytes_checked']==5348 and not f['native_target_executed']
    assert f['earlier_parent_bytes_checked']==len(parent_bytes)==85464 and f['earlier_parent_sha256']==SHA(parent_bytes)=='4e0ebb4383ce0f3d074358e851dd1bdfff67e77d675e0cfa9e73b4a03ff9a94e'
    assert f['bank_bytes_checked']==sum(len(v)for v in bankbytes.values())
    ins={i.address:i for i in CS.disasm(b,ENTRY)}
    exact={0x17bc34:('orr','w10, w0, w8'),0x17bc38:('and','w8, w0, w8'),0x17bc3c:('orn','w8, w8, w10'),
      0x17bc48:('eor','w8, w8, w10'),0x17bc54:('mul','w8, w8, w10'),0x17bc58:('ldr','w10, [x0]'),
      0x17bc5c:('eor','w14, w10, w8'),0x17bc60:('ldr','w10, [x0, #0x1c]'),0x17bc6c:('add','w6, w10, w8'),
      0x17bc70:('add','w8, w6, w15'),0x17bc74:('cmn','w8, #0x102'),0x17bc78:('cset','w8, hi'),
      0x17bde0:('ldrb','w17, [x10, w17, uxtw]'),0x17bde8:('lsl','w17, w17, w1'),
      0x17be90:('str','w17, [x7, w15, sxtw #2]'),0x17bf24:('str','w10, [x12, w13, sxtw #2]'),
      0x17c000:('cmp','w17, w5'),0x17c054:('str','w10, [x9, #4]'),0x17c06c:('str','w9, [x0, #0x18]')}
    for pc,want in exact.items():assert (ins[pc].mnemonic,ins[pc].op_str)==want
    for q in e['proofs']:
        s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_string(q['query']));assert str(s.check())==q['result']=='unsat'
    n=z3.BitVec('independent_length',32);a=n+z3.BitVecVal(0xfffffeff,32)
    carry=z3.Not(z3.BVAddNoOverflow(a,z3.BitVecVal(258,32),False));zero=(a+258)==0
    x=z3.BitVec('independent_limb',32)
    for claim in [z3.And(carry,z3.Not(zero))==z3.ULE(n,256),(x-2*(x&0x1ac70ef2)+0x1ac70ef2)==(x^0x1ac70ef2)]:
        s=z3.Solver();s.set(timeout=30000);s.add(z3.Not(claim));assert s.check()==z3.unsat
    return D,{'fresh_IDA_spans':1,'fresh_IDA_bytes':1240,'original_file_code_bytes':5348,
      'earlier_parent_file_bytes':85464,'original_file_bank_bytes':sum(len(v)for v in bankbytes.values()),
      'original_file_fixup_words':79512,'compiler_function_starts':1602,'exact_source_instructions_checked':len(exact),
      'retained_queries_unsat':2,'independent_local_queries_unsat':2}


def main():
    e=json.loads(read(ROOT/'fpsd1201_import_checks.json'));old=json.loads(read(ROOT/'fpsd1201_record_checks.json'))
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    assert e['generator_sha256']==SHA((ROOT/'recover_fpsd1201_import.py').read_bytes())and e['IDA_readback_sha256']==SHA(read(ROOT/'fpsd1201_import_ida_readback.json').encode())
    banks,D,prior=source_and_proofs(old);D2,source=reference_and_source(e,old);assert D==D2
    for a,b in banks.items():assert len(b)==256
    expected=[]
    for n in [0,1,2,3,4,5,7,8,15,16,17,31,32,33,127,128,129,255,256]:
        for pattern in ['zero','sequence','one']:
            data=bytes(n)if pattern=='zero'else bytes((j*37+11)&255 for j in range(n))if pattern=='sequence'else(bytes(n-1)+b'\1'if n else b'')
            expected.append((n,data.hex(),False))
    expected.extend([(257,'',True),(0xffffffff,'',True),(0,'',True)])
    isolated=[p for p in e['profiles']if p['configuration']['mode']=='isolated'];nested=[p for p in e['profiles']if p['configuration']['mode']=='nested']
    assert [(p['configuration']['length_u32'],p['configuration']['input_hex'],p['configuration']['null_input'])for p in isolated]==expected
    assert [(p['configuration']['seed_u64'],p['configuration']['control'])for p in nested]==[(s,c)for s in [0,1,0xffffffffffffffff,0x0123456789abcdef]for c in ['as_staged','null_auxiliary']]
    totals=Counter()
    for p in e['profiles']:totals.update(Replay(p,old,e['code_spans'],banks,D).run())
    assert not any(e[k]for k in ['whole_parent_replayed','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    result={'source':source,'pinned_predecessor_source':prior,'fresh_replay':dict(totals),'profiles':68,'isolated_profiles':60,
      'nested_profiles':8,'next_unretained_target':'0x14fac64','whole_parent_replayed':False,
      'native_target_executed':False,'full_goal_complete':False,'all_checks_pass':True}
    receipt={'result':result,'dependencies':e['dependencies'],'checks_sha256':SHA(read(ROOT/'fpsd1201_import_checks.json').encode()),
      'IDA_readback_sha256':e['IDA_readback_sha256'],'auditor_sha256':SHA(Path(__file__).read_bytes()),
      'fresh_replay_completed':True,'process_exit_code':0,'native_target_executed':False}
    (ROOT/'fpsd1201_import_audit.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(result))


if __name__=='__main__':main()
