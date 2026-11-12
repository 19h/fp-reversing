#!/usr/bin/env python3
"""Independent source, export-byte, status-flow and complete-return audit.

Never imports the new producer. Fresh CPU/RAM replay checks every original
journal entry, declared input change, selected byte and retained CPU frame.
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
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();M=0xffffffff;K=0x1ac70ef2;BASE=0x4b0cf050
ENTRY=0x32f628;RET=0x32f950;IR=FP+0x100;DESC=OWNER+0x800;PAYLOAD=OWNER+0x1000;DEST=OWNER+0x2000
PRIOR_SHA='623b257cc3ccb1e670cad46a50615f43d21cf6e0abbad4ae9cb80c7f0ea80084'


class Replay(Core):
    def __init__(self,p,prior,code,banks,D):
        self.p=p;self.c=p['configuration'];self.D=D;self.v=self.r=self.w=self.pi=self.ci=self.ei=self.ri=0;self.pending=[];self.stats=Counter();self.used=set();self.phase='export_'+self.c['mode'];self.byte_index=0;self.outcome=None
        self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.ranges=[(int(s['start'],16),int(s['start'],16)+len(bytes.fromhex(s['bytes_hex'])))for s in code];pages=set()
        for a,b in self.ranges+[(a,a+len(b))for a,b in banks.items()]+[(a,a+n)for a,n in RAM]+[(0x1c80000,0x1d20000),(HALT,HALT+4096)]:pages.update(range(a&~4095,(b+4095)&~4095,4096))
        for a in sorted(pages):self.u.mem_map(a,4096)
        for s in code:self.u.mem_write(int(s['start'],16),bytes.fromhex(s['bytes_hex']))
        for a,b in banks.items():self.u.mem_write(a,b)
        for a,row in D.items():
            if 0x1c80000<=a<a+8<=0x1d20000 and not row['bind']:self.u.mem_write(a,int(row['target'],16).to_bytes(8,'little'))
        self.u.mem_write(0x1d1c578,(0x1d43300).to_bytes(8,'little'));self.u.reg_write(A.UC_ARM64_REG_CPACR_EL1,3<<20)
        for row,(a,n)in zip(prior['final_RAM'],RAM):
            b=unpack(row['payload']);assert row['address']==hex(a)and len(b)==n;self.u.mem_write(a,b);self.stats['restored_RAM_bytes_checked']+=n
        f=prior['terminal'];assert f['pc']=='0x981bc8'
        for j,v in enumerate(f['registers31']):self.setreg(j,int(v,16))
        for name,key in [('SP','sp'),('PC','pc'),('NZCV','NZCV')]:self.u.reg_write(getattr(A,'UC_ARM64_REG_'+name),int(f[key],16))
        for j,v in enumerate(f['Q32']):self.u.reg_write(A.UC_ARM64_REG_Q0+j,int(v,16))
        self.root_count=int.from_bytes(self.ram(RECORD+16,8),'little');controls=[]
        def patch(a,b):controls.append({'address':hex(a),'before_hex':self.ram(a,len(b)).hex(),'after_hex':b.hex()});self.u.mem_write(a,b)
        c=self.c
        if c['mode']in ['retained','short_export']:
            self.argument=self.reg(0);self.entry=0x981bc8
            j=p['checkpoint_pointer_load']['prior_read_index'];r=prior['source_reads'][j];v=prior['source_visits'][r['visit']]
            assert p['checkpoint_pointer_load']=={'prior_read_index':j,'read':r,'source_visit':v}and(r['address'],r['size_B'],r['bytes_hex'])==('0x1d03d10',8,ENTRY.to_bytes(8,'little').hex())
            assert self.ram(int(v['pc'],16),4).hex()==v['bytes_hex'];self.stats['checkpoint_reaching_loads_checked']+=1
            if c['mode']=='short_export':
                h=((self.argument^0xd97ffe38)*0xfcf33521)&M;patch(self.argument+20,((h+0x2647dd39+c['length_B'])&M).to_bytes(4,'little'))
        else:
            assert p['checkpoint_pointer_load']is None and c['mode']in ['isolated','minimum_count']
            if c['mode']=='isolated':
                v=int(c['value_hex'],16);count=c['sign']*((v.bit_length()+31)//32+c['leading_zero_limbs']);ptr=PAYLOAD
                for j in range(abs(count)):patch(ptr+4*j,(((v>>(32*j))&M)^K).to_bytes(4,'little'))
            else:count=-2147483648;ptr=0
            patch(DESC,struct.pack('<IIQ',130,(BASE+count)&M,ptr));h=((IR^0xd97ffe38)*0xfcf33521)&M
            dst=0 if c.get('null_destination')else DEST;patch(IR,struct.pack('<QQIII',dst,DESC,h^0x80e8,(h+0x2647dd39+c['length_B'])&M,0xa5a5a5a5))
            self.argument=IR;self.entry=ENTRY;self.setreg(0,IR);self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_SP,SP);self.u.reg_write(A.UC_ARM64_REG_PC,ENTRY)
        assert controls==p['operand_controls'];self.frame(p['initial'])
        for row,(a,n)in zip(p['initial_RAM'],RAM):assert row['address']==hex(a)and unpack(row['payload'])==self.ram(a,n);self.stats['initial_RAM_bytes_checked']+=n
        self.u.hook_add(uc.UC_HOOK_CODE,self.hook);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.readhook);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.writehook)
    def view(self,pc):
        r=self.argument;raw=self.ram(r,28);d=int.from_bytes(raw[8:16],'little');desc=self.ram(d,16);cnt=(int.from_bytes(desc[4:8],'little')-BASE)&M;cnt=cnt-(1<<32)if cnt>>31 else cnt;ptr=int.from_bytes(desc[8:],'little');dst=int.from_bytes(raw[:8],'little')
        valid=abs(cnt)<=130 and any(a<=ptr<=ptr+4*abs(cnt)<=a+n for a,n in RAM)
        return {'pc':hex(pc),'record_pointer':hex(r),'record28_hex':raw.hex(),'descriptor_pointer':hex(d),'descriptor16_hex':desc.hex(),
          'active_payload_hex':self.ram(ptr,4*abs(cnt)).hex()if valid else None,'destination_pointer':hex(dst),'destination1024_hex':self.ram(dst,1024).hex()if dst else None}
    def export(self,pc):
        e=self.p['export_points'][self.ei];self.ei+=1;self.frame(e['CPU']);actual=self.view(pc);assert actual=={k:v for k,v in e.items()if k!='CPU'}
        raw=bytes.fromhex(e['record28_hex']);r=self.argument
        if pc==ENTRY:
            self.before=e;h=((r^0xd97ffe38)*0xfcf33521)&M;assert int.from_bytes(raw[16:20],'little')^h==0x80e8
            self.length=(int.from_bytes(raw[20:24],'little')-h+0xd9b822c7)&M;self.dst=int(e['destination_pointer'],16)
            desc=bytes.fromhex(e['descriptor16_hex']);count=(int.from_bytes(desc[4:8],'little')-BASE)&M;count=count-(1<<32)if count>>31 else count;self.count=count
            self.accepted=count!=-2147483648 and self.length>=4*abs(count)
            if count!=-2147483648:
                payload=bytes.fromhex(e['active_payload_hex']);self.magnitude=sum((int.from_bytes(payload[4*j:4*j+4],'little')^K)<<(32*j)for j in range(abs(count)))
            else:self.magnitude=None
            self.expected=self.magnitude.to_bytes(self.length,'big')if self.accepted else b''
        else:
            before=self.before;old=bytes.fromhex(before['record28_hex']);status=0xba1df9db if self.accepted else 0x45e2a205
            assert raw==old[:24]+status.to_bytes(4,'little')and before['descriptor16_hex']==e['descriptor16_hex']and before['active_payload_hex']==e['active_payload_hex']
            if self.dst:
                oldout=bytes.fromhex(before['destination1024_hex']);assert bytes.fromhex(e['destination1024_hex'])==self.expected+oldout[len(self.expected):]
            else:assert self.length==0 and self.accepted and e['destination1024_hex']is None
            assert e['CPU']['sp']==before['CPU']['sp']and e['CPU']['registers31'][19:]==before['CPU']['registers31'][19:]and e['CPU']['Q32']==before['CPU']['Q32']
            assert self.byte_index==(self.length if self.accepted else 0)
            stores=[w for w in self.p['source_writes'][:self.w]if self.p['source_visits'][w['visit']]['pc']=='0x32f880']
            assert len(stores)==len(self.expected)
            for j,w in enumerate(stores):assert w['size_B']==1 and int(w['address'],16)==self.dst+self.length-1-j and w['after_hex']==self.expected[self.length-1-j:self.length-j].hex()
            statusstores=[w for w in self.p['source_writes'][:self.w]if w['address']==hex(r+24)];assert len(statusstores)==1 and statusstores[0]['size_B']==4 and statusstores[0]['after_hex']==status.to_bytes(4,'little').hex()
            assert self.p['source_visits'][statusstores[0]['visit']]['pc']=='0x32f930';self.ret_visit=self.v
            if not self.accepted:assert not any(v['pc']=='0x32f910'for v in self.p['source_visits'][:self.v]);self.stats['rejected_without_payload_read']+=1
            self.stats['complete_export_returns_checked']+=1;self.stats['admitted_exports_checked'if self.accepted else'rejected_exports_checked']+=1
            self.outcome={'mode':self.c['mode'],'decoded_count_i32':self.count,'length_B':self.length,'accepted':self.accepted,'status_u32':hex(status),
              'magnitude_hex':hex(self.magnitude)if self.magnitude is not None else None,'exported_bytes':len(self.expected),'native_effects':False}
    def root(self,pc):
        e=self.p['root_points'][self.ri];self.ri+=1;self.frame(e['CPU']);actual={'pc':hex(pc),'record80_hex':self.ram(RECORD,80).hex(),'count_pointer':hex(self.root_count),'count_u32':int.from_bytes(self.ram(self.root_count,4),'little'),
          'delta_cell_u64':hex(int.from_bytes(self.ram(OUT,8),'little')),'candidate128_hex':self.ram(OWNER+0x880,128).hex()}
        assert actual=={k:v for k,v in e.items()if k!='CPU'}
        if pc==HALT:
            assert int.from_bytes(bytes.fromhex(e['record80_hex'])[48:52],'little')==0xba1df9db and e['delta_cell_u64']=='0x0'and e['count_u32']==8
            assert e['CPU']['sp']==hex(SP);self.stats['complete_root_helper_returns_checked']+=1
        self.stats['root_points_checked']+=1
    def hook(self,u,pc,n,data):
        self.flush()
        if pc in [ENTRY,RET]:self.export(pc)
        if pc==0x32f880:
            offset=self.length-1-self.byte_index;assert self.accepted and offset>=0 and self.reg(17)==self.dst
            assert((self.reg(11)+self.reg(8))&M)==offset and self.reg(28)&255==self.expected[offset]
            assert self.reg(26)==0x32fa and self.reg(16)==8*(self.byte_index%4)
            word=(self.magnitude>>(32*(self.byte_index//4)))&M;assert self.reg(24)^K==word and self.reg(28)==word>>(8*(self.byte_index%4))
            self.byte_index+=1;self.stats['writer_byte_oracles_checked']+=1
        if pc in [0x981be0,0x981bf8,0x981c30,0x981e54,0x981e68]or pc==HALT and self.c['mode']in ['retained','short_export']:self.root(pc)
        if pc==0x981bc8 and self.v==0:
            assert self.p['source_visits'][0]=={'phase':self.phase,'pc':hex(pc),'bytes_hex':self.ram(pc,4).hex(),'instruction':'blraa x8, x17'};self.v+=1
            e=self.p['PAC_models'][self.pi];self.pi+=1;self.frame(e['before']);assert e=={'pc':hex(pc),'kind':'blraa','before':self.p['initial'],'target':hex(ENTRY),'modifier':'0xa77e','original_slot':'0x1d03d10'}
            row=self.D[0x1d03d10];assert(row['target'],row['diversity'],row['key'],row['address_diversity'])==(hex(ENTRY),'0xa77e','IA',0)
            assert(self.reg(8),self.reg(17))==(ENTRY,0xa77e);self.used.add(0x1d03d10);self.setreg(30,pc+4);u.reg_write(A.UC_ARM64_REG_PC,ENTRY);return
        Core.hook(self,u,pc,n,data)
    def run(self):
        self.u.emu_start(self.entry,0,count=500000);self.flush();assert self.stop==self.p['stop_reason']=='returned'and self.p['frontier']is None
        assert(self.v,self.r,self.w,self.pi,self.ci)==tuple(len(self.p[k])for k in ['source_visits','source_reads','source_writes','PAC_models','CPU_points'])and self.ei==len(self.p['export_points'])==2 and self.ri==len(self.p['root_points'])
        assert self.outcome is not None and self.p['used_original_pointer_rows']==[self.D[a]for a in sorted(self.used)]
        for row in self.p['used_original_pointer_rows']:
            if row['bind']:assert row['import']['name']=='___stack_chk_guard';continue
            word=int(row['word'],16);target=word&M if word>>63 else(word&((1<<43)-1))|(((word>>43)&255)<<56);assert target==int(row['target'],16)
            if word>>63:assert word>>49&3==0 and word>>32&65535==int(row['diversity'],16)and word>>48&1==row['address_diversity']
            self.stats['original_pointer_profile_associations_checked']+=1
        for row,(a,n)in zip(self.p['final_RAM'],RAM):assert row['address']==hex(a)and unpack(row['payload'])==self.ram(a,n);self.stats['final_RAM_bytes_checked']+=n
        assert not self.p['native_effects']
        if self.c['mode']in ['retained','short_export']:
            assert len(self.p['root_points'])==6
            assert not any(int(r['address'],16)<self.argument+28 and self.argument+24<int(r['address'],16)+r['size_B']for r in self.p['source_reads']if r['visit']>self.ret_visit)
            self.stats['unread_export_statuses_checked']+=1
            for address,size,pc,after in [(self.root_count,4,'0x981be0',(8).to_bytes(4,'little')),(RECORD+48,4,'0x981bf8',(0xba1df9db).to_bytes(4,'little')),(OUT,8,'0x981e54',b'\0'*8)]:
                writes=[w for w in self.p['source_writes']if int(w['address'],16)<address+size and address<int(w['address'],16)+w['size_B']]
                assert len(writes)==1 and writes[0]['address']==hex(address)and writes[0]['size_B']==size and writes[0]['after_hex']==after.hex()and self.p['source_visits'][writes[0]['visit']]['pc']==pc
                self.stats['root_publication_stores_checked']+=1
            self.outcome['root_success_despite_export_rejection']=not self.accepted
            if not self.accepted:self.stats['short_export_status_nonpropagation_controls']+=1
        self.stats.update({'original_visits_checked':self.v,'original_reads_checked':self.r,'original_writes_checked':self.w,'PAC_models_checked':self.pi})
        return self.stats,self.outcome


def source(e,old):
    assert e['code_spans'][:25]==old['code_spans'];att=json.loads(read(ROOT/'fpsd1201_export_ida_readback.json'));assert not att['IDB_mutated']and not att['native_target_executed']and len(att['spans'])==1
    raw=(ROOT.parent/'CoreFP').read_bytes();assert SHA(raw)==att['input_sha256']=='68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f'
    slices=[struct.unpack_from('>5I',raw,8+20*j)for j in range(struct.unpack_from('>I',raw,4)[0])];_,_,off,n,_=next(s for s in slices if s[:2]==(0x100000c,0x80000002));thin=raw[off:off+n]
    assert SHA(thin)=='8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c';at=32;segments=[]
    for j in range(struct.unpack_from('<I',thin,16)[0]):
        cmd,n=struct.unpack_from('<II',thin,at)
        if cmd==0x19:
            _,vm,vs,fo,fs=struct.unpack_from('<16s4Q',thin,at+8);segments.append((vm,fo,fs))
        if cmd==0x26:fo,fs=struct.unpack_from('<II',thin,at+8);blob=thin[fo:fo+fs]
        at+=n
    def get(a,n):
        vm,fo,fs=next(s for s in segments if s[0]<=a<a+n<=s[0]+s[2]);return thin[fo+a-vm:fo+a-vm+n]
    starts=[];pc=value=shift=0
    for byte in blob:
        value|=(byte&127)<<shift
        if byte&128:shift+=7;continue
        if not value:break
        pc+=value;starts.append(hex(pc));value=shift=0
    assert starts==json.loads(read(ROOT/'corefp_library_inventory.json'))['compiler_function_starts']
    for s in e['code_spans']:assert get(int(s['start'],16),len(bytes.fromhex(s['bytes_hex'])))==bytes.fromhex(s['bytes_hex'])
    row=att['spans'][0];b=bytes.fromhex(row['bytes_hex']);assert(row['start'],row['end_exclusive'],row['size_B'])==('0x32f628','0x32f954',812)
    assert SHA(b)==row['sha256']==row['original_sha256']=='479eee35468a4630dbbe4ba06f5144ac2529d82fc9b3406fa2db0c33d14de254'and row['current_equals_IDA_original_bytes']
    assert e['code_spans'][25]=={**row,'role':'fixed_width_big_endian_export'}and starts[starts.index('0x32f628')+1]=='0x32f954'
    banks={}
    for row in json.loads(read(ROOT/'corefp_lookup_contracts.json'))['banks']:
        for ak,bk in [('first_address','first_bytes'),('second_address','second_bytes')]:
            a=int(row[ak],16);b=bytes.fromhex(row[bk]);assert a not in banks or banks[a]==b;banks[a]=b
    for a,b in banks.items():assert get(a,len(b))==b
    D={int(r['address'],16):r for r in json.loads(read(ROOT/'corefp_fixups_inventory.json'))['fixups']}
    for a,row in D.items():assert int.from_bytes(get(a,8),'little')==int(row['word'],16)
    parent=next(s for s in json.loads(read(ROOT/'fpsd1201_caller_ida_readback.json'))['spans']if s['role']=='parent');b=bytes.fromhex(parent['bytes_hex']);assert get(int(parent['start'],16),len(b))==b
    ins={i.address:(i.mnemonic,i.op_str)for i in CS.disasm(b,int(parent['start'],16))}
    ins.update({i.address:(i.mnemonic,i.op_str)for row in e['code_spans']for i in CS.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16))})
    exact={0x32f6d0:('ldr','x9, [x0, #8]'),0x32f6f0:('ldp','w13, w1, [x0, #0x10]'),0x32f708:('cmp','x17, w10, sxtw #2'),0x32f70c:('cset','w17, hs'),
      0x32f880:('strb','w28, [x17, w30, uxtw]'),0x32f8dc:('cmp','w14, w10'),0x32f910:('ldr','w24, [x17, w14, sxtw #2]'),0x32f930:('str','w26, [x0, #0x18]'),0x32f950:('retab',''),
      0x981be0:('str','w9, [x8]'),0x981bf8:('str','w10, [x0, #0x30]'),0x981c30:('retab',''),0x981e54:('str','x8, [x19]'),0x981e68:('retab',''),
      0x8f3560:('blraa','x8, x17'),0x8f3574:('mov','w3, #0xf9db'),0x8f3578:('movk','w3, #0xba1d, lsl #16'),0x8f3590:('mov','sp, x8'),
      0x8f3594:('ldur','w9, [x29, #-0x88]'),0x8f3598:('cmp','w9, w3'),
      0x981264:('ldr','w11, [x24, #4]'),0x9813dc:('str','w2, [sp, #0x1c]'),0x981768:('lsl','w10, w8, w9'),0x981788:('stp','w8, w10, [sp, #0x18]')}
    for pc,want in exact.items():assert ins[pc]==want,(hex(pc),ins[pc])
    p,n,h=z3.BitVecs('independent_export_pointer independent_export_length independent_export_mask',32)
    claims=[(((0xb42edf98|(p<<1))-p+0x25e89034)^0x036891f4)*0xfcf33521==(p^0xd97ffe38)*0xfcf33521,
      n+0x2647dd39+h-h+0xd9b822c7==n,(n+0x2647dd39==0x2647dd39)==(n==0),z3.ULT(z3.ZeroExt(32,n),z3.BitVecVal((-2147483648*4)&((1<<64)-1),64))]
    assert len(e['proofs'])==len(claims)==4
    for proof,claim in zip(e['proofs'],claims):
        s=z3.Solver();s.set(timeout=60000);s.add(z3.parse_smt2_string(proof['query']));assert proof['result']=='unsat'and s.check()==z3.unsat
        s=z3.Solver();s.set(timeout=60000);s.add(z3.Not(claim));assert s.check()==z3.unsat
    old_checks=read(ROOT/'fpsd1201_operand_checks.json');old_audit=read(ROOT/'fpsd1201_operand_audit.json')
    assert SHA(old_checks.encode())=='19ccfef6742ef1a5bb0b27a7d704eb8624b74955a51f5db6834fe12aff19919c'
    assert SHA(old_audit.encode())=='b0e6e74c85ce0092ef7db0c398f9be7b200ce18e4b1e71ee9262556b51be8cb8'
    legacy=json.loads(old_checks);receipt=json.loads(old_audit);assert receipt['fresh_replay_completed']and receipt['process_exit_code']==0
    assert receipt['checks_sha256']==SHA(old_checks.encode())and receipt['auditor_sha256']==SHA((ROOT/'audit_fpsd1201_operand.py').read_bytes())
    for p in legacy['profiles']:
        reads=lambda pc:[r for r in p['source_reads']if p['source_visits'][r['visit']]['pc']==pc]
        writes=lambda pc:[w for w in p['source_writes']if p['source_visits'][w['visit']]['pc']==pc]
        c=reads('0x981264');assert len(c)==1 and c[0]['size_B']==4 and int.from_bytes(bytes.fromhex(c[0]['bytes_hex']),'little')-BASE==2
        w=writes('0x9813dc');assert len(w)==1 and w[0]['size_B']==4 and w[0]['after_hex']=='02000000';sp=int(w[0]['address'],16)-28
        r=reads('0x981764');assert len(r)==2 and [int(x['address'],16)for x in r]==[sp+24,sp+28]and all(x['size_B']==4 and x['bytes_hex']=='02000000'for x in r)
        w=[x for x in writes('0x981788')if int(x['address'],16)==sp+28];assert len(w)==1 and w[0]['size_B']==4 and w[0]['before_hex']=='02000000'and w[0]['after_hex']=='08000000'
    assert len(legacy['profiles'])==36
    return banks,D,{'fresh_IDA_spans':1,'fresh_IDA_bytes':812,'compiler_bounded_bodies':1,'total_selected_code_bytes':41224,'original_fixup_words_checked':len(D),'compiler_starts_checked':len(starts),
      'retained_queries_unsat':4,'independent_queries_unsat':4,'exact_source_instructions_checked':len(exact),'prior_saved_count_profiles_checked':36,
      'prior_saved_count_checks_sha256':SHA(old_checks.encode()),'prior_saved_count_audit_sha256':SHA(old_audit.encode()),'native_admission_established':False}


def main():
    e=json.loads(read(ROOT/'fpsd1201_export_checks.json'));old=json.loads(read(ROOT/'fpsd1201_auxiliary_checks.json'));prior=json.loads(read(ROOT/'fpsd1201_auxiliary_audit.json'))
    assert SHA(read(ROOT/'fpsd1201_auxiliary_audit.json').encode())==PRIOR_SHA and prior['fresh_replay_completed']and prior['result']['all_checks_pass']
    assert prior['checks_sha256']==SHA(read(ROOT/'fpsd1201_auxiliary_checks.json').encode())and prior['auditor_sha256']==SHA((ROOT/'audit_fpsd1201_auxiliary.py').read_bytes())
    assert e['generator_sha256']==SHA((ROOT/'recover_fpsd1201_export.py').read_bytes())and e['IDA_readback_sha256']==SHA(read(ROOT/'fpsd1201_export_ida_readback.json').encode())
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    expected=[{'mode':'retained','prior_index':j}for j,p in enumerate(old['profiles'])if p['terminal']['pc']=='0x981bc8']
    expected.extend({'mode':'short_export','prior_index':1,'length_B':n}for n in [0,3])
    for v in [0,1,0x80,0xffffffff,(1<<32)+0x12345678,(1<<127)+0xabcd,(1<<1023)+7,(1<<2047)+9,(1<<4095)+11]:
        k=(v.bit_length()+31)//32;lengths=[0,1,3,4,5,16,128]if not k else sorted({0,4*k-1,4*k,4*k+1,max(128,4*k+1)})
        for sign in ([1]if not v else[1,-1]):
            for n in lengths:expected.append({'mode':'isolated','prior_index':1,'value_hex':hex(v),'sign':sign,'leading_zero_limbs':0,'length_B':n,'null_destination':False})
    for v in [0,1,(1<<127)+0xabcd]:
        k=(v.bit_length()+31)//32+2
        for sign in [1,-1]:
            for n in sorted({0,4*k-1,4*k,4*k+1,128}):expected.append({'mode':'isolated','prior_index':1,'value_hex':hex(v),'sign':sign,'leading_zero_limbs':2,'length_B':n,'null_destination':False})
    expected.append({'mode':'isolated','prior_index':1,'value_hex':'0x0','sign':1,'leading_zero_limbs':0,'length_B':0,'null_destination':True})
    expected.extend({'mode':'minimum_count','prior_index':1,'length_B':n}for n in [0,128])
    assert [p['configuration']for p in e['profiles']]==expected
    banks,D,src=source(e,old);total=Counter();summaries=[];modes=Counter()
    for j,p in enumerate(e['profiles']):
        assert p['prior_profile_index']==p['configuration']['prior_index'];replay=Replay(p,old['profiles'][p['prior_profile_index']],e['code_spans'],banks,D);stats,summary=replay.run();total.update(stats);summaries.append(summary);modes[p['configuration']['mode']]+=1
        if j<18 or j%24==0:print(json.dumps({'profile':j,'mode':p['configuration']['mode'],'visits':stats['original_visits_checked'],'accepted':summary['accepted']}),flush=True)
    assert not any(e[k]for k in ['whole_parent_replayed','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    result={'source':src,'fresh_replay':dict(total),'profiles':len(e['profiles']),'modes':dict(modes),'profile_summaries':summaries,'prior_replay_receipt_sha256':PRIOR_SHA,'prefix_instructions_rerun':0,
      'native_parent_continuation_replayed':False,'whole_parent_replayed':False,'native_target_executed':False,'full_goal_complete':False,'all_checks_pass':True}
    receipt={'result':result,'dependencies':e['dependencies'],'checks_sha256':SHA(read(ROOT/'fpsd1201_export_checks.json').encode()),'IDA_readback_sha256':e['IDA_readback_sha256'],
      'auditor_sha256':SHA(Path(__file__).read_bytes()),'fresh_replay_completed':True,'process_exit_code':0,'native_target_executed':False}
    (ROOT/'fpsd1201_export_audit.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({**result,'profile_summaries':'retained in receipt'}),flush=True)


if __name__=='__main__':main()
