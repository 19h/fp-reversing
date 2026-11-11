#!/usr/bin/env python3
"""Independent source/event replay of the bounded FPSD1200 pool continuation.

Never imports the arena producer. Frozen identity replay supplies prior call,
checkpoint and PAC oracles; new heap, atomic and output-region checks are local.
O(C*(B+F+K)+R+256N) time, O(B+F+R) transient space; solver cost separate.
"""
import json,struct
import unicorn as uc
from unicorn import arm64_const as A
import z3
from audit_fpsd1200_identity import Replay as Parent,STACK,HALT,SHA,PRIVATE
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,verify_original_fixups
from daemon_import_bindings import binding
from bootpolicy_cache_reader import Cache,Dylib
from verify_daemon_reader_record_payloads_publication import read

HEAP=0x74000000;HEAP_SIZE=0x10000


class Replay(Parent):
    def __init__(self,row,library):
        self.hwi=self.hri=self.ai=self.api=self.owi=0;self.defined=set();self.active=False
        super().__init__(row,library)
        self.u.mem_map(HEAP,HEAP_SIZE);self.u.mem_write(HEAP,bytes([row['fixture'].get('backing',0xa5)])*HEAP_SIZE)
        self.apcs={int(p['pc'],16)for p in row['arena_points']}

    def read_hook(self,u,access,a,n,v,data):
        if HEAP<=a<HEAP+HEAP_SIZE:
            actual={'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'offset_B':a-HEAP,'width_B':n,
              'bytes_hex':bytes(u.mem_read(a,n)).hex(),'all_bytes_defined':all(x in self.defined for x in range(a,a+n))}
            assert actual==self.row['heap_reads'][self.hri];self.hri+=1
        return super().read_hook(u,access,a,n,v,data)

    def write_hook(self,u,access,a,n,v,data):
        pc=hex(u.reg_read(A.UC_ARM64_REG_PC));v&=(1<<(8*n))-1
        if HEAP<=a<HEAP+HEAP_SIZE:
            assert {'pc':pc,'offset_B':a-HEAP,'width_B':n,'value':hex(v)}==self.row['heap_writes'][self.hwi]
            self.hwi+=1;self.defined.update(range(a,a+n))
        if self.active and any(a<b+z and b<a+n for b,z in [(self.inline,128),(self.payload+72,32)]):
            assert {'pc':pc,'address':hex(a),'width_B':n,'value':hex(v)}==self.row['protected_output_writes'][self.owi];self.owi+=1
        return super().write_hook(u,access,a,n,v,data)

    def hook(self,u,pc,n,data):
        if pc in self.apcs:
            actual={'pc':hex(pc),'sp':hex(u.reg_read(A.UC_ARM64_REG_SP)),
              'nzcv':hex(u.reg_read(A.UC_ARM64_REG_NZCV)),'registers31':[hex(self.reg(j))for j in range(31)]}
            assert actual==self.row['arena_points'][self.api];self.api+=1
        if pc==0x10065ffd8:
            self.payload=struct.unpack('<Q',u.mem_read(self.reg(0)+16,8))[0]
            self.inline=struct.unpack('<Q',u.mem_read(self.payload+64,8))[0];self.active=True
            assert hex(self.payload)==self.row['payload_address']
            assert bytes(u.mem_read(self.payload,104)).hex()==self.row['protected_payload104_before']
            assert bytes(u.mem_read(self.inline,128)).hex()==self.row['inline128_before']
        if pc==0x100660230:self.active=False
        if pc==0x1006009c0:
            e=self.row['atomics'][self.ai];self.ai+=1
            assert bytes(u.mem_read(pc,4))==IMAGE.read(pc,4)
            ins=next(CS.disasm(IMAGE.read(pc,4),pc));assert(ins.mnemonic,ins.op_str)==('casal','w8, w14, [x12]')
            old=int.from_bytes(u.mem_read(self.reg(12),4),'little');expect=self.reg(8)&0xffffffff;desired=self.reg(14)&0xffffffff
            actual={'pc':hex(pc),'address':hex(self.reg(12)),'old32':hex(old),'expected32':hex(expect),'desired32':hex(desired),
              'sp':hex(u.reg_read(A.UC_ARM64_REG_SP)),'nzcv':hex(u.reg_read(A.UC_ARM64_REG_NZCV)),
              'registers31':[hex(self.reg(j))for j in range(31)],'executed':self.row['fixture'].get('atomic_fixture',False)}
            assert actual=={k:v for k,v in e.items()if k!='stored32'}
            if not actual['executed']:
                assert self.row['stop_reason']=='before_atomic_boundary'and self.index==len(self.row['visited'])
                self.finished=True;u.emu_stop();return
            assert self.row['visited'][self.index]==hex(pc);self.index+=1
            # Scalar single-thread semantics only; no native acquire/release proof.
            stored=desired if old==expect else old;assert hex(stored)==e['stored32']
            u.mem_write(self.reg(12),stored.to_bytes(4,'little'));self.setreg(8,old)
            u.reg_write(A.UC_ARM64_REG_PC,pc+4);return
        if pc==0x100052440 and self.reg(20)==0:
            actual={'pc':hex(pc),'kind':'write_after_null_allocation','address':hex(self.reg(21)),
              'sp':hex(u.reg_read(A.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)]}
            assert actual==self.row['boundary']and self.row['stop_reason']=='null_allocation_write_guard'
            assert self.index==len(self.row['visited']);self.finished=True;u.emu_stop();return
        return super().hook(u,pc,n,data)

    def verify(self):
        self.u.emu_start(0x100004b80,0,count=260000)
        r=self.row
        assert self.finished and self.index==len(r['visited'])and self.ei==len(self.import_events)
        assert self.pi==len(r['points'])and self.ci==len(r['copies'])and self.pending_copy is None and self.bi==len(r['byte_bank_reads'])
        assert self.li==len(r['library_calls'])and self.pending_library is None
        assert self.xi==len(r['identity_points'])and self.pri==len(r['provider_reads'])and self.cri==len(r['cache_context_reads'])
        assert self.wi==len(r['image_writes'])and self.callback_count==len(r['callback_models'])and self.once is None
        assert self.api==len(r['arena_points'])and self.ai==len(r['atomics'])and self.owi==len(r['protected_output_writes'])
        assert self.hwi==len(r['heap_writes'])and self.hri==len(r['heap_reads'])and len(self.defined)==r['heap_defined_bytes']
        assert bytes(self.u.mem_read(STACK+0x2000,212)).hex()==r['reply212']
        assert bytes(self.u.mem_read(self.carrier,28)).hex()==r['carrier28_final']and bytes(self.u.mem_read(self.delta,8)).hex()==r['delta8_final']
        assert SHA(bytes(self.u.mem_read(STACK,0x80000)))==r['final_stack_sha256']and SHA(bytes(self.u.mem_read(PRIVATE,0x10000)))==r['final_private_sha256']
        assert bytes(self.u.mem_read(HEAP,44800)).hex()==r['heap44800_hex']
        assert SHA(bytes(self.u.mem_read(HEAP+44800,HEAP_SIZE-44800)))==r['heap_tail_sha256']
        assert bytes(self.u.mem_read(self.payload,104)).hex()==r['protected_payload104_final']
        assert bytes(self.u.mem_read(self.inline,128)).hex()==r['inline128_final']
        assert bytes(self.u.mem_read(0x1010c4cd8,16)).hex()==r['pool_pair16_final']
        assert bytes(self.u.mem_read(0x1010b5de0,4)).hex()==r['atomic_word32_final']
        for p in r['final_image_writes']:assert bytes(self.u.mem_read(int(p['address'],16),p['width_B'])).hex()==p['bytes_hex']
        return self.index,self.ei,self.pi


def audit():
    e=json.loads(read(ROOT/'fpsd1200_arena_checks.json'))
    assert SHA(SOURCE.read_bytes())==e['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert SHA((ROOT/'recover_fpsd1200_arena.py').read_bytes())==e['generator_sha256']
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h,n
    c=Cache();d=Dylib(c,e['library']['logical_name']);f=d.function(d.exports[e['library']['export']]['address'])
    assert(c.uuid,d.uuid,f)==(e['library']['cache_uuid'],e['library']['library_uuid'],e['library']['function'])
    ins={}
    for r in e['spans']:
        a,z=int(r['start'],16),int(r['end'],16);b=IMAGE.read(a,z-a)
        assert SHA(b)==r['sha256']and b.hex()==r['bytes_hex']
        actual=[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a)]
        assert actual==r['instructions'];ins.update({int(i['ea'],16):i for i in actual})
    for a,m,o in [(0x10013ebe0,'str','w10, [x9]'),(0x10013ebe4,'stur','xzr, [x9, #4]'),
      (0x1001b4724,'str','xzr, [x12, #0x378]'),(0x100057634,'stp','x20, x22, [x25]'),
      (0x10051e04c,'lsl','x9, x24, #0xa'),(0x10051e050,'sub','x9, x9, x24, lsl #7'),
      (0x10051e068,'str','w9, [x10, #0x36c]'),(0x1006009c0,'casal','w8, w14, [x12]'),
      (0x100052440,'strb','w17, [x20, x21]'),(0x100630448,'blraa','x8, x17'),
      (0x100635670,'and','w8, w23, #0xfffffffe')]:
        assert(ins[a]['mnemonic'],ins[a]['operands'])==(m,o)
    att=json.loads(read(ROOT/'fpsd1200_arena_ida_readback.json'))
    assert att['input_sha256']=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'
    assert att['spans']==[{'start':r['start'],'size_B':int(r['end'],16)-int(r['start'],16),'sha256':r['sha256']}for r in e['spans']]
    assert not att['IDB_mutated']
    for p in e['proofs'].values():
        s=z3.Solver();s.set(timeout=15000);s.from_string(p['query']);assert s.check()==z3.unsat and p['result']=='unsat'
    assert len(e['proofs'])==3
    accesses={int(a,16)for r in e['profiles']for a in r['fixup_reads']};binds={a for a in accesses if FIXUPS[a]['kind'].endswith('bind')}
    assert verify_original_fixups(sorted(accesses-binds))=={k:v for k,v in e['fixups'].items()if k!='bindings'}
    assert [binding(a)for a in sorted(binds)]==e['fixups']['bindings']
    pairs=0
    for p in e['byte_bank_proofs']:
        l,r,k=(int(p[n],16)for n in ['left','right','key']);left,right=IMAGE.read(l,256),IMAGE.read(r,256)
        assert {x^right[left[x]^k]for x in range(256)}=={int(p['constant'],16)}and p['inputs_checked']==256;pairs+=p['observed_uses']
    assert pairs==e['byte_bank_pairs']and sum(len(r['byte_bank_reads'])for r in e['profiles'])==pairs*2+len(e['unpaired_byte_bank_reads'])
    total=imports=points=0
    labels={r['fixture']['label']:r for r in e['profiles']};assert len(labels)==len(e['profiles'])==12
    for r in e['profiles']:
        nonnull=r['fixture'].get('malloc_nonnull',True);backing=r['fixture'].get('backing',0xa5)
        assert not r['input_ool_reads']and not r['heap_reads']and not r['protected_output_writes']
        assert r['inline128_before']==r['inline128_final']=='a5'*128
        assert r['protected_payload104_before']==r['protected_payload104_final']
        expected=bytearray([backing]*44800);writes=[]
        if nonnull:
            for i in range(50):
                for off,n,v,pc in [(876,4,0x4577df49,0x10013ebe0),(880,8,0,0x10013ebe4),(888,8,0,0x1001b4724)]:
                    expected[i*896+off:i*896+off+n]=v.to_bytes(n,'little')
                    writes.append({'pc':hex(pc),'offset_B':i*896+off,'width_B':n,'value':hex(v)})
            expected[876:880]=(0x4577df4a).to_bytes(4,'little')
            writes.append({'pc':'0x10051e068','offset_B':876,'width_B':4,'value':'0x4577df4a'})
            assert r['pool_pair16_final']==struct.pack('<QQ',HEAP,50).hex()and r['heap_defined_bytes']==1000
            published=[p for p in r['image_writes']if p['pc']=='0x100057634']
            assert published==[{'pc':'0x100057634','address':hex(a),'size':8,'value':hex(v)}for a,v in [(0x1010c4cd8,HEAP),(0x1010c4ce0,50)]]
        else:
            assert r['heap_defined_bytes']==0 and r['boundary']['address']=='0xaeff'
            assert r['pool_pair16_final']=='00'*16
        assert r['heap_writes']==writes and r['heap44800_hex']==expected.hex()
        assert r['heap_tail_sha256']==SHA(bytes([backing])*(HEAP_SIZE-44800))
        for cp in r['copies']:assert cp['size_B']==32 and cp['source_hex']==cp['destination_after_hex']==bytes(range(32)).hex()
        if r['reply_completed']:
            b=bytes.fromhex(r['reply212']);assert struct.unpack_from('<6I',b)==(0x80000012,212,0x6400,0,0,1300)
            assert r['reply_size_B']==212 and r['application_status_u32']==0 and r['delta8_final']=='00'*8
            assert b[44:48]==b'\xa5'*4
            assert b[68:196]==b'\xa5'*128 and r['reply_status_u32']is None
        for a in r['atomics']:
            assert(a['address'],a['old32'],a['expected32'],a['desired32'])==('0x1010b5de0','0x5d96','0x5d96','0xa94ef')
            if a['executed']:assert a['stored32']=='0xa94ef'
        if r['stop_reason']=='unmodeled_import_boundary':
            p=[p for p in r['events']if p['kind']=='import_fixture'][-1]
            assert p['name']=='libSystem/_arc4random'and p['site']=='0x100630448'and 'result'not in p
            assert r['atomic_word32_final']=='965d0000'
            assert [p for p in r['image_writes']if p['address']=='0x1010b5de0']==[
              {'pc':'0x1006303ec','address':'0x1010b5de0','size':4,'value':'0x5d96'}]
        v,i,p=Replay(r,e['library']).verify();total+=v;imports+=i;points+=p
    a,b=labels['default_A5'],labels['default_3C']
    for key in ['visited','reply212','final_stack_sha256','final_private_sha256','events','arena_points']:assert a[key]==b[key]
    for word in [1,2,3]:
        a=labels[f'word{word}_count8'];b=labels[f'word{word}_atomic_fixture'if word<3 else 'word3']
        assert a['visited']==b['visited']and a['stop_reason']==b['stop_reason']
    assert labels['default_A5']['visited']==labels['default_count756']['visited']
    return {'profiles':len(labels),'original_instruction_visits':total,'import_events':imports,
      'admission_checkpoints':points,'arena_checkpoints':sum(len(r['arena_points'])for r in e['profiles']),
      'heap_store_events':sum(len(r['heap_writes'])for r in e['profiles']),
      'terminal_stack_private_heap_bytes_checked':len(labels)*(0x80000+0x10000+HEAP_SIZE),
      'queries_unsat':3,'source_IDA_spans':len(e['spans']),'bank_inputs':256*len(e['byte_bank_proofs']),
      'all_checks_pass':True}


if __name__=='__main__':print(json.dumps(audit()))
