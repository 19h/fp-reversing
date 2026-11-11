#!/usr/bin/env python3
"""Independent replay of FPSD1200 environment and certificate continuations.

Never imports the context producer. Frozen arena replay supplies source/event
oracles; added environment setup, memory events and arithmetic checks are local.
O(B+F+C*K+R+256*N) time, O(B+F+R) space; solver cost separate. Private only.
"""
import base64,json,struct,zlib
from functools import lru_cache
from unittest.mock import patch
from unicorn import arm64_const as A
import z3
from audit_fpsd1200_arena import Replay as Parent,HEAP,STACK,PRIVATE,SHA
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,verify_original_fixups
from daemon_import_bindings import binding
from bootpolicy_cache_reader import Cache,Dylib
from verify_daemon_reader_record_payloads_publication import read


@lru_cache(maxsize=1)
def retained_startup():
    p=json.loads(read(ROOT/'rpc502_startup_profiles.json'))
    c=next(c for c in p['cases']if c['case']['label']=='initialized_worker')
    r=json.loads(zlib.decompress(base64.b64decode(c['payload_zlib_base64'])))
    s=r['startup_snapshot'];cells={};count=0
    for chunk in r['startup_chunks']:
        if chunk['phase']!='startup':continue
        t=json.loads(zlib.decompress(base64.b64decode(chunk['payload_zlib_base64'])))
        for w in t['image_writes']:
            a=int(w['address'],16);n=w['size'];b=(int(w['value'],16)%(1<<(n*8))).to_bytes(n,'little')
            for i,v in enumerate(b):cells[a+i]=v
            count+=1
    spans=[]
    for a in sorted(cells):
        if spans and int(spans[-1]['address'],16)+len(spans[-1]['bytes_hex'])//2==a:spans[-1]['bytes_hex']+=f'{cells[a]:02x}'
        else:spans.append({'address':hex(a),'bytes_hex':f'{cells[a]:02x}'})
    return {'source_artifact':'rpc502_startup_profiles.json','case':'initialized_worker',
      'descriptor_base':s['descriptor_base'],'descriptor88_hex':s['descriptor60_hex'][:176],
      'readiness_hex':s['readiness_hex'],'heap_owners':s['heap_owners'],
      'source_global_spans':spans,'source_global_write_count':count,
      'native_temporal_continuity_established':False}


class Replay(Parent):
    def __init__(self,r,lib):
        self.rpi=self.ssi=self.lai=self.ori=self.ti=self.sri=self.swi=0;self.owners=[];self.window=None
        super().__init__(r,lib);f=r['fixture'];u=self.u
        if f.get('startup_context'):
            s=retained_startup();assert s==r['startup_context']
            for o in s['heap_owners']:
                a=int(o['address'],16);n=o['size_bytes'];u.mem_map(a,(n+4095)&~4095);u.mem_write(a,bytes.fromhex(o['bytes_hex']))
                self.owners.append((a,n,bytearray.fromhex(o['known_mask_hex'])))
            u.mem_write(0x1010b5ef0,bytes.fromhex(s['descriptor88_hex']));u.mem_write(0x1010c5798,bytes.fromhex(s['readiness_hex']))
            if f.get('startup_globals'):
                for w in s['source_global_spans']:u.mem_write(int(w['address'],16),bytes.fromhex(w['bytes_hex']))
                self.window=int.from_bytes(u.mem_read(0x1010ca2a8,8),'little')^0x12af5504870a589f
        else:assert r['startup_context']is None
        if 'readiness'in f:u.mem_write(0x1010c5798,bytes([f['readiness']]))
        p=r['provider_snapshot']
        if f.get('provider_window'):
            for a,k in [(0x1010c6800,'encoded_window_mask64'),(0x1010ca2a8,'encoded_window_base64')]:u.mem_write(a,int(p[k],16).to_bytes(8,'little'))
            self.window=int(p['encoded_window_base64'],16)^0x12af5504870a589f
        if f.get('provider_state'):
            u.mem_write(0x1010c784c,bytes.fromhex(p['state_bytes_hex']))
            u.mem_write(0x1010c67dc,struct.pack('<I',p['index32']));u.mem_write(0x1010c8258,struct.pack('<I',p['counter32']))
        if f.get('certificate_ool'):u.mem_write(STACK+0x6000,(ROOT/'corefp_fppineboard_certificate.der').read_bytes())
        assert bytes(u.mem_read(STACK+0x6000,756)).hex()==r['initial_ool756_hex']
        assert (hex(self.window)if self.window is not None else None)==r['self_text_window_base']
        self.rpcs={int(p['pc'],16)for p in r['random_points']}

    def read_hook(self,u,access,a,n,v,data):
        pc=hex(u.reg_read(A.UC_ARM64_REG_PC));r=self.row
        if self.window is not None and self.window<=a<self.window+32768:
            b=bytes(u.mem_read(a,n));assert b==IMAGE.read(a,n)
            assert {'pc':pc,'address':hex(a),'offset_B':a-self.window,'width_B':n,'bytes_hex':b.hex()}==r['self_text_reads'][self.ti];self.ti+=1
        for base,size,known in self.owners:
            if base<=a<base+size:
                off=a-base;e={'pc':pc,'owner':hex(base),'offset_B':off,'width_B':n,
                  'bytes_hex':bytes(u.mem_read(a,n)).hex(),'all_bytes_defined':a+n<=base+size and all(known[off:off+n])}
                assert e==r['startup_owner_reads'][self.sri]and e['all_bytes_defined'];self.sri+=1
        if STACK+0x6000<=a<STACK+0x6000+756:
            off=a-STACK-0x6000;assert off+n<=756
            assert {'pc':pc,'offset_B':off,'width_B':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()}==r['input_ool_byte_reads'][self.ori]
            e=r['input_ool_reads'][self.ori]
            assert int(e['pc'],16)==int(pc,16)
            assert int(e['address'],16)==a and e['width_B']==n
            self.ori+=1;return
        return super().read_hook(u,access,a,n,v,data)

    def write_hook(self,u,access,a,n,v,data):
        for base,size,known in self.owners:
            if base<=a<a+n<=base+size:
                off=a-base;e={'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'owner':hex(base),'offset_B':off,'width_B':n,'value':hex(v% (1<<(n*8)))}
                assert e==self.row['startup_owner_writes'][self.swi];self.swi+=1;known[off:off+n]=b'\x01'*n
        return super().write_hook(u,access,a,n,v,data)

    def checkpoint(self,u,pc):
        return {'pc':hex(pc),'sp':hex(u.reg_read(A.UC_ARM64_REG_SP)),
          'nzcv':hex(u.reg_read(A.UC_ARM64_REG_NZCV)),'registers31':[hex(self.reg(j))for j in range(31)]}

    def hook(self,u,pc,n,data):
        r=self.row
        if pc==0x10037aaa4:assert self.reg(8)==self.payload+40,(hex(self.reg(8)),hex(self.payload))
        if pc==0x10037aab4:
            field=int.from_bytes(bytes.fromhex(r['initial_request128'])[56:60],'little')
            assert self.reg(8)==field&2 and self.reg(9)==0
        if pc in [0x100543cc0,0x100466d54]:
            er,dr,ar=(12,14,13)if pc==0x100543cc0 else(11,1,15)
            ins=next(CS.disasm(IMAGE.read(pc,4),pc));assert (ins.mnemonic,ins.op_str)==('casal',f'w{er}, w{dr}, [x{ar}]')
            assert bytes(u.mem_read(pc,4))==IMAGE.read(pc,4)
            a=self.reg(ar);old=int.from_bytes(u.mem_read(a,4),'little');expected=self.reg(er)&0xffffffff;desired=self.reg(dr)&0xffffffff
            e={**self.checkpoint(u,pc),'address':hex(a),'old32':hex(old),'expected32':hex(expected),'desired32':hex(desired),
              'executed':r['fixture'].get('later_atomic_fixture',False),'expected_register':er,'desired_register':dr,'address_register':ar}
            recorded=r['later_atomics'][self.lai];self.lai+=1;assert e=={k:v for k,v in recorded.items()if k!='stored32'}
            if not e['executed']:
                assert r['stop_reason']=='before_later_atomic_boundary'and self.index==len(r['visited']);self.finished=True;u.emu_stop();return
            assert r['visited'][self.index]==hex(pc);self.index+=1
            stored=desired if old==expected else old;assert hex(stored)==recorded['stored32']
            u.mem_write(a,stored.to_bytes(4,'little'));self.setreg(er,old);u.reg_write(A.UC_ARM64_REG_PC,pc+4);return
        if pc in self.rpcs:
            e=self.checkpoint(u,pc)
            if pc==0x10047ab44:e['flag_byte_hex']=bytes(u.mem_read(self.reg(8),1)).hex()
            if pc==0x100405a78:e['timeval16_hex']=bytes(u.mem_read(self.reg(21)+16,16)).hex()
            if pc==0x100405b8c:e.update(material_address=hex(self.reg(22)),material16_hex=bytes(u.mem_read(self.reg(22),16)).hex())
            assert e==r['random_points'][self.rpi];self.rpi+=1
        if r['context_guard']is not None and pc==int(r['context_guard']['pc'],16):
            a,width=(self.reg(10),4)if pc==0x10049d978 else((self.reg(14),4)if pc==0x10049da00 else((self.reg(22)+8)&((1<<64)-1),8))
            assert {**self.checkpoint(u,pc),'address':hex(a),'width_B':width}==r['context_guard']
            assert self.index==len(r['visited'])and bytes(u.mem_read(pc,4))==IMAGE.read(pc,4)
            self.finished=True;u.emu_stop();return
        if pc==0x100405a74:
            assert {'pc':hex(pc),'seed624_hex':bytes(u.mem_read(0x1010c784c,2496)).hex()}==r['seed_snapshots'][self.ssi];self.ssi+=1
        if pc in self.imports:
            e=self.import_events[self.ei]
            if 'modeled_timeval12_hex'in e:
                assert e['name']=='libSystem/_gettimeofday'and e['site']=='0x100405a74'and self.reg(1)==0
                assert bytes(u.mem_read(self.reg(0),16)).hex()==e['timeval16_before']
                raw=struct.pack('<qi',*r['fixture']['timeval']);assert raw.hex()==e['modeled_timeval12_hex']
                u.mem_write(self.reg(0),raw)
        return super().hook(u,pc,n,data)

    def verify(self):
        # Increase only the frozen auditor's instruction budget, not semantics.
        run=self.u.emu_start
        def bounded(begin,until,**kw):
            assert begin==0x100004b80 and until==0 and kw=={'count':260000}
            return run(begin,until,count=4000000)
        with patch.object(self.u,'emu_start',side_effect=bounded):out=super().verify()
        r=self.row
        for i,key in [(self.rpi,'random_points'),(self.ssi,'seed_snapshots'),(self.lai,'later_atomics'),
          (self.ori,'input_ool_byte_reads'),(self.ti,'self_text_reads'),(self.sri,'startup_owner_reads'),(self.swi,'startup_owner_writes')]:assert i==len(r[key]),key
        assert self.ori==len(r['input_ool_reads'])
        assert [hex(self.reg(j))for j in range(31)]==r['terminal_registers31']and hex(self.u.reg_read(A.UC_ARM64_REG_SP))==r['terminal_sp']
        final=[{'address':hex(a),'size_B':n,'bytes_hex':bytes(self.u.mem_read(a,n)).hex(),'known_mask_hex':known.hex()}for a,n,known in self.owners]
        assert final==r['startup_owners_final'];return out


def audit():
    e=json.loads(read(ROOT/'fpsd1200_context_checks.json'))
    assert SHA(SOURCE.read_bytes())==e['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert SHA((ROOT/'recover_fpsd1200_context.py').read_bytes())==e['generator_sha256']
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h,n
    c=Cache();d=Dylib(c,e['library']['logical_name']);f=d.function(d.exports[e['library']['export']]['address'])
    assert (c.uuid,d.uuid,f)==(e['library']['cache_uuid'],e['library']['library_uuid'],e['library']['function'])
    for s in e['spans']:
        a,z=int(s['start'],16),int(s['end'],16);b=IMAGE.read(a,z-a)
        assert SHA(b)==s['sha256']and b.hex()==s['bytes_hex']
        assert [{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a)]==s['instructions']
    att=json.loads(read(ROOT/'fpsd1200_context_ida_readback.json'))
    assert att['input_sha256']=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'and not att['IDB_mutated']
    assert att['spans']==[{'start':s['start'],'size_B':int(s['end'],16)-int(s['start'],16),'sha256':s['sha256']}for s in e['spans']]
    for p in e['proofs'].values():
        solver=z3.Solver();solver.set(timeout=15000);solver.from_string(p['query']);assert solver.check()==z3.unsat and p['result']=='unsat'
    assert len(e['proofs'])==1
    accesses={int(a,16)for r in e['profiles']for a in r['fixup_reads']};binds={a for a in accesses if FIXUPS[a]['kind'].endswith('bind')}
    assert verify_original_fixups(sorted(accesses-binds))=={k:v for k,v in e['fixups'].items()if k!='bindings'}
    assert [binding(a)for a in sorted(binds)]==e['fixups']['bindings']
    pairs=0
    for p in e['byte_bank_proofs']:
        l,r,k=(int(p[n],16)for n in ['left','right','key']);left,right=IMAGE.read(l,256),IMAGE.read(r,256)
        assert {x^right[left[x]^k]for x in range(256)}=={int(p['constant'],16)}and p['inputs_checked']==256;pairs+=p['observed_uses']
    assert pairs==e['byte_bank_pairs']and sum(len(r['byte_bank_reads'])for r in e['profiles'])==pairs*2+len(e['unpaired_byte_bank_reads'])
    cert=(ROOT/'corefp_fppineboard_certificate.der').read_bytes()
    assert len(cert)==756 and SHA(cert)==e['reference_certificate_sha256']=='a0caace76b0db1214f92e89225458e5040d3b92837c03270274ea1a1b359e2de'
    visits=imports=points=0;labels={r['fixture']['label']:r for r in e['profiles']};assert len(labels)==19
    for r in e['profiles']:
        f=r['fixture'];assert not r['heap_reads']and not r['protected_output_writes']
        assert r['protected_payload104_before']==r['protected_payload104_final']and r['inline128_before']==r['inline128_final']=='a5'*128
        assert f['request_changes'][2:]==[[40,756,4],[60,756,4]]
        for s in r['seed_snapshots']:
            state=[f['random_words'][0]]
            for i in range(1,624):state.append((0x6c078965*(state[-1]^(state[-1]>>30))+i)&0xffffffff)
            assert struct.pack('<624I',*state).hex()==s['seed624_hex']
        for p in r['random_points']:
            if 'material16_hex'in p:
                words=[f['random_words'][2],f['timeval'][1],f['timeval'][0]&0xffffffff,f['random_words'][1]]
                assert p['material16_hex']==struct.pack('<4I',*(w^0xfc564818 for w in words)).hex()
            if 'timeval16_hex'in p:assert p['timeval16_hex']==struct.pack('<qi',*f['timeval']).hex()+'a5'*4
        for i,m in enumerate(r['random_models']):
            assert m['index']==i and int(m['word32'],16)==f['random_words'][i]and m['event']['result']==m['word32']
            assert m['event']['site']==['0x100630448','0x100405af4','0x100405b68'][i]
        if f.get('certificate_ool'):assert r['initial_ool756_hex']==cert.hex()
        if r['reply_completed']:
            b=bytes.fromhex(r['reply212']);assert r['reply_size_B']==36 and r['reply_status_u32']==r['application_status_u32']==struct.unpack_from('<I',b,32)[0]
            assert r['reply_status_u32']in [8,0xffff5bde]and int.from_bytes(bytes.fromhex(r['heap44800_hex'])[876:880],'little')==0x4577df49
            assert any(p['pc']=='0x100633cb4'for p in r['heap_writes'])
        v,i,p=Replay(r,e['library']).verify();visits+=v;imports+=i;points+=p
        print(json.dumps({'replayed':f['label'],'original_visits':v}),flush=True)
    assert labels['cold_seed_base_guard']['context_guard']['address']=='0x4'
    assert labels['startup_word3_der_allocator']['events'][-1]['site']=='0x100346714'
    assert labels['startup_word3_der_allocator']['events'][-1]['args'][0]=='0x4c3'
    return {'profiles':19,'original_instruction_visits':visits,'import_events':imports,'admission_checkpoints':points,
      'source_IDA_spans':len(e['spans']),'seed_words_checked':sum(len(r['seed_snapshots'])*624 for r in e['profiles']),
      'OOL_byte_reads_checked':sum(len(r['input_ool_byte_reads'])for r in e['profiles']),
      'self_text_reads_checked':sum(len(r['self_text_reads'])for r in e['profiles']),
      'startup_owner_reads_checked':sum(len(r['startup_owner_reads'])for r in e['profiles']),
      'startup_owner_writes_checked':sum(len(r['startup_owner_writes'])for r in e['profiles']),
      'terminal_stack_private_heap_bytes_checked':19*(0x80000+0x10000+0x10000),
      'queries_unsat':1,'bank_inputs':256*len(e['byte_bank_proofs']),'all_checks_pass':True}


if __name__=='__main__':print(json.dumps(audit()))
