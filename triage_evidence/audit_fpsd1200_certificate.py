#!/usr/bin/env python3
"""Independent source replay and public arithmetic/constructor oracles.

Never imports the certificate producer. Frozen context replay supplies earlier
instruction/event oracles. New memory, call and arithmetic checks are local.
O(B+F+V+E+L) finite replay work; modular multiplication/inverse costs separate.
"""
import base64,gc,json,struct,zlib,subprocess
from pathlib import Path
from unittest.mock import patch
from unicorn import arm64_const as A
from audit_fpsd1200_context import Replay as Parent
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,verify_original_fixups
from daemon_import_bindings import binding
from bootpolicy_cache_reader import Cache,Dylib
from rpc502_startup_tools import certificate_view,rsa_sha1_relation
from verify_daemon_reader_record_payloads_publication import read
from hashlib import sha256

SHA=lambda x:sha256(x).hexdigest()
STACK=0x70000000;CERT=0x75000000;SIZE=0x100000
MONT={0x100539ea0:'square',0x10094593c:'product'}


class Replay(Parent):
    def __init__(self,r,lib):
        self.cert=[];self.cert_ri=self.cert_wi=self.nai=self.cpi=self.swi_new=self.mci=self.tri=0
        self.stack_known=bytearray(0x80000);self.active_math=[]
        super().__init__(r,lib)
        self.u.mem_map(CERT,SIZE);self.u.mem_write(CERT,b'\xa5'*SIZE)
        self.task_address=self.import_addresses['libSystem/_mach_task_self_']
        assert hex(self.task_address)==r['task_self_address']
        if 'task_self_u32'in r['fixture']:self.u.mem_write(self.task_address,struct.pack('<I',r['fixture']['task_self_u32']))
        self.cpcs={int(p['pc'],16)for p in r['certificate_points']}

    def mask(self,a,n):
        if STACK<=a<a+n<=STACK+0x80000:return bytes(self.stack_known[a-STACK:a-STACK+n]).hex()
        for base,size,known in self.owners:
            if base<=a<a+n<=base+size:return known[a-base:a-base+n].hex()
        for o in self.cert:
            b=o['address']
            if b<=a<a+n<=b+o['size_B']:return o['known'][a-b:a-b+n].hex()
        return '00'*n

    def integer(self,a):
        h=bytes(self.u.mem_read(a,16));cap,raw,ptr=struct.unpack('<IIQ',h);count=(raw-0x693be708)&0xffffffff
        if count&0x80000000:count-=1<<32
        n=abs(count);assert n<=cap and n<=132
        return {'address':hex(a),'header16_hex':h.hex(),'header_known_mask_hex':self.mask(a,16),
          'active_limbs_hex':bytes(self.u.mem_read(ptr,4*n)).hex()if n else '',
          'active_known_mask_hex':self.mask(ptr,4*n)if n else ''}

    def view(self,p,kind):
        raw=bytes(self.u.mem_read(p,48 if kind=='product'else 40));ptrs=struct.unpack_from('<'+'Q'*(len(raw)//8),raw)
        ctx=ptrs[0];cb=bytes(self.u.mem_read(ctx,20));c0,c1=struct.unpack_from('<QQ',cb)
        return {'argument':hex(p),'argument_hex':raw.hex(),'context':hex(ctx),'context20_hex':cb.hex(),
          'context_known_mask_hex':self.mask(ctx,20),'modulus':self.integer(ptrs[4 if kind=='square'else 1]),
          'left':self.integer(ptrs[3]),'right':self.integer(ptrs[3 if kind=='square'else 5]),
          'output':self.integer(ptrs[2]),'radix':self.integer(c0),'precomputation':self.integer(c1)}

    def new_checkpoint(self,u,pc):
        return {'pc':hex(pc),'visit_index':self.index,'sp':hex(u.reg_read(A.UC_ARM64_REG_SP)),
          'nzcv':hex(u.reg_read(A.UC_ARM64_REG_NZCV)),'registers31':[hex(self.reg(j))for j in range(31)]}

    def read_hook(self,u,access,a,n,v,data):
        r=self.row;pc=hex(u.reg_read(A.UC_ARM64_REG_PC))
        if a==self.task_address:
            assert 'task_self_u32'in r['fixture']and n==4
            assert {'pc':pc,'address':hex(a),'width_B':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()}==r['task_self_reads'][self.tri];self.tri+=1
        if CERT<=a<CERT+SIZE:
            o=next(o for o in self.cert if o['address']<=a<a+n<=o['address']+o['size_B']);off=a-o['address']
            e={'pc':pc,'owner':hex(o['address']),'offset_B':off,'width_B':n,'bytes_hex':bytes(u.mem_read(a,n)).hex(),
              'all_bytes_defined':all(o['known'][off:off+n]),'retired':o['retired']}
            assert e==r['certificate_owner_reads'][self.cert_ri]and e['all_bytes_defined']and not e['retired'];self.cert_ri+=1
        return super().read_hook(u,access,a,n,v,data)

    def write_hook(self,u,access,a,n,v,data):
        v%=1<<(8*n);pc=u.reg_read(A.UC_ARM64_REG_PC)
        if STACK<=a<a+n<=STACK+0x80000:self.stack_known[a-STACK:a-STACK+n]=b'\x01'*n
        if CERT<=a<CERT+SIZE:
            o=next(o for o in self.cert if o['address']<=a<a+n<=o['address']+o['size_B']);off=a-o['address']
            o['known'][off:off+n]=b'\x01'*n
            assert {'pc':hex(pc),'owner':hex(o['address']),'offset_B':off,'width_B':n,'value':hex(v)}==self.row['certificate_owner_writes'][self.cert_wi];self.cert_wi+=1
        if self.cert and n==4 and v in [0x8b3dc651,0x74c29d8a]:
            assert {**self.new_checkpoint(u,pc),'address':hex(a),'value32':hex(v)}==self.row['scalar_status_stores'][self.swi_new];self.swi_new+=1
        return super().write_hook(u,access,a,n,v,data)

    def hook(self,u,pc,n,data):
        r=self.row
        if pc==0x10049e0f8 and 'task_self_u32'not in r['fixture']:
            assert {**self.new_checkpoint(u,pc),'address':hex(self.reg(28)),'width_B':4}==r['task_self_guard']
            assert r['stop_reason']=='before_task_self_data_boundary'and self.index==len(r['visited'])
            self.finished=True;u.emu_stop();return
        if self.active_math and pc==int(r['montgomery_calls'][self.active_math[-1]]['return_pc'],16):
            c=r['montgomery_calls'][self.active_math.pop()]
            assert self.new_checkpoint(u,pc)==c['return_checkpoint']
            assert self.view(int(c['entry']['argument'],16),c['kind'])==c['returned']
        if pc in MONT:
            c=r['montgomery_calls'][self.mci];assert c['kind']==MONT[pc]and c['entry_pc']==hex(pc)
            assert c['return_pc']==hex(self.reg(30))and c['entry_checkpoint']==self.new_checkpoint(u,pc)
            assert c['entry']==self.view(self.reg(0),MONT[pc]);self.active_math.append(self.mci);self.mci+=1
        if pc in self.cpcs:assert self.new_checkpoint(u,pc)==r['certificate_points'][self.cpi];self.cpi+=1
        if pc==0x100482d98:
            ins=next(CS.disasm(IMAGE.read(pc,4),pc));assert (ins.mnemonic,ins.op_str)==('casal','w14, w11, [x15]')
            assert bytes(u.mem_read(pc,4))==IMAGE.read(pc,4)
            a=self.reg(15);old=int.from_bytes(u.mem_read(a,4),'little');expected=self.reg(14)&0xffffffff;desired=self.reg(11)&0xffffffff
            e={**self.new_checkpoint(u,pc),'address':hex(a),'old32':hex(old),'expected32':hex(expected),'desired32':hex(desired),'executed':r['fixture'].get('new_atomic_fixture',False)}
            declared=r['new_atomics'][self.nai];self.nai+=1;assert e=={k:v for k,v in declared.items()if k!='stored32'}
            if not e['executed']:
                assert r['stop_reason']=='before_new_atomic_boundary'and self.index==len(r['visited']);self.finished=True;u.emu_stop();return
            assert r['visited'][self.index]==hex(pc);self.index+=1
            stored=desired if old==expected else old;assert declared['stored32']==hex(stored)
            u.mem_write(a,stored.to_bytes(4,'little'));self.setreg(14,old);u.reg_write(A.UC_ARM64_REG_PC,pc+4);return
        if pc==0x1003f0e5c and self.reg(0)==0:
            assert {**self.new_checkpoint(u,pc),'address':hex(self.reg(11)),'width_B':1}==r['null_certificate_guard']
            assert r['stop_reason']=='null_certificate_write_guard'and self.index==len(r['visited']);self.finished=True;u.emu_stop();return
        if pc in self.imports:
            e=self.import_events[self.ei]
            if e['name']=='libSystem/_malloc'and e['site']=='0x100346714'and 'result'in e:
                size=self.reg(0);assert size==e['requested_size_B']and size in [1219,1035,893,723]
                null=r['fixture'].get('first_certificate_null',False)and not self.cert
                p=0 if null else CERT+len(self.cert)*0x10000;assert int(e['result'],16)==p
                if p:self.cert.append({'address':p,'size_B':size,'known':bytearray(size),'retired':False})
            if e['name']=='libSystem/_free':
                o=next((o for o in self.cert if o['address']==self.reg(0)),None)
                if o is not None:assert not o['retired'];o['retired']=True
        return super().hook(u,pc,n,data)

    def verify(self):
        run=self.u.emu_start
        def budget(begin,until,**kw):
            assert begin==0x100004b80 and until==0 and kw=={'count':4000000}
            return run(begin,until,count=24000000)
        with patch.object(self.u,'emu_start',side_effect=budget):out=super().verify()
        r=self.row
        for i,key in [(self.cert_ri,'certificate_owner_reads'),(self.cert_wi,'certificate_owner_writes'),
          (self.nai,'new_atomics'),(self.cpi,'certificate_points'),(self.swi_new,'scalar_status_stores'),
          (self.mci,'montgomery_calls'),(self.tri,'task_self_reads')]:assert i==len(r[key]),key
        assert len(self.active_math)==r['incomplete_montgomery_calls']==0
        final=[{'address':hex(o['address']),'size_B':o['size_B'],'bytes_hex':bytes(self.u.mem_read(o['address'],o['size_B'])).hex(),
          'known_mask_hex':o['known'].hex(),'retired':o['retired']}for o in self.cert]
        assert final==r['certificate_owners_final']
        assert SHA(bytes(self.u.mem_read(CERT,SIZE)))==r['certificate_backing_sha256']
        assert SHA(bytes(self.stack_known))==r['source_stack_known_sha256'];return out


def integer(v,require_known=True):
    cap,stored,p=struct.unpack('<IIQ',bytes.fromhex(v['header16_hex']));count=(stored-0x693be708)&0xffffffff
    if count>>31:count-=1<<32
    n=abs(count);assert n<=cap and n<=132 and len(v['active_limbs_hex'])==8*n
    if require_known:assert v['header_known_mask_hex']=='01'*16 and v['active_known_mask_hex']=='01'*(4*n)
    words=struct.unpack('<'+'I'*n,bytes.fromhex(v['active_limbs_hex']))
    value=sum((w^0xada56e3c)<<(32*i)for i,w in enumerate(words));return -value if count<0 else value,n


def audit():
    e=json.loads(read(ROOT/'fpsd1200_certificate_checks.json'))
    assert SHA(SOURCE.read_bytes())==e['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert SHA((ROOT/'recover_fpsd1200_certificate.py').read_bytes())==e['generator_sha256']
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h,n
    cache=Cache();d=Dylib(cache,e['library']['logical_name']);f=d.function(d.exports[e['library']['export']]['address'])
    assert (cache.uuid,d.uuid,f)==(e['library']['cache_uuid'],e['library']['library_uuid'],e['library']['function'])
    for s in e['spans']:
        a,z=int(s['start'],16),int(s['end'],16);b=IMAGE.read(a,z-a)
        assert b.hex()==s['bytes_hex']and SHA(b)==s['sha256']
        assert [{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a)]==s['instructions']
    att=json.loads(read(ROOT/'fpsd1200_certificate_ida_readback.json'))
    assert att['input_sha256']=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'and not att['IDB_mutated']
    assert att['spans']==[{'start':s['start'],'size_B':int(s['end'],16)-int(s['start'],16),'sha256':s['sha256']}for s in e['spans']]
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
    for h in att['SDK_context']['headers']:
        raw=(sdk/'usr/include'/h['logical_name'].removeprefix('installed SDK ')).read_bytes()
        assert SHA(raw)==h['sha256']and all(p['text']in raw.decode()for p in h['excerpts'])
    abi=att['SDK_context']['compile_only'];cmd=[str(sdk)if x=='installed SDK'else x for x in abi['logical_command']]
    checked=subprocess.run(cmd,input=abi['source'],text=True,capture_output=True)
    assert checked.returncode==abi['exit_code']==0 and checked.stdout==abi['stdout']==''and checked.stderr==abi['stderr']==''
    root=certificate_view((ROOT/'rpc502_startup_root.der').read_bytes())
    policy=json.loads(read(ROOT/'rpc502_policy_contracts.json'));aaa=policy['original_certificates'][1]['certificate']
    leaf=certificate_view((ROOT/'corefp_fppineboard_certificate.der').read_bytes())
    relations=[rsa_sha1_relation(aaa,root),rsa_sha1_relation(leaf,aaa)]
    assert all(p['exact_equality']for p in relations)
    expected_signatures={int(root['modulus_hex'],16):int(aaa['signature_hex'],16),int(aaa['modulus_hex'],16):int(leaf['signature_hex'],16)}
    constructors={1219:0x100e9eee0,893:0x100ff63a0,723:0x100ee87f0,1035:0x100f45a60}
    total=imports=points=math_checks=full_exponents=constructor_bytes=active_bytes=0;accesses=set();bank_reads=0;group_summaries=[]
    for packed in e['profiles']:
        r=json.loads(zlib.decompress(base64.b64decode(packed['payload_zlib_base64'])))
        assert r['fixture']==packed['fixture']and len(r['visited'])==packed['visits']and r['stop_reason']==packed['stop']
        for o in r['certificate_owners_final']:
            n=o['size_B'];raw=IMAGE.read(constructors[n],n);initial=bytes(b^0x98 for b in raw)
            expected=initial[4:]+initial[-4:];assert o['bytes_hex']==expected.hex()and o['known_mask_hex']=='01'*n
            ws=[w for w in r['certificate_owner_writes']if w['owner']==o['address']]
            descending=[w for w in ws if w['pc']=='0x1003f0e5c'];shift=[w for w in ws if w['pc']=='0x10030980c']
            assert len(ws)==n+(n-4)and [w['offset_B']for w in descending]==list(range(n-1,-1,-1))
            assert all(w['width_B']==1 and int(w['value'],16)==initial[w['offset_B']]for w in descending)
            assert [w['offset_B']for w in shift]==list(range(n-4))
            assert all(w['width_B']==1 and int(w['value'],16)==initial[w['offset_B']+4]for w in shift)
            constructor_bytes+=len(ws)
        exponents=set()
        for call in r['montgomery_calls']:
            before,after=call['entry'],call['returned'];N,n=integer(before['modulus']);left,_=integer(before['left']);right,_=integer(before['right']);out,_=integer(after['output'])
            assert N in set(expected_signatures)|{int(leaf['modulus_hex'],16)} and N>0 and N&1 and n in [32,64]
            R=1<<(32*n);assert out==left*right*pow(R,-1,N)%N;math_checks+=1
            assert integer(before['radix'])[0]==R%N
            ctx=bytes.fromhex(before['context20_hex']);assert before['context_known_mask_hex']=='01'*20
            assert struct.unpack_from('<I',ctx,16)[0]==(-pow(N&0xffffffff,-1,1<<32))&0xffffffff
            assert before['context20_hex']==after['context20_hex']and before['context']==after['context']
            assert call['entry_checkpoint']['sp']==call['return_checkpoint']['sp']
            for v in [before['modulus'],before['left'],before['right'],after['output'],before['radix']]:active_bytes+=len(v['active_limbs_hex'])//2+16
            if N in expected_signatures and out==pow(expected_signatures[N],65537,N):exponents.add(N)
        if r['montgomery_calls']:assert exponents==set(expected_signatures);full_exponents+=len(exponents)
        groups=[]
        for call in r['montgomery_calls']:
            modulus,limbs=integer(call['entry']['modulus'])
            if not groups or groups[-1][0]!=modulus:groups.append((modulus,limbs,[]))
            groups[-1][2].append(call)
        for modulus,limbs,calls in groups:
            width=32*limbs;radix=1<<width;precompute=width.bit_length()-1
            assert width==1<<precompute and len(calls)==precompute+21
            representative=integer(calls[precompute]['entry']['right'])[0]
            for j,c in enumerate(calls):
                left=integer(c['entry']['left'])[0];right=integer(c['entry']['right'])[0]
                if j<precompute:expected=('square',pow(2,1<<j,modulus)*radix%modulus,pow(2,1<<j,modulus)*radix%modulus)
                elif j==precompute:expected=('product',radix*radix%modulus,representative)
                elif j==precompute+1:expected=('square',radix%modulus,radix%modulus)
                elif j==precompute+2:expected=('product',radix%modulus,representative*radix%modulus)
                elif j<precompute+19:
                    a=pow(representative,1<<(j-precompute-3),modulus)*radix%modulus;expected=('square',a,a)
                elif j==precompute+19:expected=('product',pow(representative,65536,modulus)*radix%modulus,representative*radix%modulus)
                else:expected=('product',pow(representative,65537,modulus)*radix%modulus,1)
                assert (c['kind'],left,right)==expected
            result=integer(calls[-1]['returned']['output'])[0];assert result==pow(representative,65537,modulus)
            names={int(root['modulus_hex'],16):'Root',int(aaa['modulus_hex'],16):'AAA',int(leaf['modulus_hex'],16):'CoreFP_leaf'}
            raw=representative.to_bytes(width//8,'big');delimiter=raw.find(b'\0',2)
            group_summaries.append({'case':r['fixture']['label'],'key':names[modulus],'modulus_bits':modulus.bit_length(),
              'calls':len(calls),'precomputation_squares':precompute,'exponent':65537,
              'representative_prefix2_hex':raw[:2].hex(),'first_zero_after_prefix':delimiter,
              'suffix_size_B':len(raw)-delimiter-1 if delimiter>=0 else None,
              'complete_exponent_order_checked':True})
        for a in r['new_atomics']:
            assert (a['address'],a['old32'],a['expected32'],a['desired32'])==('0x1010b5de0','0x5d96','0x5d96','0xa94ef')
        accesses.update(int(a,16)for a in r['fixup_reads']);bank_reads+=len(r['byte_bank_reads'])
        v,i,p=Replay(r,e['library']).verify();total+=v;imports+=i;points+=p
        print(json.dumps({'replayed':r['fixture']['label'],'original_visits':v,'arithmetic_calls':len(r['montgomery_calls'])}),flush=True)
        del r;gc.collect()
    binds={a for a in accesses if FIXUPS[a]['kind'].endswith('bind')}
    assert verify_original_fixups(sorted(accesses-binds))=={k:v for k,v in e['fixups'].items()if k!='bindings'}
    assert [binding(a)for a in sorted(binds)]==e['fixups']['bindings']
    pairs=0
    for p in e['byte_bank_proofs']:
        l,r,k=(int(p[n],16)for n in ['left','right','key']);left,right=IMAGE.read(l,256),IMAGE.read(r,256)
        assert {x^right[left[x]^k]for x in range(256)}=={int(p['constant'],16)}and p['inputs_checked']==256;pairs+=p['observed_uses']
    assert pairs==e['byte_bank_pairs']and bank_reads==2*pairs+len(e['unpaired_byte_bank_reads'])
    return {'profiles':len(e['profiles']),'original_instruction_visits':total,'import_events':imports,'admission_checkpoints':points,
      'source_IDA_spans':len(e['spans']),'constructor_store_bytes_checked':constructor_bytes,'full_Montgomery_outputs_checked':math_checks,
      'active_arithmetic_bytes_checked':active_bytes,'public_exponent_outputs_checked':full_exponents,
      'public_signature_relations':2,'exponent_group_summaries':group_summaries,
      'bank_inputs':256*len(e['byte_bank_proofs']),'all_checks_pass':True}


if __name__=='__main__':print(json.dumps(audit()))
