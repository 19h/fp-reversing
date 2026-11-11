#!/usr/bin/env python3
"""Independent full source replay and VM-owner/output/arithmetic oracles.

Never imports the VM producer. Frozen certificate replay supplies earlier
instruction/event oracles; new private VM and output-cell checks are local.
O(B+F+V+E+L) replay work; modular arithmetic costs separate. No native effects.
"""
import base64,gc,json,struct,zlib,subprocess
from pathlib import Path
from unicorn import arm64_const as A
from audit_fpsd1200_certificate import Replay as Parent,integer
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,verify_original_fixups
from daemon_import_bindings import binding
from bootpolicy_cache_reader import Cache,Dylib
from rpc502_startup_tools import certificate_view,rsa_sha1_relation
from verify_daemon_reader_record_payloads_publication import read
from hashlib import sha256

SHA=lambda x:sha256(x).hexdigest()
STACK=0x70000000;VM=0x76000000;VM_SIZE=0x100000


class Replay(Parent):
    def __init__(self,r,lib):
        self.vm=[];self.vri=self.vwi=self.vpi=self.ori_vm=0
        super().__init__(r,lib)
        self.u.mem_map(VM,VM_SIZE);self.u.mem_write(VM,b'\xa5'*VM_SIZE)
        if 'initial_reply_OOL_address'in r['fixture']:
            self.u.mem_write(STACK+0x201c,struct.pack('<Q',r['fixture']['initial_reply_OOL_address']))
        self.vpcs={int(p['pc'],16)for p in r['vm_points']}

    def mask(self,a,n):
        for o in self.vm:
            b=o['address']
            if b<=a<a+n<=b+o['size_B']:return o['known'][a-b:a-b+n].hex()
        return super().mask(a,n)

    def read_hook(self,u,access,a,n,v,data):
        pc=hex(u.reg_read(A.UC_ARM64_REG_PC))
        if hasattr(self,'payload')and a<self.payload+104 and self.payload+72<a+n:
            actual={'pc':pc,'address':hex(a),'width_B':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()}
            assert actual==self.row['output_cell_reads'][self.ori_vm];self.ori_vm+=1
        if VM<=a<VM+VM_SIZE:
            o=next(o for o in self.vm if o['address']<=a<a+n<=o['address']+o['size_B']);off=a-o['address']
            actual={'pc':pc,'owner':hex(o['address']),'offset_B':off,'width_B':n,
              'bytes_hex':bytes(u.mem_read(a,n)).hex(),'all_bytes_defined':all(o['known'][off:off+n])}
            assert actual==self.row['vm_owner_reads'][self.vri]and actual['all_bytes_defined'];self.vri+=1
        return super().read_hook(u,access,a,n,v,data)

    def write_hook(self,u,access,a,n,v,data):
        if VM<=a<VM+VM_SIZE:
            o=next(o for o in self.vm if o['address']<=a<a+n<=o['address']+o['size_B']);off=a-o['address']
            actual={'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'owner':hex(o['address']),
              'offset_B':off,'width_B':n,'value':hex(v% (1<<(8*n)))}
            assert actual==self.row['vm_owner_writes'][self.vwi];self.vwi+=1;o['known'][off:off+n]=b'\x01'*n
        return super().write_hook(u,access,a,n,v,data)

    def hook(self,u,pc,n,data):
        if pc in self.vpcs:
            assert self.new_checkpoint(u,pc)==self.row['vm_points'][self.vpi];self.vpi+=1
        if pc in self.imports:
            event=self.import_events[self.ei]
            if event['name']=='CoreFoundation/_CFMachPortCreate':
                assert event['site']=='0x100001f8c'and 'result'not in event
                assert event['context40_hex']==bytes(u.mem_read(self.reg(2),40)).hex()=='00'*40
                assert event['context_known_mask_hex']==self.mask(self.reg(2),40)=='01'*40
                assert event['shouldFreeInfo_before']==bytes(u.mem_read(self.reg(3),1)).hex()=='00'
            if event['name']=='libSystem/_vm_deallocate':
                assert event['site']=='0x10049e114'and int(event['result'],16)==self.row['fixture']['vm_deallocate_return']
            if event['name']=='libSystem/_vm_allocate'and 'result'in event:
                assert event['site']=='0x10049e17c'
                a=self.reg(1);extent=self.reg(2);ret=self.row['fixture']['vm_allocate_return']
                assert event['result']==hex(ret)and bytes(u.mem_read(a,8)).hex()==event['address_cell_before']
                assert self.reg(0)==0x6600 and extent==719 and self.reg(3)==1
                if ret==0:
                    assert not self.vm and event['modeled_address64']==hex(VM)and event['modeled_zero_extent_B']==extent
                    self.vm.append({'address':VM,'size_B':extent,'known':bytearray(b'\x01'*extent)})
                    u.mem_write(VM,b'\0'*extent);u.mem_write(a,struct.pack('<Q',VM))
                    assert STACK<=a<a+8<=STACK+0x80000;self.stack_known[a-STACK:a-STACK+8]=b'\x01'*8
                else:assert 'modeled_address64'not in event
        return super().hook(u,pc,n,data)

    def verify(self):
        out=super().verify();r=self.row
        assert self.vri==len(r['vm_owner_reads'])and self.vwi==len(r['vm_owner_writes'])
        assert self.vpi==len(r['vm_points'])and self.ori_vm==len(r['output_cell_reads'])
        final=[{'address':hex(o['address']),'size_B':o['size_B'],
          'bytes_hex':bytes(self.u.mem_read(o['address'],o['size_B'])).hex(),'known_mask_hex':o['known'].hex()}for o in self.vm]
        assert final==r['vm_owners_final']and SHA(bytes(self.u.mem_read(VM,VM_SIZE)))==r['vm_backing_sha256']
        return out


def audit():
    e=json.loads(read(ROOT/'fpsd1200_vm_checks.json'))
    assert SHA(SOURCE.read_bytes())==e['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert SHA((ROOT/'recover_fpsd1200_vm.py').read_bytes())==e['generator_sha256']
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h,n
    cache=Cache();d=Dylib(cache,e['library']['logical_name']);f=d.function(d.exports[e['library']['export']]['address'])
    assert (cache.uuid,d.uuid,f)==(e['library']['cache_uuid'],e['library']['library_uuid'],e['library']['function'])
    for s in e['spans']:
        a,z=int(s['start'],16),int(s['end'],16);b=IMAGE.read(a,z-a)
        assert b.hex()==s['bytes_hex']and SHA(b)==s['sha256']
        assert [{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a)]==s['instructions']
    att=json.loads(read(ROOT/'fpsd1200_vm_ida_readback.json'))
    assert att['input_sha256']=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'and not att['IDB_mutated']
    assert att['spans']==[{'start':s['start'],'size_B':int(s['end'],16)-int(s['start'],16),'sha256':s['sha256']}for s in e['spans']]
    for extra in att['additional_source_ranges']:
        raw=bytes.fromhex(extra['bytes_hex']);assert raw==IMAGE.read(int(extra['start'],16),len(raw))and SHA(raw)==extra['sha256']
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
    for h in att['SDK_context']['headers']:
        raw=(sdk/h.get('SDK_relative_path','usr/include/'+h['logical_name'].removeprefix('installed SDK '))).read_bytes()
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
