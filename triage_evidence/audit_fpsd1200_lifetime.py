#!/usr/bin/env python3
"""Independent full source replay and failed-watch cleanup/queue/slot-word oracles.

Never imports the lifetime producer. Frozen port replay supplies earlier
instruction/event oracles; new mode, API, process-event and output checks are local.
O(B+F+V+E+L) replay work; modular arithmetic costs separate. No native effects.
"""
import base64,gc,json,struct,zlib,subprocess
from pathlib import Path
from unicorn import arm64_const as A
from audit_fpsd1200_port import Replay as Parent
from audit_fpsd1200_vm import Replay as VMReplay
from audit_fpsd1200_certificate import Replay as CertificateReplay,integer
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,verify_original_fixups
from daemon_import_bindings import binding
from bootpolicy_cache_reader import Cache,Dylib
from rpc502_startup_tools import certificate_view,rsa_sha1_relation
from verify_daemon_reader_record_payloads_publication import read
from hashlib import sha256

SHA=lambda x:sha256(x).hexdigest()
STACK=0x70000000;VM=0x76000000;VM_SIZE=0x100000


QUEUE=0x1010c4d20;CELL=0x700663e8;UPSTREAM=0x70066570;ERR=0x78000000


class Replay(Parent):
    def __init__(self,r,lib):
        self.lpi=self.swri=self.swwi=0;self.upstream_reads=[];self.upstream_writes=[]
        super().__init__(r,lib)
        self.lpcs={int(p['pc'],16)for p in r['lifetime_points']}
        assert r['queue_word_before_composition']==bytes(self.u.mem_read(QUEUE,4)).hex()=='69d90e06'
        old=json.loads(read(ROOT/'daemon_descriptor_source_profiles.json'))
        q=next(x for x in old['setup_cases']if x['configuration']['label']==f"setup_fd{r['fixture']['queue_fd']}")
        w=next(w for w in q['source_writes']if w['address']==hex(QUEUE))
        raw=bytes.fromhex(q['final_header96_hex'])[72:76]
        assert raw==struct.pack('<I',(r['fixture']['queue_fd']+0x060ed969)&0xffffffff)and w['after_hex']==raw.hex()
        assert r['queue_origin']=={'artifact':'daemon_descriptor_source_profiles.json','case':q['configuration']['label'],
          'source_store':q['source_visits'][w['visit']]['pc'],'source_write':w,'composed_address':hex(QUEUE),
          'composed_bytes_hex':raw.hex(),'native_temporal_continuity_established':False}
        assert r['queue_origin']['source_store']=='0x100096920'
        self.u.mem_write(QUEUE,raw)
        patch=r['slot_word_initial_patch']
        if 'initial_slot_word'in r['fixture']:
            expected={'address':hex(CELL),'before_hex':bytes(self.u.mem_read(CELL,4)).hex(),
              'after_hex':struct.pack('<I',r['fixture']['initial_slot_word']).hex(),
              'known_before':self.mask(CELL,4),'known_after':'01'*4}
            assert patch==expected;self.u.mem_write(CELL,bytes.fromhex(patch['after_hex']))
            self.stack_known[CELL-STACK:CELL-STACK+4]=b'\x01'*4
        else:assert patch is None
        assert not r['error_pointer_region_mapped']and all(not a<=ERR<=b for a,b,p in self.u.mem_regions())

    def read_hook(self,u,ac,a,n,v,d):
        if a<UPSTREAM+4 and UPSTREAM<a+n:
            self.upstream_reads.append({'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'address':hex(a),'width_B':n,
              'bytes_hex':bytes(u.mem_read(a,n)).hex(),'known_mask_hex':self.mask(a,n)})
        if a<CELL+4 and CELL<a+n:
            actual={'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'address':hex(a),'width_B':n,
              'bytes_hex':bytes(u.mem_read(a,n)).hex(),'known_mask_hex':self.mask(a,n)}
            assert actual==self.row['slot_word_reads'][self.swri];self.swri+=1
        assert not ERR<=a<ERR+4096
        return super().read_hook(u,ac,a,n,v,d)

    def write_hook(self,u,ac,a,n,v,d):
        if a<UPSTREAM+4 and UPSTREAM<a+n:
            self.upstream_writes.append({'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'address':hex(a),'width_B':n,
              'before_hex':bytes(u.mem_read(a,n)).hex(),'known_before':self.mask(a,n),'value':hex(v% (1<<(8*n)))})
        if a<CELL+4 and CELL<a+n:
            actual={'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'address':hex(a),'width_B':n,
              'before_hex':bytes(u.mem_read(a,n)).hex(),'known_before':self.mask(a,n),'value':hex(v% (1<<(8*n)))}
            assert actual==self.row['slot_word_writes'][self.swwi];self.swwi+=1
        return super().write_hook(u,ac,a,n,v,d)

    def hook(self,u,pc,n,d):
        r=self.row;f=r['fixture']
        if pc in self.lpcs:assert self.new_checkpoint(u,pc)==r['lifetime_points'][self.lpi];self.lpi+=1
        if pc in self.imports:
            e=self.import_events[self.ei]
            if e['name']=='libSystem/___error':
                assert e['site']=='0x100493a58'and e['result']==hex(f['error_pointer'])
                assert e['entry_checkpoint']==self.new_checkpoint(u,pc)
                assert all(not a<=f['error_pointer']<=b for a,b,p in u.mem_regions())
            if e['name']=='libSystem/_kevent':
                assert e['site']=='0x1003ae458'and e['entry_checkpoint']==self.new_checkpoint(u,pc)
                assert [self.reg(j)for j in [0,2,3,4,5]]==[f['queue_fd'],1,0,0,0]
                raw=bytes(u.mem_read(self.reg(1),32))
                assert raw.hex()==e['change32_hex']and e['change_known_mask_hex']==self.mask(self.reg(1),32)=='01'*32
                assert struct.unpack('<QhHIqQ',raw)==(0x17161514,-5,0x11,0x80000000,0,0)
                assert int(e['result'],16)==f['kevent_result']&0xffffffffffffffff
                return VMReplay.hook(self,u,pc,n,d)
        return super().hook(u,pc,n,d)

    def verify(self):
        out=super().verify();r=self.row
        assert self.lpi==len(r['lifetime_points'])and self.swri==len(r['slot_word_reads'])and self.swwi==len(r['slot_word_writes'])
        assert not r['error_pointer_reads']and r['slot_word_final_hex']==bytes(self.u.mem_read(CELL,4)).hex()
        assert r['slot_word_final_known_mask']==self.mask(CELL,4)
        return out


def replay_profile(packed,lib):
    r=json.loads(zlib.decompress(base64.b64decode(packed['payload_zlib_base64'])))
    x=Replay(r,lib);out=x.verify();return (*out,{'case':r['fixture']['label'],'source_upstream_reads':x.upstream_reads,'source_upstream_writes':x.upstream_writes})


def queue_origin_checks():
    from collections import Counter
    from replay_daemon_descriptor_source import Replay as DescriptorReplay
    old=json.loads(read(ROOT/'daemon_descriptor_source_profiles.json'));init=old['initializer'];counts=Counter()
    counts.update(DescriptorReplay(init).run())
    for label in ['setup_fd0','setup_fd7']:
        q=next(q for q in old['setup_cases']if q['configuration']['label']==label)
        counts.update(DescriptorReplay(q,init).run())
    startup=json.loads(read(ROOT/'rpc502_startup_profiles.json'))
    packed=next(q for q in startup['cases']if q['case']['label']=='initialized_worker')
    row=json.loads(zlib.decompress(base64.b64decode(packed['payload_zlib_base64'])))
    overlap=[];writes=0
    for c in row['startup_chunks']:
        if c['phase']!='startup':continue
        chunk=json.loads(zlib.decompress(base64.b64decode(c['payload_zlib_base64'])))
        for w in chunk['image_writes']:
            writes+=1;a=int(w['address'],16)
            if a<QUEUE+4 and QUEUE<a+w['size']:overlap.append(w)
    assert not overlap and writes==246729 and IMAGE.read(QUEUE,4).hex()=='69d90e06'
    assert counts['original_instruction_visits_checked']==22906
    return {'components_replayed':3,'source_startup_global_writes_inspected':writes,
      'startup_writes_overlapping_queue':0,'queue_static_image_word_hex':'69d90e06','replay_counts':dict(counts)}

def audit():
    e=json.loads(read(ROOT/'fpsd1200_lifetime_checks.json'))
    assert SHA(SOURCE.read_bytes())==e['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert SHA((ROOT/'recover_fpsd1200_lifetime.py').read_bytes())==e['generator_sha256']
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h,n
    cache=Cache();d=Dylib(cache,e['library']['logical_name']);f=d.function(d.exports[e['library']['export']]['address'])
    assert (cache.uuid,d.uuid,f)==(e['library']['cache_uuid'],e['library']['library_uuid'],e['library']['function'])
    for s in e['spans']:
        a,z=int(s['start'],16),int(s['end'],16);b=IMAGE.read(a,z-a)
        assert b.hex()==s['bytes_hex']and SHA(b)==s['sha256']
        assert [{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a)]==s['instructions']
    att=json.loads(read(ROOT/'fpsd1200_lifetime_ida_readback.json'))
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
    from concurrent.futures import ProcessPoolExecutor
    import multiprocessing,z3
    assert len(e['proofs'])==2
    for proof in e['proofs'].values():
        solver=z3.Solver();solver.set(timeout=10000);solver.from_string(proof['query'])
        assert solver.check()==z3.unsat and proof['result']=='unsat'
    origin_checks=queue_origin_checks()
    pool=ProcessPoolExecutor(max_workers=2,mp_context=multiprocessing.get_context('spawn'))
    futures=[pool.submit(replay_profile,p,e['library'])for p in e['profiles']]
    total=imports=points=math_checks=full_exponents=constructor_bytes=active_bytes=0;accesses=set();bank_reads=0;group_summaries=[];upstream_observations=[]
    for profile_index,packed in enumerate(e['profiles']):
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
        v,i,p,upstream=futures[profile_index].result();total+=v;imports+=i;points+=p;upstream_observations.append(upstream)
        print(json.dumps({'replayed':r['fixture']['label'],'original_visits':v,'arithmetic_calls':len(r['montgomery_calls'])}),flush=True)
        del r;gc.collect()
    pool.shutdown()
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
      'bank_inputs':256*len(e['byte_bank_proofs']),'queries_unsat':len(e['proofs']),'worker_processes':2,'queue_origin_checks':origin_checks,'upstream_observations':upstream_observations,'all_checks_pass':True}


if __name__=='__main__':print(json.dumps(audit()))
