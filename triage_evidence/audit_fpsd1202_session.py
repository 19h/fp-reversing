#!/usr/bin/env python3
"""Independent selected-session source, scalar and diagnostic digest/AES audit.

Never imports the new producer. The marker is a declared state control, stored
transform bytes have no source provenance, and no native operation executes.
O(V+J+H*R+I) time, O(J+H*R+I) space; solver costs separate. Fixed-size AES uses
constant space/time per block. SHA-1 costs O(input bytes) time and space here.
"""
import json,struct,base64,zlib,subprocess,shutil
from collections import Counter
from hashlib import sha256,sha1
from pathlib import Path
import z3
from audit_fpsd1202_ool import Replay as Parent,PRIVATE,SIZE,POOL
from recover_fpsd1200_process import CFPORT
from recover_daemon_descriptor_source import REGIONS,STACK
from replay_daemon_descriptor_source import decode
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,verify_original_fixups,TABLE,qword
from daemon_import_bindings import binding
from verify_daemon_reader_record_payloads_publication import read

POINTS={0x1004a0838,0x1004a0860,0x1004c481c,0x100495958,0x10049596c,
 0x100495984,0x100539c20,0x10053948c,0x100539e7c,0x10053da34,
 0x1004d8b34,0x1004d8b40,0x1004d8b48,0x1004d8b7c,0x1004d8b80}
HELPERS={0x100539c20,0x10053948c,0x100539e7c,0x10053da34}
LABELS=['word0','word1','word2','word3','word4','word_ffffffff','different_session_name',
 'live_slot_index1','wordB_zero','wordC_zero','OOL_zero','OOL_reverse','inline_zero']
VISITS=[3162,29298,29298,3162,3162,3162,4399,29327,29298,29298,29298,29298,29298]


def digest(b):return sha256(b).hexdigest()


class Replay(Parent):
    def __init__(self,p,o,s,m):
        self.si=0;self.transform_record=None
        super().__init__({**p,'initial_region_SHA256':p['pre_control_region_SHA256']},o,s,m)
        self.p=p;controls=[];c=self.c
        if c['OOL_control']is not None:
            assert c['OOL_control']in('zero','reverse')
            controls.append((PRIVATE+0xa000,bytes(16)if c['OOL_control']=='zero'else bytes(range(15,-1,-1))))
        if c['inline_control']is not None:
            assert c['inline_control']=='zero';controls.append((STACK+0x1040,bytes(16)))
        assert len(controls)==len(p['fixture_extensions'])
        for(at,b),r in zip(controls,p['fixture_extensions'],strict=True):
            assert r=={'address':hex(at),'before_hex':bytes(self.u.mem_read(at,len(b))).hex(),'after_hex':b.hex()}
            self.u.mem_write(at,b)
        assert p['initial_region_SHA256']==[digest(bytes(self.u.mem_read(a,n)))for a,n in REGIONS+[(POOL,SIZE),(PRIVATE,SIZE)]]
        at=POOL+c['slot_index']*896
        assert p['initial_slot_diagnostics']=={'slot':hex(at),'field812_hex':bytes(self.u.mem_read(at+812,4)).hex(),
          'transform16_hex':bytes(self.u.mem_read(at+852,16)).hex(),'transform16_known_mask_hex':self.mask[at-POOL+852:at-POOL+868].hex(),
          'counter8_hex':bytes(self.u.mem_read(at+868,8)).hex(),'counter8_known_mask_hex':self.mask[at-POOL+868:at-POOL+876].hex()}

    def external(self,a,name):
        if name=='CoreFoundation/_CFMachPortGetPort'and self.reg(0)==CFPORT:
            e=self.p['imports'][self.mi];self.mi+=1
            assert e['pc']==hex(a)and e['name']==name and not e['preserve_all_CPU']
            assert self.c['session_CF_name']in(0x6800,0x6801)
            self.modeled_return(e,self.c['session_CF_name'],[])
            self.counts['external_ABI_and_declared_effect_contracts_recomputed']+=1;return
        return super().external(a,name)

    def hook(self,u,a,n,d):
        if a in POINTS:
            p=self.p['session_points'][self.si];self.si+=1;self.frame(p)
            if a in HELPERS:
                args=[]
                for j in range(4):
                    v=self.reg(j);valid=any(lo<=v and v+64<=lo+size for lo,size in REGIONS+[(POOL,SIZE),(PRIVATE,SIZE)])
                    args.append({'address':hex(v),'bytes64_hex':bytes(u.mem_read(v,64)).hex()}if valid else None)
                assert p['bounded_argument_windows4']==args
                if a in(0x100539c20,0x10053948c):self.transform_record=self.reg(0)
                assert self.transform_record is not None
                raw=bytes(u.mem_read(self.transform_record,32));ptrs=struct.unpack_from('<3Q',raw,8)
                assert all(any(lo<=v and v+16<=lo+size for lo,size in REGIONS+[(POOL,SIZE),(PRIVATE,SIZE)])for v in ptrs)
                assert p['transform_views']=={'record':hex(self.transform_record),'record32_hex':raw.hex(),
                  'pointers3':[{'address':hex(v),'bytes16_hex':bytes(u.mem_read(v,16)).hex()}for v in ptrs]}
        return super().hook(u,a,n,d)

    def run(self):
        super().run();assert self.si==len(self.p['session_points'])
        self.counts['selected_session_CPU_point_frames_checked']+=self.si
        return dict(self.counts)


def lifted_proofs():
    """Independent instruction lift with exact 32-bit signed condition flags."""
    bv=lambda x:z3.BitVecVal(x&0xffffffff,32)
    n,p,a,t,y=z3.BitVecs('audit_name audit_received audit_operation audit_aux audit_counter',32)
    def lift(start,end,initial,loads,stores):
        regs=dict(initial);comparison=None;flags=None;written={}
        def v(s):return bv(int(s[1:],0))if s.startswith('#')else regs[s]
        for i in CS.disasm(IMAGE.read(start,end-start),start):
            q=[s.strip()for s in i.op_str.split(',')];op=i.mnemonic
            if op=='ldr':assert i.address in loads;regs[q[0].replace('x','w')]=loads[i.address];continue
            if op=='str':assert i.address in stores;written[i.address]=v(q[0]);continue
            if op=='cmp':comparison=(v(q[0]),v(q[1]));continue
            if op=='cmn':
                x,b=v(q[0]),v(q[1]);r=x+b
                negative=z3.Extract(31,31,r)==1
                overflow=z3.And(z3.Extract(31,31,x)==z3.Extract(31,31,b),z3.Extract(31,31,r)!=z3.Extract(31,31,x))
                flags=z3.Or(r==0,z3.Xor(negative,overflow));continue
            if op=='mov':r=v(q[1])
            elif op=='movk':
                shift=0 if len(q)==2 else int(q[2].removeprefix('lsl #'),0)
                r=(v(q[0])&bv(~(65535<<shift)))|(v(q[1])<<shift)
            elif op=='eor':r=v(q[1])^v(q[2])
            elif op=='add':r=v(q[1])+v(q[2])
            elif op=='sub':r=v(q[1])-v(q[2])
            elif op=='lsl':r=v(q[1])<<(v(q[2])&31)
            elif op=='and':r=v(q[1])&v(q[2])
            elif op=='orr':r=v(q[1])|v(q[2])
            elif op=='mul':r=v(q[1])*v(q[2])
            elif op=='cset':assert q[1]=='lo';r=z3.If(z3.ULT(*comparison),bv(1),bv(0))
            elif op=='cinc':assert q[2]=='le';r=v(q[1])+z3.If(flags,bv(1),bv(0))
            else:raise AssertionError((hex(i.address),op))
            regs[q[0]]=r
        return regs,comparison,written
    _,cmp,_=lift(0x1004a0838,0x1004a0864,{'w0':n,'w23':bv(0x7d7adee7),'w24':bv(0x6cf4)},
      {0x1004a0854:p},set())
    regs,_,_=lift(0x100495960,0x100495984,{'w20':bv(0x3943),'w22':a,'w10':bv(0x6cf4),'w9':bv(0x19a3)},{},set())
    _,_,writes=lift(0x1004d8b40,0x1004d8b80,{'w8':bv(0x74c23097),'w21':t},
      {0x1004d8b40:y,0x1004d8b44:bv(0x6cf4)},{0x1004d8b7c})
    rows=[(cmp[0]==cmp[1],n==p),(regs['w8'],z3.If(z3.Or(a==1,a==2),bv(0x1b08),bv(0x19a3))),
      (writes[0x1004d8b7c],y+1+z3.If(t!=0x74c29d8b,bv(1),bv(0)))]
    for left,right in rows:
        s=z3.Solver();s.set(timeout=20000);s.add(left!=right);assert s.check()==z3.unsat
    assert qword(TABLE+8*0x1b08)==0x10059b5c4 and qword(TABLE+8*0x19a3)==0x100528dd8
    return {'independently_lifted_source_queries_unsat':3,'operation12_target':'0x10059b5c4','other_operation_target':'0x100528dd8',
      'signed_LE_overflow_semantics_checked':True,'scope':'Freshly checked local CPU phases; all-u32 scalar values.'}


def aes128(key,block):
    """FIPS197 byte-oriented reference, not derived from target tables/code."""
    def mul(a,b):
        r=0
        for _ in range(8):
            r^=a if b&1 else 0;a=((a<<1)^(0x11b if a&128 else 0))&255;b>>=1
        return r
    def power(a,n):
        r=1
        while n:
            if n&1:r=mul(r,a)
            a=mul(a,a);n>>=1
        return r
    def rot(x,n):return ((x<<n)|(x>>(8-n)))&255
    box=[(lambda x:x^rot(x,1)^rot(x,2)^rot(x,3)^rot(x,4)^0x63)(power(v,254)if v else 0)for v in range(256)]
    expanded=list(key);rc=1
    while len(expanded)<176:
        v=expanded[-4:]
        if len(expanded)%16==0:
            v=[box[x]for x in v[1:]+v[:1]];v[0]^=rc;rc=mul(rc,2)
        for x in v:expanded.append(expanded[-16]^x)
    s=[v^k for v,k in zip(block,expanded[:16],strict=True)]
    for rnd in range(1,11):
        s=[box[s[4*((c+r)%4)+r]]for c in range(4)for r in range(4)]
        if rnd!=10:
            out=[]
            for c in range(4):
                a,b,c0,d=s[4*c:4*c+4]
                out.extend([mul(a,2)^mul(b,3)^c0^d,a^mul(b,2)^mul(c0,3)^d,a^b^mul(c0,2)^mul(d,3),mul(a,3)^b^c0^mul(d,2)])
            s=out
        s=[v^k for v,k in zip(s,expanded[16*rnd:16*rnd+16],strict=True)]
    return bytes(s)


def algorithm_joins(e,att):
    assert aes128(bytes.fromhex('000102030405060708090a0b0c0d0e0f'),bytes.fromhex('00112233445566778899aabbccddeeff')).hex()=='69c4e0d86a7b0430d8cdb78070b4c55a'
    cli=Path(shutil.which('openssl'));meta=att['independent_AES_CLI']
    assert cli.name==meta['executable_basename']and digest(cli.read_bytes())==meta['executable_sha256']
    assert subprocess.check_output(['openssl','version'],text=True).strip()==meta['version']
    rows=[];unique=set()
    for p in e['profiles']:
        c=p['configuration'];views={q['pc']:q for q in p['session_points']if'transform_views'in q}
        if not views:continue
        before=views['0x10053948c'];after=views['0x100539e7c'];v=before['transform_views'];v1=after['transform_views']
        x=bytes.fromhex(v['pointers3'][0]['bytes16_hex']);key=bytes.fromhex(v['pointers3'][2]['bytes16_hex']);out=bytes.fromhex(v1['pointers3'][1]['bytes16_hex'])
        assert key==b'\xa5'*16 and v['pointers3'][2]['address']==hex(POOL+896*c['slot_index']+852)
        assert p['initial_slot_diagnostics']['transform16_known_mask_hex']=='00'*16
        assert struct.unpack_from('<I',bytes.fromhex(v1['record32_hex']))[0]==0x8b3dc651
        raw_return=int(after['registers31'][0],16)
        assert raw_return==(0x30 if c['label']in('wordB_zero','wordC_zero','OOL_zero','OOL_reverse')else 0)
        data=decode(p['extra_final_region'])[0xa000:0xa010];message=struct.pack('>II',c['wordB'],c['wordC'])+data
        expected=bytes(b^0x98 for b in sha1(message).digest());at=int(v['pointers3'][0]['address'],16)
        # Join all twenty original byte stores at the digest-production epoch,
        # not just the sixteen bytes later consumed by the block transform.
        writes=[w for w in p['source_writes']if at<=int(w['address'],16)<at+20 and w['visit']<before['source_visit_index']]
        assert len(writes)==20 and [int(w['address'],16)for w in writes]==list(range(at,at+20))
        assert all(w['size_bytes']==1 for w in writes)
        actual=b''.join(bytes.fromhex(w['after_hex'])for w in writes);assert actual==expected and x==expected[:16]
        input_reads=[r for r in p['source_reads']if p['source_visits'][r['visit']]['pc']=='0x1008dac1c']
        assert len(input_reads)==8 and b''.join(bytes.fromhex(r['bytes_hex'])for r in input_reads)==bytes(b^0x98 for b in message[:8])
        decoded_key=bytes(b^0x98 for b in key);decoded_in=bytes(b^0x98 for b in x);decoded_out=bytes(b^0x98 for b in out)
        assert aes128(decoded_key,decoded_in)==decoded_out
        result=subprocess.run(['openssl','enc','-aes-128-ecb','-K',decoded_key.hex(),'-nopad','-nosalt'],input=decoded_in,capture_output=True)
        assert result.returncode==0 and not result.stderr and result.stdout==decoded_out
        compare=[r for r in p['source_reads']if p['source_visits'][r['visit']]['pc']in('0x10084ddb4','0x10084ddb8')]
        assert len(compare)==2 and [r['size_bytes']for r in compare]==[1,1]
        assert [int(r['address'],16)for r in compare]==[STACK+0x1040,int(v1['pointers3'][1]['address'],16)]
        assert bytes.fromhex(compare[0]['bytes_hex'])==(bytes(1)if c['inline_control']=='zero'else b'\x40')
        assert bytes.fromhex(compare[1]['bytes_hex'])==out[:1]
        unique.add((x,key,out))
        rows.append({'case':c['label'],'SHA1_input_hex':message.hex(),'SHA1_decoded_hex':sha1(message).hexdigest(),
          'digest_output_address':hex(at),'digest_writer_first_pc':p['source_visits'][writes[0]['visit']]['pc'],
          'digest_writer_last_pc':p['source_visits'][writes[-1]['visit']]['pc'],
          'digest_writer_visits':[w['visit']for w in writes],'AES_input_encoded_hex':x.hex(),'AES_output_encoded_hex':out.hex(),
          'body_X0_return':hex(raw_return),'stored_key_known_bytes':0,'reference_matches':True,'CLI_matches':True})
    assert len(rows)==8 and len(unique)==5
    return {'profiles':8,'distinct_AES_tuples':5,'known_vector_matches':True,'rows':rows,
      'scope':'Finite diagnostic correspondence; no real key, valid native token or complete cryptographic implementation equivalence.'}


def joins(e):
    assert [p['configuration']['label']for p in e['profiles']]==LABELS
    base=next(p['configuration']for p in json.loads(read(ROOT/'fpsd1202_ool_checks.json'))['profiles']if p['configuration']['label']=='source_marker4d')
    controls=[{'wordA':0},{},{'wordA':2},{'wordA':3},{'wordA':4},{'wordA':0xffffffff},
      {'session_CF_name':0x6801},{'slot_index':1},{'wordB':0},{'wordC':0},
      {'OOL_control':'zero'},{'OOL_control':'reverse'},{'inline_control':'zero'}]
    assert [p['configuration']for p in e['profiles']]==[{**base,'label':label,'session_CF_name':0x6800,
      'OOL_control':None,'inline_control':None,**control}for label,control in zip(LABELS,controls,strict=True)]
    rows=[]
    for ix,p in enumerate(e['profiles']):
        c=p['configuration'];slot=POOL+896*c['slot_index'];data=ix in(1,2,7,8,9,10,11,12);different=ix==6
        assert c['application_status']is None and c['marker_word']==0x4577df4d and not p['application_calls']
        assert len(p['source_visits'])==VISITS[ix]and p['boundary']['kind']=='original_return_to_declared_caller'
        status=int(next(q for q in p['abi_points']if q['pc']=='0x100004848')['registers31'][0],16)&0xffffffff
        assert status==(5 if different else 8 if data else 0)
        b=bytes.fromhex(p['reply72_final_hex']);wire=bytes.fromhex(p['request84_final_hex'])
        assert struct.unpack_from('<6I',b)==(0x12 if status else 0x80000012,36 if status else 72,0x6400,0,0,1302)
        if status:assert struct.unpack_from('<I',b,32)[0]==status
        else:
            assert struct.unpack_from('<I',b,24)[0]==1 and b[28:36]==b'\xa5'*8 and b[40:44]==bytes(4)
            assert b[52:68]==b'\xa5'*16 and b[68:72]==bytes(4)
        assert len(p['deallocation_requests'])==1 and wire[28:36]==bytes(8)and wire[40:44]==bytes(4)
        reads=[r for r in p['source_reads']if POOL<=int(r['address'],16)<POOL+SIZE]
        assert not any(int(r['address'],16)<slot+896 and slot+880<int(r['address'],16)+r['size_bytes']for r in reads)
        writes=[w for w in p['source_writes']if POOL<=int(w['address'],16)<POOL+SIZE]
        targets=[(p['source_visits'][w['visit']]['pc'],int(w['address'],16)-slot,w['after_hex'])for w in writes]
        assert targets==([]if different else[('0x10049595c',816,struct.pack('<I',c['wordC']^0x8b3dc651).hex())]+([('0x1004d8b3c',868,'a6a5a5a5'),('0x1004d8b7c',872,'a6a5a5a5')]if data else[]))
        init=p['initial_slot_diagnostics'];assert init['transform16_hex']=='a5'*16 and init['counter8_hex']=='a5'*8
        assert init['transform16_known_mask_hex']=='00'*16 and init['counter8_known_mask_hex']=='00'*8
        ool=[r for r in p['source_reads']if PRIVATE+0xa000<=int(r['address'],16)<PRIVATE+0xa010]
        inline=[r for r in p['source_reads']if STACK+0x1040<=int(r['address'],16)<STACK+0x1050]
        assert len(ool)==(16 if data else 0)and len(inline)==int(data)
        for q in p['session_points']:
            rs=[int(x,16)&0xffffffff for x in q['registers31']]
            if q['pc']=='0x1004a0838':assert rs[0]==c['session_CF_name']and rs[23]==0x7d7adee7 and rs[24]==0x6cf4
            if q['pc']=='0x1004a0860':assert rs[10]==c['local_name']
            if q['pc']=='0x100495958':assert rs[20]==0x3943 and rs[22]==c['wordA']and rs[9]==0x19a3 and rs[10]==0x6cf4
            if q['pc']=='0x10049596c':assert rs[8]==(c['wordA']-1)&0xffffffff
            if q['pc']=='0x100495984':assert rs[8]==(0x1b08 if data else 0x19a3)
            if q['pc']=='0x1004d8b48':assert rs[13]==0x6cf4 and rs[21]==0x74c29d8b
        rows.append({'case':c['label'],'visits':VISITS[ix],'original_application_status_u32':status,
          'reply_size_B':36 if status else 72,'OOL_output_size_B':None if status else 0,
          'OOL_input_bytes_read':len(ool),'inline_input_bytes_read':len(inline),'pool_stores':len(writes),'tail_bytes_read':0})
    return rows


def audit():
    e=json.loads(read(ROOT/'fpsd1202_session_checks.json'));assert digest(SOURCE.read_bytes())==e['daemon_sha256']
    assert digest(read(ROOT/'recover_fpsd1202_session.py').encode())==e['generator_sha256']
    for n,h in e['dependencies'].items():assert digest(read(ROOT/n).encode())==h
    frozen=json.loads(read(ROOT/'fpsd1200_lifetime_checks.json'));receipt=json.loads(read(ROOT/'fpsd1200_lifetime_audit.json'))
    assert receipt['fresh_replay_completed']and receipt['process_exit_code']==0
    assert receipt['checks_sha256']==digest(read(ROOT/'fpsd1200_lifetime_checks.json').encode())
    assert receipt['auditor_sha256']==digest(read(ROOT/'audit_fpsd1200_lifetime.py').encode())
    raw=zlib.decompress(base64.b64decode(next(p for p in frozen['profiles']if p['label']=='queue7_success')['payload_zlib_base64']))
    assert digest(raw)==e['frozen_session_payload_sha256'];session=json.loads(raw);mask=bytearray(SIZE)
    for w in session['heap_writes']:mask[w['offset_B']:w['offset_B']+w['width_B']]=b'\1'*w['width_B']
    assert sum(mask)==1159
    att=json.loads(read(ROOT/'fpsd1202_session_ida_readback.json'))
    assert not att['IDB_mutated']and att['input_sha256']=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'
    assert att['spans']==[{'start':s['start'],'size_B':int(s['end'],16)-int(s['start'],16),'sha256':s['sha256']}for s in e['spans']]
    for s in e['spans']:
        a,z=int(s['start'],16),int(s['end'],16);b=IMAGE.read(a,z-a)
        assert b.hex()==s['bytes_hex']and digest(b)==s['sha256']
        assert s['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a)]
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
    for h in att['SDK_context']['headers']:assert digest((sdk/h['SDK_relative_path']).read_bytes())==h['sha256']
    abi=att['SDK_context']['compile_only'];compiled=subprocess.run([str(sdk)if x=='installed SDK'else x for x in abi['logical_command']],input=abi['source'],text=True,capture_output=True)
    assert compiled.returncode==abi['exit_code']==0 and compiled.stdout==abi['stdout']==''and compiled.stderr==abi['stderr']==''
    assert set(e['proofs'])=={'name_equality','operation_fork','second_counter'}
    for q in e['proofs'].values():
        s=z3.Solver();s.set(timeout=20000);s.from_string(q['query']);assert s.check()==z3.unsat and q['result']=='unsat'
    lifted=lifted_proofs();old=json.loads(read(ROOT/'daemon_descriptor_source_profiles.json'));counts=Counter();accesses=set()
    for p in e['profiles']:
        counts.update(Replay(p,old['setup_cases'][0],session,mask).run())
        accesses.update(int(r['address'],16)for r in p['source_reads']if int(r['address'],16)in FIXUPS)
        print(json.dumps({'replayed':p['configuration']['label']}),flush=True)
    binds=sorted(a for a in accesses if FIXUPS[a]['kind'].endswith('bind'));fix=verify_original_fixups(sorted(accesses-set(binds)))
    fix['bindings']=[binding(a)for a in binds];assert fix==e['fixups']
    rows=joins(e);algorithms=algorithm_joins(e,att)
    assert counts['original_instruction_visits_checked']==e['verified_counts']['original_visits']==251460
    return {'profiles':13,'fresh_replay':dict(counts),'cases':rows,'retained_queries_unsat':3,
      'independent_source_lift':lifted,'algorithm_oracles':algorithms,'source_IDA_spans':len(e['spans']),
      'format12_rebases':len(fix['records']),'format12_bindings':len(fix['bindings']),
      'session_and_registration_prefixes_freshly_replayed':False,'native_target_executed':False,
      'full_goal_complete':False,'all_checks_pass':True}


if __name__=='__main__':print(json.dumps({'audit_result':audit()}))
