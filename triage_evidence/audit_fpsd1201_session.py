#!/usr/bin/env python3
"""Independent FPSD1201 source replay, ABI, ownership and state-join checks.

Never imports the new producer. Frozen session provenance is pinned; every
new original instruction, journal, API contract, CPU/RAM frame and field join
is independently checked. Native right/CF/heap effects remain unknown.
O(V+J+H*R+B) time, O(J+H*R+B) space; disassembly and SMT costs separate.
"""
import base64
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import re
import struct
import subprocess
import zlib
from unicorn import arm64_const as A
from audit_fpsd1200_process import Replay as Parent
from replay_daemon_descriptor_source import decode
from recover_daemon_descriptor_source import REGIONS,STACK,HALT,HEADER,OUT
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,verify_original_fixups
from daemon_import_bindings import binding
from verify_daemon_reader_record_payloads_publication import read

WORK=0x78000000;PRIVATE=0x73000000;POOL=0x74000000;SIZE=65536;CFPORT=0x77001000
POINTS={0x1000072d8,0x10065ffd8,0x1005a9a50,0x1005a9a90,0x10048bfbc,
 0x1000075a4,0x100735e50,0x1009b7d2c,0x1007fda60,0x10041eecc}
LABELS=['matching_zero','other_word','other_matching_name','different_name','allocation_NULL',
 'complex_request','wrong_size','live_slot_index1','marker4c','marker4d']


def digest(b):return sha256(b).hexdigest()


class Replay(Parent):
    def __init__(self,p,origin,s,mask):
        self.si=self.hai=0;self.owners=[];self.heap_events=[];self.work_mask=bytearray(SIZE)
        super().__init__(p,origin,s,mask)
        for o in s['startup_owners_final']:self.u.mem_write(int(o['address'],16),bytes.fromhex(o['bytes_hex']))
        for v in s['startup_context']['source_global_spans']:self.u.mem_write(int(v['address'],16),bytes.fromhex(v['bytes_hex']))
        for v in s['final_image_writes']:self.u.mem_write(int(v['address'],16),bytes.fromhex(v['bytes_hex']))
        self.u.mem_map(PRIVATE,SIZE);self.u.mem_write(PRIVATE+0x9000,bytes.fromhex(s['provider_snapshot']['published_buffer512_hex']))
        self.u.mem_map(WORK,SIZE);self.u.mem_write(WORK,b'\xa5'*SIZE)
        self.u.reg_write(A.UC_ARM64_REG_CPACR_EL1,3<<20)
        c=self.c;wire=bytearray(164);struct.pack_into('<6I',wire,0,c['header_bits'],c['request_size'],0x6400,c['local_name'],0,1201)
        wire[24:32]=bytes.fromhex('0000000001000000');struct.pack_into('<I',wire,32,c['app_word'])
        for(at,b),saved in zip([(STACK+0x1000,bytes(wire)),(STACK+0x2000,b'\xa5'*212)],p['mig_patches'],strict=True):
            assert saved=={'address':hex(at),'before_hex':bytes(self.u.mem_read(at,len(b))).hex(),'after_hex':b.hex()};self.u.mem_write(at,b)
        self.setreg(0,STACK+0x1000);self.setreg(1,STACK+0x2000);self.setreg(30,HALT)
        self.u.reg_write(A.UC_ARM64_REG_SP,STACK+0x78000);self.u.reg_write(A.UC_ARM64_REG_PC,0x100004b80)
        self.frame(p['session_entry']);self.target=0x100004b80
        assert p['initial_region_SHA256']==[digest(bytes(self.u.mem_read(a,n)))for a,n in REGIONS+[(POOL,SIZE),(PRIVATE,SIZE),(WORK,SIZE)]]

    def owner(self,a,n):
        owners=[o for o in self.owners if o['address']<=a<a+n<=o['address']+o['size_B']and o['live']]
        assert len(owners)==1;return owners[0]

    def work_access(self,a,n,kind):
        o=self.owner(a,n)
        assert self.p['heap_accesses'][self.hai]=={'visit':self.current,'kind':kind,
          'owner':hex(o['address']),'defined_mask_hex':self.work_mask[a-WORK:a-WORK+n].hex()};self.hai+=1

    def read_hook(self,u,access,a,n,v,d):
        if WORK<=a<a+n<=WORK+SIZE:self.work_access(a,n,'read')
        return super().read_hook(u,access,a,n,v,d)

    def write_hook(self,u,access,a,n,v,d):
        if WORK<=a<a+n<=WORK+SIZE:
            self.work_access(a,n,'write');self.work_mask[a-WORK:a-WORK+n]=b'\1'*n
            e=self.p['source_writes'][self.wi];self.wi+=1
            assert {k:e[k]for k in('visit','address','size_bytes','before_hex')}=={
              'visit':self.current,'address':hex(a),'size_bytes':n,'before_hex':bytes(u.mem_read(a,n)).hex()}
            self.pending.append(e);self.counts['original_writes_checked']+=1;return
        assert not PRIVATE<=a<PRIVATE+SIZE
        return super().write_hook(u,access,a,n,v,d)

    def external(self,a,name):
        if name=='CoreFoundation/_CFMachPortGetPort':assert self.reg(0)==CFPORT;result=self.c['CF_name']
        elif name=='libSystem/_malloc':
            index=sum(e['kind']=='allocate'for e in self.heap_events)
            assert index<3 and self.reg(0)==[336,336,324][index]
            result=0 if self.c['null_allocation']else WORK+index*4096
            if result:self.owners.append({'address':result,'size_B':self.reg(0),'live':True})
            self.heap_events.append({'kind':'allocate','visit':self.seq,'site':hex(self.reg(30)-4),'size_B':self.reg(0),'result':hex(result)})
        elif name=='libSystem/_free':
            o=self.owner(self.reg(0),1);assert o['address']==self.reg(0);o['live']=False;result=0
            self.heap_events.append({'kind':'free','visit':self.seq,'site':hex(self.reg(30)-4),'address':hex(self.reg(0))})
        else:return super().external(a,name)
        e=self.p['imports'][self.mi];self.mi+=1
        assert e['pc']==hex(a)and e['name']==name and e['arguments8']==[hex(self.reg(j))for j in range(8)]
        assert e['result']==hex(result)and not e['preserve_all_CPU']and not e['patches']
        self.frame(e['before'])
        target=self.reg(30)
        for j in range(18):self.setreg(j,((j+1)*0x123456789abcdef)^0x8b3dc651)
        self.setreg(0,result);self.u.reg_write(A.UC_ARM64_REG_NZCV,0xf0000000);self.u.reg_write(A.UC_ARM64_REG_PC,target)
        self.frame(e['after']);self.counts['external_ABI_and_declared_effect_contracts_recomputed']+=1

    def hook(self,u,a,n,d):
        if a in POINTS:
            p=self.p['session_points'][self.si];self.frame(p);self.si+=1
            if a==0x10065ffd8:
                c=self.reg(0);payload=int.from_bytes(u.mem_read(c+16,8),'little')
                assert p['carrier28_hex']==bytes(u.mem_read(c,28)).hex()and p['payload16_hex']==bytes(u.mem_read(payload,16)).hex()
            if a==0x1005a9a90:assert p['requested_name_cell_hex']==bytes(u.mem_read(u.reg_read(A.UC_ARM64_REG_SP)+0x9b8,4)).hex()
        return super().hook(u,a,n,d)

    def run(self):
        self.u.emu_start(self.target,0,count=1000000);self.finish_writes();p=self.p
        assert self.done and self.seq==len(p['source_visits'])and self.ri==len(p['source_reads'])and self.wi==len(p['source_writes'])and self.mi==len(p['imports'])
        for(at,n),e in zip(REGIONS,p['final_regions'],strict=True):
            assert e['address']==hex(at)and e['size_bytes']==n and decode(e)==bytes(self.u.mem_read(at,n));self.counts['complete_final_mutable_RAM_bytes_checked']+=n
        assert p['final_header96_hex']==bytes(self.u.mem_read(HEADER,96)).hex()and p['final_event32_hex']==bytes(self.u.mem_read(OUT,32)).hex()
        assert self.pi==len(p['process_points'])and self.pri==len(p['pool_defined_reads'])and self.pwi==len(p['pool_defined_writes'])
        assert decode(p['final_pool'])==bytes(self.u.mem_read(POOL,SIZE))and decode(p['final_defined_mask'])==self.mask
        assert self.hai==len(p['heap_accesses'])and self.si==len(p['session_points'])
        assert p['heap_events']==self.heap_events and p['heap_owners_final']==self.owners
        assert decode(p['final_work_defined_mask'])==self.work_mask
        for a,e in zip((PRIVATE,WORK),p['extra_final_regions'],strict=True):assert e['address']==hex(a)and decode(e)==bytes(self.u.mem_read(a,SIZE))
        assert p['declared_CPACR_EL1']==hex(self.u.reg_read(A.UC_ARM64_REG_CPACR_EL1))=='0x300000'
        assert p['request164_hex']==bytes(self.u.mem_read(STACK+0x1000,164)).hex()and p['reply36_hex']==bytes(self.u.mem_read(STACK+0x2000,36)).hex()
        self.counts['complete_extra_region_pool_and_mask_bytes_checked']+=5*SIZE
        self.counts['session_CPU_point_frames_checked']+=self.si
        self.counts['heap_owner_accesses_checked']+=self.hai
        return dict(self.counts)


def lifted_name_proof():
    import z3
    name=z3.BitVec('audit_CF_name32',32);requested=z3.BitVec('audit_local_name32',32)
    bv=lambda n:z3.BitVecVal(n&0xffffffff,32)
    regs={'w0':name,'w23':bv(0xc05c),'w27':bv(0x24df)};comparison=None
    def val(s):return bv(int(s[1:],0))if s.startswith('#')else regs[s]
    for i in CS.disasm(IMAGE.read(0x1005a9a50,0x44),0x1005a9a50):
        args=[s.strip()for s in i.op_str.split(',')];op=i.mnemonic
        if op=='ldr':assert i.address==0x1005a9a78;regs[args[0]]=requested;continue
        if op=='cmp':comparison=val(args[0])==val(args[1]);continue
        if op=='mov':value=val(args[1])
        elif op=='movk':
            shift=int(args[2].removeprefix('lsl #'),0);value=(val(args[0])&bv(~(65535<<shift)))|(val(args[1])<<shift)
        elif op=='eor':value=val(args[1])^val(args[2])
        elif op=='and':
            right=val(args[2]);assert len(args)==4 and args[3]=='lsl #1';value=val(args[1])&(right<<1)
        elif op=='add':value=val(args[1])+val(args[2])
        elif op=='sub':value=val(args[1])-val(args[2])
        else:raise AssertionError((hex(i.address),op))
        regs[args[0]]=value
    solver=z3.Solver();solver.set(timeout=20000);solver.add(comparison!=(name==requested));assert solver.check()==z3.unsat
    return {'independently_lifted_name_query_unsat':True,'reader_phases_checked_in_CPU_frames':True}


def joins(e,rows,session):
    assert [r['configuration']['label']for r in rows]==LABELS
    expected_status=[-42185,-42185,-42185,8,-42028,-304,-304,-42185,8,8]
    expected_visits=[480680,480680,480680,4518,6675,37,40,480713,4431,4431]
    summaries=[];post=None;post_mask=None
    reset=bytes.fromhex('103ca2cecc005e9228549ac6e418568a28549ac6e418568ac0ec123e7cb0ce02c0ec123e7cb0ce02d8040a3694c8c6fa')
    for r,status,visits in zip(rows,expected_status,expected_visits,strict=True):
        c=r['configuration'];slot=POOL+c['slot_index']*896;off=c['slot_index']*896
        assert len(r['source_visits'])==visits and r['boundary']['registers31'][0]=='0x1'
        b=bytes.fromhex(r['reply36_hex']);assert struct.unpack_from('<6I',b)==(0x12,36,0x6400,0,0,1301)
        assert b[24:32]==bytes.fromhex('0000000001000000')and struct.unpack_from('<i',b,32)[0]==status
        assert r['request164_hex']==r['mig_patches'][0]['after_hex']
        imports=r['imports'];cf=[m for m in imports if m['name']=='CoreFoundation/_CFMachPortGetPort']
        assert len(cf)==int(c['label']not in ['complex_request','wrong_size','marker4c','marker4d'])
        assert all(hex(int(m['before']['registers31'][30],16)-4)=='0x1005a9a4c'and m['arguments8'][0]=='0x77001000'and int(m['result'],16)==c['CF_name']for m in cf)
        names=[m['name']for m in imports]
        assert not any('mach_msg'in n or'IOConnect'in n or'CFMachPortInvalidate'in n or n=='CoreFoundation/_CFRelease'for n in names)
        for q in r['session_points']:
            regs=[int(v,16)for v in q['registers31']]
            if q['pc']=='0x10065ffd8':
                payload=bytes.fromhex(q['payload16_hex']);assert struct.unpack('<IIQ',payload)==(c['local_name'],c['app_word'],STACK+0x1024)
                carrier=bytes.fromhex(q['carrier28_hex']);phase,tag=struct.unpack_from('<II',carrier,8)
                assert phase^0x6cf4^tag==0x8f7506ee
            if q['pc']=='0x1005a9a90':
                assert regs[23]==0xc05c and regs[27]==0x24df
                assert q['requested_name_cell_hex']==struct.pack('<I',c['local_name']).hex()
            if q['pc']=='0x1007fda60':assert regs[3]==0x4577df4b
        pool=decode(r['final_pool']);writes=[w for w in r['source_writes']if POOL<=int(w['address'],16)<POOL+SIZE]
        body_reads=[q for q in r['source_reads']if STACK+0x1024<=int(q['address'],16)<STACK+0x10a4]
        footprint={a for q in body_reads for a in range(int(q['address'],16),int(q['address'],16)+q['size_bytes'])}
        full=c['label']in ['matching_zero','other_word','other_matching_name','live_slot_index1']
        assert footprint==(set(range(STACK+0x1024,STACK+0x10a4))if full else set())
        failure_reset=full or c['label']=='allocation_NULL'
        assert len(writes)==(53 if failure_reset else 0)
        if failure_reset:
            targets=[(r['source_visits'][w['visit']]['pc'],int(w['address'],16)-slot,w['after_hex'])for w in writes]
            assert targets[:5]==[('0x10048bfbc',876,'4cdf7745'),('0x10041eecc',876,'49df7745'),
              ('0x10041eed8',816,'51c63d8b'),('0x10041eee4',868,'7fe7f268'),('0x10041eef0',872,'e40b0a3f')]
            assert pool[off+820:off+868]==reset and pool[off+876:off+880]==bytes.fromhex('49df7745')
        assert pool[off:off+8]==struct.pack('<Q',CFPORT)and pool[off+880:off+896]==bytes(16)
        assert all(not o['live']for o in r['heap_owners_final'])
        assert [v['size_B']for v in r['heap_events']if v['kind']=='allocate']==([336,336,324]if full else[336]if c['label']=='allocation_NULL'else[])
        if c['label']=='matching_zero':post=pool;post_mask=decode(r['final_defined_mask'])
        summaries.append({'case':c['label'],'visits':visits,'status_s32':status,'body_bytes_read':len(footprint),
          'pool_store_events':len(writes),'final_marker_hex':pool[off+876:off+880].hex(),'CF_reference_retained':True})
    assert rows[0]['source_visits']==rows[1]['source_visits']==rows[2]['source_visits']
    cb=e['callback_join'];assert cb['composition']['source_pool_SHA256']==digest(post[:44800])
    assert cb['composition']['initial_pool_SHA256']==digest(post)
    assert cb['composition']['initial_defined_mask_SHA256']==digest(post_mask)
    assert len(cb['source_visits'])==3999 and not cb['pool_defined_writes']
    assert not any(m['name']in('CoreFoundation/_CFMachPortInvalidate','CoreFoundation/_CFRelease')for m in cb['imports'])
    assert decode(cb['final_pool'])==post
    return {'cases':summaries,'post_failure_callback_pool_bytes_identical':True,
      'post_failure_callback_skips_marker49':True,'new_native_ownership_effects_established':False}


def audit():
    import z3
    e=json.loads(read(ROOT/'fpsd1201_session_checks.json'))
    assert digest(SOURCE.read_bytes())==e['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert digest(read(ROOT/'recover_fpsd1201_session.py').encode())==e['generator_sha256']
    for n,h in e['dependencies'].items():assert digest(read(ROOT/n).encode())==h,n
    frozen=json.loads(read(ROOT/'fpsd1200_lifetime_checks.json'));receipt=json.loads(read(ROOT/'fpsd1200_lifetime_audit.json'))
    assert receipt['fresh_replay_completed']and receipt['process_exit_code']==0
    assert receipt['checks_sha256']==digest(read(ROOT/'fpsd1200_lifetime_checks.json').encode())
    assert receipt['auditor_sha256']==digest(read(ROOT/'audit_fpsd1200_lifetime.py').encode())
    raw=zlib.decompress(base64.b64decode(next(p for p in frozen['profiles']if p['label']=='queue7_success')['payload_zlib_base64']))
    assert digest(raw)==e['frozen_session_payload_sha256'];session=json.loads(raw)
    mask=bytearray(SIZE)
    for w in session['heap_writes']:mask[w['offset_B']:w['offset_B']+w['width_B']]=b'\1'*w['width_B']
    assert sum(mask)==1159
    att=json.loads(read(ROOT/'fpsd1201_session_ida_readback.json'))
    assert att['input_sha256']=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'
    assert not att['byte_readback_IDB_mutated']and not att['IDB_edit_operations_requested']and not att['automatic_IDB_analysis_side_effects_measured']
    assert att['spans']==[{'start':s['start'],'size_B':int(s['end'],16)-int(s['start'],16),'sha256':s['sha256']}for s in e['spans']]
    for s in e['spans']:
        a,z=int(s['start'],16),int(s['end'],16);b=IMAGE.read(a,z-a)
        assert b.hex()==s['bytes_hex']and digest(b)==s['sha256']
        assert s['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a)]
    for s in att['additional_source_ranges']:
        b=IMAGE.read(int(s['start'],16),s['size_B']);assert b.hex()==s['bytes_hex']and digest(b)==s['sha256']
    census=e['tail_census'];a,z=int(census['start'],16),int(census['end'],16);b=IMAGE.read(a,z-a)
    assert digest(b)==census['sha256']==att['census_extent_SHA256']
    CS.skipdata=True;rows=[];decoded=skipped=0
    for at,n,op,args in CS.disasm_lite(b,a):
        decoded+=n;skipped+=int(op=='.byte')
        if '['in args and re.search(r'#0x37[08]\b',args):rows.append({'pc':hex(at),'mnemonic':op,'operands':args})
    CS.skipdata=False;assert rows==census['literal_offset_candidates']and decoded==census['decoded_bytes']==len(b)and skipped==census['skipped_word_count']
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
    for h in att['SDK_context']['headers']:assert digest((sdk/h['SDK_relative_path']).read_bytes())==h['sha256']
    abi=att['SDK_context']['compile_only'];compiled=subprocess.run([str(sdk)if x=='installed SDK'else x for x in abi['logical_command']],input=abi['source'],text=True,capture_output=True)
    assert compiled.returncode==abi['exit_code']==0 and compiled.stdout==abi['stdout']==''and compiled.stderr==abi['stderr']==''
    solver=z3.Solver();solver.set(timeout=20000);solver.from_string(e['proof']['query']);assert solver.check()==z3.unsat and e['proof']['result']=='unsat'
    lifted=lifted_name_proof()
    old=json.loads(read(ROOT/'daemon_descriptor_source_profiles.json'));origin=old['setup_cases'][0]
    counts=Counter();profiles=[];accesses=set()
    for p in e['profiles']:
        r=json.loads(zlib.decompress(base64.b64decode(p['payload_zlib_base64'])))
        assert p['label']==r['configuration']['label']and p['visits']==len(r['source_visits'])
        counts.update(Replay(r,origin,session,mask).run())
        accesses.update(int(q['address'],16)for q in r['source_reads']if int(q['address'],16)in FIXUPS)
        profiles.append(r)
        print(json.dumps({'replayed':p['label'],'visits':p['visits']}),flush=True)
    result_joins=joins(e,profiles,session)
    post=decode(profiles[0]['final_pool']);postmask=decode(profiles[0]['final_defined_mask'])
    callback=Parent(e['callback_join'],origin,{**session,'heap44800_hex':post[:44800].hex()},postmask).run()
    accesses.update(int(q['address'],16)for q in e['callback_join']['source_reads']if int(q['address'],16)in FIXUPS)
    binds=sorted(a for a in accesses if FIXUPS[a]['kind'].endswith('bind'))
    fix=verify_original_fixups(sorted(accesses-set(binds)));fix['bindings']=[binding(a)for a in binds];assert fix==e['fixups']
    assert counts['original_instruction_visits_checked']==e['verified_counts']['original_visits']==1942885
    return {'profiles':10,'request_replay':dict(counts),'callback_join_replay':callback,
      'source_IDA_spans':len(e['spans']),'format12_rebases':len(fix['records']),'format12_bindings':len(fix['bindings']),
      'retained_query_unsat':True,'independent_source_lift':lifted,'joins':result_joins,
      'literal_offset_census':{'decoded_B':decoded,'skipped_words':skipped,'candidates':len(rows)},
      'session_prefix_freshly_replayed':False,'native_target_executed':False,'all_checks_pass':True}


if __name__=='__main__':print(json.dumps({'audit_result':audit()}))
