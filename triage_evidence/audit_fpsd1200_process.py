#!/usr/bin/env python3
"""Independent original callback replay and session-retirement data oracles.

Does not import the new producer. Reconstructs snapshot composition and CF
contracts, checks full CPU, original journals, complete RAM and local SMT.
The frozen session predecessor receipt is pinned, not freshly re-executed.
O(V+J+H*R+I) time, O(J+H*R+I) space; SMT costs separate. No native effects.
"""
import base64
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import zlib
from unicorn import arm64_const as A
from replay_daemon_descriptor_source import Replay as Parent, decode
from recover_daemon_descriptor_source import HEADER
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,verify_original_fixups
from daemon_import_bindings import binding
from verify_daemon_reader_record_payloads_publication import read

POOL=0x74000000;SIZE=65536;STRIDE=896;CFPORT=0x77001000
POINTS={0x10029a254,0x10029a260,0x1001fb82c,0x1001fb834,
        0x1001fb83c,0x1001fb8bc,0x1003f8830,0x1003f8844,0x10025e6ac}
LABELS=['matching_audit_PID','different_PID','diagnostic_word_changed','inactive_marker',
        'reserved_marker','other_marker','encoded_PID_changed','live_slot_index1']


def digest(b):return sha256(b).hexdigest()


def lifted_local_proofs():
    """Lift the actual straight-line W-register instructions independently.

    Only the three listed symbolic loads and one listed store are admitted.
    Variable shifts use ARM's low five bits. No dispatcher theorem is implied.
    """
    import z3
    pid=z3.BitVec('audit_PID32',32);stored=z3.BitVec('audit_stored32',32)
    marker=z3.BitVec('audit_marker32',32)
    bv=lambda n:z3.BitVecVal(n&0xffffffff,32)
    def lift(start,end,initial,loads):
        regs={k:bv(v)for k,v in initial.items()};cmp=None;stores=[]
        def val(s):
            if s.startswith('#'):return bv(int(s[1:],0))
            assert s.startswith('w')and s in regs,s
            return regs[s]
        for i in CS.disasm(IMAGE.read(start,end-start),start):
            op=i.mnemonic;args=[a.strip()for a in i.op_str.split(',')]
            if op=='ldr':assert i.address in loads;regs[args[0]]=loads[i.address];continue
            if op=='str':assert i.address==0x100497638;stores.append(val(args[0]));continue
            if op=='cmp':cmp=(val(args[0]),val(args[1]));continue
            assert args[0].startswith('w'),(hex(i.address),i.op_str)
            if op=='mov':value=val(args[1])
            elif op=='movk':
                shift=0 if len(args)==2 else int(args[2].removeprefix('lsl #'),0)
                value=(val(args[0])&bv(~(0xffff<<shift)))|(val(args[1])<<shift)
            elif op=='add':value=val(args[1])+val(args[2])
            elif op=='sub':value=val(args[1])-val(args[2])
            elif op=='eor':value=val(args[1])^val(args[2])
            elif op=='and':value=val(args[1])&val(args[2])
            elif op=='lsl':value=val(args[1])<<(val(args[2])&31)
            else:raise AssertionError((hex(i.address),op))
            regs[args[0]]=value
        return cmp,stores
    # Reader phases are checked in every complete callback replay. The writer
    # phase is conditional and compatible with the one frozen producer store.
    reader,_=lift(0x1001fb82c,0x1001fb8c0,{'w11':0x19b1,'w9':0x2795},
                  {0x1001fb82c:stored,0x1001fb830:pid})
    gate,_=lift(0x10029a254,0x10029a264,
                {'w4':0xba8820b5,'w9':0x2795,'w5':0xffffd869},
                {0x10029a254:marker})
    _,writer=lift(0x100497600,0x10049763c,{'w10':0x5d50},
                  {0x100497600:pid})
    rows=[(reader[0]==reader[1],stored==pid+0x382eac5c),
          (z3.ULT(*gate),z3.And(marker!=0x4577df49,marker!=0x4577df4a)),
          (writer[0],pid+0x382eac5c)]
    for left,right in rows:
        s=z3.Solver();s.set(timeout=20000);s.add(left!=right);assert s.check()==z3.unsat
    return {'source_lifted_queries_unsat':3,'writer_shift1_phase_conditional':True,
      'reader_phases_checked_by_full_CPU_replay':True}


class Replay(Parent):
    def __init__(self,p,origin,session,mask):
        self.pi=self.pri=self.pwi=0
        super().__init__(p,origin)
        self.u.mem_map(POOL,SIZE);self.u.mem_write(POOL,b'\xa5'*SIZE)
        heap=bytes.fromhex(session['heap44800_hex']);self.u.mem_write(POOL,heap)
        self.mask=bytearray(mask);before=bytes(self.u.mem_read(HEADER,16)).hex()
        self.u.mem_write(HEADER,struct.pack('<QQ',POOL,50))
        index=self.c['slot_index'];assert index in(0,1)
        if index:
            self.u.mem_write(POOL,heap[896:1792]);self.u.mem_write(POOL+896,heap[:896])
            self.mask[:896],self.mask[896:1792]=mask[896:1792],mask[:896]
        controls=[]
        for key,off in [('diagnostic_word',400),('marker_word',876),('PID_word',140)]:
            if key in self.c:
                at=POOL+index*896+off;b=struct.pack('<I',self.c[key])
                controls.append({'field':key,'address':hex(at),'before_hex':bytes(self.u.mem_read(at,4)).hex(),'after_hex':b.hex()})
                self.u.mem_write(at,b);self.mask[at-POOL:at-POOL+4]=b'\1'*4
        assert p['composition']=={'header_before_hex':before,'header_after_hex':struct.pack('<QQ',POOL,50).hex(),
          'source_pool_SHA256':digest(heap),'slot_index':index,'controls':controls,
          'initial_pool_SHA256':digest(bytes(self.u.mem_read(POOL,SIZE))),
          'initial_defined_mask_SHA256':digest(self.mask),'initial_defined_bytes':sum(self.mask),
          'native_temporal_continuity_established':False}

    def read_hook(self,u,access,a,n,v,d):
        if POOL<=a<a+n<=POOL+SIZE:
            assert self.p['pool_defined_reads'][self.pri]=={'visit':self.current,
              'defined_mask_hex':self.mask[a-POOL:a-POOL+n].hex()}
            self.pri+=1
        return super().read_hook(u,access,a,n,v,d)

    def write_hook(self,u,access,a,n,v,d):
        if POOL<=a<a+n<=POOL+SIZE:
            assert self.p['pool_defined_writes'][self.pwi]=={'visit':self.current,'address':hex(a),
              'defined_before_hex':self.mask[a-POOL:a-POOL+n].hex()};self.pwi+=1
            self.mask[a-POOL:a-POOL+n]=b'\1'*n
            e=self.p['source_writes'][self.wi];self.wi+=1
            assert {k:e[k]for k in('visit','address','size_bytes','before_hex')}=={
              'visit':self.current,'address':hex(a),'size_bytes':n,'before_hex':bytes(u.mem_read(a,n)).hex()}
            self.pending.append(e);self.counts['original_writes_checked']+=1;return
        return super().write_hook(u,access,a,n,v,d)

    def external(self,a,name):
        if name in('CoreFoundation/_CFMachPortInvalidate','CoreFoundation/_CFRelease')and self.reg(0)==CFPORT:
            e=self.p['imports'][self.mi];self.mi+=1
            assert e['pc']==hex(a)and e['name']==name and e['arguments8']==[hex(self.reg(j))for j in range(8)]
            assert e['result']=='0x0'and not e['preserve_all_CPU']and not e['patches']
            self.frame(e['before']);target=self.reg(30)
            for j in range(18):self.setreg(j,((j+1)*0x123456789abcdef)^0x8b3dc651)
            self.setreg(0,0);self.u.reg_write(A.UC_ARM64_REG_NZCV,0xf0000000)
            self.u.reg_write(A.UC_ARM64_REG_PC,target);self.frame(e['after'])
            self.counts['external_ABI_and_declared_effect_contracts_recomputed']+=1;return
        return super().external(a,name)

    def hook(self,u,a,n,d):
        if a in POINTS:self.frame(self.p['process_points'][self.pi]);self.pi+=1
        return super().hook(u,a,n,d)

    def run(self):
        super().run()
        assert self.pi==len(self.p['process_points'])and self.pri==len(self.p['pool_defined_reads'])and self.pwi==len(self.p['pool_defined_writes'])
        assert decode(self.p['final_pool'])==bytes(self.u.mem_read(POOL,SIZE))
        assert decode(self.p['final_defined_mask'])==self.mask
        self.counts['complete_final_pool_bytes_checked']+=SIZE
        self.counts['complete_final_defined_mask_bytes_checked']+=SIZE
        self.counts['process_point_CPU_frames_checked']+=self.pi
        return dict(self.counts)


def joins(e,session):
    assert [p['configuration']['label']for p in e['profiles']]==LABELS
    expected=[True,False,True,False,False,True,False,True];case_results=[]
    heap=bytes.fromhex(session['heap44800_hex'])
    assert struct.unpack_from('<I',heap,140)[0]==0x4f44c170==(0x17161514+0x382eac5c)&0xffffffff
    assert [w for w in session['heap_writes']if w['offset_B']==140]==[
      {'pc':'0x100497638','offset_B':140,'width_B':4,'value':'0x4f44c170'}]
    for p,retired in zip(e['profiles'],expected,strict=True):
        c=p['configuration'];index=c['slot_index'];slot=POOL+index*STRIDE
        assert c['phase']=='callback'and c['event_result']==1 and c['filter']==-5 and not c['event_seed']
        assert p['boundary']['kind']=='original_return_to_declared_caller'
        # These are original source requests to opaque CF identities, not native CF effects.
        cf=[(m['name'],hex(int(m['before']['registers31'][30],16)-4),m['arguments8'][0])
            for m in p['imports']if m['name']in('CoreFoundation/_CFMachPortInvalidate','CoreFoundation/_CFRelease')]
        assert cf==([('CoreFoundation/_CFMachPortInvalidate','0x10025e648','0x77001000'),
                     ('CoreFoundation/_CFRelease','0x10025e6a4','0x77001000')]if retired else[])
        writes=[w for w in p['source_writes']if POOL<=int(w['address'],16)<POOL+SIZE]
        reads=[r for r in p['source_reads']if POOL<=int(r['address'],16)<POOL+SIZE]
        assert len(writes)==(52 if retired else 0)
        assert not any(int(r['address'],16)<slot+404 and slot+400<int(r['address'],16)+r['size_bytes']for r in reads)
        marker_reads=[r for r in reads if p['source_visits'][r['visit']]['pc']=='0x10029a254']
        assert [int(r['address'],16)for r in marker_reads]==[POOL+896*j+876 for j in range(50)]
        for q in p['process_points']:
            regs=[int(x,16)for x in q['registers31']]
            if q['pc']=='0x10029a254':assert regs[3]==896 and regs[4]==0xba8820b5 and regs[5]==0xffffd869 and regs[9]==0x2795 and regs[10]==POOL
            if q['pc']=='0x10029a260':assert regs[13]==0xfffffffe
            if q['pc']=='0x1001fb834':assert regs[11]==0x19b1
            if q['pc']=='0x1001fb83c':assert regs[13]==1 and regs[9]==0x2795
        final=decode(p['final_pool'])
        if retired:
            targets=[(p['source_visits'][w['visit']]['pc'],int(w['address'],16)-slot,w['size_bytes'],w['after_hex'])for w in writes]
            assert targets[:3]==[('0x10025bc8c',888,8,'00'*8),('0x1003f8830',876,4,'49df7745'),('0x1003f8844',816,4,'51c63d8b')]
            assert targets[-1]==('0x10025e6ac',0,8,'00'*8)
            pattern=bytes.fromhex('f8a4aa56b468661a90bc224e4c80de12')
            assert final[index*896+820:index*896+868]==pattern*3
            assert all(t[0]=='0x1004840d4'and t[2]==1 for t in targets[3:-1])
            assert [t[1]for t in targets[3:-1]]==list(range(835,819,-1))+list(range(851,835,-1))+list(range(867,851,-1))
            assert final[index*896:index*896+8]==bytes(8)and final[index*896+876:index*896+880]==bytes.fromhex('49df7745')
        assert not any('mach_msg'in m['name']or'IOConnect'in m['name']or'vm_'in m['name']for m in p['imports'])
        case_results.append({'case':c['label'],'visits':len(p['source_visits']),'retirement_requests':retired,
          'slot_index':index,'pool_stores':len(writes),'marker_slots_scanned':len(marker_reads)})
    a,b=e['profiles'][0],e['profiles'][2]
    for k in ['source_visits','source_reads','source_writes','imports','boundary','final_regions']:
        assert a[k]==b[k],k
    left,right=decode(a['final_pool']),decode(b['final_pool'])
    assert left[:400]+left[404:]==right[:400]+right[404:]
    assert left[400:404]==bytes.fromhex('a5a5a5a5')and right[400:404]==struct.pack('<I',0x17161514)
    # This identifies the only possible ARM variable-shift value for the one
    # retained writer input/output. It is not a fresh complete writer CPU frame.
    shifts=[n for n in range(32)if (((0x17161514^0xff3fefff)+((0x17161514<<n)&0xfe7fdffe)+0x38eebc5d)&0xffffffff)==0x4f44c170]
    assert shifts==[1]
    return {'cases':case_results,'writer_shift_values_compatible_with_frozen_store':shifts,
      'writer_phase_freshly_replayed':False,'diagnostic_word_nonconsumer_control_equal':True,
      'native_temporal_continuity_established':False}


def audit():
    import z3
    e=json.loads(read(ROOT/'fpsd1200_process_checks.json'))
    assert digest(SOURCE.read_bytes())==e['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert digest(read(ROOT/'recover_fpsd1200_process.py').encode())==e['generator_sha256']
    for n,h in e['dependencies'].items():assert digest(read(ROOT/n).encode())==h,n
    previous=json.loads(read(ROOT/'fpsd1200_lifetime_checks.json'))
    receipt=json.loads(read(ROOT/'fpsd1200_lifetime_audit.json'))
    assert receipt['fresh_replay_completed']and receipt['process_exit_code']==0
    assert receipt['checks_sha256']==digest(read(ROOT/'fpsd1200_lifetime_checks.json').encode())
    assert receipt['auditor_sha256']==digest(read(ROOT/'audit_fpsd1200_lifetime.py').encode())
    assert receipt['IDA_SDK_readback_sha256']==digest(read(ROOT/'fpsd1200_lifetime_ida_readback.json').encode())
    for n,h in previous['dependencies'].items():assert digest(read(ROOT/n).encode())==h,n
    packed=next(p for p in previous['profiles']if p['label']=='queue7_success')
    raw=zlib.decompress(base64.b64decode(packed['payload_zlib_base64']))
    assert digest(raw)==e['frozen_session_payload_sha256'];session=json.loads(raw)
    assert session['pool_pair16_final']==e['source_pool_pair16_hex']==struct.pack('<QQ',POOL,50).hex()
    mask=bytearray(SIZE)
    for w in session['heap_writes']:mask[w['offset_B']:w['offset_B']+w['width_B']]=b'\1'*w['width_B']
    assert sum(mask)==e['source_pool_defined_bytes']==1159
    att=json.loads(read(ROOT/'fpsd1200_process_ida_readback.json'))
    assert att['input_sha256']=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'and not att['IDB_mutated']
    assert att['spans']==[{'start':s['start'],'size_B':int(s['end'],16)-int(s['start'],16),'sha256':s['sha256']}for s in e['spans']]
    for s in e['spans']:
        a,z=int(s['start'],16),int(s['end'],16);b=IMAGE.read(a,z-a)
        assert b.hex()==s['bytes_hex']and digest(b)==s['sha256']
        assert s['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a)]
    w=e['PID_writer_range'];assert IMAGE.read(int(w['start'],16),60).hex()==w['bytes_hex']==att['additional_source_ranges'][0]['bytes_hex']
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
    for h in att['SDK_context']['headers']:assert digest((sdk/h['SDK_relative_path']).read_bytes())==h['sha256']
    abi=att['SDK_context']['compile_only'];r=subprocess.run([str(sdk)if x=='installed SDK'else x for x in abi['logical_command']],input=abi['source'],text=True,capture_output=True)
    assert r.returncode==abi['exit_code']==0 and r.stdout==abi['stdout']==''and r.stderr==abi['stderr']==''
    assert set(e['proofs'])=={'marker_gate','PID_reader','PID_writer_shift1'}
    for q in e['proofs'].values():
        s=z3.Solver();s.set(timeout=20000);s.from_string(q['query']);assert s.check()==z3.unsat and q['result']=='unsat'
    old=json.loads(read(ROOT/'daemon_descriptor_source_profiles.json'));origin=old['setup_cases'][0]
    setup=Counter();setup.update(Parent(old['initializer']).run());setup.update(Parent(origin,old['initializer']).run())
    assert setup['original_instruction_visits_checked']==22599
    counts=Counter()
    for p in e['profiles']:counts.update(Replay(p,origin,session,mask).run())
    accesses={int(r['address'],16)for p in e['profiles']for r in p['source_reads']if int(r['address'],16)in FIXUPS}
    binds=sorted(a for a in accesses if FIXUPS[a]['kind'].endswith('bind'))
    fix=verify_original_fixups(sorted(accesses-set(binds)));fix['bindings']=[binding(a)for a in binds]
    assert e['fixups']==fix
    assert counts['original_instruction_visits_checked']==e['verified_counts']['callback_original_visits']==44440
    return {'profiles':8,'callback_replay':dict(counts),'initializer_setup_replay':dict(setup),
      'queries_unsat':3,'source_IDA_spans':len(e['spans']),'original_format12_rebases':len(fix['records']),
      'original_format12_binds':len(fix['bindings']),'joins':joins(e,session),
      'independent_source_lift':lifted_local_proofs(),
      'frozen_session_predecessor_receipt_pinned':True,'session_prefix_freshly_replayed':False,
      'native_target_executed':False,'all_checks_pass':True}


if __name__=='__main__':print(json.dumps(audit()))
