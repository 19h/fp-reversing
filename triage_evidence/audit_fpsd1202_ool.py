#!/usr/bin/env python3
"""Independent FPSD1202 original-source, OOL ABI and phase audit.

Does not import the new producer. Reconstructs composition and API/application
contracts; checks complete CPU, journals and RAM. Stub outputs are declared
controls. Native endpoint, VM, CF, right and ownership effects remain unknown.
O(V+J+H*R+I) time, O(J+H*R+I) space; solver cost separate.
"""
import json,struct,base64,zlib,subprocess
from collections import Counter
from hashlib import sha256
from pathlib import Path
import z3
from unicorn import arm64_const as A
from audit_fpsd1200_process import Replay as Parent
from replay_daemon_descriptor_source import decode
from recover_daemon_descriptor_source import REGIONS,STACK,HALT,HEADER
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,verify_original_fixups,TABLE,qword
from daemon_import_bindings import binding
from verify_daemon_reader_record_payloads_publication import read

PRIVATE=0x73000000;SIZE=65536;POOL=0x74000000;APP=0x1000060b4
POINTS={APP,0x10065ffd8,0x10000639c,0x100501d28,0x100501d4c,0x100501d6c,
 0x10052184c,0x100521878,0x100004848,0x100004858,0x100004860,0x100735e50,0x1009b7d2c}
LABELS=['source_word0','source_word1','source_word2','source_word3','source_session_name',
 'source_marker4d','source_moved_session','source_no_registration','stub_success','stub_error',
 'guard_simple','guard_descriptor_count','guard_size','guard_descriptor_type','guard_repeated_count']


def digest(b):return sha256(b).hexdigest()


def registration():
    p=next(p for p in json.loads(read(ROOT/'daemon_registration_profiles.json'))['profiles']if p['label']=='services_success')
    b=bytes.fromhex(p['final_header_72_bytes'])[40:48]
    writes=[w for w in p['image_writes']if int(w['address'],16)==HEADER+40]
    assert writes==[{'pc':'0x100315354','address':hex(HEADER+40),'size':8,'value':'0x5000000200'}]
    call=next(c for c in p['calls']if c['name']=='CoreFoundation/_CFMachPortCreateWithPort'and c['result']=='0x5000000200')
    assert call['args'][1]=='0x1003'and b==struct.pack('<Q',0x5000000200)
    return b,{'profile':p['label'],'cell':hex(HEADER+40),'bytes_hex':b.hex(),'original_store':writes[0],
      'CF_construction':call,'native_temporal_continuity_established':False}


class Replay(Parent):
    def __init__(self,p,o,s,m):
        self.ai=self.ci=self.di=0
        super().__init__(p,o,s,m)
        for v in s['startup_owners_final']:self.u.mem_write(int(v['address'],16),bytes.fromhex(v['bytes_hex']))
        for v in s['startup_context']['source_global_spans']:self.u.mem_write(int(v['address'],16),bytes.fromhex(v['bytes_hex']))
        for v in s['final_image_writes']:self.u.mem_write(int(v['address'],16),bytes.fromhex(v['bytes_hex']))
        b,j=registration();j.update(applied=self.c['registration_cell'],before_hex=bytes(self.u.mem_read(HEADER+40,8)).hex());assert p['registration_join']==j
        if self.c['registration_cell']:self.u.mem_write(HEADER+40,b)
        self.u.mem_map(PRIVATE,SIZE);self.u.mem_write(PRIVATE+0x9000,bytes.fromhex(s['provider_snapshot']['published_buffer512_hex']))
        self.u.mem_write(PRIVATE+0xa000,bytes(range(16)));self.u.reg_write(A.UC_ARM64_REG_CPACR_EL1,3<<20)
        c=self.c;b=bytearray(84);struct.pack_into('<7I',b,0,c['header_bits'],c['request_size'],0x6400,c['local_name'],0,1202,c['descriptor_count'])
        struct.pack_into('<Q',b,28,PRIVATE+0xa000);b[39]=c['descriptor_type'];struct.pack_into('<I',b,40,16)
        b[44:52]=bytes.fromhex('0000000001000000');struct.pack_into('<3I',b,52,c['wordA'],c['wordB'],c['wordC'])
        b[64:80]=bytes(range(0x40,0x50));struct.pack_into('<I',b,80,c['repeated_count'])
        for(at,b),v in zip([(STACK+0x1000,bytes(b)),(STACK+0x2000,b'\xa5'*212)],p['mig_patches'],strict=True):
            assert v=={'address':hex(at),'before_hex':bytes(self.u.mem_read(at,len(b))).hex(),'after_hex':b.hex()};self.u.mem_write(at,b)
        self.setreg(0,STACK+0x1000);self.setreg(1,STACK+0x2000);self.setreg(30,HALT)
        self.u.reg_write(A.UC_ARM64_REG_SP,STACK+0x78000);self.u.reg_write(A.UC_ARM64_REG_PC,0x100004b80)
        self.frame(p['mig_entry']);self.target=0x100004b80
        assert p['initial_region_SHA256']==[digest(bytes(self.u.mem_read(a,n)))for a,n in REGIONS+[(POOL,SIZE),(PRIVATE,SIZE)]]

    def modeled_return(self,e,result,patches):
        self.frame(e['before']);assert e['arguments8']==[hex(self.reg(j))for j in range(8)]and e['result']==hex(result)
        assert len(e['patches'])==len(patches)
        for(at,b),v in zip(patches,e['patches'],strict=True):
            assert v=={'address':hex(at),'before_hex':bytes(self.u.mem_read(at,len(b))).hex(),'after_hex':b.hex()};self.u.mem_write(at,b)
        target=self.reg(30)
        for j in range(18):self.setreg(j,((j+1)*0x123456789abcdef)^0x8b3dc651)
        self.setreg(0,result);self.u.reg_write(A.UC_ARM64_REG_NZCV,0xf0000000);self.u.reg_write(A.UC_ARM64_REG_PC,target);self.frame(e['after'])

    def stop_boundary(self,kind):
        self.finish_writes();assert self.p['boundary']['kind']==kind;self.frame(self.p['boundary']);self.done=True;self.u.emu_stop()

    def external(self,a,name):
        if name=='CoreFoundation/_CFMachPortGetPort':
            if self.reg(0)==0x77001000:
                assert self.c['label']=='source_marker4d';return self.stop_boundary('before_session_CF_name_request')
            assert self.reg(0)==(0x5000000200 if self.c['registration_cell']else 0)
            if not self.c['registration_cell']:return self.stop_boundary('before_unmodeled_NULL_CF_name_request')
            result=0x1003
        elif name=='libSystem/_mig_deallocate':
            assert [self.reg(0),self.reg(1)]==[PRIVATE+0xa000,16]
            assert self.p['deallocation_requests'][self.di]=={'original_call':hex(self.reg(30)-4),
              'address':hex(PRIVATE+0xa000),'size_B':16,'native_unmap_established':False};self.di+=1;result=0
        else:return super().external(a,name)
        e=self.p['imports'][self.mi];self.mi+=1
        assert e['pc']==hex(a)and e['name']==name and not e['preserve_all_CPU']
        self.modeled_return(e,result,[]);self.counts['external_ABI_and_declared_effect_contracts_recomputed']+=1

    def hook(self,u,a,n,d):
        if a in POINTS:
            p=self.p['abi_points'][self.ai];self.ai+=1;self.frame(p)
            if a==0x10065ffd8:
                carrier=self.reg(0);payload=int.from_bytes(u.mem_read(carrier+16,8),'little')
                assert p['carrier28_hex']==bytes(u.mem_read(carrier,28)).hex()and p['payload64_hex']==bytes(u.mem_read(payload,64)).hex()
            if a in(0x100501d28,0x100501d4c,0x100501d6c):
                assert p['context96_hex']==bytes(u.mem_read(HEADER,96)).hex()
                assert p['stack_context_cell_hex']==bytes(u.mem_read(u.reg_read(A.UC_ARM64_REG_SP)+0x448,8)).hex()==struct.pack('<Q',HEADER).hex()
        if a==APP and self.c['application_status']is not None:
            self.finish_writes();e=self.p['application_calls'][self.ci];self.ci+=1
            args=[self.reg(j)for j in range(8)];sp=self.u.reg_read(A.UC_ARM64_REG_SP);outs=struct.unpack('<3Q',bytes(u.mem_read(sp,24)))
            assert args==[self.c['local_name'],self.c['wordA'],self.c['wordB'],self.c['wordC'],STACK+0x1040,PRIVATE+0xa000,16,STACK+0x2034]
            assert outs[:2]==(STACK+0x201c,STACK+0x2044)
            assert e['pc']==hex(a)and e['declared_application_return']and e['stack_arguments3']==[hex(v)for v in outs]
            self.modeled_return(e,self.c['application_status'],[(args[7],bytes(range(0x80,0x90))),
              (outs[0],struct.pack('<Q',PRIVATE+0xb000)),(outs[1],struct.pack('<I',24)),(outs[2],struct.pack('<I',1))])
            self.counts['declared_application_return_contracts_checked']+=1;return
        return super().hook(u,a,n,d)

    def run(self):
        super().run();p=self.p
        assert self.ai==len(p['abi_points'])and self.ci==len(p['application_calls'])and self.di==len(p['deallocation_requests'])
        assert p['request84_final_hex']==bytes(self.u.mem_read(STACK+0x1000,84)).hex()
        assert p['reply72_final_hex']==bytes(self.u.mem_read(STACK+0x2000,72)).hex()
        assert p['extra_final_region']['address']==hex(PRIVATE)and decode(p['extra_final_region'])==bytes(self.u.mem_read(PRIVATE,SIZE))
        assert self.u.reg_read(A.UC_ARM64_REG_CPACR_EL1)==0x300000
        self.counts['extra_final_private_bytes_checked']+=SIZE;self.counts['ABI_CPU_point_frames_checked']+=self.ai
        return dict(self.counts)


def lifted_proofs():
    bv=lambda x:z3.BitVecVal(x&0xffffffff,32)
    def lift(start,end,initial,stores=()):
        regs=dict(initial);comparison=None
        def v(s):return bv(int(s[1:],0))if s.startswith('#')else regs[s]
        for i in CS.disasm(IMAGE.read(start,end-start),start):
            a=[s.strip()for s in i.op_str.split(',')];op=i.mnemonic
            if op=='str':assert i.address in stores;continue
            if op=='cmp':comparison=v(a[0])==v(a[1]);continue
            if op=='mov':x=v(a[1])
            elif op=='movk':
                shift=0 if len(a)==2 else int(a[2].removeprefix('lsl #'),0);x=(v(a[0])&bv(~(65535<<shift)))|(v(a[1])<<shift)
            elif op=='eor':x=v(a[1])^v(a[2])
            elif op=='add':x=v(a[1])+v(a[2])
            elif op=='sub':x=v(a[1])-v(a[2])
            elif op=='lsl':x=v(a[1])<<(v(a[2])&31)
            elif op=='lsr':x=z3.LShR(v(a[1]),v(a[2])&31)
            elif op=='orr':x=v(a[1])|v(a[2])
            elif op=='bic':x=v(a[1])&~v(a[2])
            elif op=='and':x=v(a[1])&v(a[2])
            elif op=='mul':x=v(a[1])*v(a[2])
            else:raise AssertionError((hex(i.address),op))
            regs[a[0]]=x
        return regs,comparison
    n,p,m=z3.BitVecs('audit_CF32 audit_received32 audit_marker32',32)
    _,cmp=lift(0x100501d4c,0x100501d70,{'w0':n,'w28':p},(0x100501d60,))
    phase={'w11':m,'w24':bv(0x6cf4),'w16':bv(0x45777259),'w20':bv(0x39d3),
      'w1':bv(0xffffc64c),'w26':bv(1),'w25':bv(0x6f),'w22':bv(0xffffcdc8)}
    regs,_=lift(0x100521850,0x100521878,phase)
    for left,right in [(cmp,n==p),(regs['w11'],z3.If(m==0x4577df4d,bv(0x3ad3),bv(0x3abc)))]:
        s=z3.Solver();s.set(timeout=20000);s.add(left!=right);assert s.check()==z3.unsat
    assert qword(TABLE+8*0x3ad3)==0x1004a07b4 and qword(TABLE+8*0x3abc)==0x1005bec24
    return {'independently_lifted_source_queries_unsat':2,'marker_match_target':'0x1004a07b4','marker_other_target':'0x1005bec24'}


def joins(e):
    assert [p['configuration']['label']for p in e['profiles']]==LABELS
    expected_visits=[2296,2296,2390,2296,4332,2544,2296,2133,100,91,37,40,43,46,50]
    rows=[]
    for ix,p in enumerate(e['profiles']):
        c=p['configuration'];b=bytes.fromhex(p['reply72_final_hex']);wire=bytes.fromhex(p['request84_final_hex'])
        assert len(p['source_visits'])==expected_visits[ix]
        assert not p['pool_defined_writes']and digest(decode(p['final_pool']))==p['composition']['initial_pool_SHA256']
        assert decode(p['extra_final_region'])[0xa000:0xa010]==bytes(range(16))
        ool_reads=[r for r in p['source_reads']if PRIVATE+0xa000<=int(r['address'],16)<PRIVATE+0xa010];assert not ool_reads
        for q in p['abi_points']:
            rs=[int(v,16)&0xffffffff for v in q['registers31']]
            if q['pc']=='0x100501d4c':assert rs[0]==0x1003 and rs[28]==c['local_name']
            if q['pc']=='0x10052184c':
                assert {j:rs[j]for j in(0,14,15,16,22,24,25,26,1)}=={
                  0:896,14:0xffffcc5d,15:0x82,16:0x45777259,22:0xffffcdc8,24:0x6cf4,25:0x6f,26:1,1:0xffffc64c}
            if q['pc']=='0x10065ffd8':
                carrier=bytes.fromhex(q['carrier28_hex']);body=bytes.fromhex(q['payload64_hex'])
                assert (int.from_bytes(carrier[8:12],'little')^0x6cf4^int.from_bytes(carrier[12:16],'little'))==0x8799a4f1
                assert struct.unpack_from('<4I',body)==(c['local_name'],c['wordA'],c['wordC'],c['wordB'])
                assert struct.unpack_from('<QQI',body,16)==(STACK+0x1040,PRIVATE+0xa000,16)
                assert int.from_bytes(body[40:48],'little')==STACK+0x2034
        pending=ix in(5,7);guard=ix>=10;deallocated=not(pending or guard)
        assert len(p['deallocation_requests'])==int(deallocated)
        assert struct.unpack_from('<Q',wire,28)[0]==(0 if deallocated else PRIVATE+0xa000)
        assert struct.unpack_from('<I',wire,40)[0]==(0 if deallocated else 16)
        status=None
        if not pending:
            header=struct.unpack_from('<6I',b);success=ix==8
            assert header==(0x80000012 if success else 0x12,72 if success else 36,0x6400,0,0,1302)
            if success:
                assert struct.unpack_from('<I',b,24)[0]==1 and struct.unpack_from('<Q',b,28)[0]==PRIVATE+0xb000
                assert b[36:40]==bytes.fromhex('01010001')and struct.unpack_from('<I',b,40)[0]==24
                assert b[44:52]==bytes.fromhex('0000000001000000')and b[52:68]==bytes(range(0x80,0x90))and struct.unpack_from('<I',b,68)[0]==24
            else:
                status=struct.unpack_from('<i',b,32)[0];assert status==(5 if ix<8 else 8 if ix==9 else -304 if ix<13 else -300)
                assert b[24:32]==bytes.fromhex('0000000001000000')
        rows.append({'case':c['label'],'visits':len(p['source_visits']),'boundary':p['boundary']['kind'],
          'simple_reply_status_s32':status,'reply_size_B':None if pending else struct.unpack_from('<I',b,4)[0],
          'pool_reads':len(p['pool_defined_reads']),'deallocation_requested':deallocated,'OOL_body_bytes_read':0})
    assert len(e['profiles'][4]['pool_defined_reads'])==50 and len(e['profiles'][5]['pool_defined_reads'])==2
    return rows


def audit():
    e=json.loads(read(ROOT/'fpsd1202_ool_checks.json'));assert digest(SOURCE.read_bytes())==e['daemon_sha256']
    assert digest(read(ROOT/'recover_fpsd1202_ool.py').encode())==e['generator_sha256']
    for n,h in e['dependencies'].items():assert digest(read(ROOT/n).encode())==h
    frozen=json.loads(read(ROOT/'fpsd1200_lifetime_checks.json'));receipt=json.loads(read(ROOT/'fpsd1200_lifetime_audit.json'))
    assert receipt['fresh_replay_completed']and receipt['process_exit_code']==0
    assert receipt['checks_sha256']==digest(read(ROOT/'fpsd1200_lifetime_checks.json').encode())
    assert receipt['auditor_sha256']==digest(read(ROOT/'audit_fpsd1200_lifetime.py').encode())
    raw=zlib.decompress(base64.b64decode(next(p for p in frozen['profiles']if p['label']=='queue7_success')['payload_zlib_base64']))
    assert digest(raw)==e['frozen_session_payload_sha256'];session=json.loads(raw);mask=bytearray(SIZE)
    for w in session['heap_writes']:mask[w['offset_B']:w['offset_B']+w['width_B']]=b'\1'*w['width_B']
    assert sum(mask)==1159
    att=json.loads(read(ROOT/'fpsd1202_ool_ida_readback.json'))
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
    for k in ['name_comparator_proof','marker_selector_proof']:
        s=z3.Solver();s.set(timeout=20000);s.from_string(e[k]['query']);assert s.check()==z3.unsat and e[k]['result']=='unsat'
    lifted=lifted_proofs();old=json.loads(read(ROOT/'daemon_descriptor_source_profiles.json'));counts=Counter();accesses=set()
    for p in e['profiles']:
        counts.update(Replay(p,old['setup_cases'][0],session,mask).run())
        accesses.update(int(r['address'],16)for r in p['source_reads']if int(r['address'],16)in FIXUPS)
        print(json.dumps({'replayed':p['configuration']['label']}),flush=True)
    binds=sorted(a for a in accesses if FIXUPS[a]['kind'].endswith('bind'));fix=verify_original_fixups(sorted(accesses-set(binds)))
    fix['bindings']=[binding(a)for a in binds];assert fix==e['fixups']
    rows=joins(e);assert counts['original_instruction_visits_checked']==e['verified_counts']['original_visits']==20990
    return {'profiles':15,'fresh_replay':dict(counts),'cases':rows,'retained_queries_unsat':2,
      'independent_source_lift':lifted,'source_IDA_spans':len(e['spans']),'format12_rebases':len(fix['records']),
      'format12_bindings':len(fix['bindings']),'session_and_registration_prefixes_freshly_replayed':False,
      'native_target_executed':False,'full_goal_complete':False,'all_checks_pass':True}


if __name__=='__main__':print(json.dumps({'audit_result':audit()}))
