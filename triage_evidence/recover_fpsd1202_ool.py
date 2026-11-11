#!/usr/bin/env python3
"""FPSD1202 control-endpoint prefix and MIG OOL ownership ABI.

Original source executes in private mappings. Session/startup state and one
registration-produced CF cell are explicitly composed. Stub return controls
replace the application call and are not application success observations.
No native CF, Mach, VM, allocator or IOKit API executes.
O(V+J+H*R+I) time, O(J+H*R+I) space; solver cost separate.
"""
import json,struct
from hashlib import sha256
from pathlib import Path
from unicorn import arm64_const as A
from recover_fpsd1200_process import Process,inputs,POOL,SIZE,CFPORT
from recover_daemon_descriptor_source import REGIONS,STACK,HALT,HEADER
from probe_daemon_descriptor_source import zipbytes
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS
from recover_fpsd1200_admission import fixup_checks
from verify_daemon_reader_record_payloads_publication import read

PRIVATE=0x73000000;APP=0x1000060b4
POINTS={APP,0x10065ffd8,0x10000639c,0x100501d28,0x100501d4c,0x100501d6c,
 0x10052184c,0x100521878,0x100004848,0x100004858,0x100004860,0x100735e50,0x1009b7d2c}
DEPS=['recover_fpsd1200_process.py','audit_fpsd1200_process.py','fpsd1200_process_checks.json',
 'fpsd1200_process_audit.json','fpsd1200_lifetime_checks.json','fpsd1200_lifetime_audit.json',
 'daemon_registration_profiles.json','daemon_registration_profile_checks.json',
 'probe_daemon_descriptor_source.py','replay_daemon_descriptor_source.py',
 'daemon_descriptor_source_profiles.json','daemon_receive_tools.py','daemon_receive_fixups.txt',
 'daemon_import_bindings.py','daemon_mig_tables.json']


def digest(b):return sha256(b).hexdigest()


def registration():
    p=next(p for p in json.loads(read(ROOT/'daemon_registration_profiles.json'))['profiles']if p['label']=='services_success')
    b=bytes.fromhex(p['final_header_72_bytes'])[40:48]
    w=[w for w in p['image_writes']if w['address']==hex(HEADER+40)]
    assert len(w)==1 and w[0]['pc']=='0x100315354'and int(w[0]['value'],16)==int.from_bytes(b,'little')==0x5000000200
    call=next(c for c in p['calls']if c['name']=='CoreFoundation/_CFMachPortCreateWithPort'and c['result']==hex(int.from_bytes(b,'little')))
    assert call['args'][1]=='0x1003'
    return b,{'profile':p['label'],'cell':hex(HEADER+40),'bytes_hex':b.hex(),'original_store':w[0],
      'CF_construction':call,'native_temporal_continuity_established':False}


def configurations():
    rows=[('source_word0',{'wordA':0}),('source_word1',{}),('source_word2',{'wordA':2}),
      ('source_word3',{'wordA':3}),('source_session_name',{'local_name':0x6800}),
      ('source_marker4d',{'local_name':0x6800,'marker_word':0x4577df4d}),
      ('source_moved_session',{'slot_index':1}),('source_no_registration',{'registration_cell':False}),
      ('stub_success',{'application_status':0}),('stub_error',{'application_status':8}),
      ('guard_simple',{'header_bits':0x1212}),('guard_descriptor_count',{'descriptor_count':0}),
      ('guard_size',{'request_size':80}),('guard_descriptor_type',{'descriptor_type':2}),
      ('guard_repeated_count',{'repeated_count':17})]
    for label,extra in rows:
        yield {'phase':'callback','label':label,'filter':-5,'ident':0x17161514,'event_result':1,
          'mach_object':True,'event_seed':False,'slot_index':0,'header_bits':0x80001212,
          'request_size':84,'descriptor_count':1,'descriptor_type':1,'repeated_count':16,
          'local_name':0x1003,'wordA':1,'wordB':2,'wordC':3,'registration_cell':True,
          'application_status':None,**extra}


class Request(Process):
    def __init__(self,c,o,s,m):
        self.abi_points=[];self.application_calls=[];self.deallocation_requests=[]
        super().__init__(c,o,s,m)
        for v in s['startup_owners_final']:self.u.mem_write(int(v['address'],16),bytes.fromhex(v['bytes_hex']))
        for v in s['startup_context']['source_global_spans']:self.u.mem_write(int(v['address'],16),bytes.fromhex(v['bytes_hex']))
        for v in s['final_image_writes']:self.u.mem_write(int(v['address'],16),bytes.fromhex(v['bytes_hex']))
        b,self.registration_join=registration();self.registration_join={**self.registration_join,
          'applied':c['registration_cell'],'before_hex':self.regbytes(HEADER+40,8).hex()}
        if c['registration_cell']:self.u.mem_write(HEADER+40,b)
        self.u.mem_map(PRIVATE,SIZE)
        self.u.mem_write(PRIVATE+0x9000,bytes.fromhex(s['provider_snapshot']['published_buffer512_hex']))
        self.u.mem_write(PRIVATE+0xa000,bytes(range(16)))
        self.u.reg_write(A.UC_ARM64_REG_CPACR_EL1,3<<20)
        self.req=STACK+0x1000;self.reply=STACK+0x2000
        wire=bytearray(84);struct.pack_into('<7I',wire,0,c['header_bits'],c['request_size'],0x6400,c['local_name'],0,1202,c['descriptor_count'])
        struct.pack_into('<Q',wire,28,PRIVATE+0xa000);wire[39]=c['descriptor_type'];struct.pack_into('<I',wire,40,16)
        wire[44:52]=bytes.fromhex('0000000001000000');struct.pack_into('<3I',wire,52,c['wordA'],c['wordB'],c['wordC'])
        wire[64:80]=bytes(range(0x40,0x50));struct.pack_into('<I',wire,80,c['repeated_count'])
        self.mig_patches=[]
        for at,b in [(self.req,bytes(wire)),(self.reply,b'\xa5'*212)]:
            self.mig_patches.append({'address':hex(at),'before_hex':self.regbytes(at,len(b)).hex(),'after_hex':b.hex()});self.u.mem_write(at,b)
        self.setreg(0,self.req);self.setreg(1,self.reply);self.setreg(30,HALT)
        self.u.reg_write(A.UC_ARM64_REG_SP,STACK+0x78000);self.u.reg_write(A.UC_ARM64_REG_PC,0x100004b80)
        self.target=0x100004b80;self.mig_entry=self.frame()
        self.initial_region_SHA256=[digest(self.regbytes(a,n))for a,n in REGIONS+[(POOL,SIZE),(PRIVATE,SIZE)]]

    def return_model(self,e,result,patches):
        e.update(before=self.frame(),arguments8=[hex(self.reg(j))for j in range(8)],result=hex(result),patches=[])
        for at,b in patches:
            e['patches'].append({'address':hex(at),'before_hex':self.regbytes(at,len(b)).hex(),'after_hex':b.hex()});self.u.mem_write(at,b)
        target=self.reg(30)
        for j in range(18):self.setreg(j,((j+1)*0x123456789abcdef)^0x8b3dc651)
        self.setreg(0,result);self.u.reg_write(A.UC_ARM64_REG_NZCV,0xf0000000);self.u.reg_write(A.UC_ARM64_REG_PC,target);e['after']=self.frame()

    def model(self,a,name):
        if name=='CoreFoundation/_CFMachPortGetPort':
            if self.reg(0)==CFPORT:
                assert self.c['label']=='source_marker4d';return self.finish('before_session_CF_name_request')
            assert self.reg(0)==(0x5000000200 if self.c['registration_cell']else 0)
            if not self.c['registration_cell']:return self.finish('before_unmodeled_NULL_CF_name_request')
            e={'pc':hex(a),'name':name,'preserve_all_CPU':False};self.models.append(e);self.return_model(e,0x1003,[]);return
        if name=='libSystem/_mig_deallocate':
            assert [self.reg(0),self.reg(1)]==[PRIVATE+0xa000,16]
            self.deallocation_requests.append({'original_call':hex(self.reg(30)-4),'address':hex(self.reg(0)),'size_B':self.reg(1),'native_unmap_established':False})
            e={'pc':hex(a),'name':name,'preserve_all_CPU':False};self.models.append(e);self.return_model(e,0,[]);return
        return super().model(a,name)

    def hook(self,u,a,n,d):
        if a in POINTS:
            p=self.frame()
            if a==0x10065ffd8:
                carrier=self.reg(0);payload=int.from_bytes(self.regbytes(carrier+16,8),'little')
                p.update(carrier28_hex=self.regbytes(carrier,28).hex(),payload64_hex=self.regbytes(payload,64).hex())
            if a in(0x100501d28,0x100501d4c,0x100501d6c):
                p['context96_hex']=self.regbytes(HEADER,96).hex();p['stack_context_cell_hex']=self.regbytes(self.u.reg_read(A.UC_ARM64_REG_SP)+0x448,8).hex()
            self.abi_points.append(p)
        if a==APP and self.c['application_status']is not None:
            self.flush();sp=self.u.reg_read(A.UC_ARM64_REG_SP);outs=struct.unpack('<3Q',self.regbytes(sp,24))
            assert [self.reg(j)for j in range(8)]==[self.c['local_name'],self.c['wordA'],self.c['wordB'],self.c['wordC'],self.req+64,PRIVATE+0xa000,16,self.reply+52]
            assert outs[:2]==(self.reply+28,self.reply+68)
            e={'pc':hex(a),'stack_arguments3':[hex(v)for v in outs],'declared_application_return':True};self.application_calls.append(e)
            self.return_model(e,self.c['application_status'],[(self.reg(7),bytes(range(0x80,0x90))),
              (outs[0],struct.pack('<Q',PRIVATE+0xb000)),(outs[1],struct.pack('<I',24)),(outs[2],struct.pack('<I',1))]);return
        return super().hook(u,a,n,d)

    def run_request(self):
        r=self.run_process();r.update(registration_join=self.registration_join,mig_patches=self.mig_patches,
          mig_entry=self.mig_entry,initial_region_SHA256=self.initial_region_SHA256,abi_points=self.abi_points,
          application_calls=self.application_calls,deallocation_requests=self.deallocation_requests,
          request84_final_hex=self.regbytes(self.req,84).hex(),reply72_final_hex=self.regbytes(self.reply,72).hex(),
          extra_final_region={'address':hex(PRIVATE),**zipbytes(self.regbytes(PRIVATE,SIZE))})
        return r


def main():
    old,s,m,payload_sha=inputs();profiles=[];sites=set();accesses=set()
    for c in configurations():
        p=Request(c,old['setup_cases'][0],s,m).run_request();profiles.append(p)
        sites.update(int(v['pc'],16)for v in p['source_visits']);accesses.update(int(v['address'],16)for v in p['source_reads']if int(v['address'],16)in FIXUPS)
        print(json.dumps({'case':c['label'],'visits':len(p['source_visits']),'boundary':p['boundary']['kind'],
          'status_at_reply32':struct.unpack_from('<i',bytes.fromhex(p['reply72_final_hex']),32)[0]}),flush=True)
    spans=[]
    for a in sorted(sites):
        if spans and a==spans[-1][1]:spans[-1][1]+=4
        else:spans.append([a,a+4])
    cat=[{'start':hex(a),'end':hex(z),'bytes_hex':IMAGE.read(a,z-a).hex(),'sha256':digest(IMAGE.read(a,z-a)),
      'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(IMAGE.read(a,z-a),a)]}for a,z in spans]
    counts={'profiles':len(profiles),'original_visits':sum(len(p['source_visits'])for p in profiles),
      'imports':sum(len(p['imports'])for p in profiles),'application_controls':sum(len(p['application_calls'])for p in profiles),
      'source_reads':sum(len(p['source_reads'])for p in profiles),'source_writes':sum(len(p['source_writes'])for p in profiles),
      'source_spans':len(cat),'source_instructions':len(sites),'ABI_CPU_points':sum(len(p['abi_points'])for p in profiles)}
    import z3
    n,p=z3.BitVecs('raw_CF_name32 received_local_name32',32);v=(n^0x80000010)-((n<<1)&0xffffffdf)+p
    solver=z3.Solver();solver.set(timeout=20000);solver.add((v==0x80000010)!=(n==p));query=solver.to_smt2();assert solver.check()==z3.unsat
    marker=z3.BitVec('session_marker32',32);delta=marker-0x4577df4d
    key=((1&~z3.LShR(delta|(-delta),31))*0x6f)^0x3abc
    ms=z3.Solver();ms.set(timeout=20000);ms.add(key!=z3.If(marker==0x4577df4d,z3.BitVecVal(0x3ad3,32),z3.BitVecVal(0x3abc,32)));mq=ms.to_smt2();assert ms.check()==z3.unsat
    e={'scope':__doc__,'daemon_sha256':digest(SOURCE.read_bytes()),'generator_sha256':digest(Path(__file__).read_bytes()),
      'dependencies':{n:digest(read(ROOT/n).encode())for n in DEPS},'frozen_session_payload_sha256':payload_sha,
      'profiles':profiles,'spans':cat,'fixups':fixup_checks(accesses),'verified_counts':counts,
      'marker_selector_proof':{'query':mq,'result':'unsat','scope':'Local all-u32 marker predicate under freshly checked CPU phases; declared marker4d control does not prove a source-produced state.'},
      'name_comparator_proof':{'query':query,'result':'unsat','scope':'Local all-u32 equality conditional on W28 being the received local name; complete source frames check this dependency.'},
      'native_target_executed':False,'IDB_edit_operations_requested':False,'full_goal_complete':False}
    (ROOT/'fpsd1202_ool_checks.json').write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
