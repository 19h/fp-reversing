#!/usr/bin/env python3
"""FPSD1201 request-to-session lookup, original failure returns and retirement.

Frozen post-FPSD1200 globals, startup owners and session pool are explicitly
composed with a new MIG entry. CF names, heap APIs, locks, once and PAC are
private models; arithmetic results are never supplied. No native IPC executes.
O(V+J+H*R+B) time, O(J+H*R+B) space; census and solver costs are separate.
"""
import base64
from hashlib import sha256
import json
from pathlib import Path
import re
import struct
import zlib
from unicorn import arm64_const as A
from recover_fpsd1200_process import Process,inputs,POOL,SIZE,CFPORT
from probe_daemon_descriptor_source import zipbytes,unzip
from recover_daemon_descriptor_source import ROOT,REGIONS,STACK,HALT
from daemon_receive_tools import SOURCE,IMAGE,CS,FIXUPS
from recover_fpsd1200_admission import fixup_checks
from verify_daemon_reader_record_payloads_publication import read

WORK=0x78000000;PRIVATE=0x73000000;POINTS={0x1000072d8,0x10065ffd8,
 0x1005a9a50,0x1005a9a90,0x10048bfbc,0x1000075a4,0x100735e50,0x1009b7d2c,
 0x1007fda60,0x10041eecc}
DEPS=['recover_fpsd1200_process.py','audit_fpsd1200_process.py','fpsd1200_process_checks.json',
 'fpsd1200_process_audit.json','fpsd1200_lifetime_checks.json','fpsd1200_lifetime_audit.json',
 'daemon_descriptor_source_profiles.json','probe_daemon_descriptor_source.py',
 'replay_daemon_descriptor_source.py','daemon_rpc502_probe.py','daemon_receive_tools.py',
 'daemon_receive_fixups.txt','daemon_import_bindings.py','daemon_mig_tables.json']


def digest(b):return sha256(b).hexdigest()


def configurations():
    for label,extra in [('matching_zero',{}),('other_word',{'app_word':2}),
      ('other_matching_name',{'local_name':0x6801,'CF_name':0x6801}),
      ('different_name',{'local_name':0x6801}),('allocation_NULL',{'null_allocation':True}),
      ('complex_request',{'header_bits':0x80001212}),('wrong_size',{'request_size':160}),
      ('live_slot_index1',{'slot_index':1}),
      ('marker4c',{'marker_word':0x4577df4c}),('marker4d',{'marker_word':0x4577df4d})]:
        yield {'phase':'callback','component':'MIG1201','label':label,'filter':-5,
          'ident':0x17161514,'event_result':1,'mach_object':True,'event_seed':False,
          'slot_index':0,'local_name':0x6800,'CF_name':0x6800,'app_word':1,
          'header_bits':0x1212,'request_size':164,'null_allocation':False,**extra}


class Session(Process):
    def __init__(self,c,origin,s,mask):
        self.session_points=[];self.owners=[];self.heap_events=[];self.heap_accesses=[]
        self.work_mask=bytearray(SIZE);self.carrier=None
        super().__init__(c,origin,s,mask)
        for o in s['startup_owners_final']:self.u.mem_write(int(o['address'],16),bytes.fromhex(o['bytes_hex']))
        for v in s['startup_context']['source_global_spans']:self.u.mem_write(int(v['address'],16),bytes.fromhex(v['bytes_hex']))
        for v in s['final_image_writes']:self.u.mem_write(int(v['address'],16),bytes.fromhex(v['bytes_hex']))
        self.u.mem_map(PRIVATE,SIZE);self.u.mem_write(PRIVATE+0x9000,bytes.fromhex(s['provider_snapshot']['published_buffer512_hex']))
        self.u.mem_map(WORK,SIZE);self.u.mem_write(WORK,b'\xa5'*SIZE)
        self.u.reg_write(A.UC_ARM64_REG_CPACR_EL1,3<<20)
        self.req=STACK+0x1000;self.reply=STACK+0x2000
        wire=bytearray(164);struct.pack_into('<6I',wire,0,c['header_bits'],c['request_size'],0x6400,c['local_name'],0,1201)
        wire[24:32]=bytes.fromhex('0000000001000000');struct.pack_into('<I',wire,32,c['app_word'])
        self.mig_patches=[]
        for at,b in [(self.req,bytes(wire)),(self.reply,b'\xa5'*212)]:
            self.mig_patches.append({'address':hex(at),'before_hex':self.regbytes(at,len(b)).hex(),'after_hex':b.hex()});self.u.mem_write(at,b)
        self.setreg(0,self.req);self.setreg(1,self.reply);self.setreg(30,HALT)
        self.u.reg_write(A.UC_ARM64_REG_SP,STACK+0x78000);self.u.reg_write(A.UC_ARM64_REG_PC,0x100004b80)
        self.target=0x100004b80;self.session_entry=self.frame()
        self.initial_region_hashes=[digest(self.regbytes(a,n))for a,n in REGIONS+[(POOL,SIZE),(PRIVATE,SIZE),(WORK,SIZE)]]

    def owner(self,a,n):
        owners=[o for o in self.owners if o['address']<=a<a+n<=o['address']+o['size_B']and o['live']]
        assert len(owners)==1,(hex(a),n);return owners[0]

    def read_hook(self,u,access,a,n,v,d):
        if WORK<=a<a+n<=WORK+SIZE:
            o=self.owner(a,n);self.heap_accesses.append({'visit':self.current,'kind':'read',
              'owner':hex(o['address']),'defined_mask_hex':self.work_mask[a-WORK:a-WORK+n].hex()})
        return super().read_hook(u,access,a,n,v,d)

    def write_hook(self,u,access,a,n,v,d):
        if WORK<=a<a+n<=WORK+SIZE:
            o=self.owner(a,n);self.heap_accesses.append({'visit':self.current,'kind':'write',
              'owner':hex(o['address']),'defined_mask_hex':self.work_mask[a-WORK:a-WORK+n].hex()})
            self.work_mask[a-WORK:a-WORK+n]=b'\1'*n
            e={'visit':self.current,'address':hex(a),'size_bytes':n,'before_hex':self.regbytes(a,n).hex()}
            self.writes_all.append(e);self.pending.append(e);return
        assert not PRIVATE<=a<PRIVATE+SIZE
        return super().write_hook(u,access,a,n,v,d)

    def model(self,a,name):
        if name=='CoreFoundation/_CFMachPortGetPort':assert self.reg(0)==CFPORT;result=self.c['CF_name']
        elif name=='libSystem/_malloc':
            index=sum(e['kind']=='allocate'for e in self.heap_events)
            assert index<3 and self.reg(0)==[336,336,324][index]
            result=0 if self.c['null_allocation']else WORK+4096*index
            if result:self.owners.append({'address':result,'size_B':self.reg(0),'live':True})
            self.heap_events.append({'kind':'allocate','visit':len(self.visits),'site':hex(self.reg(30)-4),'size_B':self.reg(0),'result':hex(result)})
        elif name=='libSystem/_free':
            o=self.owner(self.reg(0),1);assert o['address']==self.reg(0);o['live']=False;result=0
            self.heap_events.append({'kind':'free','visit':len(self.visits),'site':hex(self.reg(30)-4),'address':hex(self.reg(0))})
        else:return super().model(a,name)
        e={'pc':hex(a),'name':name,'before':self.frame(),'arguments8':[hex(self.reg(j))for j in range(8)],
           'result':hex(result),'preserve_all_CPU':False,'patches':[]};self.models.append(e);target=self.reg(30)
        for j in range(18):self.setreg(j,((j+1)*0x123456789abcdef)^0x8b3dc651)
        self.setreg(0,result);self.u.reg_write(A.UC_ARM64_REG_NZCV,0xf0000000);self.u.reg_write(A.UC_ARM64_REG_PC,target);e['after']=self.frame()

    def hook(self,u,a,n,d):
        if a in POINTS:
            p=self.frame()
            if a==0x10065ffd8:
                self.carrier=self.reg(0);self.payload=int.from_bytes(self.regbytes(self.carrier+16,8),'little')
                p.update(carrier28_hex=self.regbytes(self.carrier,28).hex(),payload16_hex=self.regbytes(self.payload,16).hex())
            if a==0x1005a9a90:p['requested_name_cell_hex']=self.regbytes(u.reg_read(A.UC_ARM64_REG_SP)+0x9b8,4).hex()
            self.session_points.append(p)
        return super().hook(u,a,n,d)

    def run(self):
        self.u.emu_start(self.target,0,count=1000000);self.flush()
        assert self.boundary is not None and self.boundary['kind']=='original_return_to_declared_caller'
        return {'configuration':self.c,'origin':self.origin,'handoff_before':self.handoff_before,
          'fixture_patches':self.fixture,'entry':self.entry,'source_visits':self.visits,
          'source_reads':self.reads,'source_writes':self.writes_all,'imports':self.models,'boundary':self.boundary,
          'final_regions':[{'address':hex(a),**zipbytes(self.regbytes(a,n))}for a,n in REGIONS],
          'final_header96_hex':self.regbytes(0x1010c4cd8,96).hex(),'final_event32_hex':self.regbytes(0x7005eb64,32).hex()}

    def run_session(self):
        r=self.run_process();r.update(mig_patches=self.mig_patches,session_entry=self.session_entry,
          initial_region_SHA256=self.initial_region_hashes,session_points=self.session_points,
          declared_CPACR_EL1=hex(self.u.reg_read(A.UC_ARM64_REG_CPACR_EL1)),
          extra_final_regions=[{'address':hex(a),**zipbytes(self.regbytes(a,SIZE))}for a in(PRIVATE,WORK)],
          heap_events=self.heap_events,heap_accesses=self.heap_accesses,heap_owners_final=self.owners,
          final_work_defined_mask=zipbytes(self.work_mask),request164_hex=self.regbytes(self.req,164).hex(),
          reply36_hex=self.regbytes(self.reply,36).hex())
        return r


def census():
    start=0x100001058;end=0x100e2ac40;raw=IMAGE.read(start,end-start)
    CS.skipdata=True;rows=[];decoded=skipped=0
    for a,n,op,args in CS.disasm_lite(raw,start):
        decoded+=n;skipped+=int(op=='.byte')
        if '['in args and re.search(r'#0x37[08]\b',args):rows.append({'pc':hex(a),'mnemonic':op,'operands':args})
    CS.skipdata=False;assert decoded==len(raw)
    return {'start':hex(start),'end':hex(end),'sha256':digest(raw),'decoded_bytes':decoded,
      'skipped_word_count':skipped,'literal_offset_candidates':rows,
      'scope':'Literal displacement census only; computed offsets, aliases and object identity are not exhaustively recovered.'}


def proof():
    import z3
    name=z3.BitVec('CF_name32',32);requested=z3.BitVec('received_local_name32',32)
    value=(name^0x77fedf9a)+((name<<1)&0xeffdbf34)+0x51cee081-requested
    s=z3.Solver();s.set(timeout=20000);s.add((value==0xc9cdc01b)!=(name==requested))
    q=s.to_smt2();assert s.check()==z3.unsat
    return {'query':q,'result':'unsat','scope':'Original local name comparison under observed W23=0xc05c,W27=0x24df; no native right or authorization theorem.'}


def main():
    old,s,mask,payload_sha=inputs();origin=old['setup_cases'][0]
    profiles=[];sites=set();accesses=set();counts={};post=None
    for c in configurations():
        x=Session(c,origin,s,mask);r=x.run_session()
        if c['label']=='matching_zero':post=(unzip(r['final_pool'])[:44800],unzip(r['final_defined_mask']))
        for key,value in {'profiles':1,'original_visits':len(r['source_visits']),'imports':len(r['imports']),
          'source_reads':len(r['source_reads']),'source_writes':len(r['source_writes']),
          'session_CPU_points':len(r['session_points']),'heap_accesses':len(r['heap_accesses'])}.items():counts[key]=counts.get(key,0)+value
        sites.update(int(v['pc'],16)for v in r['source_visits'])
        accesses.update(int(v['address'],16)for v in r['source_reads']if int(v['address'],16)in FIXUPS)
        status=struct.unpack_from('<i',bytes.fromhex(r['reply36_hex']),32)[0]
        packed={'label':c['label'],'visits':len(r['source_visits']),'status':status,
          'payload_zlib_base64':base64.b64encode(zlib.compress(json.dumps(r,separators=(',',':')).encode(),9)).decode()}
        profiles.append(packed);print(json.dumps({k:v for k,v in packed.items()if k!='payload_zlib_base64'}),flush=True)
        del x,r
    cb_config={'phase':'callback','label':'after_original_1201_failure','filter':-5,'ident':0x17161514,
      'event_result':1,'mach_object':True,'event_seed':False,'slot_index':0}
    cb=Process(cb_config,origin,{**s,'heap44800_hex':post[0].hex()},post[1]).run_process()
    sites.update(int(v['pc'],16)for v in cb['source_visits'])
    accesses.update(int(v['address'],16)for v in cb['source_reads']if int(v['address'],16)in FIXUPS)
    spans=[]
    for a in sorted(sites):
        if spans and a==spans[-1][1]:spans[-1][1]+=4
        else:spans.append([a,a+4])
    cat=[{'start':hex(a),'end':hex(z),'bytes_hex':IMAGE.read(a,z-a).hex(),'sha256':digest(IMAGE.read(a,z-a)),
      'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(IMAGE.read(a,z-a),a)]}for a,z in spans]
    counts.update(callback_join_visits=len(cb['source_visits']),source_spans=len(cat),source_instructions=len(sites))
    e={'scope':__doc__,'daemon_sha256':digest(SOURCE.read_bytes()),'generator_sha256':digest(Path(__file__).read_bytes()),
      'dependencies':{n:digest(read(ROOT/n).encode())for n in DEPS},'frozen_session_payload_sha256':payload_sha,
      'profiles':profiles,'callback_join':cb,'spans':cat,'fixups':fixup_checks(accesses),'tail_census':census(),
      'proof':proof(),'verified_counts':counts,'native_target_executed':False,'IDB_edit_operations_requested':False,
      'automatic_IDB_analysis_side_effects_measured':False,'full_goal_complete':False}
    (ROOT/'fpsd1201_session_checks.json').write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
