#!/usr/bin/env python3
"""Original process-event callback composed with a frozen FPSD1200 session.

The descriptor and session are separately produced snapshots. Event delivery,
CF effects, locks, once and PAC remain declared private models; no native IPC.
O(V+J+H*R+I) time, O(J+H*R+I) space for visits, journals, snapshots and image.
"""
import base64
from hashlib import sha256
import json
from pathlib import Path
import struct
import zlib
from unicorn import arm64_const as A
from probe_daemon_descriptor_source import Probe as Parent, zipbytes
from daemon_receive_tools import ROOT, SOURCE, IMAGE, CS, FIXUPS
from recover_daemon_descriptor_source import HEADER
from recover_fpsd1200_admission import fixup_checks
from verify_daemon_reader_record_payloads_publication import read

POOL=0x74000000; SIZE=0x10000; STRIDE=896; CFPORT=0x77001000
POINTS={0x10029a254,0x10029a260,0x1001fb82c,0x1001fb834,
        0x1001fb83c,0x1001fb8bc,0x1003f8830,0x1003f8844,0x10025e6ac}
DEPS=['probe_daemon_descriptor_source.py','replay_daemon_descriptor_source.py',
      'recover_daemon_descriptor_source.py','daemon_descriptor_source_profiles.json',
      'daemon_descriptor_source_source.json','fpsd1200_lifetime_checks.json',
      'fpsd1200_lifetime_audit.json','fpsd1200_lifetime_ida_readback.json',
      'recover_fpsd1200_lifetime.py','audit_fpsd1200_lifetime.py',
      'daemon_rpc502_probe.py','daemon_receive_tools.py','daemon_import_bindings.py',
      'daemon_receive_fixups.txt','recover_fpsd1200_admission.py']


def digest(b):return sha256(b).hexdigest()


def inputs():
    old=json.loads(read(ROOT/'daemon_descriptor_source_profiles.json'))
    e=json.loads(read(ROOT/'fpsd1200_lifetime_checks.json'))
    packed=next(p for p in e['profiles']if p['label']=='queue7_success')
    raw=zlib.decompress(base64.b64decode(packed['payload_zlib_base64']))
    session=json.loads(raw)
    assert session['pool_pair16_final']==struct.pack('<QQ',POOL,50).hex()
    mask=bytearray(SIZE)
    for w in session['heap_writes']:
        a=w['offset_B'];n=w['width_B'];assert 0<=a<a+n<=44800
        mask[a:a+n]=b'\1'*n
    return old,session,mask,digest(raw)


def configurations():
    for label,extra in [
      ('matching_audit_PID',{}),('different_PID',{'ident':15}),
      ('diagnostic_word_changed',{'diagnostic_word':0x17161514}),
      ('inactive_marker',{'marker_word':0x4577df49}),
      ('reserved_marker',{'marker_word':0x4577df4a}),
      ('other_marker',{'marker_word':0x4577df4c}),
      ('encoded_PID_changed',{'PID_word':(15+0x382eac5c)&0xffffffff}),
      ('live_slot_index1',{'slot_index':1})]:
        yield {'phase':'callback','label':label,'filter':-5,'ident':0x17161514,
               'event_result':1,'mach_object':True,'event_seed':False,
               'slot_index':0,**extra}


class Process(Parent):
    def __init__(self,c,origin,session,mask):
        self.points=[];self.pool_reads=[];self.pool_writes=[]
        super().__init__(c,origin)
        self.u.mem_map(POOL,SIZE)
        heap=bytes.fromhex(session['heap44800_hex'])
        self.u.mem_write(POOL,b'\xa5'*SIZE);self.u.mem_write(POOL,heap)
        self.mask=bytearray(mask)
        before=self.regbytes(HEADER,16).hex()
        self.u.mem_write(HEADER,bytes.fromhex(session['pool_pair16_final']))
        index=c['slot_index'];assert index in(0,1)
        if index:
            self.u.mem_write(POOL,heap[STRIDE:2*STRIDE])
            self.u.mem_write(POOL+STRIDE,heap[:STRIDE])
            self.mask[:STRIDE],self.mask[STRIDE:2*STRIDE]=mask[STRIDE:2*STRIDE],mask[:STRIDE]
        controls=[]
        for key,off in [('diagnostic_word',400),('marker_word',876),('PID_word',140)]:
            if key in c:
                a=POOL+index*STRIDE+off;raw=struct.pack('<I',c[key])
                controls.append({'field':key,'address':hex(a),'before_hex':self.regbytes(a,4).hex(),'after_hex':raw.hex()})
                self.u.mem_write(a,raw);self.mask[a-POOL:a-POOL+4]=b'\1'*4
        self.composition={'header_before_hex':before,'header_after_hex':self.regbytes(HEADER,16).hex(),
          'source_pool_SHA256':digest(heap),'slot_index':index,'controls':controls,
          'initial_pool_SHA256':digest(self.regbytes(POOL,SIZE)),
          'initial_defined_mask_SHA256':digest(self.mask),'initial_defined_bytes':sum(self.mask),
          'native_temporal_continuity_established':False}

    def read_hook(self,u,access,a,n,v,d):
        if POOL<=a<a+n<=POOL+SIZE:
            self.pool_reads.append({'visit':self.current,'defined_mask_hex':self.mask[a-POOL:a-POOL+n].hex()})
        return super().read_hook(u,access,a,n,v,d)

    def write_hook(self,u,access,a,n,v,d):
        if POOL<=a<a+n<=POOL+SIZE:
            self.pool_writes.append({'visit':self.current,'address':hex(a),
              'defined_before_hex':self.mask[a-POOL:a-POOL+n].hex()})
            self.mask[a-POOL:a-POOL+n]=b'\1'*n
            e={'visit':self.current,'address':hex(a),'size_bytes':n,'before_hex':self.regbytes(a,n).hex()}
            self.writes_all.append(e);self.pending.append(e);return
        return super().write_hook(u,access,a,n,v,d)

    def model(self,a,name):
        if name in('CoreFoundation/_CFMachPortInvalidate','CoreFoundation/_CFRelease')and self.reg(0)==CFPORT:
            e={'pc':hex(a),'name':name,'before':self.frame(),
              'arguments8':[hex(self.reg(j))for j in range(8)],'result':'0x0',
              'preserve_all_CPU':False,'patches':[]}
            self.models.append(e);target=self.reg(30)
            for j in range(18):self.setreg(j,((j+1)*0x123456789abcdef)^0x8b3dc651)
            self.setreg(0,0);self.u.reg_write(A.UC_ARM64_REG_NZCV,0xf0000000)
            self.u.reg_write(A.UC_ARM64_REG_PC,target);e['after']=self.frame();return
        return super().model(a,name)

    def hook(self,u,a,n,d):
        if a in POINTS:self.points.append(self.frame())
        return super().hook(u,a,n,d)

    def run_process(self):
        r=self.run();r.update(composition=self.composition,process_points=self.points,
          pool_defined_reads=self.pool_reads,pool_defined_writes=self.pool_writes,
          final_pool=zipbytes(self.regbytes(POOL,SIZE)),final_defined_mask=zipbytes(self.mask))
        return r


def proofs():
    import z3
    p=z3.BitVec('PID32',32);stored=z3.BitVec('stored32',32);m=z3.BitVec('marker32',32)
    encoded=(p^0xff3fefff)+((p<<1)&0xfe7fdffe)+0x38eebc5d
    t=p-((p<<1)&0x2be265cc)+0x95f132e6
    candidate=(((t^0x6ceffbfc)+0x93100404)^((t^0xe448d282)+(0x2795^0x1bb70aeb)))^((t^0x1d561b98)+0xe2a9e468)
    rows={}
    for name,left,right,scope in [
      ('marker_gate',z3.ULT(m-0x4577df4b,0xfffffffe),z3.And(m!=0x4577df49,m!=0x4577df4a),
       'All marker32 patterns under observed W4=0xba8820b5,W9=0x2795,W5=0xffffd869; native marker validity unknown.'),
      ('PID_reader',(stored-candidate)==0xce1fdf42,stored==p+0x382eac5c,
       'All PID32/stored32 patterns in the local original comparator under observed W11=0x19b1, W9=0x2795, shift=1.'),
      ('PID_writer_shift1',encoded,p+0x382eac5c,
       'All PID32 patterns in original writer expression conditional on shift=1. Writer CPU phase is not freshly replayed in this increment.')]:
        s=z3.Solver();s.set(timeout=20000);s.add(left!=right);query=s.to_smt2();assert s.check()==z3.unsat
        rows[name]={'query':query,'result':'unsat','scope':scope}
    return rows


def main():
    old,session,mask,payload_sha=inputs();origin=old['setup_cases'][0]
    assert origin['configuration']['label']=='setup_fd7'
    profiles=[];sites=set();accesses=set()
    for c in configurations():
        r=Process(c,origin,session,mask).run_process();profiles.append(r)
        assert r['boundary']['kind']=='original_return_to_declared_caller'
        sites.update(int(v['pc'],16)for v in r['source_visits'])
        accesses.update(int(v['address'],16)for v in r['source_reads']if int(v['address'],16)in FIXUPS)
        print(json.dumps({'label':c['label'],'visits':len(r['source_visits']),
          'pool_store_events':len(r['pool_defined_writes'])}),flush=True)
    spans=[]
    for a in sorted(sites):
        if spans and a==spans[-1][1]:spans[-1][1]+=4
        else:spans.append([a,a+4])
    catalog=[]
    for a,z in spans:
        raw=IMAGE.read(a,z-a)
        catalog.append({'start':hex(a),'end':hex(z),'bytes_hex':raw.hex(),'sha256':digest(raw),
          'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)]})
    counts={'profiles':len(profiles),'callback_original_visits':sum(len(p['source_visits'])for p in profiles),
      'imports':sum(len(p['imports'])for p in profiles),'pool_store_events':sum(len(p['pool_defined_writes'])for p in profiles),
      'pool_read_events':sum(len(p['pool_defined_reads'])for p in profiles),
      'complete_process_CPU_frames':sum(len(p['process_points'])for p in profiles),
      'source_spans':len(catalog),'source_instructions':len(sites),'queries_unsat':3}
    e={'scope':__doc__,'daemon_sha256':digest(SOURCE.read_bytes()),
      'generator_sha256':digest(Path(__file__).read_bytes()),'profiles':profiles,'spans':catalog,
      'dependencies':{n:digest(read(ROOT/n).encode())for n in DEPS},
      'frozen_session_payload_sha256':payload_sha,'source_pool_pair16_hex':session['pool_pair16_final'],
      'source_pool_defined_bytes':sum(mask),'proofs':proofs(),'fixups':fixup_checks(accesses),
      'PID_writer_range':{'start':'0x100497600','bytes_hex':IMAGE.read(0x100497600,60).hex()},
      'verified_counts':counts,'new_IDA_access':True,'new_IDB_mutations':False,
      'new_native_execution':False,'full_goal_complete':False}
    (ROOT/'fpsd1200_process_checks.json').write_text(json.dumps(e,indent=2)+'\n')
    print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
