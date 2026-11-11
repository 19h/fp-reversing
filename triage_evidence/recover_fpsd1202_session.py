#!/usr/bin/env python3
"""FPSD1202 selected-session name, operation fork and finite data-flow recovery.

Only marker4d is a declared session-state control. The CF name pair is pinned
to the predecessor model; no cryptographic result, output or status is supplied.
Stored transform bytes are diagnostic A5 with no source-write provenance.
O(V+J+H*R+I) time, O(J+H*R+I) space; solver costs separate.
"""
import json,struct
from pathlib import Path
from hashlib import sha256
from recover_fpsd1202_ool import Request,configurations as prior_configs,inputs,PRIVATE,POINTS as PRIOR_POINTS
from recover_fpsd1200_process import POOL,SIZE,CFPORT
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS
from recover_fpsd1200_admission import fixup_checks
from recover_daemon_descriptor_source import REGIONS,STACK
from verify_daemon_reader_record_payloads_publication import read

POINTS={0x1004a0838,0x1004a0860,0x1004c481c,0x100495958,0x10049596c,
 0x100495984,0x100539c20,0x10053948c,0x100539e7c,0x10053da34,
 0x1004d8b34,0x1004d8b40,0x1004d8b48,0x1004d8b7c,0x1004d8b80}
HELPERS={0x100539c20,0x10053948c,0x100539e7c,0x10053da34}
DEPS=['recover_fpsd1202_ool.py','audit_fpsd1202_ool.py','fpsd1202_ool_checks.json',
 'fpsd1202_ool_audit.json','fpsd1200_lifetime_checks.json','fpsd1200_lifetime_audit.json',
 'recover_fpsd1200_process.py','audit_fpsd1200_process.py','daemon_receive_tools.py',
 'daemon_receive_fixups.txt','daemon_import_bindings.py','daemon_descriptor_source_profiles.json']


def digest(b):return sha256(b).hexdigest()


def configurations():
    base=next(c for c in prior_configs()if c['label']=='source_marker4d')
    for label,extra in [('word0',{'wordA':0}),('word1',{}),('word2',{'wordA':2}),
      ('word3',{'wordA':3}),('word4',{'wordA':4}),('word_ffffffff',{'wordA':0xffffffff}),
      ('different_session_name',{'session_CF_name':0x6801}),('live_slot_index1',{'slot_index':1}),
      ('wordB_zero',{'wordB':0}),('wordC_zero',{'wordC':0}),('OOL_zero',{'OOL_control':'zero'}),
      ('OOL_reverse',{'OOL_control':'reverse'}),('inline_zero',{'inline_control':'zero'})]:
        yield {**base,'label':label,'session_CF_name':0x6800,'OOL_control':None,'inline_control':None,**extra}


class Session(Request):
    def __init__(self,c,o,s,m):
        self.session_points=[];self.transform_record=None;super().__init__(c,o,s,m)
        self.pre_control_region_SHA256=list(self.initial_region_SHA256);self.fixture_extensions=[]
        controls=[]
        if c['OOL_control']is not None:controls.append((PRIVATE+0xa000,bytes(16)if c['OOL_control']=='zero'else bytes(range(15,-1,-1))))
        if c['inline_control']is not None:controls.append((STACK+0x1040,bytes(16)))
        for a,b in controls:
            self.fixture_extensions.append({'address':hex(a),'before_hex':self.regbytes(a,len(b)).hex(),'after_hex':b.hex()});self.u.mem_write(a,b)
        self.initial_region_SHA256=[digest(self.regbytes(a,n))for a,n in REGIONS+[(POOL,SIZE),(PRIVATE,SIZE)]]
        at=POOL+c['slot_index']*896
        self.initial_slot_diagnostics={'slot':hex(at),'field812_hex':self.regbytes(at+812,4).hex(),
          'transform16_hex':self.regbytes(at+852,16).hex(),'transform16_known_mask_hex':self.mask[at-POOL+852:at-POOL+868].hex(),
          'counter8_hex':self.regbytes(at+868,8).hex(),'counter8_known_mask_hex':self.mask[at-POOL+868:at-POOL+876].hex()}

    def model(self,a,name):
        if name=='CoreFoundation/_CFMachPortGetPort'and self.reg(0)==CFPORT:
            e={'pc':hex(a),'name':name,'preserve_all_CPU':False};self.models.append(e);self.return_model(e,self.c['session_CF_name'],[]);return
        return super().model(a,name)

    def hook(self,u,a,n,d):
        if a in POINTS:
            p=self.frame()
            if a in HELPERS:
                args=[]
                for j in range(4):
                    v=self.reg(j);valid=any(lo<=v and v+64<=lo+size for lo,size in REGIONS+[(POOL,SIZE),(PRIVATE,SIZE)])
                    args.append({'address':hex(v),'bytes64_hex':self.regbytes(v,64).hex()}if valid else None)
                p['bounded_argument_windows4']=args
                if a in(0x100539c20,0x10053948c):self.transform_record=self.reg(0)
                assert self.transform_record is not None
                raw=self.regbytes(self.transform_record,32);ptrs=struct.unpack_from('<3Q',raw,8)
                assert all(any(lo<=v and v+16<=lo+size for lo,size in REGIONS+[(POOL,SIZE),(PRIVATE,SIZE)])for v in ptrs)
                p['transform_views']={'record':hex(self.transform_record),'record32_hex':raw.hex(),'pointers3':[{'address':hex(v),'bytes16_hex':self.regbytes(v,16).hex()}for v in ptrs]}
            self.session_points.append(p)
        return super().hook(u,a,n,d)

    def run_session(self):
        p=self.run_request();p.update(session_points=self.session_points,initial_slot_diagnostics=self.initial_slot_diagnostics,
          pre_control_region_SHA256=self.pre_control_region_SHA256,fixture_extensions=self.fixture_extensions)
        return p


def main():
    old,s,m,payload_sha=inputs();profiles=[];sites=set();accesses=set()
    for c in configurations():
        p=Session(c,old['setup_cases'][0],s,m).run_session();profiles.append(p)
        sites.update(int(v['pc'],16)for v in p['source_visits']);accesses.update(int(r['address'],16)for r in p['source_reads']if int(r['address'],16)in FIXUPS)
        app=next(q for q in p['abi_points']if q['pc']=='0x100004848')
        print(json.dumps({'case':c['label'],'visits':len(p['source_visits']),'original_application_status_u32':int(app['registers31'][0],16)&0xffffffff}),flush=True)
    spans=[]
    for a in sorted(sites):
        if spans and a==spans[-1][1]:spans[-1][1]+=4
        else:spans.append([a,a+4])
    catalog=[{'start':hex(a),'end':hex(z),'bytes_hex':IMAGE.read(a,z-a).hex(),'sha256':digest(IMAGE.read(a,z-a)),
      'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(IMAGE.read(a,z-a),a)]}for a,z in spans]
    counts={'profiles':len(profiles),'original_visits':sum(len(p['source_visits'])for p in profiles),
      'imports':sum(len(p['imports'])for p in profiles),'source_reads':sum(len(p['source_reads'])for p in profiles),
      'source_writes':sum(len(p['source_writes'])for p in profiles),'session_CPU_points':sum(len(p['session_points'])for p in profiles),
      'source_spans':len(catalog),'source_instructions':len(sites)}
    import z3
    n,p,a,t,y=z3.BitVecs('session_name32 requested_name32 operation32 auxiliary32 counter32',32)
    k=z3.BitVecVal(0x74c29d8b,32);h=(t-k)|(k-t)
    rows=[('name_equality',((n^0x7d7adee7)+((n<<1)&0xfaf5bdce)-p)==0x7d7adee7,n==p),
      ('operation_fork',z3.ULT(a-1,2),z3.Or(a==1,a==2)),
      ('second_counter',y+k+0xc0f5f41b+0xca476e5b+z3.If(h+1<=0,z3.BitVecVal(1,32),z3.BitVecVal(0,32)),y+1+z3.If(t!=k,z3.BitVecVal(1,32),z3.BitVecVal(0,32)))]
    proofs={}
    for label,left,right in rows:
        solver=z3.Solver();solver.set(timeout=20000);solver.add(left!=right);query=solver.to_smt2();assert solver.check()==z3.unsat
        proofs[label]={'query':query,'result':'unsat','scope':'Local source expression under freshly checked CPU phases; no native validity or ownership theorem.'}
    e={'scope':__doc__,'daemon_sha256':digest(SOURCE.read_bytes()),'generator_sha256':digest(Path(__file__).read_bytes()),
      'dependencies':{n:digest(read(ROOT/n).encode())for n in DEPS},'frozen_session_payload_sha256':payload_sha,
      'profiles':profiles,'proofs':proofs,'spans':catalog,'fixups':fixup_checks(accesses),'verified_counts':counts,
      'native_target_executed':False,'IDB_edit_operations_requested':False,'full_goal_complete':False}
    (ROOT/'fpsd1202_session_checks.json').write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
