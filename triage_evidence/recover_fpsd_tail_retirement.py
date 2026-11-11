#!/usr/bin/env python3
"""Original process-event nonzero-tail cleanup frontiers and local null gates.

Tail pointers are declared controls, not source-produced objects. Stop before
the first read of either opaque object. A mapped A5 diagnostic backing permits
the earlier original object+24 store; it supplies no target object bytes.
O(V+J+H*R+I) time and space; local solver costs separate. No native effects.
"""
import json,struct
from hashlib import sha256
from pathlib import Path
import z3
from recover_fpsd1200_process import Process,inputs,configurations as old_configs,POOL,SIZE
from probe_daemon_descriptor_source import zipbytes
from recover_daemon_descriptor_source import REGIONS
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,TABLE,block
from recover_fpsd1200_admission import fixup_checks
from verify_daemon_reader_record_payloads_publication import read

WORK=0x78000000
POINTS={0x10022de34,0x1003ce728,0x1003ce750,0x100265248,0x100265274,
 0x100406d60,0x1001faa0c,0x1003e508c,0x100735e14,0x1009b7d10}
STOPS={0x1001faa20:(880,11,108,4),0x100406d64:(888,20,0,8)}
STATIC=[(0x100735e14,0x100735e64),(0x1009b7d10,0x1009b7d80),
 (0x1003e508c,0x1003e5104),(0x100406d5c,0x100406d78),(0x1001faa0c,0x1001faa88)]
DEPS=['recover_fpsd1200_process.py','audit_fpsd1200_process.py','fpsd1200_process_checks.json',
 'fpsd1200_process_audit.json','fpsd1200_lifetime_checks.json','fpsd1200_lifetime_audit.json',
 'daemon_descriptor_source_profiles.json','probe_daemon_descriptor_source.py',
 'replay_daemon_descriptor_source.py','daemon_receive_tools.py','daemon_receive_fixups.txt',
 'daemon_import_bindings.py','fpsd1201_session_checks.json']


def digest(b):return sha256(b).hexdigest()


def configurations():
    base=next(old_configs())
    for label,extra in [('null_tails',{}),('tail880',{'tail880':True}),('tail888',{'tail888':True}),
      ('both',{'tail880':True,'tail888':True}),('different_PID',{'tail880':True,'tail888':True,'ident':15}),
      ('inactive_marker',{'tail880':True,'tail888':True,'marker_word':0x4577df49}),
      ('marker4d',{'tail880':True,'tail888':True,'marker_word':0x4577df4d}),
      ('index1_both',{'tail880':True,'tail888':True,'slot_index':1}),
      ('index1_tail880',{'tail880':True,'slot_index':1})]:
        yield {**base,'label':label,'tail880':False,'tail888':False,**extra}


class Tail(Process):
    def __init__(self,c,o,s,m):
        self.tail_points=[];self.object_writes=[];super().__init__(c,o,s,m)
        self.u.mem_map(WORK,SIZE);self.u.mem_write(WORK,b'\xa5'*SIZE);self.tail_patches=[]
        for off,address in[(880,WORK),(888,WORK+4096)]:
            if not c['tail'+str(off)]:continue
            at=POOL+c['slot_index']*896+off;b=struct.pack('<Q',address)
            self.tail_patches.append({'address':hex(at),'before_hex':self.regbytes(at,8).hex(),'after_hex':b.hex()})
            self.u.mem_write(at,b);self.mask[at-POOL:at-POOL+8]=b'\1'*8
        self.tail_initial_region_SHA256=[digest(self.regbytes(a,n))for a,n in REGIONS+[(POOL,SIZE),(WORK,SIZE)]]
        self.tail_initial_mask_SHA256=digest(self.mask)

    def read_hook(self,u,access,a,n,v,d):
        assert not WORK<=a<a+n<=WORK+SIZE,'opaque object bytes must not be consumed'
        return super().read_hook(u,access,a,n,v,d)

    def write_hook(self,u,access,a,n,v,d):
        if WORK<=a<a+n<=WORK+SIZE:
            assert a==WORK+4096+24 and n==8 and self.c['tail888']
            assert self.visits[self.current]['pc']=='0x100406d60'
            e={'visit':self.current,'address':hex(a),'size_bytes':n,'before_hex':self.regbytes(a,n).hex()}
            self.object_writes.append({'visit':self.current,'address':hex(a),'size_bytes':n})
            self.writes_all.append(e);self.pending.append(e);return
        return super().write_hook(u,access,a,n,v,d)

    def hook(self,u,a,n,d):
        if a in STOPS:
            off,reg,delta,width=STOPS[a];base=WORK+(4096 if off==888 else 0)
            assert self.c['tail'+str(off)]and self.reg(reg)==base
            self.finish('before_unproven_tail_object_read')
            self.boundary['pending_object_read']={'tail_offset_B':off,'object_base':hex(base),
              'address':hex(base+delta),'offset_B':delta,'size_B':width,
              'instruction_bytes_hex':IMAGE.read(a,4).hex(),'object_allocation_extent_known':False}
            return
        if a in POINTS:self.tail_points.append(self.frame())
        return super().hook(u,a,n,d)

    def run_tail(self):
        p=self.run_process();p.update(tail_patches=self.tail_patches,tail_points=self.tail_points,
          tail_initial_region_SHA256=self.tail_initial_region_SHA256,tail_initial_mask_SHA256=self.tail_initial_mask_SHA256,
          object_writes=self.object_writes,final_diagnostic_backing={'address':hex(WORK),**zipbytes(self.regbytes(WORK,SIZE))})
        return p


def proofs():
    p=z3.BitVec('opaque_tail_pointer64',64);zero=z3.If(p==0,z3.BitVecVal(1,32),z3.BitVecVal(0,32))
    rows=[('tail888_null_selector',zero*0x47^0x9686,z3.If(p==0,z3.BitVecVal(0x96c1,32),z3.BitVecVal(0x9686,32))),
      ('tail880_null_selector',((1&~(0x980c^zero))*0x2d)^0x6ad8,z3.If(p==0,z3.BitVecVal(0x6ad8,32),z3.BitVecVal(0x6af5,32)))]
    out={}
    for label,left,right in rows:
        solver=z3.Solver();solver.set(timeout=20000);solver.add(left!=right);q=solver.to_smt2();assert solver.check()==z3.unsat
        out[label]={'query':q,'result':'unsat','scope':'All u64 pointers under freshly checked local CPU phases; object validity and ownership unknown.'}
    return out


def main():
    old,s,m,payload_sha=inputs();profiles=[];sites=set();accesses=set()
    for c in configurations():
        p=Tail(c,old['setup_cases'][0],s,m).run_tail();profiles.append(p)
        sites.update(int(v['pc'],16)for v in p['source_visits'])
        if p['boundary']['kind']=='before_unproven_tail_object_read':sites.add(int(p['boundary']['pc'],16))
        accesses.update(int(r['address'],16)for r in p['source_reads']if int(r['address'],16)in FIXUPS)
        print(json.dumps({'case':c['label'],'visits':len(p['source_visits']),'boundary':p['boundary']['kind']}),flush=True)
    for a,z in STATIC:sites.update(range(a,z,4))
    spans=[]
    for a in sorted(sites):
        if spans and spans[-1][1]==a:spans[-1][1]+=4
        else:spans.append([a,a+4])
    catalog=[{'start':hex(a),'end':hex(z),'bytes_hex':IMAGE.read(a,z-a).hex(),'sha256':digest(IMAGE.read(a,z-a)),
      'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(IMAGE.read(a,z-a),a)]}for a,z in spans]
    pointer_sites={a for a,r in FIXUPS.items()if r['target']==0x1009b7d10}
    pointer_sites.update(TABLE+8*i for i in(0x96c1,0x9686,0x6ad8,0x6af5))
    pointers=[{'address':hex(a),'bytes_hex':IMAGE.read(a,8).hex(),'fixup':FIXUPS[a]}for a in sorted(pointer_sites)]
    counts={'profiles':len(profiles),'original_visits':sum(len(p['source_visits'])for p in profiles),
      'source_reads':sum(len(p['source_reads'])for p in profiles),'source_writes':sum(len(p['source_writes'])for p in profiles),
      'imports':sum(len(p['imports'])for p in profiles),'tail_CPU_points':sum(len(p['tail_points'])for p in profiles),
      'object_stores':sum(len(p['object_writes'])for p in profiles),'source_spans':len(catalog),'source_instructions':len(sites),
      'static_additional_intervals':len(STATIC),'local_proofs':2,'pointer_records':len(pointers)}
    e={'scope':__doc__,'daemon_sha256':digest(SOURCE.read_bytes()),'generator_sha256':digest(Path(__file__).read_bytes()),
      'dependencies':{n:digest(read(ROOT/n).encode())for n in DEPS},'frozen_session_payload_sha256':payload_sha,
      'profiles':profiles,'spans':catalog,'pointer_records':pointers,'proofs':proofs(),
      'fixups':fixup_checks(accesses|pointer_sites),'verified_counts':counts,
      'static_additional_intervals':[{'start':hex(a),'end':hex(z)}for a,z in STATIC],
      'native_target_executed':False,'IDB_edit_operations_requested':False,'full_goal_complete':False}
    (ROOT/'fpsd_tail_retirement_checks.json').write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
