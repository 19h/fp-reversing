#!/usr/bin/env python3
"""Independent original-source replay of opaque-tail retirement frontiers.

Does not import the new producer. Reconstructs declared pointer controls,
checks complete CPU/journals/RAM, proves local null selectors independently,
and forbids consuming diagnostic object bytes. No native effects execute.
O(V+J+H*R+I) time and space; solver costs separate.
"""
import json,struct,base64,zlib,subprocess
from collections import Counter
from hashlib import sha256
from pathlib import Path
import z3
from audit_fpsd1200_process import Replay as Parent
from replay_daemon_descriptor_source import decode
from recover_daemon_descriptor_source import REGIONS
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,TABLE,qword,verify_original_fixups
from daemon_import_bindings import binding
from verify_daemon_reader_record_payloads_publication import read

WORK=0x78000000;POOL=0x74000000;SIZE=65536
POINTS={0x10022de34,0x1003ce728,0x1003ce750,0x100265248,0x100265274,
 0x100406d60,0x1001faa0c,0x1003e508c,0x100735e14,0x1009b7d10}
STOPS={0x1001faa20:(880,11,108,4),0x100406d64:(888,20,0,8)}
LABELS=['null_tails','tail880','tail888','both','different_PID','inactive_marker','marker4d','index1_both','index1_tail880']
VISITS=[7088,5205,3057,3057,4045,3999,3057,3089,5237]


def digest(b):return sha256(b).hexdigest()


class Replay(Parent):
    def __init__(self,p,o,s,m):
        self.ti=self.owi=0;super().__init__(p,o,s,m)
        self.u.mem_map(WORK,SIZE);self.u.mem_write(WORK,b'\xa5'*SIZE);controls=[]
        for off,v in[(880,WORK),(888,WORK+4096)]:
            if not self.c['tail'+str(off)]:continue
            at=POOL+896*self.c['slot_index']+off;b=struct.pack('<Q',v)
            controls.append({'address':hex(at),'before_hex':bytes(self.u.mem_read(at,8)).hex(),'after_hex':b.hex()})
            self.u.mem_write(at,b);self.mask[at-POOL:at-POOL+8]=b'\1'*8
        assert controls==p['tail_patches']and digest(self.mask)==p['tail_initial_mask_SHA256']
        assert p['tail_initial_region_SHA256']==[digest(bytes(self.u.mem_read(a,n)))for a,n in REGIONS+[(POOL,SIZE),(WORK,SIZE)]]

    def read_hook(self,u,access,a,n,v,d):
        assert not WORK<=a<a+n<=WORK+SIZE,'opaque object read is outside the checked interval'
        return super().read_hook(u,access,a,n,v,d)

    def write_hook(self,u,access,a,n,v,d):
        if WORK<=a<a+n<=WORK+SIZE:
            assert a==WORK+4096+24 and n==8 and self.c['tail888']
            assert self.p['source_visits'][self.current]['pc']=='0x100406d60'
            assert self.p['object_writes'][self.owi]=={'visit':self.current,'address':hex(a),'size_bytes':n};self.owi+=1
            e=self.p['source_writes'][self.wi];self.wi+=1
            assert {k:e[k]for k in('visit','address','size_bytes','before_hex')}=={
              'visit':self.current,'address':hex(a),'size_bytes':n,'before_hex':bytes(u.mem_read(a,n)).hex()}
            self.pending.append(e);self.counts['original_writes_checked']+=1;return
        return super().write_hook(u,access,a,n,v,d)

    def hook(self,u,a,n,d):
        if a in STOPS:
            off,reg,delta,width=STOPS[a];base=WORK+(4096 if off==888 else 0)
            assert self.c['tail'+str(off)]and self.reg(reg)==base
            self.finish_writes();b=self.p['boundary']
            assert b['kind']=='before_unproven_tail_object_read'
            assert b['pending_object_read']=={'tail_offset_B':off,'object_base':hex(base),'address':hex(base+delta),
              'offset_B':delta,'size_B':width,'instruction_bytes_hex':IMAGE.read(a,4).hex(),'object_allocation_extent_known':False}
            self.frame(b);self.done=True;u.emu_stop();return
        if a in POINTS:self.frame(self.p['tail_points'][self.ti]);self.ti+=1
        return super().hook(u,a,n,d)

    def run(self):
        super().run();assert self.ti==len(self.p['tail_points'])and self.owi==len(self.p['object_writes'])
        f=self.p['final_diagnostic_backing'];assert f['address']==hex(WORK)and decode(f)==bytes(self.u.mem_read(WORK,SIZE))
        self.counts['complete_diagnostic_backing_bytes_checked']+=SIZE;self.counts['tail_CPU_frames_checked']+=self.ti
        return dict(self.counts)


def lifted_proofs():
    ptr=z3.BitVec('independent_opaque_pointer64',64);bv=lambda x:z3.BitVecVal(x&0xffffffff,32)
    def lift(start,end,phase,initial=None):
        regs={'w19':bv(phase),'x20':ptr,'x11':ptr};cmp=None
        if initial:regs.update(initial)
        def v(q):return bv(int(q[1:],0))if q.startswith('#')else regs[q]
        for i in CS.disasm(IMAGE.read(start,end-start),start):
            op=i.mnemonic;q=[s.strip()for s in i.op_str.split(',')]
            if op=='str':assert i.address==0x1003ce738;continue
            if op=='cmp':assert q in(['x20','#0'],['x11','#0']);cmp=ptr==0;continue
            if op=='cset':assert q[1]=='eq';x=z3.If(cmp,bv(1),bv(0))
            elif op=='mov':x=v(q[1])
            elif op=='add':x=v(q[1])+v(q[2])
            elif op=='orr':x=v(q[1])|v(q[2])
            elif op=='eor':x=v(q[1])^v(q[2])
            elif op=='bic':x=v(q[1])&~v(q[2])
            elif op=='mul':x=v(q[1])*v(q[2])
            else:raise AssertionError((hex(i.address),op))
            regs[q[0]]=x
        return regs
    a=lift(0x1003ce728,0x1003ce754,0x9686)['w8']
    b=lift(0x10026524c,0x100265274,0x6ad8,{'w8':bv(0x2d34)})['w12']
    for left,right in[(a,z3.If(ptr==0,bv(0x96c1),bv(0x9686))),(b,z3.If(ptr==0,bv(0x6ad8),bv(0x6af5)))]:
        s=z3.Solver();s.set(timeout=20000);s.add(left!=right);assert s.check()==z3.unsat
    targets={hex(k):hex(qword(TABLE+8*k))for k in(0x96c1,0x9686,0x6ad8,0x6af5)}
    assert targets['0x96c1']=='0x10025bc54'and targets['0x9686']=='0x100406d5c'and targets['0x6af5']=='0x1001faa0c'
    return {'source_queries_unsat':2,'tail888_PHASE_W19':'0x9686','tail880_PHASE_W19':'0x6ad8','targets':targets}


def joins(e):
    base=next(p['configuration']for p in json.loads(read(ROOT/'fpsd1200_process_checks.json'))['profiles']if p['configuration']['label']=='matching_audit_PID')
    controls=[{},{'tail880':True},{'tail888':True},{'tail880':True,'tail888':True},
      {'tail880':True,'tail888':True,'ident':15},{'tail880':True,'tail888':True,'marker_word':0x4577df49},
      {'tail880':True,'tail888':True,'marker_word':0x4577df4d},
      {'tail880':True,'tail888':True,'slot_index':1},{'tail880':True,'slot_index':1}]
    assert [p['configuration']for p in e['profiles']]==[{**base,'label':label,'tail880':False,'tail888':False,**c}for label,c in zip(LABELS,controls,strict=True)]
    rows=[]
    for ix,p in enumerate(e['profiles']):
        c=p['configuration'];slot=POOL+896*c['slot_index'];stopped=ix in(1,2,3,6,7,8)
        assert len(p['source_visits'])==VISITS[ix]
        assert (p['boundary']['kind']=='before_unproven_tail_object_read')==stopped
        assert not any(WORK<=int(r['address'],16)<WORK+SIZE for r in p['source_reads'])
        writes=[w for w in p['source_writes']if WORK<=int(w['address'],16)<WORK+SIZE]
        assert len(writes)==int(ix in(2,3,6,7))
        if writes:assert writes[0]['after_hex']=='00'*8 and writes[0]['before_hex']=='a5'*8
        pool_reads=[r for r in p['source_reads']if POOL<=int(r['address'],16)<POOL+SIZE]
        tails=[(int(r['address'],16)-slot,r['size_bytes'])for r in pool_reads if int(r['address'],16)in(slot+880,slot+888)]
        assert tails==([]if ix in(4,5)else[(888,8)]+([]if ix in(2,3,6,7)else[(880,8)]))
        cf=[m['name']for m in p['imports']if m['arguments8'][0]=='0x77001000']
        assert cf==(['CoreFoundation/_CFMachPortInvalidate','CoreFoundation/_CFRelease']if ix in(0,1,8)else[])
        assert not any(any(s in m['name']for s in('mach_msg','IOConnect','_free','vm_'))for m in p['imports'])
        pool_writes=[w for w in p['source_writes']if POOL<=int(w['address'],16)<POOL+SIZE]
        if ix in(4,5):assert not pool_writes
        for q in p['tail_points']:
            rs=[int(v,16)for v in q['registers31']]
            if q['pc']=='0x1003ce728':assert rs[19]==0x9686 and rs[20]==(WORK+4096 if c['tail888']else 0)
            if q['pc']=='0x1003ce750':assert rs[8]==(0 if c['tail888']else 0x47)and rs[19]==0x9686
            if q['pc']=='0x100265248':assert rs[19]==0x6ad8 and rs[8]==0x2d34 and rs[10]+rs[20]==slot
            if q['pc']=='0x100265274':assert rs[12]==(0x6af5 if c['tail880']else 0x6ad8)
        final=decode(p['final_pool']);marker=struct.unpack_from('<I',final,c['slot_index']*896+876)[0]
        rows.append({'case':c['label'],'visits':VISITS[ix],'boundary':p['boundary']['kind'],
          'pending_read':p['boundary'].get('pending_object_read'),'tail_loads_in_order':tails,
          'object_stores':len(writes),'pool_stores':len(pool_writes),'CF_requests':cf,
          'final_marker_u32':hex(marker),'final_CF_reference':hex(struct.unpack_from('<Q',final,c['slot_index']*896)[0])})
    return rows


def audit():
    e=json.loads(read(ROOT/'fpsd_tail_retirement_checks.json'))
    assert digest(SOURCE.read_bytes())==e['daemon_sha256']and digest(read(ROOT/'recover_fpsd_tail_retirement.py').encode())==e['generator_sha256']
    for n,h in e['dependencies'].items():assert digest(read(ROOT/n).encode())==h
    old=json.loads(read(ROOT/'daemon_descriptor_source_profiles.json'));frozen=json.loads(read(ROOT/'fpsd1200_lifetime_checks.json'))
    receipt=json.loads(read(ROOT/'fpsd1200_lifetime_audit.json'))
    assert receipt['fresh_replay_completed']and receipt['process_exit_code']==0
    assert receipt['checks_sha256']==digest(read(ROOT/'fpsd1200_lifetime_checks.json').encode())
    assert receipt['auditor_sha256']==digest(read(ROOT/'audit_fpsd1200_lifetime.py').encode())
    raw=zlib.decompress(base64.b64decode(next(p for p in frozen['profiles']if p['label']=='queue7_success')['payload_zlib_base64']))
    assert digest(raw)==e['frozen_session_payload_sha256'];s=json.loads(raw);mask=bytearray(SIZE)
    for w in s['heap_writes']:mask[w['offset_B']:w['offset_B']+w['width_B']]=b'\1'*w['width_B']
    att=json.loads(read(ROOT/'fpsd_tail_retirement_reference.json'))
    assert not att['new_live_source_byte_readback_completed']and not att['new_IDB_edit_operations_requested']
    loc=att['completed_read_only_IDA_locator']
    assert not loc['IDB_mutated']and loc['input_sha256']=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'
    for n,h in att['retained_artifacts'].items():assert digest(read(ROOT/n).encode())==h
    prior=json.loads(read(ROOT/'fpsd1201_session_checks.json'));oldatt=json.loads(read(ROOT/'fpsd1201_session_ida_readback.json'))
    oldreceipt=json.loads(read(ROOT/'fpsd1201_session_audit.json'))
    assert oldreceipt['fresh_replay_completed']and oldreceipt['process_exit_code']==0
    assert oldreceipt['checks_sha256']==digest(read(ROOT/'fpsd1201_session_checks.json').encode())
    assert oldreceipt['IDA_SDK_readback_sha256']==digest(read(ROOT/'fpsd1201_session_ida_readback.json').encode())
    code=att['retained_IDA_code_extent'];lo,hi=int(code['start'],16),int(code['end'],16)
    assert code=={k:prior['tail_census'][k]for k in('start','end','sha256')}
    assert code['sha256']==oldatt['census_extent_SHA256']==digest(IMAGE.read(lo,hi-lo))
    incoming=[int(p['address'],16)for p in e['pointer_records']if p['fixup']['target']==0x1009b7d10]
    row=next(r for r in loc['rows']if r['address']=='0x1009b7d10')
    assert [int(x['from'],16)for x in row['xrefs']]==incoming and all(not x['code']for x in row['xrefs'])
    for r in e['spans']:
        a,z=int(r['start'],16),int(r['end'],16);b=IMAGE.read(a,z-a)
        assert lo<=a<z<=hi
        assert b.hex()==r['bytes_hex']and digest(b)==r['sha256']
        assert r['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a)]
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
    for h in att['SDK_context']['headers']:assert digest((sdk/h['SDK_relative_path']).read_bytes())==h['sha256']
    abi=att['SDK_context']['compile_only'];r=subprocess.run([str(sdk)if x=='installed SDK'else x for x in abi['logical_command']],input=abi['source'],text=True,capture_output=True)
    assert r.returncode==abi['exit_code']==0 and r.stdout==abi['stdout']==''and r.stderr==abi['stderr']==''
    for q in e['proofs'].values():
        solver=z3.Solver();solver.set(timeout=20000);solver.from_string(q['query']);assert solver.check()==z3.unsat and q['result']=='unsat'
    counts=Counter();accesses={int(p['address'],16)for p in e['pointer_records']}
    for p in e['profiles']:
        counts.update(Replay(p,old['setup_cases'][0],s,mask).run())
        accesses.update(int(r['address'],16)for r in p['source_reads']if int(r['address'],16)in FIXUPS)
        print(json.dumps({'replayed':p['configuration']['label']}),flush=True)
    binds=sorted(a for a in accesses if FIXUPS[a]['kind'].endswith('bind'));fix=verify_original_fixups(sorted(accesses-set(binds)))
    fix['bindings']=[binding(a)for a in binds];assert fix==e['fixups']
    rows=joins(e);lifted=lifted_proofs()
    assert counts['original_instruction_visits_checked']==e['verified_counts']['original_visits']==37834
    return {'profiles':9,'fresh_replay':dict(counts),'cases':rows,'retained_queries_unsat':2,
      'independent_source_lift':lifted,'source_spans_under_retained_IDA_extent':len(e['spans']),
      'retained_IDA_extent_bytes':hi-lo,'new_live_IDA_byte_readback_completed':False,'source_pointer_words':len(e['pointer_records']),
      'format12_rebases':len(fix['records']),'format12_bindings':len(fix['bindings']),
      'opaque_object_bytes_consumed':0,'session_prefix_freshly_replayed':False,
      'native_target_executed':False,'full_goal_complete':False,'all_checks_pass':True}


if __name__=='__main__':print(json.dumps({'audit_result':audit()}))
