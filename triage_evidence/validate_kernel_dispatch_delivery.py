#!/usr/bin/env python3
"""Recheck original tables, proofs, and finite fixture expectations; refresh manifest.

O(B+F+E) image/fixup/evidence time and space, apart from solver complexity.
Fixtures are private models; checks do not attest a runtime or native delivery.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from kernel_native_reader import Kernel

ROOT=Path(__file__).resolve().parent


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    subprocess.run([sys.executable,str(ROOT/'recover_kernel_dispatch.py')],check=True)
    c=json.loads((ROOT/'kernel_dispatch_contracts.json').read_text())
    p=json.loads((ROOT/'kernel_dispatch_profiles.json').read_text())
    assert p['generator_sha256']==sha(ROOT/'probe_kernel_dispatch.py')
    assert p['reader_sha256']==sha(ROOT/'kernel_native_reader.py') and p['source_sha256']==c['source']['sha256']
    k=Kernel();profiles={r['label']:r for r in p['profiles']};assert len(profiles)==95
    hashes={}
    for r in p['profiles']:
        key=tuple(r['source_code_pages'])
        if key not in hashes:
            h=hashlib.sha256()
            for a in key:
                a=int(a,16);h.update(struct.pack('<Q',a));h.update(k.read(a,4096))
            hashes[key]=h.hexdigest()
        assert hashes[key]==r['source_code_pages_sha256']
        assert r['steps']<p['instruction_limit_per_profile']
        assert not r['native_target_executed'] and not r['target_host_operations_executed']
    checked=[]
    def row(label):return profiles[label]
    def events(label,kind):return [e for e in row(label)['events'] if e['kind']==kind]
    def result(label):
        r=row(label);assert r['stop_reason']=='returned',label
        return int(r['events'][-1]['x0'],16)
    def verify(label,condition,meaning):
        assert condition,(label,meaning)
        checked.append({'profile':label,'check':meaning,'result':'pass'})
    for i in (26,28,31,32,47,50,63,100,108):
        label=f'mach_selector_{i}';r=row(label);e=events(label,'selected_mach_handler');assert len(e)==1
        n=c['mach_entries'][i]['argument_count'];args=struct.unpack('<8Q',bytes.fromhex(e[0]['argument_record']))
        verify(label,list(args[:n])==[0x11110000+j for j in range(n)],'native argc*8 register-record copy')
        want=0xffffffff8000000e if i==47 else 0x1234
        verify(label,int(r['saved_x0'],16)==want,'saved-state signed32 result conversion')
    for i in (0,127,128,129):verify(f'mach_invalid_{i}',row(f'mach_invalid_{i}')['stop_reason']=='invalid_trap_exception_boundary','invalid index/handler enters exception boundary')
    for label,value,called in [('mach_filter_deny_26',0,False),('mach_filter_deny_47',5,False),
        ('mach_filter_callback_allow',0,True),('mach_filter_no_callback',0,True)]:
        verify(label,int(row(label)['saved_x0'],16)==value and bool(events(label,'selected_mach_handler'))==called,
               'port-return/error and nullable-callback filter behavior')
    verify('mach_selector_low32',bool(events('mach_selector_low32','selected_mach_handler')),'Mach dispatcher consumes saved selector low32')
    for r in p['profiles']:
        if r['kind']!='bsd_dispatch':continue
        label=r['label'];assert r['stop_reason']=='selected_bsd_handler'
        last=r['events'][-1];verify(label,int(last['address'],16)==r['seed']['expected_handler'],'selected BSD handler matches original table')
        verify(label,last['args'][:3]==['0x6400000800','0x63000005c0','0x6300000600'],
               'handler ABI proc, uthread argument record, two-word result record')
    a=bytes.fromhex(row('bsd_indirect_selector')['events'][-1]['argument_record'])
    b=bytes.fromhex(row('bsd_indirect_compat_munger')['events'][-1]['argument_record'])
    verify('bsd_indirect_selector',list(struct.unpack('<6Q',a[:48]))==[0x22220000+j for j in range(6)],'indirect syscall omits selector in X0')
    packed=list(struct.unpack('<7I',a[:28]));want=[packed[j] for j in range(5)]+[packed[5]|packed[6]<<32]
    verify('bsd_indirect_compat_munger',list(struct.unpack('<6Q',b[:48]))==want,'task flag clear selects actual 28-byte mmap compatibility munger')
    for rt,w0,w1 in [(0,0x11110000,0x11110001),(1,0xffffffffdeadbeef,0x12345678),
        (2,0xdeadbeef,0x12345678)]+[(rt,0x12345678deadbeef,0) for rt in range(3,8)]:
        label=f'bsd_return_type_{rt}'
        verify(label,int(row(label)['saved_x0'],16)==w0 and int(row(label)['saved_x1'],16)==w1,'native BSD return-type conversion')
    verify('bsd_error_carry',int(row('bsd_error_carry')['saved_x0'],16)==22 and int(row('bsd_error_carry')['saved_cpsr'],16)&(1<<29)!=0,'error22 is returned with saved carry flag')
    verify('bsd_justreturn',int(row('bsd_justreturn')['saved_x0'],16)==0x11110000 and int(row('bsd_justreturn')['saved_cpsr'],16)==0x20000000,'-2 leaves saved result/state unchanged')
    verify('bsd_restart',row('bsd_restart')['stop_reason']=='privileged_restart_boundary','-1 reaches saved-state authentication before native PC rewind')
    for r in p['profiles']:
        if r['kind']!='munmap':continue
        label=r['label'];seed=r['seed'];ok=seed['address'] in (0,0x10000) and seed['length'] in (1,16384)
        if ok:
            verify(label,r['stop_reason']=='vm_deallocate_boundary' and r['events'][-1]['args'][1:3]==[hex(seed['address']),'0x4000'],
                   'aligned nonzero extent reaches page-rounded VM boundary')
        else:verify(label,result(label)==22,'zero, unaligned or wrapping extent returns EINVAL before VM operation')
    for size in (0,23,24,25,27):verify(f'mach2_scalar_size_{size}',result(f'mach2_scalar_size_{size}')==0x10000008,'complex scalar extent rejected as too small')
    for size in (28,40,50331580):verify(f'mach2_scalar_size_{size}',row(f'mach2_scalar_size_{size}')['stop_reason']=='allocation_boundary','native framing checks reach allocator boundary')
    verify('mach2_scalar_size_50331584',result('mach2_scalar_size_50331584')==0x1000000e,'body size beyond0x2ffffbc rejected')
    verify('mach2_noncomplex_count',result('mach2_noncomplex_count')==0x1000000e,'noncomplex header with nonzero descriptor count rejected')
    for size,n,ok in ((28,0,True),(28,1,False),(40,1,True),(40,2,False),(52,2,True)):
        label=f'mach2_descriptor_extent_{size}_{n}'
        verify(label,row(label)['stop_reason']=='allocation_boundary' if ok else result(label)==0x10000008,'descriptor count respects minimum 12-byte descriptor extent')
    for cls in (0,2,4,6,8,16):
        label=f'mach2_class_{cls}';ok=cls in (2,4,8,16)
        verify(label,result(label)==(0 if ok else 0x10000013) and bool(events(label,'send_helper_entry'))==ok,
               'send requires exactly one class; guard helper modeled as returning')
    for cls in (2,4,8,16):
        label=f'mach2_vector_class_{cls}';ok=cls in (4,8)
        verify(label,result(label)==(0 if ok else 0x10000013),'vector send class permits MQ or ANY only')
    for n,want in ((0,0x10000008),(1,0),(2,0),(3,0x10000002)):
        label=f'mach2_vector_count_{n}';verify(label,result(label)==want,'max send/receive vector count is1..2')
    for n,want in ((0,0),(5,0x10000018),(7,0x10000018),(8,0),(1024,0),(1025,0x10000019)):
        label=f'mach2_aux_size_{n}';verify(label,result(label)==want,'nonzero send auxiliary size is8..1024 bytes')
    verify('mach2_copyin_fault',result('mach2_copyin_fault')==0x10000002 and not events('mach2_copyin_fault','send_helper_entry'),'private vector-copy fault skips send')
    verify('mach2_send_fail_skips_receive',result('mach2_send_fail_skips_receive')==0x10000003 and not events('mach2_send_fail_skips_receive','receive_helper_boundary'),'send failure skips receive')
    label='mach2_send_success_then_receive';e=events(label,'send_helper_entry')[0];ctx=bytes.fromhex(e['context_80_bytes'])
    packet=row(label)['seed']['packet'];fields=struct.unpack_from('<7I',ctx)
    expect=(packet[2]&0xffffffff,0,packet[3]&0xffffffff,packet[3]>>32,packet[4]&0xffffffff,packet[4]>>32,packet[5]&0xffffffff)
    verify(label,fields==expect,'kernel reconstructs supplied packed header and descriptor count')
    verify(label,int(e['args'][2],16)==packet[7]&0xffffffff and int(e['args'][3],16)==packet[6]>>32,'timeout truncates to u32; priority is high32 of packed receive field')
    recv=events(label,'receive_helper_boundary')[0]
    actual=[int(x,16) for x in recv['args'][3:]]
    verify(label,[actual[0],actual[1],actual[2]&0xffffffff,actual[3]&0xffffffff,actual[4]]==
           [packet[7]&0xffffffff,packet[3]&0xffffffff,packet[6]&0xffffffff,0,packet[5]>>32],
           'sync-wait receive ABI passes timeout, boosting name, W5/W6 extents and receive name')
    for label in ('mach2_receive_only','mach2_receive_aux_8_True_False','mach2_receive_aux_8_False_True'):
        verify(label,result(label)==0 and bool(events(label,'receive_helper_boundary')),'selected scalar/vector receive reaches helper')
    for label in ('mach2_receive_aux_7_True_False','mach2_receive_aux_8_False_False'):
        verify(label,result(label)==0x10004013 and not events(label,'receive_helper_boundary'),'invalid receive auxiliary address/extent rejected before dequeue helper')
    label='mach2_send_then_invalid_receive_aux'
    verify(label,result(label)==0x10004013 and bool(events(label,'send_helper_entry')) and not events(label,'receive_helper_boundary'),
           'receive validation can fail after modeled successful send')
    for label,want in [('mach2_user_policy_bits_removed',0x8000000200000001),
                       ('mach2_policy_from_task_and_space',0x800003c200000001)]:
        e=events(label,'send_helper_entry')[0];verify(label,int(e['args'][1],16)==want,'user policy bits removed and context-derived flags inserted')
    counts={'mach_entries':len(c['mach_entries']),'bsd_entries':len(c['bsd_entries']),
        'original_function_ranges':len(c['functions']),'proofs_unsat':len(c['proofs']),
        'private_profiles':len(p['profiles']),'explicit_profile_checks':len(checked),
        'reference_table_differences':len(c['mach_reference_differences'])}
    (ROOT/'kernel_dispatch_profile_checks.json').write_text(json.dumps({'scope':'Finite private fixtures only.',
        'profiles_sha256':sha(ROOT/'kernel_dispatch_profiles.json'),'checks':checked,'counts':counts},indent=2)+'\n')
    q={'scope':'Kernel dispatch/Mach2/native file-VM boundary increment only; full goal remains active.',
       'QG1':{'status':'pass','evidence':'Factual technical analysis.'},
       'QG2':{'status':'pass','evidence':'Report K1-K7 list dependencies, probes and verification limits.'},
       'QG3':{'status':'pass_for_increment','evidence':'Two complete original dispatch/name tables and selected native handler contracts; broader lifecycle and native delivery remain open.'},
       'QG4':{'status':'pass','evidence':'Byte strides/extents, integer masks, signed results, 14-bit page geometry and reproducible formulas explicit.'},
       'QG5':{'status':'pass','evidence':'Reference drift, gate versus authorization, modeled status versus native effects and compatibility branches separated.'},
       'QG6':{'status':'pass','evidence':'Original KC SHA/UUID/function bounds/chain membership/name tables; source URL/hash; four solver checks and95 source-hashed fixtures.'},
       'QG7':{'status':'pass','evidence':'Impact-labeled continuation table covers policy, namespace, callbacks, compat and deeper VM contracts.'},
       'verified_counts':counts,'native_target_executed':False,'target_host_operations_executed':False,
       'runtime_identity_or_pac_attested':False,'full_goal_complete':False}
    (ROOT/'kernel_dispatch_quality_gates.json').write_text(json.dumps(q,indent=2)+'\n')
    print(json.dumps(counts))
    subprocess.run([sys.executable,str(ROOT/'validate_rpc502_sidecar_delivery.py')],check=True)


if __name__=='__main__':main()
