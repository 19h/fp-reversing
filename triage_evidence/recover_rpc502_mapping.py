#!/usr/bin/env python3
"""Original-byte mapping/copy/cleanup contracts with distinct proof/fixture scopes.

No target host operations or IDB writes. Extraction and retained-case validation
are O(B+E) time/space, plus streamed input hashing and solver-dependent cost;
B is retained original code and E is bounded recorded fixture evidence.
"""
import hashlib
import json
import struct
import subprocess
from pathlib import Path
from daemon_receive_tools import IMAGE,ROOT,SOURCE,TABLE,qword,selected,verify_original_fixups
from daemon_import_bindings import binding
from recover_rpc502_runtime import native
from probe_rpc502_sidecar_data import PROFILES as DATA
from probe_rpc502_sidecar_mapping import PROFILES as MAPPING
from probe_rpc502_sidecar_copy import PROFILES as COPY
from probe_rpc502_sidecar_contents import PROFILES as CONTENTS


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def load_case(path,field,generator,inherited):
    r=json.loads((ROOT/path).read_text())
    assert r[field]==sha(ROOT/generator),(path,'generator')
    for n,h in r[inherited].items():assert sha(ROOT/n)==h,(path,n)
    assert r['source_sha256']==sha(SOURCE)
    assert r['generator_sha256']==sha(ROOT/'daemon_rpc502_context_probe.py')
    assert r['base_generator_sha256']==sha(ROOT/'daemon_rpc502_probe.py')
    assert r['native_target_executed'] is False and r['target_host_ipc_files_or_system_calls_executed'] is False
    return r


def main():
    ranges=[native(a,b) for a,b in [
        (0x100ca39f8,0x100ca3a44),(0x100c85da8,0x100c85e6c),
        (0x100dacb54,0x100dacb78),(0x100dcf770,0x100dcf794),
        (0x10095b534,0x10095b5f8),(0x1005d0314,0x1005d0394),
        (0x10059ccd0,0x10059cd04),(0x1009b6eac,0x1009b7014),
        (0x1003aae74,0x1003aaf04),(0x1001f1988,0x1001f19fc),
        (0x1008ec6a0,0x1008ec720),(0x1005ffa78,0x1005ffac8),
        (0x1005eeb20,0x1005eebac)]]
    queries={
      'fstat_status_guard':'''(declare-fun status () (_ BitVec 32))
(define-fun a () (_ BitVec 32) #x000027ae)
(define-fun c () (_ BitVec 32) (bvmul (bvxor a #x00002595) #x00000025))
(define-fun success () (_ BitVec 32) (bvadd (bvmul (bvxor a #x000027a6) #x00001358) #x8b3d2b91))
(define-fun result () (_ BitVec 32)
 (bvxor a (bvmul (ite (= status success) #x00000001 #x00000000) (bvadd c #x000063df))))
(assert (not (= result (ite (= status #x8b3dc651) #x000091c8 #x000027ae))))''',
      'mmap_length':'''(declare-fun size () (_ BitVec 64))
(define-fun encoded () (_ BitVec 64) (bvxor size #xb3800b93c8bcf32b))
(define-fun c () (_ BitVec 32) (bvand (bvadd #x00005287 #xbc7a4d60) #x4385fad8))
(define-fun control () (_ BitVec 64)
 (bvadd ((_ zero_extend 32) (bvadd #x00005287 #xffffd527)) #xb3800b93c8bc30bd ((_ zero_extend 32) c)))
(assert (not (= (bvxor control encoded) size)))''',
      'malloc_length':'''(declare-fun size () (_ BitVec 64))
(define-fun encoded () (_ BitVec 64) (bvxor size #xb3800b93c8bcf32b))
(define-fun control () (_ BitVec 64) (bvadd #x000000000000242c (bvxor #x000000000000072a #xb3800b93c8bcc9d5)))
(assert (not (= (bvxor control encoded) size)))''',
      'mmap_result_guard':'''(declare-fun pointer () (_ BitVec 64))
(define-fun result () (_ BitVec 32)
 (bvxor #x00005287 (bvmul (ite (= (bvadd pointer #x0000000000000001) #x0000000000000000) #x00000001 #x00000000) #x0000000d)))
(assert (not (= result (ite (= pointer #xffffffffffffffff) #x0000528a #x00005287))))''',
      'malloc_result_guard':'''(declare-fun pointer () (_ BitVec 64))
(define-fun result () (_ BitVec 32)
 (bvxor #x000049e5 (bvmul (ite (= pointer #x0000000000000000) #x00000001 #x00000000) #x00000016)))
(assert (not (= result (ite (= pointer #x0000000000000000) #x000049f3 #x000049e5))))''',
      'be32_reader':'''(declare-fun word () (_ BitVec 32))
(define-fun hi () (_ BitVec 32) (bvand word #xffffff00))
(define-fun lo () (_ BitVec 32) (bvand word #x000000ff))
(define-fun a () (_ BitVec 32) (bvadd (bvsub hi (bvand (bvshl hi #x00000001) #x29a8f200)) #x94d479dc))
(define-fun b () (_ BitVec 32) (bvadd (bvsub lo (bvand (bvshl lo #x00000001) #x000000d2)) #x61c3dc69))
(define-fun result () (_ BitVec 32)
 (bvxor (bvand (bvxor a #xf3d7f17c) (bvxor b #x9e3c2396)) (bvand b #x0000475f) #xec3e0ab8))
(assert (not (= result (bvxor word #x8b3dc651))))''',
      'qos_late_flag':'''(declare-fun flag () (_ BitVec 32))
(define-fun a () (_ BitVec 32) (bvand #x00000001 (bvnot flag)))
(define-fun result () (_ BitVec 32)
 (bvxor #x0000251d (bvsub (bvshl a #x00000006) (bvshl a #x00000002))))
(assert (not (= result (ite (= (bvand flag #x00000001) #x00000001) #x0000251d #x00002521))))'''}
    proofs=[]
    for name,body in queries.items():
        path=ROOT/f'rpc502_mapping_{name}.smt2';path.write_text('(set-logic QF_BV)\n'+body+'\n(check-sat)\n')
        answer=subprocess.run(['z3','-smt2',str(path)],check=True,capture_output=True,text=True).stdout.strip()
        assert answer=='unsat',(name,answer)
        proofs.append({'name':name,'path':path.name,'result':answer,
                       'scope':'all indicated bit-vector values under explicit native register preconditions'})
    data=[];mapping=[];copies=[];contents=[];case_reads=[]
    for label,size,status in DATA:
        path=f'rpc502_sidecar_data_{label}.json'
        r=load_case(path,'data_generator_sha256','probe_rpc502_sidecar_data.py','inherited_generator_sha256')
        last=r['records'][-1];enc=next(x for x in r['records'] if x['kind']=='file_size_encoding_checkpoint')
        assert int(enc['encoded_x23'],16)==size^0xb3800b93c8bcf32b
        if status==0:assert last['name']=='libSystem/_mmap' and [int(x,16) for x in last['args'][:6]]==[0,size,1,2,7,0]
        else:assert last['result']=='0xffff5b82'
        data.append({'profile':path,'size_bits':hex(size),'fstat_status':status,'last_boundary':last})
        case_reads.extend(r['bound_import_reads'])
    for label,size,success in MAPPING:
        path=f'rpc502_sidecar_mapping_{label}.json'
        r=load_case(path,'mapping_generator_sha256','probe_rpc502_sidecar_mapping.py','inherited_mapping_generators')
        last=r['records'][-1]
        if success:assert last['name']=='libSystem/_malloc' and int(last['args'][0],16)==size
        else:assert last['result']=='0xffff5bd4'
        mapping.append({'profile':path,'size_bytes':size,'mapping_success':success,'last_boundary':last})
        case_reads.extend(r['bound_import_reads'])
    for label,size,success in COPY:
        path=f'rpc502_sidecar_copy_{label}.json'
        r=load_case(path,'copy_generator_sha256','probe_rpc502_sidecar_copy.py','inherited_copy_generators')
        last=r['records'][-1]
        if success:
            assert last['reason']=='unknown_mapped_file_read' and last['offset_bytes']==size-1 and last['size_bytes']==1
        else:assert last['name']=='libSystem/_munmap' and [int(x,16) for x in last['args'][:2]]==[0x5100000000,size]
        copies.append({'profile':path,'size_bytes':size,'malloc_success':success,'last_boundary':last})
        case_reads.extend(r['bound_import_reads'])
    for label,size in CONTENTS:
        path=f'rpc502_sidecar_contents_{label}.json'
        r=load_case(path,'contents_generator_sha256','probe_rpc502_sidecar_contents.py','inherited_contents_generators')
        pattern=bytes(((i*73)^0xa5)&255 for i in range(size))
        assert bytes.fromhex(r['source_pattern_hex'])==bytes.fromhex(r['copied_allocation_hex'])==pattern
        assert r['copy_initialized_bytes']==size
        reads=[x for x in r['file_read_events'] if x['kind']=='mapping']
        assert [x['offset_bytes'] for x in reads]==list(reversed(range(size)))
        assert all(x['size_bytes']==1 and bytes.fromhex(x['bytes_hex'])==pattern[x['offset_bytes']:x['offset_bytes']+1] for x in reads)
        writes=[x for x in r['records'] if x['kind']=='native_copy_allocation_write']
        assert [x['offset_bytes'] for x in writes]==list(reversed(range(size)))
        if size>=4:
            word=int.from_bytes(pattern[:4],'big')^0x8b3dc651
            checkpoints=[x for x in r['header_checkpoints'] if x['pc']=='0x1009b6f64']
            assert len(checkpoints)==2 and all(int(x['registers']['x20'],16)==word for x in checkpoints)
            assert r['records'][-1]['name']=='libSystem/_free'
        else:assert r['records'][-1]['pc']=='0x1009b6ed0' and r['records'][-1]['address']=='0x5200000001'
        contents.append({'profile':path,'size_bytes':size,'exact_descending_copy':True,
                         'last_boundary':r['records'][-1]})
        case_reads.extend(r['bound_import_reads'])
    assert len(set(bytes(((i*73)^0xa5)&255 for i in range(256))))==256
    frames=json.loads((ROOT/'rpc502_mapping_frames.json').read_text())
    assert frames['generator_sha256']==sha(ROOT/'capture_rpc502_mapping_frames.py')
    for name,h in frames['inherited_generators'].items():assert sha(ROOT/name)==h
    assert len(frames['profiles'])==10
    assert {x['label'] for x in frames['profiles']}=={
        'fstat_error','mmap_failed','malloc_null','pattern64','malloc_null_unmap_success',
        'malloc_null_cleanup_success','malloc_null_cleanup_unmap_failed','malloc_null_cleanup_close_failed',
        'fstat_error_qos_query_failed','fstat_error_qos_set_failed'}
    summaries=[]
    for r in frames['profiles']:
        assert r['model_generator_sha256']==sha(ROOT/'daemon_rpc502_context_probe.py')
        assert r['base_generator_sha256']==sha(ROOT/'daemon_rpc502_probe.py')
        case_reads.extend(r['bound_import_reads'])
        label=r['label'];get=lambda a:next(x for x in r['frames'] if x['pc']==hex(a))
        initial=get(0x100d943d0)
        initial_record=bytes.fromhex(initial['record_initial_hex'])
        assert struct.unpack_from('<Q',initial_record,0x18)[0]==0x700734c0
        assert struct.unpack_from('<Q',initial_record,0x20)[0]==int(r['descriptor_pointer'],16)
        if label.startswith('fstat_error') or label=='mmap_failed':
            assert r['descriptor_final_hex']=='ffffffff'
            assert not any(x['name']=='libSystem/_close' for x in r['imports'])
            assert r['last_record']['result']==('0xffff5bd4' if label=='mmap_failed' else '0xffff5b82')
        else:
            publication=get(0x100dacb54)['registers']
            assert int(publication['x22'],16)==7 and int(publication['x0'],16)==0x5100000000
            assert int(publication['x23'],16)==64^0xb3800b93c8bcf32b and int(publication['x25'],16)==0
        encoded=struct.unpack_from('<Q',bytes.fromhex(r['mapping_result_final_hex']),16)[0]
        if label.startswith('malloc_null') or label=='pattern64':assert encoded==64^0xb3800b93c8bcf32b
        if 'cleanup_' in label:
            assert r['last_record']['result']=='0xffff5bd4' and r['descriptor_final_hex']=='ffffffff'
            assert any(x['pc']=='0x1001f19cc' for x in r['record_and_descriptor_writes'])
        late=[x for x in r['imports'] if x['name']=='libSystem/_pthread_set_qos_class_self_np' and x['return_pc']=='0x1005eeb9c']
        if label in ['fstat_error_qos_query_failed','fstat_error_qos_set_failed']:
            assert not late and get(0x1005ffa78)['qos_change_flag_byte']==0
        elif r['stop_reason']=='returned_to_fixture':
            assert len(late)==1 and [int(x,16) for x in late[0]['args'][:2]]==[0x15,0]
            q=get(0x1005eeb74);assert int(q['stack_qwords']['0xab0'],16)&0xffffffff==0xfffffffe
            assert get(0x1005ffa78)['qos_change_flag_byte']==1
        summaries.append({'label':label,'stop_reason':r['stop_reason'],'last_boundary':r['last_record'],
            'descriptor_final_hex':r['descriptor_final_hex'],'mapping_result_final_hex':r['mapping_result_final_hex'],
            'late_qos_calls':late,'record_and_descriptor_writes':r['record_and_descriptor_writes']})
    pattern=next(x for x in frames['profiles'] if x['label']=='pattern64')
    free_frame=next(x for x in pattern['frames'] if x['pc']=='0x1008ec708')
    banks=[]
    specs=[('mmap',0x100fc4230,0x101031fa0,0xe4,0xcd7a,'libSystem/_mmap'),
      ('malloc',0x100fc4130,0x101031ea0,0x4e,0xcb0e,'libSystem/_malloc'),
      ('munmap',0x100e99a00,0x100f4e390,0x9c,0xcde3,'libSystem/_munmap'),
      ('close',0x100fc4230,0x101031fa0,0x6c,0xcc76,'libSystem/_close'),
      ('free',int(free_frame['stack_qwords']['0x5d0'],16),int(free_frame['stack_qwords']['0x5d8'],16),0x61,0xcbef,'libSystem/_free'),
      ('late QoS',0x100fc4230,0x101031fa0,0xf3,0xcdfb,'libSystem/_pthread_set_qos_class_self_np')]
    bindings=[]
    for label,l,right,key,add,want in specs:
        b=selected(l,right,key,add);assert b['target']==want
        assert any(x['target']==want and x['slot']==b['slot'] for x in case_reads)
        b['label']=label;banks.append(b);bindings.append(binding(int(b['slot'],16)))
    targets={0x91c8:0x100c85da8,0x27ae:0x100dcf770,0x5287:0x100dacb54,
             0x528a:0x100dcf770,0x49e5:0x10082c504,0x49f3:0x100723af8,
             0x251d:0x1005eeb20,0x2521:0x1005faecc}
    for ix,target in targets.items():assert qword(TABLE+ix*8)==target
    idb=json.loads((ROOT/'rpc502_mapping_ida_readback.json').read_text())['actual_tool_output']
    assert idb['recorded_input_sha256']=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'
    for row in idb['rows']:
        raw=bytes.fromhex(row['bytes_hex']);assert IMAGE.read(int(row['address'],16),len(raw))==raw
    assert len(idb['rows'])==9 and idb['idb_mutated'] is False
    universal=Path('/Users/___/Downloads/fpx/fairplayd')
    assert sha(universal)==idb['recorded_input_sha256']
    universal_bytes=universal.read_bytes();thin_bytes=SOURCE.read_bytes()
    assert universal_bytes[3407872:3407872+len(thin_bytes)]==thin_bytes
    sdk=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk')
    command=['clang','-target','arm64e-apple-macos13.0','-isysroot',str(sdk),'-std=c11','-fsyntax-only',str(ROOT/'rpc502_mapping_layouts.c')]
    subprocess.run(command,check=True,capture_output=True,text=True)
    out={'scope':__doc__,'source_sha256':sha(SOURCE),'generator_sha256':sha(Path(__file__)),
      'ranges':ranges,'proofs':proofs,'import_banks_256':banks,'original_import_bindings':bindings,
      'dispatch_original_fixups':verify_original_fixups([TABLE+ix*8 for ix in targets]),
      'dispatch_targets':{hex(k):hex(v) for k,v in targets.items()},
      'data_profiles':data,'mapping_profiles':mapping,'copy_profiles':copies,'contents_profiles':contents,
      'frame_profiles':summaries,'frame_evidence':'rpc502_mapping_frames.json',
      'live_ida':{'path':'rpc502_mapping_ida_readback.json','ranges_matched':len(idb['rows']),
        'input_locator_exists_at_query':idb['input_path_exists'],'recorded_input_sha256':idb['recorded_input_sha256'],
        'locator_missing_does_not_preclude_live_byte_readback':True,'idb_mutated':False},
      'available_universal_source':{'path':str(universal),'sha256':sha(universal),
          'arm64e_slice_offset_bytes':3407872,'arm64e_slice_extent_bytes':len(thin_bytes),
          'exact_thin_slice_match':True},
      'sdk_compile':{'command':command,'exit_code':0,'headers':[{'path':str(sdk/p),'sha256':sha(sdk/p)}
         for p in ['usr/include/sys/mman.h','usr/include/pthread/qos.h','usr/include/sys/qos.h']]},
      'native_target_executed':False,'target_host_operations_executed':False,'full_goal_complete':False}
    (ROOT/'rpc502_mapping_contracts.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'native_ranges':len(ranges),'proofs_unsat':len(proofs),'banks_256':len(banks),
      'size_profiles':len(data),'mapping_profiles':len(mapping),'copy_profiles':len(copies),
      'contents_profiles':len(contents),'frame_profiles':len(summaries),'live_ida_ranges':9,'sdk_compile':0}))


if __name__=='__main__':main()
