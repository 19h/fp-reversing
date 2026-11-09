#!/usr/bin/env python3
"""Original-byte sidecar contracts and explicit finite/proof validation.

No target host operations. Extraction/validation is O(B+C*L) time and O(B+E)
space for retained bytes B, C cases of bounded length L, and events E. Solver
cost is separate. Read-only input hashes are checked by daemon_receive_tools.
"""
import hashlib
import json
import struct
import subprocess
from pathlib import Path
from daemon_receive_tools import IMAGE,ROOT,SOURCE,CS,TABLE,qword,selected,verify_original_fixups
from daemon_import_bindings import binding
from recover_rpc502_runtime import native
from run_rpc502_sidecar_profiles import GLOBAL,INITIAL,PROFILES,PREFIX


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ranges=[native(a,b) for a,b in [
        (0x1005bbb20,0x1005bbbfc),(0x1005d130c,0x1005d1388),
        (0x1007f0d70,0x1007f0dc4),(0x1005c6778,0x1005c67c4),
        (0x10074cbc8,0x10074cc18),(0x100787b9c,0x100787fb0),
        (0x1004f5980,0x1004f5a00),(0x10078e168,0x10078e1ac),
        (0x1009ab630,0x1009ab664),(0x10083ec3c,0x10083ec74),
        (0x100d943d0,0x100d944dc),(0x100aaf8d8,0x100aaf990),
        (0x100c2119c,0x100c21250),(0x100cc082c,0x100cc087c)]]
    assert struct.unpack('<I',IMAGE.read(GLOBAL,4))[0]==INITIAL
    encoder=[{'input':b,'output':(b-((b<<1)&0x30)-0x68)&255} for b in range(256)]
    assert all(r['output']==r['input']^0x98 for r in encoder)
    queries={
      'policy_state_update':'''(declare-fun g () (_ BitVec 32))
(declare-fun m () (_ BitVec 32))
(declare-fun i () (_ BitVec 32))
(define-fun w19 () (_ BitVec 32) (bvor (bvadd #x00006cf4 #x0000077c) #x00000885))
(define-fun native () (_ BitVec 32)
 (bvadd g m i (bvxor w19 #x6258e701) #x346a14aa))
(assert (not (= native (bvadd g (bvsub m #x693d4f62) i))))''',
      'scan_initial_state':'''(declare-fun delta () (_ BitVec 32))
(define-fun g () (_ BitVec 32) (bvadd #x1cea168a delta))
(assert (not (= ((_ zero_extend 32) (bvadd g #xe315e976))
               ((_ zero_extend 32) delta))))''',
      'open_result_dispatch':'''(declare-fun fd () (_ BitVec 32))
(define-fun neg () (_ BitVec 32) (ite (bvslt fd #x00000000) #x00000001 #x00000000))
(define-fun w11 () (_ BitVec 32) (bvadd #x00009ac0 #xffff8aee))
(define-fun w23 () (_ BitVec 32) (bvor w11 #x00000200))
(define-fun native () (_ BitVec 32)
 (bvor (bvmul (bvand (bvxor (bvxor w11 #x000040c3) neg) #x00000001)
               (bvadd w23 #xffffd884)) #x00009ac0))
(assert (not (= native (ite (bvslt fd #x00000000) #x00009ac0 #x00009af2))))''',
      'file_size_encoding':'''(declare-fun size () (_ BitVec 64))
(define-fun w25 () (_ BitVec 32) (bvor (bvadd #x0000699b #xffff9bda) #x0000c080))
(define-fun mask () (_ BitVec 64) (bvadd ((_ zero_extend 32) w25) #x6700172791792061))
(define-fun native () (_ BitVec 64)
 (bvadd (bvsub size (bvand mask (bvshl size #x0000000000000001))) #xb3800b93c8bcf32b))
(assert (not (= native (bvxor size #xb3800b93c8bcf32b))))'''}
    proofs=[]
    for name,body in queries.items():
        path=ROOT/f'rpc502_sidecar_{name}.smt2'
        path.write_text('(set-logic QF_BV)\n'+body+'\n(check-sat)\n')
        answer=subprocess.run(['z3','-smt2',str(path)],capture_output=True,text=True,check=True).stdout.strip()
        assert answer=='unsat',(name,answer)
        proofs.append({'name':name,'path':path.name,'result':answer,
                       'scope':'arithmetic only, explicit native register preconditions'})
    p=json.loads((ROOT/'rpc502_sidecar_profiles.json').read_text())
    assert p['generator_sha256']==sha(ROOT/'run_rpc502_sidecar_profiles.py')
    assert len(p['profiles'])==len(PROFILES)==15
    summary=[]
    for c,r in zip(PROFILES,p['profiles']):
        assert c==r['explicit_seeds']
        assert r['model_source_sha256']==sha(ROOT/'daemon_rpc502_context_probe.py')
        assert r['base_model_source_sha256']==sha(ROOT/'daemon_rpc502_probe.py')
        regs=r['snapshots']['policy_update']['registers']
        assert int(regs['x24'],16)==0x6cf4
        marker=0x693d4f68 if c.get('bootpolicy_status',0)!=0 or c['mode'] not in [1,2,3] else (
               0x693d4f65 if c['mode']==3 else 0x693d4f62)
        indicator=2 if c.get('csr_status',0)!=0 else int(bool(c.get('csr',0)&0xffffffef))
        assert int(regs['x9'],16)==marker and int(regs['x23'],16)==indicator
        initial=c.get('global_seed',INITIAL)
        final=(initial+marker-0x693d4f62+indicator)&0xffffffff
        assert len(r['global_writes'])==1
        w=r['global_writes'][0]
        assert (int(w['pc'],16),int(w['address'],16),w['size_bytes'])==(0x1005bbb68,GLOBAL,4)
        assert int.from_bytes(bytes.fromhex(w['value_hex']),'little')==final==int(r['global_final'],16)
        start=(final+0xe315e976)&0xffffffff
        assert int(r['snapshots']['scan_start']['registers']['x8'],16)==start
        row={'label':r['label'],'mode_marker':hex(marker),'csr_indicator':indicator,
             'global_before':hex(initial),'global_after':hex(final),'scan_start_byte_index':start}
        if c.get('cpu')==0xabcd:
            assert r['stop_reason']=='returned_to_fixture' and not r['open_boundaries']
            assert int(r['end_registers']['x0'],16)&0xffffffff==0xffff5869
            row['finite_result']='CPU-sentinel fixture returns 0xffff5869 before sidecar open'
        else:
            name=bytes.fromhex(r['filename_hex'])[:-1]
            slash=name.rfind(b'/',start);split=slash>>1
            shifts=r['snapshots']['shift_first']['registers']
            assert (int(shifts['x8'],16),int(shifts['x13'],16),int(shifts['x11'],16))==(slash,0,1)
            bound=r['snapshots']['scan_bound']['registers']
            assert int(bound['x13'],16)==1024
            enc=r['snapshots']['encoder_shift']['registers']
            assert (int(enc['x12'],16)&31)==1 and int(enc['x14'],16)==0x6be
            assert int(r['snapshots']['encoded_terminator']['registers']['x8'],16)==split
            buf=bytearray([c.get('prefix_seed',0)]*1024)
            for i in range(start,len(name)):buf[i]=name[i]^0x98
            buf[split]=0x98
            expected=bytes(b^0x98 for b in buf[:split])+b'/SC_Info/'+name[split+1:]+b'.sinf'
            ob=r['open_boundaries'];assert len(ob)==1 and ob[0]['flags']=='0x0'
            assert ob[0]['return_pc']=='0x100d94498' and ob[0]['path_hex']==expected.hex()
            row.update({'last_slash_byte_index':slash,'split_byte_index':split,
                        'path_hex':expected.hex(),'path_ascii_escaped':expected.decode('ascii',errors='backslashreplace')})
        summary.append(row)
    idb=json.loads((ROOT/'rpc502_sidecar_ida_readback.json').read_text())
    native_idb=idb['native_bytes'];assert native_idb['input_sha256']=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'
    for row in native_idb['rows']:
        raw=bytes.fromhex(row['bytes_hex'])
        assert IMAGE.read(int(row['address'],16),len(raw))==raw
    assert len(native_idb['rows'])==4
    io=[];banks=[];bindings=[]
    for status,suffix in [(-1,'minus1'),(0,'0'),(7,'7')]:
        path=ROOT/f'rpc502_sidecar_io_{suffix}.json';r=json.loads(path.read_text())
        assert r['sidecar_io_generator_sha256']==sha(ROOT/'probe_rpc502_sidecar_io.py')
        assert r['generator_sha256']==sha(ROOT/'daemon_rpc502_context_probe.py')
        assert r['base_generator_sha256']==sha(ROOT/'daemon_rpc502_probe.py')
        want='libSystem/___error' if status<0 else 'libSystem/_fstat'
        last=r['records'][-1];assert last['name']==want
        if status>=0:assert int(last['args'][0],16)==status
        records=[x for x in r['records'] if x['kind']=='sidecar_io_checkpoint']
        get=lambda a:next(x['registers'] for x in records if int(x['pc'],16)==a)
        dispatch=get(0x100d944d0);ix=int(dispatch['x8'],16)
        assert ix==(0x9ac0 if status<0 else 0x9af2)
        assert qword(TABLE+ix*8)==(0x100c2119c if status<0 else 0x100dbedac)
        if status in [-1,0]:
            if status<0:
                a=get(0x100c2119c);l=int(a['x22'],16);right=int(a['x21'],16);key=0x6d;add=0xcb72
            else:
                a=get(0x100aaf8d8);l=int(a['x2'],16);right=int(a['x1'],16);key=0xe4;add=0xcd03
            bank=selected(l,right,key,add);assert bank['target']==want;banks.append(bank)
            hit=next(x for x in r['bound_import_reads'] if x['target']==want)
            bindings.append(binding(int(hit['slot'],16)))
        io.append({'profile':path.name,'open_result_signed32':status,'dispatch_index':hex(ix),
                   'dispatch_target':hex(qword(TABLE+ix*8)),'last_boundary':last,'steps':r['steps']})
    metadata=[]
    for status,suffix in [(0,'0'),(-1,'minus1')]:
        path=ROOT/f'rpc502_sidecar_metadata_{suffix}.json';r=json.loads(path.read_text())
        assert r['metadata_generator_sha256']==sha(ROOT/'probe_rpc502_sidecar_metadata.py')
        assert r['io_generator_sha256']==sha(ROOT/'probe_rpc502_sidecar_io.py')
        assert r['generator_sha256']==sha(ROOT/'daemon_rpc502_context_probe.py')
        assert r['base_generator_sha256']==sha(ROOT/'daemon_rpc502_probe.py')
        last=r['records'][-1]
        assert r['stop_reason']=='unknown_fstat_output_read'
        assert (last['pc'],last['size_bytes'],last['offset_bytes'],last['stat_status'])==('0x100cc083c',8,96,status)
        assert int(last['address'],16)==int(last['buffer'],16)+96==int(r['stop_sp'],16)+0x90
        assert not any(x['kind']=='native_metadata_buffer_write' for x in r['records'])
        regs=r['stop_registers'];assert int(regs['x21'],16)==0x699b and int(regs['x25'],16)==0xc5f5
        assert int(regs['x28'],16)==(0x74c29dd3 if status<0 else 0x8b3dc651)
        checkpoint=next(x['registers'] for x in r['records']
            if x['kind']=='sidecar_io_checkpoint' and x['pc']=='0x100aaf93c')
        assert int(checkpoint['x23'],16)==0 and int(checkpoint['x20'],16)==0x6c4a
        metadata.append({'profile':path.name,'fstat_result_signed32':status,
            'first_unknown_read':last,'status_marker_w28':regs['x28'],
            'selected_control_w21':regs['x21'],'selected_control_w25':regs['x25'],
            'metadata_bytes_synthesized':False,'subsequent_field_encoding_executed':False})
    assert qword(TABLE+0x6c4a*8)==0x100cc082c
    sdk=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk')
    command=['clang','-target','arm64e-apple-macos13.0','-isysroot',str(sdk),
             '-std=c11','-fsyntax-only',str(ROOT/'rpc502_sidecar_layouts.c')]
    subprocess.run(command,check=True,capture_output=True,text=True)
    out={'scope':__doc__,'source_sha256':sha(SOURCE),'generator_sha256':sha(Path(__file__)),
        'ranges':ranges,'global':{'address':hex(GLOBAL),'original_u32':hex(INITIAL),
          'write_pc':'0x1005bbb68','scan_start_write_pc':'0x1005d136c',
          'formula_u32':'g_after = g_before + marker - 0x693d4f62 + csr_indicator (mod 2^32)',
          'formula_precondition':'native update entry W24=0x6cf4; native SP+0x358 aliases this global',
          'scan_u64':'zero_extend_64((g_after + 0xe315e976) mod 2^32)',
          'native_cross_request_lifetime':'unknown; no native reset/concurrency proof'},
        'encoder_exhaustive_256':encoder,'proofs':proofs,'profiles':summary,
        'live_ida':{'readback':'rpc502_sidecar_ida_readback.json','matching_ranges':4,
                    'original_bytes_matched':True,'idb_mutated':False},
        'io_profiles':io,'io_banks_exhaustive_256':banks,'original_io_bindings':bindings,
        'io_dispatch_original_fixups':verify_original_fixups([TABLE+ix*8 for ix in [0x9ac0,0x9af2]]),
        'metadata_profiles':metadata,
        'metadata_original_dispatch_fixup':verify_original_fixups([TABLE+0x6c4a*8]),
        'file_size_encoding':{'native_range':'0x100cc082c..0x100cc087c',
            'read_pc':'0x100cc083c','sdk_field':'struct stat.st_size','width_bytes':8,
            'buffer_offset_bytes':96,'destination_register':'x23',
            'formula_u64':'X23 = size_bits XOR 0xb3800b93c8bcf32b',
            'precondition':'W21=0x699b; unknown metadata read stops both fixtures before encoding executes',
            'proof_scope':'Original instructions plus all-64-bit arithmetic; no synthetic file-size value or downstream use'} ,
        'sdk_compile':{'command':command,'exit_code':0,'headers':[
           {'path':str(sdk/rel),'sha256':sha(sdk/rel)} for rel in ['usr/include/sys/stat.h','usr/include/fcntl.h','usr/include/sys/errno.h']]},
        'native_target_executed':False,'target_host_operations_executed':False,
        'full_goal_complete':False}
    (ROOT/'rpc502_sidecar_contracts.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'ranges':len(ranges),'proofs_unsat':len(proofs),'encoder_bytes':len(encoder),
                      'profiles':len(summary),'io_profiles':len(io),'bank_checks':len(banks),
                      'metadata_profiles':len(metadata),'ida_ranges':4,'sdk_compile':0}))


if __name__=='__main__':main()
