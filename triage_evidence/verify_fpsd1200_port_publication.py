#!/usr/bin/env python3
"""Verify owned publication, pinned fresh-replay receipt and independent data joins.

This command does not replay instructions. Use the separate auditor for a fresh
source replay. O(owned bytes + manifest entries + decoded profiles) time and
O(largest profile + manifest) space, excluding bounded integer operations.
"""
import base64
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import zlib
from compression import zstd
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_lskd_vector_origin_publication import path_hygiene

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='92d19851e03457c4f7936f3093d30f6269a69dba'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'fpsd1200_vm_report.md','daemon_receive_interface_report.md','mach_ports_report.md',
 'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md',
 'obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1200_port_report.md','triage_evidence/recover_fpsd1200_port.py',
 'triage_evidence/audit_fpsd1200_port.py','triage_evidence/verify_fpsd1200_port_publication.py',
 'triage_evidence/fpsd1200_port_checks.json','triage_evidence/fpsd1200_port_ida_readback.json',
 'triage_evidence/fpsd1200_port_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/fpsd1200_port_checks.json',
 'triage_evidence/fpsd1200_port_ida_readback.json','triage_evidence/fpsd1200_port_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles': 6, 'daemon_visits': 60558137, 'library_visits': 114, 'import_events': 265, 'returned_replies': 3, 'complex_replies': 1, 'error_replies': 2, 'vm_allocations': 6, 'vm_store_events': 4314, 'output_cell_read_events': 33, 'protected_output_store_events': 780, 'heap_read_events': 3, 'heap_store_events': 1702, 'complete_montgomery_calls': 564, 'OOL_read_events': 13926, 'mode_read_events': 3, 'mode_guards': 1, 'queue_word_read_events': 3, 'source_spans': 854, 'source_instructions_including_guards': 40645, 'format12_rebases': 1140, 'format12_bindings': 38, 'bank_identities': 17, 'bank_inputs': 4352, 'bank_pair_uses': 25521, 'unpaired_byte_bank_reads': 210, 'queries_unsat': 1}
FINITE={'profiles': 6, 'original_instruction_visits': 60558251, 'import_events': 265, 'admission_checkpoints': 114, 'source_IDA_spans': 854, 'constructor_store_bytes_checked': 33948, 'full_Montgomery_outputs_checked': 564, 'active_arithmetic_bytes_checked': 525960, 'public_exponent_outputs_checked': 12, 'public_signature_relations': 2, 'bank_inputs': 4352, 'queries_unsat': 1, 'worker_processes': 2, 'all_checks_pass': True}
LABELS=['CF_port_NULL','CF_source_NULL','default_mode_guard','kevent_boundary','endpoint_success','kevent_error']


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def integer(v):
    cap,raw,_=struct.unpack('<IIQ',bytes.fromhex(v['header16_hex']))
    n=(raw-0x693be708)&0xffffffff
    if n>>31:n-=1<<32
    assert 0<=n<=cap and v['header_known_mask_hex']=='01'*16
    b=bytes.fromhex(v['active_limbs_hex']);assert len(b)==4*n and v['active_known_mask_hex']=='01'*len(b)
    return sum((int.from_bytes(b[j:j+4],'little')^0xada56e3c)<<(8*j)for j in range(0,len(b),4))



def data_joins(e):
    import z3
    assert [p['label']for p in e['profiles']]==LABELS
    inline_stores=vm_stores=representative_stores=0
    for p in e['profiles']:
        r=json.loads(zlib.decompress(base64.b64decode(p['payload_zlib_base64'])))
        path_hygiene(json.dumps(r).encode());f=r['fixture'];label=f['label']
        assert not r['native_messages_emitted']and not r['native_target_executed']
        assert r['fixture']==p['fixture']and len(r['visited'])==p['visits']and r['stop_reason']==p['stop']
        assert len(r['montgomery_calls'])==94 and all(o['retired']for o in r['certificate_owners_final'])
        assert len(r['vm_owners_final'])==1
        owner=r['vm_owners_final'][0];der=bytes.fromhex(owner['bytes_hex'])
        assert owner['size_B']==719 and owner['known_mask_hex']=='01'*719
        assert sha256(der).hexdigest()=='d43ca892b364466d885a38418b11469c2634ddcfe493ff3beda2f022edde4102'
        assert bytes.fromhex(r['certificate_owners_final'][2]['bytes_hex'])[:719]==der
        ws=r['vm_owner_writes'];assert len(ws)==719 and not r['vm_owner_reads']
        assert [w['offset_B']for w in ws]==list(range(718,-1,-1))
        assert all(w['width_B']==1 and int(w['value'],16)==der[w['offset_B']]for w in ws)
        vm_stores+=len(ws)
        output=r['protected_output_writes'];payload=int(r['payload_address'],16)
        inline=[w for w in output if 0x70002044<=int(w['address'],16)<0x700020c4]
        result=integer(r['montgomery_calls'][-1]['returned']['output']).to_bytes(128,'big')
        assert len(inline)==128 and [int(w['address'],16)for w in inline]==list(range(0x700020c3,0x70002043,-1))
        assert all(w['pc']=='0x1002212a0'and w['width_B']==1 for w in inline)
        assert bytes(int(w['value'],16)for w in reversed(inline))==result==bytes.fromhex(r['inline128_final'])
        inline_stores+=len(inline)
        events=r['events'];cf=next(v for v in events if v.get('name')=='CoreFoundation/_CFMachPortCreate')
        assert cf['site']=='0x100001f8c'and cf['args'][:2]==['0x0','0x100425f78']and int(cf['result'],16)==f['cf_port_result']
        assert cf['context40_hex']=='00'*40 and cf['context_known_mask_hex']=='01'*40 and cf['shouldFreeInfo_before']=='00'
        cfstore=[w for w in r['heap_writes']if w['pc']=='0x100624eb4']
        assert cfstore==[{'pc':'0x100624eb4','offset_B':0,'width_B':8,'value':hex(f['cf_port_result'])}]
        heap=bytes.fromhex(r['heap44800_hex'])
        assert int.from_bytes(heap[:8],'little')==(0 if label=='CF_source_NULL'else f['cf_port_result'])
        if label=='CF_source_NULL':assert [w for w in r['heap_writes']if w['offset_B']==0][-1]=={'pc':'0x100474eb8','offset_B':0,'width_B':8,'value':'0x0'}
        saved=[w for w in r['heap_writes']if w['pc']=='0x100552948']
        rep=integer(r['montgomery_calls'][73]['entry']['right']).to_bytes(128,'big')
        assert bytes(b^0x98 for b in heap[404:532])==rep and rep[:9]==bytes.fromhex('006664706300000001')
        assert len(saved)==128 and [w['offset_B']for w in saved]==list(range(531,403,-1))
        assert all(w['width_B']==1 and int(w['value'],16)==(rep[w['offset_B']-404]^0x98)for w in saved)
        representative_stores+=len(saved)
        late=[w for w in output if w not in inline]
        count={'pc':'0x100543d3c','address':hex(payload+80),'width_B':4,'value':'0x2cf'}
        assert late[0]==count
        if label=='endpoint_success':
            fields=[(84,4,1,'0x100624c68'),(72,8,0x76000000,'0x100624c70'),
              (88,4,76,'0x1005a7378'),(92,4,9,'0x1005a7394'),(96,4,0,'0x1005a73ac'),(100,4,0x6800,'0x1005a7458')]
            assert late[1:]==[{'pc':pc,'address':hex(payload+off),'width_B':n,'value':hex(v)}for off,n,v,pc in fields]
            after=bytes.fromhex(r['protected_payload104_final'])
            assert struct.unpack_from('<Q6I',after,72)==(0x76000000,719,1,76,9,0,0x6800)
            b=bytes.fromhex(r['reply212'])
            assert r['reply_completed']and r['reply_size_B']==212 and r['application_status_u32']==0
            assert struct.unpack_from('<7I',b)==(0x80000012,212,0x6400,0,0,1300,2)
            assert struct.unpack_from('<Q',b,28)[0]==0x76000000 and b[36:40]==bytes([1,1,0,1])
            assert struct.unpack_from('<I',b,40)[0]==719 and struct.unpack_from('<I',b,44)[0]==0x6800
            assert b[48:56]==bytes.fromhex('0000000000001300')and b[68:196]==result
            assert struct.unpack_from('<4I',b,196)==(719,76,9,0)
            get=next(v for v in events if v.get('name')=='CoreFoundation/_CFMachPortGetPort')
            assert get['site']=='0x1005a7410'and get['args'][0]=='0x77001000'and get['result']=='0x6800'
            assert r['heap_reads']==[{'pc':'0x1005a73f8','offset_B':0,'width_B':8,'bytes_hex':'0010007700000000','all_bytes_defined':True}]
            point=next(q for q in r['port_points']if q['pc']=='0x1005a7414')
            assert int(point['registers31'][0],16)==0x6800 and int(point['registers31'][19],16)==0x25d1
            assert heap[876:880]==bytes.fromhex('4bdf7745')
        else:
            assert late==[count]
            assert not any(v.get('name')=='CoreFoundation/_CFMachPortGetPort'for v in events)
            if label in ['CF_port_NULL','CF_source_NULL']:
                assert r['reply_completed']and r['reply_size_B']==36 and r['application_status_u32']==0xffff5b38
                assert heap[876:880]==bytes.fromhex('49df7745')
                assert not any(v.get('name')=='libSystem/_vm_deallocate'and v['site']!='0x10049e114'for v in events)
                cleanup=[(v['name'],v['site'],v['args'][0])for v in events if v.get('name')in ['CoreFoundation/_CFMachPortInvalidate','CoreFoundation/_CFRelease']and v['site']in ['0x100474e6c','0x100474eb4']]
                assert cleanup==([]if label=='CF_port_NULL'else [('CoreFoundation/_CFMachPortInvalidate','0x100474e6c','0x77001000'),('CoreFoundation/_CFRelease','0x100474eb4','0x77001000')])
                if label=='CF_port_NULL':assert not any(v.get('name')=='CoreFoundation/_CFMachPortCreateRunLoopSource'for v in events)
            else:assert not r['reply_completed']and heap[876:880]==bytes.fromhex('4adf7745')
        if label in ['kevent_boundary','endpoint_success','kevent_error']:
            ev=next(v for v in events if v.get('name')=='libSystem/_kevent')
            assert ev['site']=='0x1003ae458'and [int(a,16)for a in ev['args'][:6]]==[0,0x70065fd8,1,0,0,0]
            assert struct.unpack('<QhHIqQ',bytes.fromhex(ev['change32_hex']))==(0x17161514,-5,0x11,0x80000000,0,0)
            assert ev['change_known_mask_hex']=='01'*32
            assert r['queue_word_reads']==[{'pc':'0x1003ae3d8','address':'0x1010c4d20','width_B':4,'bytes_hex':'69d90e06'}]
            assert len(r['mode_reads'])==1
            if label=='kevent_boundary':assert 'result'not in ev and events[-1]==ev
            if label=='endpoint_success':assert ev['result']=='0x0'
            if label=='kevent_error':
                assert ev['result']=='0xffffffffffffffff'and events[-1]['name']=='libSystem/___error'
                assert events[-1]['site']=='0x100493a58'and 'result'not in events[-1]
        elif label=='default_mode_guard':assert r['mode_guard']['pc']=='0x1003ae314'and not r['mode_reads']
        if r['reply_completed']:assert events[-1]['site']=='0x10000468c'and int(events[-1]['args'][1],16)==756
    ins={i['ea']:i for span in e['spans']for i in span['instructions']}
    for pc,m,o in [('0x1005a7414','mov','w8, #0xefb6'),('0x1005a7418','movk','w8, #0xf3fc, lsl #16'),
      ('0x1005a7420','mov','w9, #0xfabd'),('0x1005a7424','movk','w9, #0xe7f9, lsl #16'),
      ('0x1005a7448','mov','w11, #0x104a'),('0x1005a744c','movk','w11, #0xc03, lsl #16')]:
        assert(ins[pc]['mnemonic'],ins[pc]['operands'])==(m,o)
    assert ins['0x1005a741c']['operands']=='w8, w0, w8'
    assert ins['0x1005a7428']['operands']=='w9, w19, w9'
    assert ins['0x1005a742c']['operands']=='w9, w9, w0, lsl #1'
    assert ins['0x1005a7450']['operands']=='w8, w8, w11'and ins['0x1005a7454']['operands']=='w8, w8, w9'
    x=z3.BitVec('raw_mach_name32',32);k=z3.BitVecVal(0xf3fcefb6,32)
    y=(x^k)+z3.BitVecVal(0x0c03104a,32)+((x<<1)&z3.BitVecVal(0x25d1^0xe7f9fabd,32))
    solver=z3.Solver();solver.set(timeout=10000);solver.add(y!=x);assert solver.check()==z3.unsat
    assert inline_stores==768 and vm_stores==4314 and representative_stores==768
    return {'inline_store_result_joins':inline_stores,'VM_copy_store_byte_joins':vm_stores,
      'saved_representative_store_joins':representative_stores,'complete_original_output_tuples':1,
      'selected_phase_raw_name_query_unsat':True,'process_event_ABI_joins':3,'NULL_error_replies':2,'errno_boundary_controls':1}


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()=='bfbb0f5978c20a941f3aa6986f2303aa5fbd7110b97a09eba4fffb7b5721dc31'
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8185 and len(new)==len(current['files'])==8192
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==previous['inputs_preserved']
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1200_port_report.md')
    assert all(f'| FP{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'fpsd1200_port_checks.json'))
    assert e['verified_counts']==COUNTS and sha(ROOT/'recover_fpsd1200_port.py')==e['generator_sha256']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    assert e['new_IDA_access']and not any(e[k]for k in ['new_IDB_mutations','new_native_execution','full_goal_complete'])
    receipt=json.loads(read(ROOT/'fpsd1200_port_audit.json'))
    assert receipt['fresh_replay_completed']and receipt['process_exit_code']==0 and not receipt['native_target_executed']
    assert receipt['auditor_sha256']==sha(ROOT/'audit_fpsd1200_port.py')
    assert receipt['checks_sha256']==sha(ROOT/'fpsd1200_port_checks.json')
    assert receipt['IDA_SDK_readback_sha256']==sha(ROOT/'fpsd1200_port_ida_readback.json')
    assert receipt['daemon_sha256']==e['daemon_sha256']and receipt['dependencies']==e['dependencies']
    for n,h in receipt['public_DER_inputs'].items():assert sha(ROOT/n)==h
    finite=receipt['result']
    assert {k:v for k,v in finite.items()if k!='exponent_group_summaries'}==FINITE
    assert finite['all_checks_pass']and finite['profiles']==6 and finite['original_instruction_visits']==60558251
    assert finite['import_events']==265 and finite['full_Montgomery_outputs_checked']==564 and finite['public_exponent_outputs_checked']==12
    assert finite['public_signature_relations']==2 and finite['queries_unsat']==1 and finite['worker_processes']==2
    groups=finite['exponent_group_summaries'];assert len(groups)==18
    assert [(g['case'],g['key'],g['calls'])for g in groups]==[(case,key,calls)for case in LABELS for key,calls in [('Root',32),('AAA',31),('CoreFP_leaf',31)]]
    assert all(g['exponent']==65537 and g['complete_exponent_order_checked']for g in groups)
    att=json.loads(read(ROOT/'fpsd1200_port_ida_readback.json'))
    assert not att['IDB_mutated']and att['spans']==[{'start':s['start'],'size_B':int(s['end'],16)-int(s['start'],16),'sha256':s['sha256']}for s in e['spans']]
    assert att['SDK_context']['compile_only']['exit_code']==0 and len(att['SDK_context']['headers'])==7
    joins=data_joins(e)
    assert current['validation']['fpsd1200_port_increment_checks']==COUNTS
    assert current['validation']['fpsd1200_port_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==414
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        if p=='triage_evidence/fpsd1200_port_checks.json.zst':
            # Every decoded profile was checked above. Random Base64 alphabet
            # runs are compressed binary spellings, not analyst path strings.
            outer=json.loads(read(ROOT/'fpsd1200_port_checks.json'))
            for profile in outer['profiles']:profile['payload_zlib_base64']='decoded profile independently path checked'
            path_hygiene(json.dumps(outer).encode())
        else:path_hygiene((BASE/p).read_bytes())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
      'original_inputs_preserved':3,'pinned_fresh_audit':{k:v for k,v in finite.items()if k!='exponent_group_summaries'},
      'publication_does_not_replay_instructions':True,**joins,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
