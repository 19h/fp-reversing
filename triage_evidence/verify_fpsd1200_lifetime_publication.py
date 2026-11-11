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
PREVIOUS='40e6a31d4eafe5380d3cbf63a6d2b4740839f01e'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'fpsd1200_port_report.md','daemon_receive_interface_report.md','mach_ports_report.md',
 'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md',
 'obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1200_lifetime_report.md','triage_evidence/recover_fpsd1200_lifetime.py',
 'triage_evidence/audit_fpsd1200_lifetime.py','triage_evidence/verify_fpsd1200_lifetime_publication.py',
 'triage_evidence/fpsd1200_lifetime_checks.json','triage_evidence/fpsd1200_lifetime_ida_readback.json',
 'triage_evidence/fpsd1200_lifetime_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/fpsd1200_lifetime_checks.json',
 'triage_evidence/fpsd1200_lifetime_ida_readback.json','triage_evidence/fpsd1200_lifetime_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles': 4, 'daemon_visits': 40374146, 'library_visits': 76, 'import_events': 192, 'returned_replies': 4, 'complex_replies': 2, 'error_replies': 2, 'vm_allocations': 4, 'vm_store_events': 2876, 'output_cell_read_events': 36, 'protected_output_store_events': 528, 'heap_read_events': 6, 'heap_store_events': 1146, 'complete_montgomery_calls': 376, 'OOL_read_events': 9284, 'mode_read_events': 4, 'mode_guards': 0, 'queue_word_read_events': 4, 'slot_word_reads': 2, 'slot_word_writes': 4, 'error_pointer_reads': 0, 'source_spans': 853, 'source_instructions_including_guards': 40637, 'format12_rebases': 1138, 'format12_bindings': 38, 'bank_identities': 17, 'bank_inputs': 4352, 'bank_pair_uses': 17028, 'unpaired_byte_bank_reads': 140, 'queries_unsat': 2}
FINITE={'profiles': 4, 'original_instruction_visits': 40374222, 'import_events': 192, 'admission_checkpoints': 84, 'source_IDA_spans': 853, 'constructor_store_bytes_checked': 22632, 'full_Montgomery_outputs_checked': 376, 'active_arithmetic_bytes_checked': 350640, 'public_exponent_outputs_checked': 8, 'public_signature_relations': 2, 'bank_inputs': 4352, 'queries_unsat': 2, 'worker_processes': 2, 'queue_origin_checks': {'components_replayed': 3, 'source_startup_global_writes_inspected': 246729, 'startup_writes_overlapping_queue': 0, 'queue_static_image_word_hex': '69d90e06', 'replay_counts': {'complete_CPU_frames_checked': 55, 'declared_full_state_component_entries_checked': 3, 'original_instruction_visits_checked': 22906, 'original_writes_checked': 1091, 'original_reads_checked': 2891, 'external_ABI_and_declared_effect_contracts_recomputed': 23, 'complete_final_mutable_RAM_bytes_checked': 7323648}}, 'all_checks_pass': True}
LABELS=['error_pointer_NULL','error_pointer_opaque','queue7_success','slot_word_control']


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def integer(v):
    cap,raw,_=struct.unpack('<IIQ',bytes.fromhex(v['header16_hex']))
    n=(raw-0x693be708)&0xffffffff
    if n>>31:n-=1<<32
    assert 0<=n<=cap and v['header_known_mask_hex']=='01'*16
    b=bytes.fromhex(v['active_limbs_hex']);assert len(b)==4*n and v['active_known_mask_hex']=='01'*len(b)
    return sum((int.from_bytes(b[j:j+4],'little')^0xada56e3c)<<(8*j)for j in range(0,len(b),4))




def data_joins(e):
    assert [p['label']for p in e['profiles']]==LABELS
    profiles=[];inline_stores=vm_stores=0
    for p in e['profiles']:
        r=json.loads(zlib.decompress(base64.b64decode(p['payload_zlib_base64'])))
        path_hygiene(json.dumps(r).encode());f=r['fixture'];label=f['label']
        assert not r['native_messages_emitted']and not r['native_target_executed']
        assert r['fixture']==p['fixture']and len(r['visited'])==p['visits']and r['stop_reason']==p['stop']=='returned_to_fixture'
        assert len(r['montgomery_calls'])==94 and all(o['retired']for o in r['certificate_owners_final'])
        assert r['queue_word_before_composition']=='69d90e06'and not r['queue_origin']['native_temporal_continuity_established']
        raw=struct.pack('<I',f['queue_fd']+0x060ed969).hex()
        assert r['queue_origin']['source_store']=='0x100096920'and r['queue_origin']['composed_bytes_hex']==raw
        assert r['queue_word_reads']==[{'pc':'0x1003ae3d8','address':'0x1010c4d20','width_B':4,'bytes_hex':raw}]
        ev=next(v for v in r['events']if v.get('name')=='libSystem/_kevent')
        assert ev['site']=='0x1003ae458'and [int(a,16)for a in ev['args'][:6]]==[f['queue_fd'],0x70065fd8,1,0,0,0]
        assert struct.unpack('<QhHIqQ',bytes.fromhex(ev['change32_hex']))==(0x17161514,-5,0x11,0x80000000,0,0)
        assert ev['change_known_mask_hex']=='01'*32
        assert not r['error_pointer_reads']and not r['error_pointer_region_mapped']
        assert len(r['vm_owners_final'])==1
        owner=r['vm_owners_final'][0];der=bytes.fromhex(owner['bytes_hex'])
        assert owner['size_B']==719 and owner['known_mask_hex']=='01'*719
        assert sha256(der).hexdigest()=='d43ca892b364466d885a38418b11469c2634ddcfe493ff3beda2f022edde4102'
        ws=r['vm_owner_writes'];assert len(ws)==719 and not r['vm_owner_reads']
        assert [w['offset_B']for w in ws]==list(range(718,-1,-1))
        assert all(w['width_B']==1 and int(w['value'],16)==der[w['offset_B']]for w in ws);vm_stores+=len(ws)
        output=r['protected_output_writes'];payload=int(r['payload_address'],16)
        inline=[w for w in output if 0x70002044<=int(w['address'],16)<0x700020c4]
        result=integer(r['montgomery_calls'][-1]['returned']['output']).to_bytes(128,'big')
        assert len(inline)==128 and [int(w['address'],16)for w in inline]==list(range(0x700020c3,0x70002043,-1))
        assert all(w['pc']=='0x1002212a0'and w['width_B']==1 for w in inline)
        assert bytes(int(w['value'],16)for w in reversed(inline))==result==bytes.fromhex(r['inline128_final']);inline_stores+=len(inline)
        heap=bytes.fromhex(r['heap44800_hex']);events=r['events'];count={'pc':'0x100543d3c','address':hex(payload+80),'width_B':4,'value':'0x2cf'}
        late=[w for w in output if w not in inline]
        assert r['reply_completed']and late[0]==count
        assert r['slot_word_writes']==[{'pc':'0x1006219bc','address':'0x700663e8','width_B':4,
          'before_hex':'44332211'if label=='slot_word_control'else'a5a5a5a5',
          'known_before':'01010101'if label=='slot_word_control'else'00000000','value':'0xa5a5a5a5'}]
        assert r['slot_word_final_hex']=='a5a5a5a5'and r['slot_word_final_known_mask']=='01010101'
        assert not any(v.get('name')=='libSystem/_vm_deallocate'and v['site']!='0x10049e114'for v in events)
        cleanup=[(v['name'],v['site'],v['args'][0])for v in events if v.get('site')in ['0x100474e6c','0x100474eb4']]
        if f['kevent_result']==-1:
            assert ev['result']=='0xffffffffffffffff'and r['application_status_u32']==0xffffffff and r['reply_size_B']==36
            error=next(v for v in events if v.get('name')=='libSystem/___error')
            assert error['site']=='0x100493a58'and error['result']==hex(f['error_pointer'])
            assert cleanup==[('CoreFoundation/_CFMachPortInvalidate','0x100474e6c','0x77001000'),('CoreFoundation/_CFRelease','0x100474eb4','0x77001000')]
            assert heap[:8]==bytes(8)and heap[876:880]==bytes.fromhex('49df7745')
            assert late==[count]and not r['slot_word_reads']
            assert not any(v.get('name')=='CoreFoundation/_CFMachPortGetPort'for v in events)
            assert r['carrier28_final'][-8:]=='ae39c274'and r['delta8_final']=='00'*8
            point=next(q for q in r['lifetime_points']if q['pc']=='0x10061aa0c')
            assert point['registers31'][22]==point['registers31'][27]=='0x74c239ae'
            assert any(w['pc']=='0x100474eb8'and w['offset_B']==0 and w['value']=='0x0'for w in r['heap_writes'])
            assert any(w['pc']=='0x1004d8440'and w['offset_B']==876 and w['value']=='0x4577df49'for w in r['heap_writes'])
        else:
            assert ev['result']=='0x0'and r['application_status_u32']==0 and r['reply_size_B']==212 and not cleanup
            assert not any(v.get('name')=='libSystem/___error'for v in events)
            assert struct.unpack_from('<Q6I',bytes.fromhex(r['protected_payload104_final']),72)==(0x76000000,719,1,76,9,0,0x6800)
            assert r['slot_word_reads']==[{'pc':'0x1005a7330','address':'0x700663e8','width_B':4,'bytes_hex':'a5a5a5a5','known_mask_hex':'01010101'}]
            assert [w for w in r['heap_writes']if w['pc']=='0x1005a7340']==[{'pc':'0x1005a7340','offset_B':400,'width_B':4,'value':'0xa5a5a5a5'}]
            assert heap[:8]==struct.pack('<Q',0x77001000)and heap[876:880]==bytes.fromhex('4bdf7745')
            b=bytes.fromhex(r['reply212']);assert struct.unpack_from('<7I',b)==(0x80000012,212,0x6400,0,0,1300,2)
            assert b[68:196]==result and struct.unpack_from('<4I',b,196)==(719,76,9,0)
        assert events[-1]['site']=='0x10000468c'and int(events[-1]['args'][1],16)==756
        profiles.append(r)
    compare=['visited','terminal_registers31','terminal_sp','final_stack_sha256','final_private_sha256',
      'heap44800_hex','heap_tail_sha256','certificate_backing_sha256','source_stack_known_sha256',
      'vm_backing_sha256','reply212','protected_payload104_final']
    for left,right in [(profiles[0],profiles[1]),(profiles[2],profiles[3])]:
        for key in compare:assert left[key]==right[key],key
    assert inline_stores==512 and vm_stores==2876
    return {'failed_watch_cleanup_paths':2,'unmapped_accessor_result_controls':2,'errno_storage_reads':0,
      'queue_initializer_to_watch_joins':4,'source_overwrite_controls':1,
      'terminal_GP31_SP_stack_private_heap_certificate_VM_and_reply_pairs_equal':2,
      'inline_store_result_joins':inline_stores,'VM_copy_store_byte_joins':vm_stores}

def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()=='0a0df5459d8522b6b99aeef8a81a6c43d2e2fc168dfd74cf58c16073aa17cd68'
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8192 and len(new)==len(current['files'])==8199
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==previous['inputs_preserved']
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1200_lifetime_report.md')
    assert all(f'| FL{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'fpsd1200_lifetime_checks.json'))
    assert e['verified_counts']==COUNTS and sha(ROOT/'recover_fpsd1200_lifetime.py')==e['generator_sha256']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    assert e['new_IDA_access']and not any(e[k]for k in ['new_IDB_mutations','new_native_execution','full_goal_complete'])
    receipt=json.loads(read(ROOT/'fpsd1200_lifetime_audit.json'))
    assert receipt['fresh_replay_completed']and receipt['process_exit_code']==0 and not receipt['native_target_executed']
    assert receipt['auditor_sha256']==sha(ROOT/'audit_fpsd1200_lifetime.py')
    assert receipt['checks_sha256']==sha(ROOT/'fpsd1200_lifetime_checks.json')
    assert receipt['IDA_SDK_readback_sha256']==sha(ROOT/'fpsd1200_lifetime_ida_readback.json')
    assert receipt['daemon_sha256']==e['daemon_sha256']and receipt['dependencies']==e['dependencies']
    for n,h in receipt['public_DER_inputs'].items():assert sha(ROOT/n)==h
    finite=receipt['result']
    assert {k:v for k,v in finite.items()if k not in ['exponent_group_summaries','upstream_observations']}==FINITE
    assert finite['all_checks_pass']and finite['profiles']==4 and finite['original_instruction_visits']==40374222
    assert finite['import_events']==192 and finite['full_Montgomery_outputs_checked']==376 and finite['public_exponent_outputs_checked']==8
    assert finite['public_signature_relations']==2 and finite['queries_unsat']==2 and finite['worker_processes']==2
    observations=finite['upstream_observations']
    assert observations==[{'case':label,'source_upstream_reads':[{'pc':'0x1006219b8','address':'0x70066570',
      'width_B':4,'bytes_hex':'a5a5a5a5','known_mask_hex':'00000000'}],'source_upstream_writes':[]}for label in LABELS]
    groups=finite['exponent_group_summaries'];assert len(groups)==12
    assert [(g['case'],g['key'],g['calls'])for g in groups]==[(case,key,calls)for case in LABELS for key,calls in [('Root',32),('AAA',31),('CoreFP_leaf',31)]]
    assert all(g['exponent']==65537 and g['complete_exponent_order_checked']for g in groups)
    att=json.loads(read(ROOT/'fpsd1200_lifetime_ida_readback.json'))
    assert not att['IDB_mutated']and att['spans']==[{'start':s['start'],'size_B':int(s['end'],16)-int(s['start'],16),'sha256':s['sha256']}for s in e['spans']]
    assert att['SDK_context']['compile_only']['exit_code']==0 and len(att['SDK_context']['headers'])==8 and len(att['additional_source_ranges'])==13
    joins=data_joins(e)
    assert current['validation']['fpsd1200_lifetime_increment_checks']==COUNTS
    assert current['validation']['fpsd1200_lifetime_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==415
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        if p=='triage_evidence/fpsd1200_lifetime_checks.json.zst':
            # Every decoded profile was checked above. Random Base64 alphabet
            # runs are compressed binary spellings, not analyst path strings.
            outer=json.loads(read(ROOT/'fpsd1200_lifetime_checks.json'))
            for profile in outer['profiles']:profile['payload_zlib_base64']='decoded profile independently path checked'
            path_hygiene(json.dumps(outer).encode())
        else:path_hygiene((BASE/p).read_bytes())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
      'original_inputs_preserved':3,'pinned_fresh_audit':{k:v for k,v in finite.items()if k not in ['exponent_group_summaries','upstream_observations']},
      'publication_does_not_replay_instructions':True,**joins,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
