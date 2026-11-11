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
PREVIOUS='629b3ac52bd150f5ff5a2d04509de3ef0d4c0843'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'fpsd1200_certificate_report.md','daemon_receive_interface_report.md','mach_ports_report.md',
 'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md',
 'obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1200_vm_report.md','triage_evidence/recover_fpsd1200_vm.py',
 'triage_evidence/audit_fpsd1200_vm.py','triage_evidence/verify_fpsd1200_vm_publication.py',
 'triage_evidence/fpsd1200_vm_checks.json','triage_evidence/fpsd1200_vm_ida_readback.json',
 'triage_evidence/fpsd1200_vm_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/fpsd1200_vm_checks.json',
 'triage_evidence/fpsd1200_vm_ida_readback.json','triage_evidence/fpsd1200_vm_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles': 3, 'daemon_visits': 30274392, 'library_visits': 57, 'import_events': 120, 'returned_replies': 1, 'vm_allocations': 2, 'vm_store_events': 1438, 'vm_read_events': 0, 'output_cell_read_events': 13, 'protected_output_store_events': 386, 'complete_montgomery_calls': 282, 'OOL_read_events': 6963, 'source_spans': 843, 'source_instructions': 39665, 'format12_rebases': 1124, 'format12_bindings': 30, 'bank_identities': 17, 'bank_inputs': 4352, 'bank_pair_uses': 12746, 'unpaired_byte_bank_reads': 105}
FINITE={'profiles': 3, 'original_instruction_visits': 30274449, 'import_events': 120, 'admission_checkpoints': 55, 'source_IDA_spans': 843, 'constructor_store_bytes_checked': 16974, 'full_Montgomery_outputs_checked': 282, 'active_arithmetic_bytes_checked': 262980, 'public_exponent_outputs_checked': 6, 'public_signature_relations': 2, 'bank_inputs': 4352, 'all_checks_pass': True}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def integer(v):
    cap,raw,_=struct.unpack('<IIQ',bytes.fromhex(v['header16_hex']))
    n=(raw-0x693be708)&0xffffffff
    if n>>31:n-=1<<32
    assert 0<=n<=cap and v['header_known_mask_hex']=='01'*16
    b=bytes.fromhex(v['active_limbs_hex']);assert len(b)==4*n and v['active_known_mask_hex']=='01'*len(b)
    return sum((int.from_bytes(b[j:j+4],'little')^0xada56e3c)<<(8*j)for j in range(0,len(b),4))


def data_joins(e):
    expected=['allocation_success','allocation_failure','zero_address_success']
    assert [p['label']for p in e['profiles']]==expected
    leaf_hash='d43ca892b364466d885a38418b11469c2634ddcfe493ff3beda2f022edde4102'
    lanes={'0x10048d95c':7,**{hex(p):89 for p in [0x100633d64,0x100633d70,0x100633d7c,0x100633d90,
      0x100633da4,0x100633db4,0x100633dd0,0x100633ddc]}}
    inline_stores=vm_stores=cf_boundaries=0
    seqs=[]
    for p in e['profiles']:
        r=json.loads(zlib.decompress(base64.b64decode(p['payload_zlib_base64'])))
        path_hygiene(json.dumps(r).encode())
        assert not r['native_messages_emitted']and not r['native_target_executed']
        before=bytes.fromhex(r['protected_payload104_before']);after=bytes.fromhex(r['protected_payload104_final'])
        address=0 if p['label']=='zero_address_success'else 0xa5a5a5a5a5a5a5a5
        assert struct.unpack_from('<Q',before,72)[0]==address and struct.unpack_from('<I',before,80)[0]==0
        deallocate=next(v for v in r['events']if v.get('name')=='libSystem/_vm_deallocate')
        assert deallocate['site']=='0x10049e114'and deallocate['result']=='0x0'
        assert [int(a,16)for a in deallocate['args'][:3]]==[0x6600,address,0]
        allocate=next(v for v in r['events']if v.get('name')=='libSystem/_vm_allocate')
        assert allocate['site']=='0x10049e17c'and [int(allocate['args'][j],16)for j in [0,2,3]]==[0x6600,719,1]
        assert len(r['task_self_reads'])==2 and [v['pc']for v in r['task_self_reads']]==['0x10049e0f8','0x10049e118']
        assert all(v['bytes_hex']=='00660000'and v['width_B']==4 for v in r['task_self_reads'])
        output=r['protected_output_writes']
        writes=[w for w in output if 0x70002044<=int(w['address'],16)<0x700020c4]
        result=integer(r['montgomery_calls'][-1]['returned']['output']).to_bytes(128,'big')
        assert len(writes)==128 and all(w['pc']=='0x1002212a0'and w['width_B']==1 for w in writes)
        assert [int(w['address'],16)for w in writes]==list(range(0x700020c3,0x70002043,-1))
        assert bytes(int(w['value'],16)for w in reversed(writes))==result==bytes.fromhex(r['inline128_final'])
        assert len(r['montgomery_calls'])==94 and all(o['retired']for o in r['certificate_owners_final'])
        count_writes=[w for w in output if w not in writes]
        if p['label']=='allocation_failure':
            assert allocate['result']=='0x3'and not r['vm_owners_final']and not r['vm_owner_writes']
            assert not count_writes and before==after
            assert r['reply_completed']and r['reply_size_B']==36 and r['application_status_u32']==0xffff5bd4
            assert bytes.fromhex(r['heap44800_hex'])[876:880]==bytes.fromhex('49df7745')
            assert r['events'][-1]['site']=='0x10000468c'and int(r['events'][-1]['args'][1],16)==756
            assert not any(v.get('name')=='CoreFoundation/_CFMachPortCreate'for v in r['events'])
        else:
            assert allocate['result']=='0x0'and not r['reply_completed']
            assert len(r['vm_owners_final'])==1
            owner=r['vm_owners_final'][0];der=bytes.fromhex(owner['bytes_hex'])
            assert owner['size_B']==719 and owner['known_mask_hex']=='01'*719 and sha256(der).hexdigest()==leaf_hash
            assert bytes.fromhex(r['certificate_owners_final'][2]['bytes_hex'])[:719]==der
            stores=r['vm_owner_writes'];assert len(stores)==719 and not r['vm_owner_reads']
            assert [w['offset_B']for w in stores]==list(range(718,-1,-1))
            assert {pc:sum(w['pc']==pc for w in stores)for pc in lanes}==lanes
            assert all(w['width_B']==1 and int(w['value'],16)==der[w['offset_B']]for w in stores)
            assert count_writes==[{'pc':'0x100543d3c','address':hex(int(r['payload_address'],16)+80),'width_B':4,'value':'0x2cf'}]
            assert before[:80]==after[:80]and after[80:84]==struct.pack('<I',719)and before[84:]==after[84:]
            cf=r['events'][-1];assert cf['name']=='CoreFoundation/_CFMachPortCreate'and cf['site']=='0x100001f8c'and 'result'not in cf
            assert cf['args'][:2]==['0x0','0x100425f78']and cf['context40_hex']=='00'*40
            assert cf['context_known_mask_hex']=='01'*40 and cf['shouldFreeInfo_before']=='00'
            vm_stores+=len(stores);cf_boundaries+=1;seqs.append(r['visited'])
        assert [(v['address'],v['width_B'])for v in r['output_cell_reads'][:2]]==[(hex(int(r['payload_address'],16)+72),8),(hex(int(r['payload_address'],16)+80),4)]
        assert r['output_cell_reads'][0]['pc']=='0x100400bc8'and r['output_cell_reads'][0]['bytes_hex']==struct.pack('<Q',address).hex()
        assert r['output_cell_reads'][1]['pc']=='0x100475dd4'and r['output_cell_reads'][1]['bytes_hex']=='00'*4
        inline_stores+=len(writes)
    ins={i['ea']:i for s in e['spans']for i in s['instructions']}
    assert ins['0x10049e118']['mnemonic']=='ldr'and ins['0x10049e118']['operands']=='w0, [x28]'
    assert seqs[0]==seqs[1]
    assert inline_stores==384 and vm_stores==1438 and cf_boundaries==2
    return {'inline_store_result_joins':inline_stores,'VM_copy_store_byte_joins':vm_stores,
      'CF_create_boundaries':cf_boundaries,'zero_address_success_same_original_sequence':True}


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()=='a12973b42f4dea2bcbcdec22f27d8a3db6e08ea7353e482bd3eb784145a34aa9'
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8178 and len(new)==len(current['files'])==8185
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==previous['inputs_preserved']
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1200_vm_report.md')
    assert all(f'| VM{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'fpsd1200_vm_checks.json'))
    assert e['verified_counts']==COUNTS and sha(ROOT/'recover_fpsd1200_vm.py')==e['generator_sha256']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    assert e['new_IDA_access']and not any(e[k]for k in ['new_IDB_mutations','new_native_execution','full_goal_complete'])
    receipt=json.loads(read(ROOT/'fpsd1200_vm_audit.json'))
    assert receipt['fresh_replay_completed']and receipt['process_exit_code']==0 and not receipt['native_target_executed']
    assert receipt['auditor_sha256']==sha(ROOT/'audit_fpsd1200_vm.py')
    assert receipt['checks_sha256']==sha(ROOT/'fpsd1200_vm_checks.json')
    assert receipt['IDA_SDK_readback_sha256']==sha(ROOT/'fpsd1200_vm_ida_readback.json')
    assert receipt['daemon_sha256']==e['daemon_sha256']and receipt['dependencies']==e['dependencies']
    for n,h in receipt['public_DER_inputs'].items():assert sha(ROOT/n)==h
    finite=receipt['result'];assert {k:v for k,v in finite.items()if k!='exponent_group_summaries'}==FINITE
    groups=finite['exponent_group_summaries'];assert len(groups)==9
    assert [(g['case'],g['key'],g['calls'])for g in groups]==[(case,key,calls)for case in ['allocation_success','allocation_failure','zero_address_success']for key,calls in [('Root',32),('AAA',31),('CoreFP_leaf',31)]]
    assert all(g['exponent']==65537 and g['complete_exponent_order_checked']for g in groups)
    att=json.loads(read(ROOT/'fpsd1200_vm_ida_readback.json'))
    assert not att['IDB_mutated']and att['spans']==[{'start':s['start'],'size_B':int(s['end'],16)-int(s['start'],16),'sha256':s['sha256']}for s in e['spans']]
    assert att['SDK_context']['compile_only']['exit_code']==0
    joins=data_joins(e)
    assert current['validation']['fpsd1200_vm_increment_checks']==COUNTS
    assert current['validation']['fpsd1200_vm_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==413
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene((BASE/p).read_bytes())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
      'original_inputs_preserved':3,'pinned_fresh_audit':{k:v for k,v in finite.items()if k!='exponent_group_summaries'},
      'publication_does_not_replay_instructions':True,**joins,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
