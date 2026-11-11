#!/usr/bin/env python3
"""Audit middle-span staging source/ABI certificates and publication delta.

Read-only; native provider effects and object epochs remain premises.
O(source/index bytes + owned bytes + retained expressions) time/space;
SMT solver cost is separate.
"""
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess

from compression import zstd
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_MEM
import z3

from kernel_native_reader import Kernel
from kext_port_tools import IMAGE,SOURCE
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene

ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent
PREVIOUS='a7cbdabefbc6a4bd45e746efd2f04db78e2257e0'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={
 'lskd_byte_spans_report.md','lskd_operation_preflight_report.md',
 'lskd_reader_lineage_report.md','lskd_context_return_report.md','sample_transfer_report.md',
 'obfuscated_routines_report.md','foundational_triage_report.md',
 'interface_abi_report.md','interface_investigation_status.md',
 'triage_evidence/validate_rpc502_sidecar_delivery.py',
}
ADDED={
 'lskd_hardware_staging_report.md','triage_evidence/recover_lskd_hardware_staging.py',
 'triage_evidence/lskd_hardware_staging_checks.json','triage_evidence/verify_lskd_hardware_staging_publication.py',
}
ARCHIVES={MANIFEST,'triage_evidence/lskd_hardware_staging_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'queries_unsat':36,'negative_controls_sat':1,'source_pieces':33,
 'source_lifted_instances':12986,'bank_rules':4,'bank_byte_inputs':1024,
 'bank_source_lifted_instances':12800,'spans':12,'instructions':312,'code_B':1248,
 'original_loaded_slots':7,'original_slots':17}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def check(query,expected):
 solver=z3.Solver();solver.set(timeout=15000);solver.from_string(query)
 assert solver.check()==expected


def main():
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
 assert sha256(raw).hexdigest()=='5850f099d1204cb21e7e6e49335fa5eaed9af2ba9a7065c3e8069fe3d149e99e'
 previous=json.loads(raw);current=json.loads(read(BASE/MANIFEST))
 old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
 assert len(old)==len(previous['files'])==8074 and len(new)==len(current['files'])==8078
 assert not old.keys()-new.keys() and new.keys()-old.keys()==ADDED
 assert {p for p in old if old[p]!=new[p]}==CHANGED
 assert current['inputs_preserved']==previous['inputs_preserved']
 for row in current['inputs_preserved']:
  assert sha(BASE/row['path'])==row['sha256'] and size(BASE/row['path'])==row['size_bytes']
 for p in CHANGED|ADDED:
  assert sha(BASE/p)==new[p]['sha256'] and size(BASE/p)==new[p]['size_bytes']
 report=read(BASE/'lskd_hardware_staging_report.md')
 assert all(f'| HS{i} |' in report for i in range(1,9)) and all(f'**QG{i}**' in report for i in range(1,8))
 e=json.loads(read(ROOT/'lskd_hardware_staging_checks.json'))
 assert e['generator_sha256']==sha(ROOT/'recover_lskd_hardware_staging.py')
 for p,digest in e['dependencies'].items():assert sha(ROOT/p)==digest
 assert e['verified_counts']==COUNTS and len(e['proofs'])==36
 assert {'context_window','context_window_length','chunk_partition','hardware_args',
  'provider_arguments','provider_tail','hardware_result_gate','finish'}<=e['proofs'].keys()
 for proof in e['proofs'].values():assert proof['result']=='unsat';check(proof['query'],z3.unsat)
 assert set(e['negative_controls'])=={'upper_result_bits_are_not_tested'}
 for control in e['negative_controls'].values():
  assert control['result']=='sat' and not control['native_target_state']
  n=int(control['result64'],16);assert n and n&0xffffffff==0
  check(control['query'],z3.sat)
 prior_unsat=prior_sat=0
 for name,count in [('lskd_byte_spans_checks.json',156),('lskd_context_return_checks.json',39),('lskd_reader_lineage_checks.json',26)]:
  prior=json.loads(read(ROOT/name));assert len(prior['proofs'])==count
  for proof in prior['proofs'].values():
   assert proof['result']=='unsat';check(proof['query'],z3.unsat);prior_unsat+=1
  for control in prior.get('negative_controls',{}).values():
   assert control['result']=='sat';check(control['query'],z3.sat);prior_sat+=1
 assert (prior_unsat,prior_sat)==(221,5)
 k=Kernel();assert e['kernel_collection_sha256']==k.sha256 and e['normalized_image_sha256']==sha(SOURCE)
 cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
 spans={r['label']:r for r in e['spans']};assert len(spans)==12
 ranges=sorted((int(r['start'],16),int(r['end'],16)) for r in spans.values())
 assert all(z<=a for (_,z),(a,_) in zip(ranges,ranges[1:]))
 for row in spans.values():
  data=bytes.fromhex(row['bytes_hex']);a=int(row['start'],16)
  assert len(data)==int(row['end'],16)-a==4*len(row['instructions'])
  assert data==k.read(a,len(data))==IMAGE.read(a,len(data))
  decoded=[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in cs.disasm(data,a)]
  assert row['instructions']==decoded
 assert sum(len(r['instructions']) for r in spans.values())==312
 assert len(e['source_pieces'])==33 and sum(e['source_lift_counts'].values())==12986
 for name,piece in e['source_pieces'].items():
  a,z=int(piece['start'],16),int(piece['end'],16)
  assert piece['instructions']==(z-a)//4 and piece['instructions']*piece['instances']==e['source_lift_counts'][name]
  assert piece['instances']==(256 if name.startswith('bank_') else 1)
  assert any(left<=a<z<=right for left,right in ranges)
  assert not any(i.mnemonic.startswith('bl') for i in cs.disasm(k.read(a,z-a),a))
 assert len(e['slots'])==17 and len(e['table_loads'])==7
 for a,row in e['slots'].items():assert row==pointer(k,int(a,16)) and row['authenticated']
 for a,target in e['table_loads'].items():
  assert a in e['slots'] and int(target,16)==int(e['slots'][a]['target'],16)
  assert int.from_bytes(IMAGE.read(int(a,16),8),'little')==int(target,16)
 assert set(e['rules'])==set(e['bank_source_cuts'])=={'initial_copy','copy_in','hardware','copy_out'}
 for name,rule in e['rules'].items():
  left,right=[bytes.fromhex(b) for b in rule['banks_hex']]
  for field,data in [('left',left),('right',right)]:
   a=int(rule[field],16);assert len(data)==256 and data==k.read(a,256)==IMAGE.read(a,256)
  constant=int(rule['constant'],16);key=int(rule['key'],16)
  assert {x^right[left[x]^key] for x in range(256)}=={constant}
  index=int(rule['additive'],16)+constant;assert index==int(rule['index'],16)
  slot=0xfffffe000846c420+8*index
  assert slot==int(rule['slot'],16) and rule['original_fixup']==e['slots'][hex(slot)]
  assert rule['target']==rule['original_fixup']['target'] and rule['inputs_checked']==256
  cut=e['bank_source_cuts'][name];assert cut['arbitrary_upper_input_bits']==24 and len(cut['rows'])==256
  for byte,row in enumerate(cut['rows']):
   assert row['input_byte']==byte and row['target']==rule['target'] and len(row['reads'])==2
   first,second=row['reads']
   assert int(first['address'],16)==int(rule['left'],16)+byte and first['value']==left[byte]
   assert int(second['address'],16)==int(rule['right'],16)+(left[byte]^key) and second['value']==right[left[byte]^key]
 assert e['exact_symbols']==k.symbols([0xfffffe000abff358,0xfffffe000c647f10])
 assert {r['name'] for r in e['exact_symbols']['0xfffffe000c647f10']}=={'_memcpy','_memmove'}
 assert [r['name'] for r in e['exact_symbols']['0xfffffe000abff358']]==[
  '__ZN16IOAESAccelerator10performAESEP18IOMemoryDescriptorS1_yP7IOAESIV14IOAESOperationP12IOAESKeyDatayyPFvPviES7_']
 assert int(e['slots']['0xfffffe000847c4c8']['target'],16)==0xfffffe000c647f10
 assert int(e['slots']['0xfffffe0008588c10']['target'],16)==0xfffffe000abff358
 frozen=json.loads(read(ROOT/'kext_aes_handoff_contracts.json'))
 wrapper=next(r for r in frozen['functions'] if r['start']=='0xfffffe000a5083d8')
 assert wrapper['bytes_hex']==spans['aes_wrapper']['bytes_hex'] and wrapper['end']==spans['aes_wrapper']['end']
 # Independent register/store/call checks qualify composition through cuts.
 def writes(ins):
  return {re.sub(r'^w(?=\d)','x',{'fp':'x29','lr':'x30'}.get(ins.reg_name(r),ins.reg_name(r))) for r in ins.regs_access()[1]}
 def preserved(a,z,regs):
  for ins in cs.disasm(k.read(a,z-a),a):assert not writes(ins)&regs,(hex(ins.address),ins.op_str)
 preserved(0xfffffe000a5722bc,0xfffffe000a57231c,{'x0','x1','x14','x21','x29','sp'})
 preserved(0xfffffe000a52e534,0xfffffe000a52e54c,{'x8','x9','x10','x12','x14','x15','x21','x22','x29','sp'})
 preserved(0xfffffe000a5237dc,0xfffffe000a5237f0,{'x8','x9','x10','x12','x14','x15','x21','x22','x29','sp'})
 preserved(0xfffffe000a54aa1c,0xfffffe000a54aa64,{'x19','x20','x22','x23','x24','x25','x27','x28','x29','sp'})
 preserved(0xfffffe000a526a24,0xfffffe000a526aa0,{'x20','x23','x24','x27','x28','x29','sp'})
 preserved(0xfffffe000a526a40,0xfffffe000a526aa0,{'x0'})
 preserved(0xfffffe000a526aa4,0xfffffe000a526b00,{'x20','x22','x23','x24','x25','x27','x28','x29','sp'})
 preserved(0xfffffe000a526b04,0xfffffe000a526b34,{'x22','x23','x24','x25','x26','x27','x28','x29','sp'})
 preserved(0xfffffe000a53667c,0xfffffe000a5366d0,{'x0','x19','x20','x22','x23','x24','x25','x26','x27','x28','x29','sp'})
 preserved(0xfffffe000a591e68,0xfffffe000a591e80,{'x21'})
 calls=[]
 for row in spans.values():
  for ins in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if ins.mnemonic.startswith('bl'):calls.append(ins.address)
   if ins.mnemonic.startswith('st'):
    mem=[o for o in ins.operands if o.type==ARM64_OP_MEM]
    assert len(mem)==1 and ins.reg_name(mem[0].mem.base)=='sp'
 assert set(calls)=={0xfffffe000a54aa64,0xfffffe000a526aa0,0xfffffe000a526b00,
  0xfffffe000a5366d0,0xfffffe000a508440,0xfffffe000a508464} and len(calls)==6
 code={r['ea']:(r['mnemonic'],r['operands']) for row in spans.values() for r in row['instructions']}
 assert code['0xfffffe000a508444']==('cbz','w0, #0xfffffe000a50846c')
 assert code['0xfffffe000a508464']==('bl','#0xfffffe000a508c78')
 assert code['0xfffffe000a50846c']==('mov','w19, #0')
 assert code['0xfffffe000a526af4']==('mov','x2, x27')
 assert code['0xfffffe000a69f340']==('braa','x16, x17')
 source=e['supplied_reference'];assert sha(BASE/source['path'])==source['sha256']
 lines=read(BASE/source['path']).splitlines(keepends=True)
 for row in source['excerpts']:assert row['text']==''.join(lines[row['first_line']-1:row['last_line']])
 c=e['selected_contract'];assert c['original_operations']==[1,5]
 assert [c[n] for n in ['context_window_offset_B','context_window_length_B','key_data_offset_B',
  'context_copy_frame_offset_B','working_IV_frame_offset_B','staging_cap_B','provider_operation32']]==[0x134,16,0x184,0x280,0x270,81920,1]
 assert c['provider_length_is_saved_total32'] and c['copy_length_is_chunk32']
 assert (c['conditional_outer_success32'],c['conditional_outer_failure32'])==('0x0','0xffffffea')
 assert not any(c[n] for n in ['public_operation_meanings_proven','whole_operation_overlap_contract_proven',
  'native_descriptor_capacity_matched','native_epoch_matched','daemon_request_lineage_proven'])
 assert not any(e[n] for n in ['new_IDA_access','new_native_execution','new_IDB_mutations','full_goal_complete'])
 assert current['validation']['lskd_hardware_staging_increment_checks']==COUNTS
 assert current['validation']['lskd_hardware_staging_static_scope']==e['scope']
 assert current['validation']['reports']==previous['validation']['reports']+1==393
 assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
 assert current['goal_status']=='active' and len(OWNED)==15
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:path_hygiene((BASE/p).read_bytes())
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
  'original_inputs_preserved':3,'new_UNSAT_queries_rechecked':36,'new_SAT_controls_rechecked':1,
  'prior_UNSAT_queries_rechecked':prior_unsat,'prior_SAT_controls_rechecked':prior_sat,
  'bank_byte_cases':1024,'original_fixup_addresses':17,'original_call_sites':6,
  'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
