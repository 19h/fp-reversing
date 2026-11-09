#!/usr/bin/env python3
"""Independently audit serializer proofs, byte effects and value compositions.
O(source+all visits/effects+retained audit+solver resources) time; space includes
compressed artifacts, largest decoded/fresh component, private map and solver.
"""
import json,hashlib,struct,capstone
from pathlib import Path
from collections import Counter
import z3,unicorn as uc
from unicorn import arm64_const as ar
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE
from recover_daemon_object_creation import sha,span
from recover_daemon_descriptor_producers import verify_used_fixups
from recover_daemon_cache36 import ida_matches
from replay_daemon_descriptor_producers import unpack
from validate_daemon_object_clock import checked,logical_read
from daemon_digest_output_access import register_access,key,audit
from daemon_digest_output_inputs import serialized,retained_short,pipeline_configurations
from recover_daemon_digest_output import helper_abis,root_census
from prove_daemon_digest_output import obligations
from probe_daemon_digest_output import execute,execute_pipeline,configurations,decision_configurations
from daemon_sha1_core_model import reference,STATE_XOR
def norm(x):return z3.simplify(x,bv_sort_ac=True)
def shift_checks():
 count=0
 for row in audit():
  a=int(row['address'],16);raw=bytes.fromhex(row['bytes_hex']);values=[0,1,0x89abcdef,0xffffffff]
  inputs=[(v,fill)for v in values for fill in [0,0xffffffff]]if a!=0x1008b6078 else[(v,shift)for v in values for shift in [0,1,31,32,63]]
  for v,other in inputs:
   u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);base=0x710000;u.mem_map(base,4096);u.mem_write(base,raw)
   if a==0x100be71e4:src,dst='W9','W14';expected=v>>24
   elif a==0x100be7218:src,dst='W14','W15';expected=(v<<1)&0xffffffff
   else:src,dst='W16','W8';expected=v>>(other&31)
   u.reg_write(getattr(ar,'UC_ARM64_REG_'+src),v);u.reg_write(getattr(ar,'UC_ARM64_REG_'+dst),other);u.emu_start(base,base+4,count=1);assert u.reg_read(getattr(ar,'UC_ARM64_REG_'+dst))==expected;count+=1
 return count
def check_trace(t,c,instructions,counts,group):
 cfg=t['configuration'];F=int(t['SP'],16);C=int(t['context'],16);O=int(t['output'],16);assert t['entry_defined_GPRs']=={'sp':hex(F),'x30':hex(TABLE)};known={'sp','x30'}
 for pc,raw in t['steps']:
  if pc not in instructions:
   cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;instructions[pc]=next(cs.disasm(IMAGE.read(pc,4),pc))
  i=instructions[pc];assert bytes(i.bytes).hex()==raw;reads,writes=register_access(i);assert all(i.reg_name(r)in ['wzr','xzr']or key(i.reg_name(r))in known for r in reads),(hex(pc),i.mnemonic);known.update(key(i.reg_name(r))for r in writes);counts[group+'_defined_source_visits']+=1
 data={int(f['address'],16)+j:x for f in t['initial_fixtures']for j,x in enumerate(bytes.fromhex(f['bytes_hex']))};assert t['context_input_mask100']==[False]*72+[True]*28;assert all(C+j in data for j in range(72,100));output_writes=[]
 decision=cfg.get('decision_only',False);expected=b''if decision else serialized(cfg['state5'],cfg['selector'],cfg['output_size'])
 for e in t['events']:
  a=e['address'];n=e['size'];raw=bytes.fromhex(e['hex']if e['kind']=='read'else e['after_hex']);assert len(raw)==n
  if e['kind']=='read':assert raw==(bytes(data[a+j]for j in range(n))if 0x6b00000000<=a<0x6b00100000 else logical_read(a,n));counts[group+'_ordered_reads']+=1
  else:
   assert(a==F+0x2a70 and n==8)or(O<=a<a+n<=O+len(expected));data.update({a+j:x for j,x in enumerate(raw)});counts[group+'_ordered_writes']+=1
   if O<=a<O+32:assert n==1;output_writes.append(e)
 for pc,target,slot,modifier in t['edges']:
  f=FIXUPS[slot];assert f['target']==target and f'div=0x{modifier:04X} 'in f['annotation'];counts[group+'_modeled_BRAA_edges']+=1
 assert t['context_after']==t['context_before'];assert bytes.fromhex(t['output_hex32'])[:len(expected)]==expected;assert t['output_defined_mask32']==[True]*len(expected)+[False]*(32-len(expected));assert len(output_writes)==len(expected);assert {e['address']for e in output_writes}==set(range(O,O+len(expected)))
 if expected:assert bytes(data[O+j]for j in range(len(expected)))==expected
 counts[group+'_defined_output_bytes']+=len(expected)
 if decision:
  b=cfg['selector']&255;target=0x100b57120 if b==1 else 0x100be71bc if b==2 else 0x100bb1574;assert t['boundary']=={'pc':hex(target),'kind':'before_serializer_or_common_continuation','detail':{'target':hex(target)}}
 else:assert t['boundary']=={'pc':'0x100bb15d0','kind':'before_unknown_frame_read','detail':{'address':hex(F+0x3050),'size_bytes':8,'instruction':'ldr x12, [sp, #0x3050]'}}
 return expected
def main():
 c=checked('daemon_digest_output_contracts.json','recover_daemon_digest_output.py');p=checked('daemon_digest_output_proofs.json','prove_daemon_digest_output.py');r=checked('daemon_digest_output_profiles.json','probe_daemon_digest_output.py');counts=Counter();totals=Counter();assert c['source_sha256']==r['source_sha256']==sha(SOURCE)
 for s in c['spans']:assert span(s['label'],int(s['start'],16),int(s['end'],16))==s;counts['original_source_spans']+=1
 for a,b in c['source_pool'].items():assert IMAGE.read(int(a,16),4).hex()==b;counts['unique_observed_serializer_instructions']+=1
 assert verify_used_fixups([int(x['address'],16)for x in c['original_fixups']['records']])==c['original_fixups'];counts['original_fixups_checked']=len(c['original_fixups']['records']);live=ida_matches('daemon_digest_output_ida_bytes.json');assert live==c['live_IDB_matches'];counts['live_IDB_ranges']=len(live);counts['live_IDB_bytes']=sum(x['size_bytes']for x in live);assert root_census()==c['SP3050_census'];counts['exact_SP3050_scalar_accesses']=len(c['SP3050_census']['records']);assert audit()==c['shift_access_audit']and capstone.__version__==c['capstone_version'];counts['shift_access_records_checked']=len(audit());counts['independent_shift_instruction_cases']=shift_checks()
 qs,lifts=obligations(c);assert lifts==p['source_lift_counts']
 for(name,pred),proof in zip(qs,p['proofs'],strict=True):
  assert name==proof['name'];a=ROOT/proof['original_file'];b=ROOT/proof['file'];assert sha(a)==proof['original_sha256']and sha(b)==proof['sha256'];aa=z3.parse_smt2_file(str(a));bb=z3.parse_smt2_file(str(b));assert len(aa)==len(bb)==1 and z3.eq(norm(aa[0]),norm(pred))and z3.eq(norm(bb[0]),norm(pred));s=z3.Solver();s.set(timeout=30000);s.add(bb[0]);assert str(s.check())=='unsat',name;counts['source_obligations_rebuilt_unsat']+=1;counts['SMT_artifacts_formula_matched']+=2
 for abi in c['helper_ABIs'].values():
  j=z3.BitVec('output_index32',32);lo,hi=abi['counter_domain'];s=z3.Solver();s.add(z3.UGE(j,lo),z3.ULE(j,hi));assert str(s.check())=='sat';counts['nonempty_helper_domains']+=1
 counts['source_lift_visits']=sum(lifts.values());assert [x['configuration']for x in r['cases']]==list(configurations())and len(r['cases'])==64;assert[x['configuration']for x in r['decision_cases']]==list(decision_configurations())and len(r['decision_cases'])==512;assert[x['configuration']for x in r['conditional_pipelines']]==list(pipeline_configurations())and len(r['conditional_pipelines'])==6;instructions={};pipeline_outputs={}
 for group in ['cases','decision_cases']:
  for row in r[group]:
   t=unpack(row);check_trace(t,c,instructions,counts,group)
   for name,abi in helper_abis(t).items():assert abi==c['helper_ABIs'][name];counts['helper_ABI_configurations_checked']+=1
   assert json.loads(json.dumps(execute(row['configuration'])))==t;counts[group+'_freshly_recomputed']+=1
 for row in r['conditional_pipelines']:
  t=unpack(row);cfg=row['configuration'];core=t['core_trace'];fmt=t['serializer_trace'];message=bytes.fromhex(cfg['message_hex']);prepared=bytes.fromhex(cfg['prepared_context100_hex']);assert t['core_input_contract']['block_hex']==bytes(x^0x98 for x in prepared[:64]).hex();expected=check_trace(fmt,c,instructions,counts,'pipeline_serializer');assert expected==bytes(x^0x98 for x in hashlib.sha1(message).digest());assert [x^STATE_XOR for x in struct.unpack_from('<5I',bytes.fromhex(core['context_after']),0x48)]==fmt['configuration']['state5'];assert struct.unpack_from('<II',bytes.fromhex(core['context_after']),0x5c)==(fmt['configuration']['output_size'],fmt['configuration']['selector'])==(20,2);m=reference(bytes.fromhex(t['core_input_contract']['block_hex']),t['core_input_contract']['initial_state5']);assert bytes.fromhex(core['decoded_state20'])==b''.join(x.to_bytes(4,'big')for x in m['final_state5']);assert json.loads(json.dumps(execute_pipeline(cfg)))==t;pipeline_outputs.setdefault(cfg['message_hex'],set()).add(expected.hex());counts['conditional_pipelines_freshly_recomputed']+=1;counts['conditional_pipeline_hashlib_oracles']+=1;totals['pipeline_core_source_visits']+=len(core['steps']);totals['pipeline_core_BRAA']+=len(core['edges']);totals['pipeline_core_reads']+=sum(e['kind']=='read'for e in core['events']);totals['pipeline_core_writes']+=sum(e['kind']=='write'for e in core['events'])
 assert all(len(v)==1 for v in pipeline_outputs.values())and len(pipeline_outputs)==3;retained,rc=retained_short();assert retained==c['retained_short_inputs']and rc==c['retained_counts']
 for row in retained:assert pipeline_outputs[row['message_hex']]=={row['conditional_expected_output20_hex']};counts['retained_prepared_inputs_value_matched']+=1
 totals['serializer_source_visits']=sum(counts[g+'_defined_source_visits']for g in ['cases','decision_cases','pipeline_serializer']);totals['serializer_BRAA']=sum(counts[g+'_modeled_BRAA_edges']for g in ['cases','decision_cases','pipeline_serializer']);totals['serializer_reads']=sum(counts[g+'_ordered_reads']for g in ['cases','decision_cases','pipeline_serializer']);totals['serializer_writes']=sum(counts[g+'_ordered_writes']for g in ['cases','decision_cases','pipeline_serializer']);aggregate={'source_visits':totals['serializer_source_visits']+totals['pipeline_core_source_visits'],'modeled_BRAA_visits':totals['serializer_BRAA']+totals['pipeline_core_BRAA'],'read_effects':totals['serializer_reads']+totals['pipeline_core_reads'],'write_effects':totals['serializer_writes']+totals['pipeline_core_writes']};aggregate['A64_executed_instructions']=aggregate['source_visits']-aggregate['modeled_BRAA_visits'];assert aggregate=={'source_visits':141948,'modeled_BRAA_visits':2990,'read_effects':7976,'write_effects':1908,'A64_executed_instructions':138958}
 counts.update(rc);deps=['daemon_digest_output_contracts.json','daemon_digest_output_proofs.json','daemon_digest_output_profiles.json','daemon_digest_output_access.py','daemon_digest_output_inputs.py','prove_daemon_digest_output.py','probe_daemon_digest_output.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':dict(counts),'independent_A64_totals':aggregate,'component_A64_totals':dict(totals),'source_lift_counts':lifts,'all_checks_pass':True,'new_port_emission_established':False,'native_identity_or_cache_publication_established':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_digest_output_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'counts':dict(counts),'pipeline_core_totals':dict(totals)}),flush=True)
if __name__=='__main__':main()
