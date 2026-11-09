#!/usr/bin/env python3
"""Verify source,loader addends,opaque-byte flow,source proofs and fresh replays.
O(cache/artifact bytes+SMT+fresh source visits+effects) time,O(largest trace+RAM)
space. Current installed-cache ABI evidence is distinct from native execution.
"""
import json,hashlib,struct
from pathlib import Path
from collections import Counter
import z3
import unicorn as uc
from unicorn import arm64_const as ar
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,qword
from bootpolicy_cache_reader import Cache,Dylib
from capture_daemon_descriptor_producers import terminal
from recover_daemon_descriptor_producers import verify_used_fixups
from replay_daemon_descriptor_producers import Replay,unpack,IMPORTS
from daemon_seed_material_symbolic import decode
P=0x6800000000
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1048576):h.update(b)
 return h.hexdigest()
def checked(n,g):
 r=json.loads((ROOT/n).read_text());assert r['generator_sha256']==sha(ROOT/g)and r['full_goal_complete']is False
 for dep,h in r.get('dependencies',{}).items():assert sha(ROOT/dep)==h,(n,dep)
 if'source_sha256'in r:assert sha(SOURCE)==r['source_sha256']
 return r
def probe_helper(source,N,walk,pattern):
 start=int(source['stack_probe_original_function']['start'],16);end=int(source['stack_probe_original_function']['end'],16);raw=bytes.fromhex(source['stack_probe_original_function']['bytes']);u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);SP=P+0x80000;TLS=P+0xf0000;RET=P+0xfff00;u.mem_map(P,0x100000);u.mem_write(P,bytes([pattern&255])*0x100000);u.mem_map(start&~4095,4096);u.mem_write(start,raw);u.mem_write(TLS-48,struct.pack('<QQ',0 if walk else SP+1,SP-0x40000));u.reg_write(ar.UC_ARM64_REG_TPIDRRO_EL0,TLS);u.reg_write(ar.UC_ARM64_REG_SP,SP);u.reg_write(ar.UC_ARM64_REG_NZCV,pattern&0xf0000000)
 for j in range(31):u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),((0x11223344556677*j)^pattern)&((1<<64)-1))
 for j in range(32):u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),(pattern<<64)|pattern)
 u.reg_write(ar.UC_ARM64_REG_X9,N);u.reg_write(ar.UC_ARM64_REG_X30,RET);before=[u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(j)))for j in range(31)];qbefore=[u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j)))for j in range(32)];touches=[];writes=[];visits=[]
 def code(u,a,n,d):assert start<=a<end and bytes(u.mem_read(a,4))==raw[a-start:a-start+4];visits.append(a)
 def read(u,t,a,n,v,d):
  pc=u.reg_read(ar.UC_ARM64_REG_PC)
  if pc in[0x180587d24,0x180587d38]:touches.append(a)
 def write(u,t,a,n,v,d):writes.append((a,n))
 u.hook_add(uc.UC_HOOK_CODE,code);u.hook_add(uc.UC_HOOK_MEM_READ,read);u.hook_add(uc.UC_HOOK_MEM_WRITE,write);u.emu_start(start,RET,count=1000);assert u.reg_read(ar.UC_ARM64_REG_PC)==RET and u.reg_read(ar.UC_ARM64_REG_SP)==SP
 expected=[];remaining=N;cursor=SP
 if walk:
  if remaining>=4096:
   while True:
    cursor-=4096;expected.append(cursor);remaining-=4096
    if remaining<=4096:break
  expected.append(cursor-remaining)
 assert touches==expected and writes==[(SP-16,8),(SP-8,8)]
 for j,b in enumerate(before):assert u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(j)))==(remaining if j==9 and walk else b),j
 assert[u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j)))for j in range(32)]==qbefore
 return {'allocation_size64':N,'walk':walk,'physical_pattern64':hex(pattern),'source_visits':len(visits),'stack_touch_addresses':[hex(a)for a in touches],'remaining_X9':remaining if walk else N,'SP_preserved':True,'X0_X1_preserved':True,'other_GPRs_except_X9_preserved':True,'SIMD_preserved':True,'all_checks_pass':True}
def main():
 source=checked('daemon_descriptor_producers_source.json','capture_daemon_descriptor_producers.py');p=checked('daemon_descriptor_producers_profiles.json','probe_daemon_descriptor_producers.py');co=checked('daemon_descriptor_producers_copies.json','continue_daemon_descriptor_producers.py');c=checked('daemon_descriptor_producers_contracts.json','recover_daemon_descriptor_producers.py');proofs=checked('daemon_descriptor_producers_proofs.json','prove_daemon_descriptor_producers.py');replays=checked('daemon_descriptor_producers_replays.json','replay_daemon_descriptor_producers.py');counts=Counter();rawhelper=bytes.fromhex(source['stack_probe_original_function']['bytes']);cache=Cache();pthread=Dylib(cache,'/usr/lib/system/libsystem_pthread.dylib');compiler=Dylib(cache,'/usr/lib/system/libcompiler_rt.dylib');system=Dylib(cache,'/usr/lib/libSystem.B.dylib');a=pthread.exports['____chkstk_darwin']['address'];assert cache.uuid==source['cache_UUID']and cache.read(a,len(rawhelper))==rawhelper and pthread.function(a)==source['stack_probe_original_function'];assert terminal(compiler,'___chkstk_darwin')==source['compiler_rt_alias'];assert terminal(pthread,'____chkstk_darwin')==source['pthread_export'];assert compiler.path in[r[24:].split(b'\0')[0].decode()for cmd,r in system.commands if cmd==0x8000001f]
 for f in source['cache_files']:path=Path(f['path']);assert path.stat().st_size==f['size_bytes']and sha(path)==f['sha256'];counts['installed_cache_files_hashed']+=1
 counts['installed_cache_helper_bytes_checked']=len(rawhelper);counts['original_reexport_aliases_checked']=1;counts['libSystem_reexport_edges_checked']=1
 for r in c['spans']:
  b=bytes.fromhex(r['bytes_hex']);assert IMAGE.read(int(r['start'],16),len(b))==b and hashlib.sha256(b).hexdigest()==r['sha256'];counts['original_source_spans_checked']+=1
 for b in c['banks_exhaustive256']:
  left,right,key=[int(b[k],16)for k in['left','right','key']];lb=IMAGE.read(left,256);rb=IMAGE.read(right,256);assert all(i^rb[lb[i]^key]==int(b['constant'],16)for i in range(256));assert(qword(int(b['slot'],16))+int(b['bias'],16))&((1<<64)-1)==int(b['target'],16)if b['target'].startswith('0x')else qword(int(b['slot'],16))==b['target'];counts['exhaustive_bank_input_cases']+=256;counts['selection_rules_checked']+=1
 counts['distinct_bank_identities_checked']=len({(b['left'],b['right'],b['key'])for b in c['banks_exhaustive256']});assert verify_used_fixups({int(r['address'],16)for r in c['original_fixups']['records']})==c['original_fixups'];counts['original_fixups_checked']=len(c['original_fixups']['records']);special=c['original_bindings']['0x1010a7e18'];assert special['import_table_addend']==special['total_addend']==0x6ae8388f and special['pointer_addend']==0;counts['nonzero_import_addends_checked']=1
 for row in proofs['proofs']:
  for fk,hk in[('original_file','original_sha256'),('file','sha256')]:
   path=ROOT/row[fk];assert sha(path)==row[hk];s=z3.Solver();s.set(timeout=30000);s.from_file(str(path));assert str(s.check())=='unsat',row['name'];counts['SMT_queries_unsat']+=1
 counts['source_proof_pairs_unsat']=len(proofs['proofs']);counts['source_lift_visits']=sum(proofs['source_lift_counts'].values());counts['nonempty_premise_witnesses']=len(proofs['nonempty_premise_witnesses']);assert counts['source_proof_pairs_unsat']==23 and counts['nonempty_premise_witnesses']==2
 boundaries=Counter();pool={};nulls=0
 for r in p['cases']:
  cfg=r['configuration'];R=int(r['record_address'],16);k=(((R&0xffffffff)^0xdc40790b)*0x5973a279)&0xffffffff;b=bytes.fromhex(r['final_record']['bytes_hex']);assert int.from_bytes(b[:4],'little')^k==0x471c and(int.from_bytes(b[20:24],'little')-k)&0xffffffff==0x2be18a5d and int.from_bytes(b[8:16],'little')==(P+0x1000 if cfg['nonnull']else 0);assert r['fixture_PC_transitions']==0;assert[(e['pc'],e['target'])for e in r['source_calls']]==[('0x10039c92c','0x100abca64'),('0x100abcc98','0x100a59bb4'),('0x100a59be4','0x180587cd4')];assert r['source_calls'][-1]['modifier']=='0x1010b1e28'
  if not cfg['nonnull']:assert r['boundary']['kind']=='after_original_outer_stack_adjustment'and int(r['boundary']['SP'],16)==int(r['entry_SP'],16)and int.from_bytes(b[16:20],'little')==0x74c29d88 and bytes.fromhex(r['final_counter']['bytes_hex'])==bytes(8);nulls+=1
  else:assert r['boundary']['pc']=='0x100a222a4'and r['boundary']['kind']=='before_unknown_private_read'and not any(bytes.fromhex(r['final_payload']['known_mask_hex']))
  for s in r['source_visits']:
   a=int(s['pc'],16);raw=rawhelper[a-int(source['stack_probe_original_function']['start'],16):a-int(source['stack_probe_original_function']['start'],16)+4]if s['image']!='daemon'else IMAGE.read(a,4);assert raw.hex()==s['bytes_hex'];pool[(s['image'],s['pc'])]=s['bytes_hex']
  boundaries[r['boundary']['kind']]+=1;counts['continuous_prefix_source_visits']+=len(r['source_visits']);counts['continuous_prefix_cases']+=1
 assert len(p['cases'])==48 and nulls==24;counts['returning_null_cases']=nulls;assert not c['reader_B_reached']and c['new_lock_cell']!=c['prior_descriptor_G']
 for r in co['cases']:
  t=unpack(r);F=int(t['initial_SP'],16);assert len(t['steps'])==711 and r['unknown_input_bytes_used']==36 and not t['definitions'];assert r['boundary']['pc']=='0x10019385c'and r['boundary']['target']==hex(IMPORTS['libSystem/_malloc'])and int.from_bytes(bytes.fromhex(r['boundary']['registers31'][0]['hex']),'little')==200;assert r['boundary']['modifier16']=='0x6aa4';creator=next(s for s in t['steps']if s['pc']=='0x1009729d0');assert creator['target']=='0x10043a240'
  for s in t['steps']:
   assert IMAGE.read(int(s['pc'],16),4).hex()==s['bytes_hex'];pool[('daemon',s['pc'])]=s['bytes_hex']
   for e in s['events']:
    if e['kind']=='write'and('terms'in e['value']or'expr'in e['value']):assert P<=int(e['address'],16)<P+0x100000;counts['private_unknown_write_effects_retained']+=1
  record=next(e for s in t['steps']if s['pc']=='0x100972974'for e in s['events']if e['kind']=='write');assert record['value']['hex']=='c0670c0101000000';R=F+0xde90;k=((R^0xdc40790b)*0x5973a279)&0xffffffff;control=next(e for s in t['steps']if s['pc']=='0x10097296c'for e in s['events']if e['kind']=='write');assert(int.from_bytes(bytes.fromhex(control['value']['hex']),'little')+k)&0xffffffff==0xaed7
  word=next(e for s in t['steps']if s['pc']=='0x1009d0304'for e in s['events']if e['kind']=='write');actual=decode(word['value'],F);expected=z3.Concat(*[z3.BitVec('unknown_'+hex(P+0x1000+j),8)for j in range(8)])^0x9898989898989898^0xe3b88695c0d52dbc;s=z3.Solver();s.set(timeout=30000);s.add(actual!=expected);assert str(s.check())=='unsat';counts['retained_word_expression_checks']+=1;counts['arbitrary_byte_continuations']+=1;counts['arbitrary_byte_continuation_visits']+=len(t['steps']);counts['unknown_byte_origins_retained']+=len(t['origins'])
 assert counts['arbitrary_byte_continuations']==4;counts['distinct_retired_daemon_opcodes_checked']=sum(image=='daemon'for image,pc in pool);counts['distinct_cache_helper_opcodes_in_compositions']=sum(image!='daemon'for image,pc in pool);assert counts['distinct_retired_daemon_opcodes_checked']==1169
 inspected={pc for image,pc in pool if image=='daemon'}
 for r in co['cases']:
  for pc,s in unpack(r)['source_pool'].items():assert IMAGE.read(int(pc,16),4).hex()==s['bytes_hex'];inspected.add(pc)
 counts['distinct_inspected_daemon_opcodes_checked']=len(inspected);counts['additional_unretired_boundary_opcodes_checked']=len(inspected)-counts['distinct_retired_daemon_opcodes_checked'];assert len(inspected)==c['distinct_daemon_source_opcodes']==1170
 dec=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);dec.detail=True;instructions=list(dec.disasm(rawhelper,int(source['stack_probe_original_function']['start'],16)));writes=set()
 for i in instructions:
  rr,ww=i.regs_access();writes.update(i.reg_name(x)for x in ww);assert 'sp'not in[i.reg_name(x)for x in ww];assert not i.writeback
 assert writes<={'x9','x10','x11','nzcv'}and sum(i.mnemonic=='ret'for i in instructions)==1 and sum(i.mnemonic=='stp'for i in instructions)==1;counts['cache_helper_instruction_rows_checked']=len(instructions)
 helpercases=[probe_helper(source,n,walk,pattern)for n in[0,1,16,4095,4096,4097,8192,57072]for walk in[False,True]for pattern in[0,0xffffffffffffffff]];counts['fresh_original_helper_cases']=len(helpercases);counts['fresh_original_helper_visits']=sum(r['source_visits']for r in helpercases);duplicate=[r for r in helpercases if r['walk']and r['allocation_size64']==4096];assert all(len(r['stack_touch_addresses'])==2 and len(set(r['stack_touch_addresses']))==1 for r in duplicate);counts['exact_4096_duplicate_touch_cases']=len(duplicate)
 totals=Counter()
 for r in replays['cases']:assert r['all_checks_pass'];totals.update(r['verified_counts'])
 assert dict(totals)==replays['verified_totals']and len(replays['cases'])==64 and totals['source_visits']==39576 and totals['stack_probe_register_preservation_checks']==64;counts['independent_A64_replay_cases']=64
 assert Replay(p['cases'][0]).run()['all_checks_pass'];assert Replay(co['cases'][-1]['prefix'],unpack(co['cases'][-1]),3).run()['all_checks_pass'];counts['fresh_independent_composed_replays']=2
 for r in c['live_IDB_matches']:counts['live_IDB_raw_ranges']+=1;counts['live_IDB_raw_bytes']+=r['size_bytes'];counts['live_IDB_display_rows']+=r['instruction_rows_checked'];counts['live_IDB_partial_macro_rows']+=r['partial_macro_rows']
 deps=['daemon_descriptor_producers_source.json','daemon_descriptor_producers_profiles.json','daemon_descriptor_producers_copies.json','daemon_descriptor_producers_contracts.json','daemon_descriptor_producers_proofs.json','daemon_descriptor_producers_replays.json','replay_daemon_descriptor_producers.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'verified_counts':dict(counts),'independent_A64_totals':dict(totals),'fresh_helper_cases':helpercases,'boundary_counts':dict(boundaries),'all_checks_pass':True,'reader_B_reached':False,'native_incoming_reader_phases':'unknown','native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_descriptor_producers_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts)}),flush=True)
if __name__=='__main__':main()
