#!/usr/bin/env python3
"""Independent source, record-epoch, compact predicate and replay verification.
O(cases*events+SMT+fresh A64) time, O(largest evidence file+RAM) space.
Native phase reachability and imported implementations remain outside scope.
"""
import json,hashlib,struct
from pathlib import Path
from collections import Counter
import z3
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,qword
from daemon_import_bindings import binding
from recover_daemon_callback_revisit import verify_fixups
from recover_daemon_context_lock import ida_output
from replay_daemon_descriptor_readers import Replay
def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def checked(n,g):
 r=json.loads((ROOT/n).read_text());assert r['generator_sha256']==sha(ROOT/g)and r['full_goal_complete']is False
 for p,h in r.get('dependencies',{}).items():assert sha(ROOT/p)==h,(n,p)
 if 'source_sha256'in r:assert sha(SOURCE)==r['source_sha256']
 return r
def guard(phase,pointer,pattern):
 u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);start=0x100a636ec;end=0x100a63790;G=0x1010c8218;F=0x71002000;pages=set();visits=[]
 def page(a):
  pg=a&~4095
  if pg in pages:return
  u.mem_map(pg,4096);pages.add(pg);b=bytearray(IMAGE.read(pg,4096))if 0x100000000<=pg<0x1010c8000 else bytearray(4096)
  for at,r in FIXUPS.items():
   if pg<=at<pg+4096:b[at-pg:at-pg+8]=struct.pack('<Q',r['target']if isinstance(r['target'],int)else 0x7c100000)
  u.mem_write(pg,bytes(b))
 def missing(u,t,a,n,v,d):page(a);page(a+n-1);return True
 def visit(u,a,n,d):visits.append(a);assert bytes(u.mem_read(a,4))==IMAGE.read(a,4)
 u.hook_add(uc.UC_HOOK_MEM_UNMAPPED,missing);u.hook_add(uc.UC_HOOK_CODE,visit)
 for a in [start,F,G,0x1010c4e18,0x1010c4670]:page(a)
 for j in range(31):u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),((0x9182736455463728*j)^pattern)&((1<<64)-1))
 for j in range(32):u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),((pattern<<64)|pattern)&((1<<128)-1))
 u.reg_write(ar.UC_ARM64_REG_SP,F);u.reg_write(ar.UC_ARM64_REG_X22,0x1010c4e18);u.reg_write(ar.UC_ARM64_REG_X26,0x1010a1960);u.reg_write(ar.UC_ARM64_REG_W24,phase);u.mem_write(F+0x48,struct.pack('<QQ',0x101031fa0,0x100fc4230));u.mem_write(G+16,struct.pack('<Q',pointer));u.mem_write(0x1010c4e18,struct.pack('<I',pattern&0xffffffff));u.mem_write(0x1010c4670,struct.pack('<I',((pattern>>32)^0xcafebabe)&0xffffffff));u.emu_start(start,end,count=42);assert len(visits)==41 and u.reg_read(ar.UC_ARM64_REG_PC)==end and u.reg_read(ar.UC_ARM64_REG_X21)==G
 flag=((phase&1)+int(pointer==0))%2;expected=((phase-0x4c6f)&0xffffffff)^(((phase-0x8a85)&0xffffffff)if flag else 0);assert u.reg_read(ar.UC_ARM64_REG_W9)==expected
 return {'phase32':hex(phase),'pointer64':hex(pointer),'physical_pattern64':hex(pattern),'index32':hex(expected),'source_visits':len(visits),'all_checks_pass':True}
def main():
 p=checked('daemon_descriptor_readers_profiles.json','probe_daemon_descriptor_readers.py');g=checked('daemon_descriptor_guard_profiles.json','probe_daemon_descriptor_guard.py');c=checked('daemon_descriptor_readers_contracts.json','recover_daemon_descriptor_readers.py');proofs=checked('daemon_descriptor_readers_proofs.json','prove_daemon_descriptor_readers.py');replays=checked('daemon_descriptor_readers_replays.json','replay_daemon_descriptor_readers.py');counts=Counter();summary=[];G=0x1010c8218;entry=struct.pack('<QQQQIIII',0,0,0,0xe3b88695c0d52dbc,0x9008b011,0x95bddb,0x95bddb,0x95bddb)
 for r in c['spans']:
  b=bytes.fromhex(r['bytes_hex']);assert IMAGE.read(int(r['start'],16),len(b))==b and hashlib.sha256(b).hexdigest()==r['sha256'];counts['original_spans_checked']+=1
 for r in c['banks_exhaustive256']:
  left,right,key=[int(r[k],16)for k in ['left','right','key']];lb=IMAGE.read(left,256);rb=IMAGE.read(right,256);out=[i^rb[lb[i]^key]for i in range(256)];assert set(out)=={int(r['constant'],16)};slot=int(r['slot'],16);v=qword(slot);assert (v+int(r['bias'],16))&((1<<64)-1)==int(r['target'],16);counts['bank_cases_checked']+=256;counts['banks_checked']+=1
 assert verify_fixups([int(r['address'],16)for r in c['original_fixups']['records']])==c['original_fixups'];counts['original_fixups_checked']=len(c['original_fixups']['records'])
 for row in proofs['proofs']:
  for fk,hk in [('original_file','original_sha256'),('file','sha256')]:
   path=ROOT/row[fk];assert sha(path)==row[hk];s=z3.Solver();s.set(timeout=30000);s.from_file(str(path));assert str(s.check())=='unsat',row['name'];counts['SMT_queries_unsat']+=1
 counts['source_proof_pairs_unsat']=len(proofs['proofs']);counts['nonempty_premise_witnesses']=len(proofs['nonempty_premise_witnesses']);counts['source_lift_visits']=sum(proofs['source_lift_counts'].values());assert counts['source_proof_pairs_unsat']==18 and counts['nonempty_premise_witnesses']==3
 pool={};APIs=Counter();boundaries=Counter();CS.detail=True
 for r in p['cases']:
  cfg=r['configuration'];R=int(r['record_address'],16);assert R&7==0 and R==int(r['caller_FP'],16)-256;calls=r['reader_calls'];assert len(calls)==(2 if cfg['count']==0 else 1)and len(r['reader_returns'])==len(calls);b=bytes.fromhex(calls[0]['record']['bytes_hex']);assert int.from_bytes(b[8:16],'little')==cfg['pointer'];key=(((R&0xffffffff)^0x987eac8a)*0x316f29c1)&0xffffffff;assert(int.from_bytes(b[:4],'little')^key)==0x593d;assert bytes.fromhex(calls[0]['record']['known_mask_hex'])[4:8]==bytes(4)
  if cfg['count']==0:
   b=bytes.fromhex(calls[1]['record']['bytes_hex']);key=(((R&0xffffffff)^0xeaae0ac9)*0x7398180b)&0xffffffff;assert int.from_bytes(b[:8],'little')==cfg['pointer']and(int.from_bytes(b[8:12],'little')+key)&0xffffffff==0xa293;assert r['boundary']['pc']=='0x100246b84'
  else:assert r['boundary']['pc']=='0x10025f0e8'and int(r['boundary']['registers31'][12],16)==0x6400003000 and int(r['boundary']['registers31'][13],16)==0
  desc=struct.pack('<QIIQ',cfg['pointer'],cfg['count'],0,0x6400003000);assert bytes.fromhex(r['descriptor_after']['bytes_hex'])==desc and len(bytes.fromhex(r['descriptor_after']['known_mask_hex']))==24 and bytes.fromhex(r['array_after']['bytes_hex'])==entry*20
  acq=next(e for e in r['source_reads']if e['pc']=='0x10021ed7c');cnt=next(e for e in r['source_reads']if e['pc']=='0x10021ee20');assert acq['address']==hex(G)and cnt['address']==hex(G+8)and acq['source_visit_index']<calls[0]['source_visit_index']<r['reader_returns'][0]['source_visit_index']<=cnt['source_visit_index'];assert not any(G<=int(e['address'],16)<G+24 or 0x6400003000<=int(e['address'],16)<0x6400003000+960 for e in r['source_writes']);assert not any(0x6400003000<=int(e['address'],16)<0x6400003000+960 for e in r['source_reads'])
  if cfg['count']==0:clean=next(e for e in r['source_reads']if e['pc']=='0x10025c4e8');assert cnt['source_visit_index']<clean['source_visit_index']<calls[1]['source_visit_index']
  for m in r['sync_models']:
   APIs[m['name']]+=1;assert not m['native_target_executed']and not m['modeled_writes'];expected=cfg['pointer']or r['input']['sync']['fallback']
   if m['name']in ['write_lock','unlock']:assert int(m['registers8'][0],16)==expected!=0 and int(m['returned_u32'],16)==cfg['primitive_status']
   else:assert m['registers8'][:2]==['0x1010b8cd0','0x10040ebd4']
  for i,e in enumerate(r['source_visits']):assert e['source_visit_index']==i and IMAGE.read(int(e['pc'],16),4).hex()==e['bytes_hex'];pool[e['pc']]=e['bytes_hex']
  assert len(r['staged_source_transitions'])==2 and all(e['fixture_transition_not_original_branch']for e in r['staged_source_transitions']);counts['source_visits_checked']+=len(r['source_visits']);counts['record_epochs_checked']+=len(calls);counts['fixture_transitions_checked']+=2;boundaries[r['boundary']['kind']]+=1;summary.append({'configuration':cfg,'acquire_pointer':hex(cfg['pointer']),'calls':[m['name']for m in r['sync_models']],'boundary':r['boundary']['pc']})
 for pc,b in pool.items():
  ins=next(CS.disasm(bytes.fromhex(b),int(pc,16)));rd,wr=ins.regs_access();names=[ins.reg_name(x)for x in list(rd)+list(wr)];assert not any(n.startswith(('q','v','d','s','h','b'))and n[1:].isdigit()for n in names);assert not any(n in ['x18','w18']for n in names);counts['integer_only_X18_free_opcodes_checked']+=1
 assert len(p['cases'])==96 and len(g['cases'])==4608;counts['conditional_reader_cases_checked']=96
 for row in g['cases']:
  phase=int(row['phase32'],16);ptr=int(row['buffer_pointer64'],16);parity=phase&1;z=int(ptr==0);flag=(parity+z)%2;expected=((phase-0x4c6f)&0xffffffff)^(((phase-0x8a85)&0xffffffff)if flag else 0);assert int(row['index32'],16)==expected and row['all_checks_pass']
 counts['isolated_guard_cases_checked']=4608;counts['isolated_guard_source_visits']=4608*41;assert len({r['phase32']for r in g['cases']})==768
 fresh=[]
 for phase in [0,1,0x4c6f,0x8a85,0x80004c6f,0x80008a85,0xfffffffe,0xffffffff]:
  for ptr in [0,1]:fresh.append(guard(phase,ptr,0 if phase&1 else 0xffffffffffffffff))
 counts['fresh_independent_guard_cases']=len(fresh);counts['fresh_independent_guard_visits']=sum(r['source_visits']for r in fresh)
 live=ida_output(json.loads((ROOT/'daemon_descriptor_readers_live_ida.json').read_text()))
 for r in live['results']:
  b=bytes.fromhex(r['bytes']);assert IMAGE.read(int(r['address'],16),len(b))==b;counts['live_IDB_raw_bytes']+=len(b);counts['live_IDB_raw_ranges']+=1
  for i in r['instructions']:
   b=bytes.fromhex(i['bytes']);assert IMAGE.read(int(i['address'],16),len(b))==b and len(b)<=i['size'];counts['live_IDB_display_rows']+=1;counts['live_IDB_partial_macro_rows']+=len(b)<i['size']
 assert len(c['live_IDB_incoming_data_xrefs'])==2;counts['live_IDB_incoming_data_xrefs']=2;counts['model_API_calls_checked']=sum(APIs.values());counts['source_pool_opcodes_checked']=len(pool)
 assert replays['all_checks_pass']and len(replays['cases'])==96;totals=Counter()
 for r in replays['cases']:assert r['all_checks_pass'];totals.update(r['verified_counts'])
 assert dict(totals)==replays['verified_totals']and totals['source_visits']==49528 and totals['modeled_API_calls_checked']==200;counts['independent_A64_reader_cases']=96
 for j in [0,len(p['cases'])-1]:assert Replay(p['cases'][j]).run()['all_checks_pass'];counts['fresh_independent_reader_cases']+=1
 deps=['daemon_descriptor_readers_profiles.json','daemon_descriptor_guard_profiles.json','daemon_descriptor_readers_contracts.json','daemon_descriptor_readers_proofs.json','daemon_descriptor_readers_replays.json','daemon_descriptor_readers_live_ida.json','replay_daemon_descriptor_readers.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'verified_counts':dict(counts),'independent_A64_totals':dict(totals),'primitive_names_and_counts':dict(APIs),'boundary_counts':dict(boundaries),'case_summaries':summary,'fresh_guard_cases':fresh,'all_checks_pass':True,'live_IDB_automatic_analysis_complete':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_descriptor_readers_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts)}),flush=True)
if __name__=='__main__':main()
