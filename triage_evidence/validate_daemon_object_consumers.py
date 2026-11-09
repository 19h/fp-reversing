#!/usr/bin/env python3
"""Independently verify cleanup journals,raw prefixes,owners,byte pattern,
original imports,SMT files and fresh A64 executions. O(artifacts+events+SMT+fresh
visits) time; O(largest trace+RAM) space. Native targets and IDBs are unchanged.
"""
import json,hashlib,struct
from pathlib import Path
from collections import Counter
import z3,unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,qword
from replay_daemon_descriptor_producers import unpack
from replay_daemon_object_consumers import ConsumersReplay
from recover_daemon_descriptor_producers import verify_used_fixups
from recover_daemon_context_lock import ida_output
from prove_daemon_object_consumers import obligations

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def checked(n,g):
 r=json.loads((ROOT/n).read_text());assert r['generator_sha256']==sha(ROOT/g)and not r['full_goal_complete']
 for dep,h in r.get('dependencies',{}).items():assert sha(ROOT/dep)==h,(n,dep)
 if'source_sha256'in r:assert r['source_sha256']==sha(SOURCE)
 return r
def body_cases():
 start=0x100a1bf1c;end=0x100a1bf84;raw=IMAGE.read(start,end-start);F=0x6d00010000;B=0x6d00001000;constant={20:0x8aefa97d,21:0xd17a2e6e,22:0x887bad6d,23:0xb72b493a,24:0x5b958712,25:0x48948111,26:0x6e561c40,27:0xd4};rows=[]
 for n in[1,872]:
  for byte in range(256):
   seed=(0xfedcba9876543200^(n<<32))|byte;u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);u.mem_map(start&~4095,4096);u.mem_write(start,raw);u.mem_map(B,4096);u.mem_write(B,bytes([0xa5])*4096);u.mem_map((F+0x2ba0)&~4095,4096)
   for j in range(31):u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),0xa5a5a5a5a5a5a5a5)
   for j,v in {1:n,4:0x471c,6:B,11:seed,**constant}.items():u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),v)
   u.reg_write(ar.UC_ARM64_REG_SP,F);writes=[];reads=[];visits=[]
   def code(u,a,size,d):assert start<=a<end and bytes(u.mem_read(a,4))==IMAGE.read(a,4);visits.append(a)
   u.hook_add(uc.UC_HOOK_CODE,code);u.hook_add(uc.UC_HOOK_MEM_WRITE,lambda u,t,a,z,v,d:writes.append((a,z)));u.hook_add(uc.UC_HOOK_MEM_READ,lambda u,t,a,z,v,d:reads.append((a,z)));u.emu_start(start,end,count=100);expected=((((byte+0x6e)&255)^0xba)*((byte+0x7f)&255))&255
   assert u.reg_read(ar.UC_ARM64_REG_PC)==end and len(visits)==26 and reads==[]and writes==[(F+0x2ba0,8),(B+n-1,1)];assert bytes(u.mem_read(B+n-1,1))==bytes([expected])and int.from_bytes(u.mem_read(F+0x2ba0,8),'little')==n-1 and u.reg_read(ar.UC_ARM64_REG_X11)==(seed+1)&((1<<64)-1);rows.append({'remaining64':n,'counter_low8':byte,'source_visits':len(visits),'expected_byte':expected,'all_checks_pass':True})
 return rows

def main():
 raw=checked('daemon_object_consumers_profiles.json','probe_daemon_object_consumers.py');p=checked('daemon_object_consumers_continuations.json','continue_daemon_object_consumers.py');sup=checked('daemon_object_consumers_counters.json','probe_daemon_object_consumers_counters.py');c=checked('daemon_object_consumers_contracts.json','recover_daemon_object_consumers.py');proofs=checked('daemon_object_consumers_proofs.json','prove_daemon_object_consumers.py');r1=checked('daemon_object_consumers_replays.json','replay_daemon_object_consumers.py');r2=checked('daemon_object_consumers_counter_replays.json','replay_daemon_object_consumers_counters.py');counts=Counter();apis=Counter();freePCs=Counter();result_counts=Counter();totals=Counter();seedbytes=set();rewrites=Counter();P=0x6800000000;KEY=P+0x10000;PAY=P+0x18000;OBJ=P+0x20000;SECOND=P+0x24000
 assert sha(SOURCE)==c['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for s in c['spans']:
  b=bytes.fromhex(s['bytes_hex']);assert IMAGE.read(int(s['start'],16),len(b))==b and hashlib.sha256(b).hexdigest()==s['sha256'];assert[(hex(i.address),i.mnemonic,i.op_str)for i in CS.disasm(b,int(s['start'],16))]==[(i['pc'],i['mnemonic'],i['operands'])for i in s['instructions']];counts['original_source_spans_checked']+=1
 assert verify_used_fixups({int(x['address'],16)for x in c['original_fixups']['records']})==c['original_fixups'];counts['original_fixups_checked']=len(c['original_fixups']['records'])
 for b in c['banks_exhaustive256']:
  l=IMAGE.read(int(b['left'],16),256);r=IMAGE.read(int(b['right'],16),256);assert all(j^r[l[j]^int(b['key'],16)]==int(b['constant'],16)for j in range(256));assert qword(int(b['slot'],16))==b['target'];counts['exhaustive_bank_inputs_checked']+=256
 for d in c['dispatch_slots']:assert hex(qword(int(d['slot'],16)))==d['target'];counts['dispatch_slots_checked']+=1
 for x in proofs['proofs']:
  for fk,hk in[('original_file','original_sha256'),('file','sha256')]:
   f=ROOT/x[fk];assert sha(f)==x[hk];solver=z3.Solver();solver.set(timeout=30000);solver.from_file(str(f));assert str(solver.check())=='unsat',x['name'];counts['SMT_file_queries_unsat']+=1
 rebuilt,lifts=obligations(c);assert lifts==proofs['source_lift_counts']and[n for n,pred in rebuilt]==[x['name']for x in proofs['proofs']]
 for n,pred in rebuilt:
  solver=z3.Solver();solver.set(timeout=30000);solver.add(pred);assert str(solver.check())=='unsat';counts['rebuilt_source_obligations_unsat']+=1
 counts['source_lift_visits']=sum(lifts.values());assert len(proofs['nonempty_premise_witnesses'])==4
 for j,r in enumerate(raw['cases']):
  t=unpack(r);full=unpack(p['cases'][j]);assert r['configuration']==p['cases'][j]['configuration']and r['prefix']==p['cases'][j]['prefix'];assert t['steps']==full['steps'][:len(t['steps'])];assert t['boundary']['pc']==full['steps'][len(t['steps'])]['pc']if len(t['steps'])<len(full['steps'])else t['boundary']['pc']==full['boundary']['pc'];counts['raw_stage_prefixes_matched']+=1
 for dataset in[p,sup]:
  for r in dataset['cases']:
   cfg=r['configuration'];t=unpack(r);F=int(t['initial_SP'],16);chain=cfg['chain'];matched=chain!='exhausted';selected=OBJ if chain=='head'else SECOND;nodes=[OBJ]if chain=='head'else[OBJ,SECOND];regs={};S=None;bytewrites=[];headwrites=[];midwrites=[];clear=[];counter=[];owners={P+0x1000:8,**{a:4096 for a in nodes}}
   if cfg['fields']in['310','both']:owners[P+0x30000]=8
   if cfg['fields']in['d8','both']:owners[P+0x34000]=8
   assert t['boundary']['pc']=='0x10039c998'and t['boundary']['kind']=='before_unresolved_source_effect'and int(t['boundary']['SP'],16)==int(r['prefix']['entry_SP'],16)and not t['callback_pending']and t['definitions']==[]
   for st in t['steps']:
    pc=int(st['pc'],16);assert IMAGE.read(pc,4).hex()==st['bytes_hex'];counts['source_opcodes_checked']+=1
    if st['pc']=='0x100a1bf1c'and S is None:S=int.from_bytes(bytes.fromhex(regs['x11']['hex']),'little');assert S==((F+0x2ba0)+0x2f40b33d2e85d192)&((1<<64)-1)
    for e in st['events']:
     a=int(e['address'],16);n=e['size_bytes']
     if e['kind']=='write'and st['pc']=='0x100a1bf7c':bytewrites.append(e)
     if e['kind']=='write'and st['pc']=='0x100a264e0':headwrites.append(e)
     if e['kind']=='write'and st['pc']=='0x100926c0c':midwrites.append(e)
     if e['kind']=='write'and st['pc']in['0x100b11d50','0x100b11d70','0x100b11d7c']:clear.append(e)
     if e['kind']=='write'and a==0x1010c5754:counter.append(e)
     for base in nodes:
      if base<=a<base+0x4000:assert base<=a<a+n<=base+4096;counts['object_owner_effects_checked']+=1
     if KEY<=a<KEY+0x1000:assert a+n<=KEY+16*len(cfg['records']);counts['key_owner_effects_checked']+=1
     if PAY<=a<PAY+0x1000:assert a+n<=PAY+32*len(cfg['payload_keys']);counts['payload_owner_effects_checked']+=1
    regs.update(st['registers_after'])
   assert len(bytewrites)==872*int(matched)
   if matched:
    seedbytes.add(S&255)
    for i,e in enumerate(bytewrites):assert(e['address'],e['size_bytes'],e['value'])==(hex(selected+871-i),1,{'hex':bytes([((((S+i+0x6e)&255)^0xba)*((S+i+0x7f)&255))&255]).hex()});counts['overwrite_bytes_verified']+=1
    assert len(clear)==3 and {(e['address'],e['size_bytes'])for e in clear}=={(hex(KEY+32),8),(hex(KEY+40),4),(hex(KEY+44),4)};assert counter==[{'kind':'write','address':'0x1010c5754','size_bytes':4,'value':{'hex':((cfg.get('active_keys',0)-1)&0xffffffff).to_bytes(4,'little').hex()}}];counts['key_clear_and_counter_paths_checked']+=1
   else:assert clear==[]and counter==[]
   assert len(headwrites)==int(chain=='head')and len(midwrites)==int(chain=='interior')
   if headwrites:assert headwrites[0]['address']==hex(PAY+16)and headwrites[0]['value']=={'hex':'0000000000000000'};rewrites['head']+=1
   if midwrites:assert midwrites[0]['address']==hex(OBJ+0x360)and midwrites[0]['value']=={'hex':'0000000000000000'};rewrites['interior']+=1
   expectedfree=[]
   if matched:
    if cfg['fields']in['310','both']:expectedfree.append(('0x100bdf330',P+0x30000))
    if cfg['fields']in['d8','both']:expectedfree.append(('0x100be0e80',P+0x34000))
    expectedfree.append(('0x100bd9d88',selected))
   expectedfree.append(('0x10039c988',P+0x1000));free=[m for m in t['api_models']if m['name']=='free'];assert[(m['pc'],int.from_bytes(bytes.fromhex(m['arguments8'][0]['hex']),'little'))for m in free]==expectedfree
   for m,(pc,ptr)in zip(free,expectedfree):assert m['binding']==c['original_bindings']['free']and m['memory_effects']==[]and m['owner_effects']==[{'kind':'retire','address':hex(ptr),'size_bytes':owners[ptr]}];freePCs[pc]+=1
   assert t['retired_owners']==[{'address':hex(ptr),'size_bytes':owners[ptr]}for pc,ptr in expectedfree];names=[m['name']for m in t['api_models']];assert names.count('pthread_once')==2 and names.count('pthread_rwlock_wrlock')==names.count('pthread_rwlock_unlock')==1;apis.update(names);result=[e['value']for st in t['steps']if st['pc']=='0x10095f074'for e in st['events']];expected='51c63d8b'if matched else'009fc274';assert result==[{'hex':expected}];result_counts[expected]+=1;counts['completed_cleanup_cases_checked']+=1;counts['continuation_source_visits']+=len(t['steps']);counts['private_byte_origins_retained']+=len(t['origins']);counts['API_byte_origins_retained']+=len(t['API_origins'])
 assert seedbytes=={0x92,0xa2};assert dict(rewrites)=={'head':13,'interior':10};assert len(p['cases'])==24 and len(sup['cases'])==3
 for r in[r1,r2]:
  subtotal=Counter();assert r['all_checks_pass']
  for row in r['cases']:assert row['all_checks_pass'];subtotal.update(row['verified_counts']);counts['independent_A64_replays']+=1
  assert dict(subtotal)==r['verified_totals'];totals.update(subtotal)
 for row in[p['cases'][6],sup['cases'][1]]:assert ConsumersReplay(row,3).run()['all_checks_pass'];counts['fresh_composed_replays']+=1
 micro=body_cases();counts['exhaustive_byte_A64_cases']=len(micro);counts['exhaustive_byte_A64_source_visits']=sum(x['source_visits']for x in micro)
 for name in['daemon_object_consumers_live_ida.json','daemon_object_consumers_more_ida.json','daemon_object_consumers_alloc_ida.json']:
  d=json.loads((ROOT/name).read_text());assert not d['isError']
  for row in ida_output(d)['results']:
   b=bytes.fromhex(row['bytes']);assert IMAGE.read(int(row['address'],16),len(b))==b;counts['live_IDB_ranges_checked']+=1;counts['live_IDB_raw_bytes_checked']+=len(b)
   for i in row['instructions']:rawbytes=bytes.fromhex(i['bytes']);assert IMAGE.read(int(i['address'],16),len(rawbytes))==rawbytes;counts['live_IDB_display_rows_checked']+=1;counts['live_IDB_partial_macro_rows']+=len(rawbytes)<i.get('size',len(rawbytes));counts['live_IDB_undecoded_byte_rows']+='size'not in i
 census=c['literal_allocation_census'];rawtext=IMAGE.read(int(census['text_address'],16),census['text_size_bytes']);assert hashlib.sha256(rawtext).hexdigest()==census['text_sha256'];assert[hex(int(census['text_address'],16)+4*j)for j,(w,)in enumerate(struct.iter_unpack('<I',rawtext))if w in[0x52800000|(872<<5),0xd2800000|(872<<5)]]==census['matches']==['0x100c116a8'];counts['literal_allocation_candidates_checked']=1
 deps=['daemon_object_consumers_profiles.json','daemon_object_consumers_continuations.json','daemon_object_consumers_counters.json','daemon_object_consumers_contracts.json','daemon_object_consumers_proofs.json','daemon_object_consumers_replays.json','daemon_object_consumers_counter_replays.json','replay_daemon_object_consumers.py','prove_daemon_object_consumers.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'verified_counts':dict(counts),'API_counts':dict(apis),'free_call_PC_counts':dict(freePCs),'raw_result_counts':dict(result_counts),'rewrite_counts':dict(rewrites),'overwrite_seed_low8_values':sorted(seedbytes),'independent_A64_totals':dict(totals),'isolated_original_body_cases':micro,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False,'all_checks_pass':True};(ROOT/'daemon_object_consumers_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'API_counts':dict(apis),'results':dict(result_counts)}),flush=True)
if __name__=='__main__':main()
