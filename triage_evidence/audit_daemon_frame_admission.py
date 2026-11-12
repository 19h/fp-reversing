#!/usr/bin/env python3
"""Original-A64 admission controls with two physical backing patterns.

O(parent visits+patterns*control effects) time/space;30 s/query.
No native API, IPC, hardware PAC or extension through the unspecified load.
"""
import json
from pathlib import Path
from collections import Counter
import z3
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,IMAGE
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_daemon_frame_admission as R

def replay(case,pattern):
 u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);pages=set();counts=Counter();trace=case['trace'];cursor=0;events=[];pending=None
 def put(a,data):
  for page in range(a&~4095,(a+len(data)+4095)&~4095,4096):
   if page not in pages:u.mem_map(page,4096);u.mem_write(page,bytes([pattern])*4096);pages.add(page)
  u.mem_write(a,data)
 for _,a,b in R.SPECS:put(a,IMAGE.read(a,b-a))
 f=int(case['initial_registers']['sp'],16);put(f,bytes([pattern])*4096)
 for c in case['initial_cells']:put(int(c['address'],16),int(c['value'],16).to_bytes(c['size_B'],'little'))
 expected={k:int(x,16)for k,x in case['initial_registers'].items()};flags=int(case['initial_NZCV'],16)
 for k,x in expected.items():u.reg_write(getattr(ar,'UC_ARM64_REG_'+k.upper()),x)
 u.reg_write(ar.UC_ARM64_REG_NZCV,flags)
 def finish():
  nonlocal pending,flags
  if pending is None:return
  assert events==pending['events'],('effects',pending['pc'],events,pending['events'])
  expected.update({k:int(x,16)for k,x in pending['registers_after'].items()});flags=int(pending.get('NZCV_after',hex(flags)),16)
  for k,x in expected.items():assert u.reg_read(getattr(ar,'UC_ARM64_REG_'+k.upper()))==x,('register',pending['pc'],k)
  assert u.reg_read(ar.UC_ARM64_REG_NZCV)==flags,('NZCV',pending['pc'])
  counts['register_values_checked']+=len(expected);counts['NZCV_values_checked']+=1;pending=None
 def code(engine,a,n,d):
  nonlocal cursor,pending,events
  finish();assert cursor<len(trace)and a==int(trace[cursor]['pc'],16)
  pending=trace[cursor];events=[];cursor+=1;assert n==4 and bytes(engine.mem_read(a,4))==IMAGE.read(a,4)==bytes.fromhex(pending['bytes_hex']);counts['source_visits']+=1
  if pending['mnemonic']=='braa':
   i=next(R.DEC.disasm(IMAGE.read(a,4),a));target=engine.reg_read(getattr(ar,'UC_ARM64_REG_'+i.reg_name(i.operands[0].reg).upper()));modifier=engine.reg_read(ar.UC_ARM64_REG_X17)
   assert target==int(pending['target'],16)and modifier==int(pending['modifier16'],16);counts['logical_PAC_transfers']+=1;engine.reg_write(ar.UC_ARM64_REG_PC,target)
 def memory(engine,kind,a,n,value,d):
  assert pending is not None
  write=kind==uc.UC_MEM_WRITE;x=value&((1<<(8*n))-1)if write else int.from_bytes(engine.mem_read(a,n),'little')
  assert not(a<f+0x564 and f+0x560<a+n),'unspecified word must remain unconsumed'
  events.append({'kind':'write'if write else'read','address':hex(a),'size_B':n,'value':hex(x)});counts['write_B_checked'if write else'read_B_checked']+=n
 u.hook_add(uc.UC_HOOK_CODE,code);u.hook_add(uc.UC_HOOK_MEM_READ|uc.UC_HOOK_MEM_WRITE,memory)
 u.emu_start(int(trace[0]['pc'],16),int(case['boundary'],16),count=len(trace)+1);finish();assert cursor==len(trace)and u.reg_read(ar.UC_ARM64_REG_PC)==int(case['boundary'],16)
 count=int(case['count_u32'],16);decoded=int(case['decoded_word_u32'],16)
 assert case['reader_selected']==(count<decoded)
 assert int.from_bytes(u.mem_read(f+0x55c,4),'little')==count and int.from_bytes(u.mem_read(f+0x3c4,4),'little')==case['limit_u32']
 if case['kind']=='setup':
  cls=int(case['class_u32'],16);assert case['limit_u32']==(12 if cls>1 else 0)
  assert bytes(u.mem_read(f+0x4ff,1))==bytes([int(cls>1)])and int.from_bytes(u.mem_read(f+0x558,4),'little')==int(case['raw_word_u32'],16)
  if not decoded:assert int.from_bytes(u.mem_read(f+0x4ec,4),'little')==case['limit_u32']
 return {'kind':case['kind'],'epoch':case['epoch'],'class_u32':case['class_u32'],'count_u32':case['count_u32'],'decoded_word_u32':case['decoded_word_u32'],
  'backing_byte':pattern,'reader_selected':case['reader_selected'],'boundary':case['boundary'],'verified_counts':dict(counts),'all_checks_pass':True,'native_target_executed':False}

def lineage_checks(e,parent):
 out=[]
 for row in e['actual_lineages']:
  case=next(c for c in parent['cases']if c['configuration']['epoch']==row['epoch']and c['configuration']['name']==row['variant']);a=int(case['configuration']['allocation'],16);f=int(row['frame_SP'],16)
  events=[{'pc':r['pc'],**v}for r in case['trace']['steps']for v in r['events']]
  old=next(v for v in events if v['pc']=='0x100461a50'and v['kind']=='read');frame=next(v for v in events if v['pc']=='0x100461c10'and v['kind']=='write')
  copied=next(v for v in events if v['pc']=='0x1004c5794'and v['kind']=='read');committed=next(v for v in events if v['pc']=='0x1004c5798'and v['kind']=='write');consumed=next(v for v in events if v['pc']=='0x1004c75e0'and v['kind']=='read')
  assert old['address']==consumed['address']==committed['address']==hex(a+16)and old['value']=={'hex':'51c63d8b'}
  assert frame['address']==copied['address']==hex(f+0x3ac)and frame['value']==copied['value']==committed['value']==consumed['value']=={'hex':'4dc63d8b'}
  raw=int.from_bytes(bytes.fromhex(consumed['value']['hex']),'little');assert raw^R.C==28 and row['count_u32']==0 and row['selected_limit_u32']==12 and row['class_u32']==(2 if row['variant']=='prefix'else 5)
  assert not any(v['kind']=='write'and int(v['address'],16)<f+0x4f0 and f+0x4ec<int(v['address'],16)+v['size_bytes']for v in events)
  assert row['partial_boundary']['pc']=='0x10063736c'
  out.append({'epoch':row['epoch'],'variant':row['variant'],'object_word_read_from_committed_source_value':True,'decoded_u32':28,'count_u32':0,'class_u32':row['class_u32'],'limit_u32':12,'comparison':True,'partial_fixture_resumed':False,'all_checks_pass':True})
 return out

def main():
 parent=R.inputs();e=json.loads(read(ROOT/(R.P+'_checks.json')))
 assert e['generator_sha256']==sha(ROOT/('recover_'+R.P+'.py'))and e['parent_pins']==R.PINS and e['dependencies']=={n:sha(ROOT/n)for n in R.DEPS}
 assert e['source_regions']==R.source()and e['source_fixups']==R.Parent.Parent.R.verify_fixups(set(R.SLOTS))and e['actual_lineages']==R.actual(parent)
 fresh=R.obligations();assert [r['label']for r in fresh]==[r['label']for r in e['source_proofs']]
 for row in e['source_proofs']:
  s=z3.Solver();s.set(timeout=30000);s.from_string(row['query']);assert str(s.check())==row['result']=='unsat'
 assert e['control_cases']==R.controls();runs=[];totals=Counter()
 for c in e['control_cases']:
  for pattern in [0,0xa5]:r=replay(c,pattern);runs.append(r);totals.update(r['verified_counts'])
 out={'scope':__doc__,'generator_sha256':e['generator_sha256'],'auditor_sha256':sha(Path(__file__)),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
  'source_sha256':e['source_sha256'],'parent_pins':R.PINS,'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],'source_proofs_unsat':len(fresh),
  'actual_lineage_checks':lineage_checks(e,parent),'independent_controls':runs,'independent_totals':dict(totals),'all_checks_pass':True,
  'parent_A64_replays_repeated':False,'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'live_IDA_claim':False,'actual_partial_fixture_resumed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False}
 (ROOT/(R.P+'_audit.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':e['verified_counts'],'independent_totals':dict(totals),'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
