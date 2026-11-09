#!/usr/bin/env python3
"""Restore clock cutpoints from sealed ordered writes and pointer def-use.
O(parent source visits+effects+distinct opcodes) time, O(largest parent journal)
space. No emulator, host API or native PAC executes; flags/vector state absent.
"""
import json,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64_const import ARM64_OP_MEM,ARM64_OP_REG
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from recover_daemon_object_creation import sha
from replay_daemon_descriptor_producers import unpack

def canonical(n):return 'x'+n[1:]if n.startswith('w')and n[1:].isdigit()else {'fp':'x29','lr':'x30','wsp':'sp'}.get(n,n)
def memory_width(i):
 m=i.mnemonic;n=i.reg_name(i.operands[0].reg)
 return (1 if m.endswith('b')else 2 if m.endswith('h')else 4 if m.endswith('sw')or n.startswith('w')else 16 if n.startswith('q')else 8)*(2 if m.startswith(('ldp','stp','ldnp','stnp'))else 1)
def groups(data,writers):
 out=[];addresses=sorted(data);start=last=None
 for a in addresses:
  if last is None or a!=last+1:
   if last is not None:out.append({'address':hex(start),'bytes_hex':bytes(data[x]for x in range(start,last+1)).hex(),'last_source_writers':sorted({writers[x]for x in range(start,last+1)})})
   start=a
  last=a
 if last is not None:out.append({'address':hex(start),'bytes_hex':bytes(data[x]for x in range(start,last+1)).hex(),'last_source_writers':sorted({writers[x]for x in range(start,last+1)})})
 return out
def restore(t):
 cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;pool={}
 for pc,row in t['source_pool'].items():
  a=int(pc,16);raw=bytes.fromhex(row['bytes_hex']);assert IMAGE.read(a,4)==raw;pool[a]=next(cs.disasm(raw,a))
 events=t['events'];pos=0;regs={};spills={};data={};writers={};api={int(x['pc'],16)for x in t['api_models']};vector_reads=set()
 for pc,raw in t['steps']:
  i=pool[pc];assert bytes(i.bytes).hex()==raw;before=regs.copy();es=[]
  if any(o.type==ARM64_OP_MEM for o in i.operands):
   need=memory_width(i);got=0
   while got<need:
    e=events[pos];pos+=1;assert e['pc']==hex(pc),(hex(pc),e);got+=e['size_bytes'];es.append(e)
   assert got==need
  reads,written=i.regs_access()
  for reg in written:regs.pop(canonical(i.reg_name(reg)),None)
  for reg in reads:
   name=i.reg_name(reg)
   if name.startswith(('q','v','d','s'))and name[1:].isdigit():vector_reads.add(name)
  for e in es:
   if e['kind']=='write':
    a=int(e['address'],16);b=bytes.fromhex(e['after_hex'])
    for at in list(spills):
     if a<at+8 and at<a+len(b):spills.pop(at)
    for j,x in enumerate(b):data[a+j]=x;writers[a+j]=e['pc']
  if i.mnemonic in ['ldr','ldur']and i.reg_name(i.operands[0].reg).startswith('x'):
   rs=[e for e in es if e['kind']=='read'and e['size_bytes']==8]
   if len(rs)==1:
    at=int(rs[0]['address'],16);origin=at if at in FIXUPS else spills.get(at)
    if origin is not None:regs[canonical(i.reg_name(i.operands[0].reg))]=origin
  elif i.mnemonic=='mov'and len(i.operands)==2 and i.operands[1].type==ARM64_OP_REG:
   origin=before.get(canonical(i.reg_name(i.operands[1].reg)))
   if origin is not None:regs[canonical(i.reg_name(i.operands[0].reg))]=origin
  elif i.mnemonic in ['str','stur']and i.reg_name(i.operands[0].reg).startswith('x'):
   origin=before.get(canonical(i.reg_name(i.operands[0].reg)));ws=[e for e in es if e['kind']=='write'and e['size_bytes']==8]
   if origin is not None and len(ws)==1:spills[int(ws[0]['address'],16)]=origin
  if pc in api:
   for j in list(range(18))+[30]:regs.pop('x'+str(j),None)
 assert pos==len(events),(pos,len(events));assert not vector_reads,vector_reads
 assert regs['x9']==0x10109ff20
 return {'source_memory_groups':groups(data,writers),'source_written_bytes':len(data),'register_pointer_origins':{n:hex(a)for n,a in regs.items()},'memory_pointer_origins':{hex(a):hex(v)for a,v in spills.items()},'events_consumed':pos,'source_visits_consumed':len(t['steps']),'parent_vector_register_reads':sorted(vector_reads)}
def main():
 profiles=json.loads((ROOT/'daemon_object_initialization_profiles.json').read_text());out=[]
 for j,row in enumerate(profiles['cases'][:3]):
  t=unpack(row);assert t['boundary']['pc']=='0x100bad4c8';r=restore(t);out.append({'parent_case_index':j,'configuration':row['configuration'],'parent_payload_sha256':row['payload_sha256'],'boundary':t['boundary'],'allocated_owners':t['allocated_owners'],'owner_snapshots':t['owner_snapshots'],**r});print(json.dumps({'parent':j,'source_visits':r['source_visits_consumed'],'written_bytes':r['source_written_bytes'],'groups':len(r['source_memory_groups']),'pointer_spills':len(r['memory_pointer_origins'])}),flush=True)
 deps=['daemon_object_initialization_profiles.json','daemon_object_initialization_checks.json','probe_daemon_object_initialization.py','daemon_entropy_return_sdk.c','daemon_seed_material_contracts.json'];r={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'contexts':out,'unavailable_state':['NZCV before clock call','vector register values','native library side effects'],'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_object_clock_context.json').write_text(json.dumps(r,indent=2)+'\n')
if __name__=='__main__':main()
