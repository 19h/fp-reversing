#!/usr/bin/env python3
"""Fresh A64 replay of continuous source and arbitrary private-byte expressions.
No source executor is reused. O(F+C*(J+V+E+expression evaluation)) time;
O(F+largest trace+mapped RAM) space. Logical PAC only; no native target calls.
"""
import json,hashlib,struct,base64,zlib
from pathlib import Path
from collections import defaultdict,Counter
import z3
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,CS
from daemon_seed_material_symbolic import decode
from daemon_import_bindings import binding
P=0x6800000000;SIZE=0x100000;HELPER=0x180587cd4;TLS=P+0xf0000;GUARD=P+0xe0000
FIXPAGES=defaultdict(list)
for at,r in FIXUPS.items():FIXPAGES[at&~4095].append((at,r))
IMPORTS={name:0x7c000000+256*j for j,name in enumerate(sorted({r['target']for r in FIXUPS.values()if isinstance(r['target'],str)}),1)}
ADDENDS={at:binding(at)['total_addend']for at,r in FIXUPS.items()if r['kind'].endswith('bind')}
def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def unpack(r):
 b=zlib.decompress(base64.b64decode(r['payload_zlib_base64']));assert hashlib.sha256(b).hexdigest()==r['payload_sha256'];return json.loads(b)
class Replay:
 def __init__(self,prefix,continuation=None,pattern=0):
  self.p=prefix;self.t=continuation;self.pattern=pattern;self.F=int(continuation['initial_SP'],16)if continuation else 0;self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);self.pages=set();self.seq=0;self.counts=Counter();self.pending=[];self.current=None;self.rc=self.wc=0;self.helper=json.loads((ROOT/'daemon_descriptor_producers_source.json').read_text())['stack_probe_original_function'];self.reads=defaultdict(list);self.writes=defaultdict(list);self.events={};self.evalcache={};self.fixed=[]
  self.ram=bytes([prefix['configuration']['pattern']&255])*SIZE if pattern==0 else bytes([0 if pattern==1 else 255])*SIZE if pattern in [1,2]else bytes((j*73+19)&255 for j in range(SIZE));self.u.mem_map(P,SIZE);self.u.mem_write(P,self.ram)
  for r in prefix['initial_private_fixtures']+prefix['initial_image_fixtures']:
   a=int(r['address'],16);b=bytes.fromhex(r['bytes_hex']);self.ensure(a,len(b));self.u.mem_write(a,b)
  self.seed(prefix['entry_registers31']);self.u.reg_write(ar.UC_ARM64_REG_SP,int(prefix['entry_SP'],16));self.u.reg_write(ar.UC_ARM64_REG_NZCV,int(prefix['entry_NZCV'],16));self.u.reg_write(ar.UC_ARM64_REG_TPIDRRO_EL0,int(prefix['entry_TPIDRRO_EL0'],16))
  for j,v in enumerate(prefix['entry_Q_registers32']):self.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),int(v,16))
  for key,out in [('source_reads',self.reads),('source_writes',self.writes)]:
   for e in prefix[key]:out[e['source_visit_index']].append(e)
  self.steps=prefix['source_visits'].copy();self.edges={e['source_visit_index']:e for e in prefix['logical_edges']};self.boundary=prefix['boundary']
  if continuation:
   off=len(self.steps);self.boundary=continuation['boundary']
   for k,s in enumerate(continuation['steps']):
    row={'pc':s['pc'],'bytes_hex':s['bytes_hex'],'symbolic_register_effects':s.get('registers_after',{}),'symbolic_NZCV_after':s.get('NZCV_after')};self.steps.append(row)
    for e in s['events']:(self.reads if e['kind']=='read'else self.writes)[off+k].append(e)
    if 'target'in s:self.edges[off+k]={'target':s['target'],'modifier':s.get('modifier16')}
  self.u.hook_add(uc.UC_HOOK_MEM_UNMAPPED,self.missing);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write);self.u.hook_add(uc.UC_HOOK_CODE,self.code)
 def reg(self,name):return self.u.reg_read(getattr(ar,'UC_ARM64_REG_'+name.upper()))
 def seed(self,values):
  for j,v in enumerate(values):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),int(v,16))
 def ensure(self,a,n=1):
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):
   if P<=pg<P+SIZE or pg in self.pages:continue
   if pg==HELPER&~4095:
    b=bytearray(4096);raw=bytes.fromhex(self.helper['bytes']);b[HELPER-pg:HELPER-pg+len(raw)]=raw
   else:
    assert 0x100000000<=pg<0x102000000,hex(pg)
    try:b=bytearray(IMAGE.read(pg,4096))
    except ValueError:b=bytearray(4096)
    for at,r in FIXPAGES[pg]:
     t=r['target'];v=HELPER if t=='libSystem/___chkstk_darwin'else GUARD if t=='libSystem/___stack_chk_guard'else IMPORTS[t]if isinstance(t,str)else t;v=(v+ADDENDS.get(at,0))&((1<<64)-1);b[at-pg:at-pg+8]=struct.pack('<Q',v)
   self.u.mem_map(pg,4096);self.pages.add(pg);self.u.mem_write(pg,bytes(b))
 def missing(self,u,t,a,n,v,d):self.ensure(a,n);return True
 def value(self,s):
  if 'hex'in s:return bytes.fromhex(s['hex'])
  key=json.dumps(s,sort_keys=True)
  if key in self.evalcache:return self.evalcache[key]
  if'terms'in s:out=bytes(x if isinstance(x,int)else self.ram[self.F+x['origin']-P]for x in s['terms'])
  else:
   v=decode(s,self.F);replacements=[]
   for name,bits in s['symbols']:
    assert name.startswith('unknown_')and bits==8;addr=int(name[8:],16);assert P<=addr<P+SIZE;replacements.append((z3.BitVec(name,8),z3.BitVecVal(self.ram[addr-P],8)))
   val=z3.simplify(z3.substitute(v,*replacements));assert z3.is_bv_value(val);out=val.as_long().to_bytes(s['bits']//8,'little')
  self.evalcache[key]=out;return out
 def finish(self):
  for e in self.pending:
   a=int(e['address'],16);n=e['size_bytes'];expected=self.value(e['value'])if'value'in e else bytes.fromhex(e['after_hex']);assert bytes(self.u.mem_read(a,n))==expected,(self.seq,e);self.counts['write_effects_checked']+=1;self.counts['write_bytes_checked']+=n
  self.pending=[]
  if self.current is not None:
   assert self.rc==len(self.reads[self.current])and self.wc==len(self.writes[self.current]),self.current;s=self.steps[self.current]
   for name,val in s.get('symbolic_register_effects',{}).items():assert self.reg(name)==int.from_bytes(self.value(val),'little'),(s['pc'],name);self.counts['symbolic_register_effects_checked']+=1
   if s.get('symbolic_NZCV_after')is not None:assert self.reg('NZCV')==s['symbolic_NZCV_after'];self.counts['symbolic_NZCV_effects_checked']+=1
  self.current=None
 def read(self,u,t,a,n,v,d):
  rows=self.reads[self.current];assert self.rc<len(rows),(self.current,hex(a));e=rows[self.rc];self.rc+=1;assert(e['address'],e['size_bytes'])==(hex(a),n);b=bytes(u.mem_read(a,n))
  if'value'in e:assert b==self.value(e['value']),(self.steps[self.current]['pc'],e)
  else:
   expected=bytes.fromhex(e['bytes_hex']);mask=bytes.fromhex(e['known_mask_hex'])if'known_mask_hex'in e else bytes([1])*n;assert all(not k or x==y for x,y,k in zip(b,expected,mask)),(self.current,e);self.counts['uninterpreted_probe_read_bytes']+=sum(k==0 for k in mask)
  self.counts['read_effects_checked']+=1;self.counts['read_bytes_checked']+=n
 def write(self,u,t,a,n,v,d):
  rows=self.writes[self.current];assert self.wc<len(rows);e=rows[self.wc];self.wc+=1;assert(e['address'],e['size_bytes'])==(hex(a),n);self.pending.append(e)
 def code(self,u,a,n,d):
  self.finish()
  if a==HELPER:self.helper_entry=([self.reg('X'+str(j))for j in range(31)],self.reg('SP'))
  if a==0x100a59be8:
   saved,sp=self.helper_entry;assert self.reg('SP')==sp
   for j in range(31):
    if j!=9:assert self.reg('X'+str(j))==saved[j],j
   self.counts['stack_probe_register_preservation_checks']+=1
  if self.seq==len(self.steps):
   b=self.boundary;assert b['pc']==hex(a)and self.reg('SP')==int(b['SP'],16)
   for j,v in enumerate(b['registers31']):expected=int(v,16)if isinstance(v,str)else int.from_bytes(self.value(v),'little');assert self.reg('X'+str(j))==expected,(hex(a),j)
   self.counts['final_boundaries_checked']+=1;return u.emu_stop()
  s=self.steps[self.seq];assert s['pc']==hex(a);raw=bytes(u.mem_read(a,4));assert raw.hex()==s['bytes_hex'];source=bytes.fromhex(self.helper['bytes'])[a-HELPER:a-HELPER+4]if HELPER<=a<HELPER+108 else IMAGE.read(a,4);assert raw==source;ins=next(CS.disasm(raw,a));self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits']+=1;self.counts['cache_helper_visits']+=HELPER<=a<HELPER+108
  if ins.mnemonic in['pacibsp','paciasp','autibsp','autiasp','paciza']:self.counts['logical_PAC_instructions']+=1;return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if ins.mnemonic in['braa','br','blraa','blr','blraaz','retab','retaa']:
   ret=ins.mnemonic in['retab','retaa'];args=[x.strip()for x in ins.op_str.split(',')];target=self.reg('X30')if ret else self.reg(args[0]);e=self.edges[self.current];assert target==int(e['target'],16)
   if not ret and len(args)>1:assert self.reg(args[1])==int(e['modifier'],16)
   if ins.mnemonic.startswith('bl'):u.reg_write(ar.UC_ARM64_REG_X30,a+4)
   self.counts['logical_edges_checked']+=1;self.ensure(target);return u.reg_write(ar.UC_ARM64_REG_PC,target)
  assert ins.mnemonic not in['bl','svc','hvc','smc']
 def run(self):
  start=int(self.p['entry_PC'],16);self.ensure(start);self.u.emu_start(start,0,count=len(self.steps)+10);self.finish();assert self.seq==len(self.steps)and self.counts['final_boundaries_checked']==1;return {'configuration':self.p['configuration'],'continuation':self.t is not None,'physical_pattern':self.pattern,'boundary':self.boundary['pc'],'verified_counts':dict(self.counts),'all_checks_pass':True}
def main():
 p=json.loads((ROOT/'daemon_descriptor_producers_profiles.json').read_text());c=json.loads((ROOT/'daemon_descriptor_producers_copies.json').read_text());rows=[];totals=Counter()
 for r in p['cases']:
  row=Replay(r).run();rows.append(row);totals.update(row['verified_counts'])
 for r in c['cases']:
  t=unpack(r)
  for pattern in range(4):row=Replay(r['prefix'],t,pattern).run();rows.append(row);totals.update(row['verified_counts'])
 deps=['daemon_descriptor_producers_source.json','daemon_descriptor_producers_profiles.json','daemon_descriptor_producers_copies.json','daemon_seed_material_symbolic.py','daemon_receive_tools.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'verified_totals':dict(totals),'all_checks_pass':True,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_descriptor_producers_replays.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'verified_totals':dict(totals)}),flush=True)
if __name__=='__main__':main()
