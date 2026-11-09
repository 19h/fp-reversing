#!/usr/bin/env python3
"""Declared completion-to-cache phases with retained defined-byte state.
O(restored bytes+source visits+effects) time/space per case, plus compressed
outputs retained by the generator. No native framework/allocator/IPC/PAC.
"""
import json,hashlib,base64,zlib
from pathlib import Path
from daemon_receive_tools import ROOT,IMAGE,SOURCE
from replay_daemon_descriptor_producers import unpack
from probe_daemon_identity_cache import Run as Parent,P,SIZE
from daemon_digest_output_access import register_access,key
from recover_daemon_object_creation import sha
class Run(Parent):
 def __init__(self,context,cfg):
  parents=json.loads((ROOT/'daemon_identity_cache_context.json').read_text());parent=next(x for x in parents['contexts']if x['cache_case_index']==context['cache_case_index']);oldcfg=dict(context['parent_identity_configuration']);oldcfg.update({'clobber_pattern':cfg['clobber_pattern'],'NZCV_after':cfg['NZCV_after']});super().__init__(parent,oldcfg)
  self.context=context;self.outcome=cfg;self.message=bytes.fromhex(context['message_hex'])
  for a,h in context['owner_snapshots'].items():self.u.mem_write(int(a,16),bytes.fromhex(h))
  known=set()
  for g in context['known_byte_groups']:
   a=int(g['address'],16);b=bytes.fromhex(g['bytes_hex']);self.ensure(a,len(b));self.u.mem_write(a,b);known.update(range(a,a+len(b)))
  self.defined={a for a in known if P<=a<P+SIZE};self.global_defined={a for a in known if 0x100000000<=a<0x102000000};self.mutable_globals.update(self.global_defined);self.allocated={int(a,16):n for a,n in context['allocated_owners'].items()};self.owners.update(self.allocated)
  for j in range(31):self.set('x'+str(j),0)
  for n,v in context['entry_defined_GPRs'].items():self.set(n,int(v,16))
  self.known={key(n)for n in context['entry_defined_GPRs']};self.reg_sources={};self.memory_sources={};self.steps=[];self.events=[];self.edges=[];self.api=[];self.fix=set();self.source_pool={};self.pending=[];self.reason=None;self.done=False;self.previous_i=None;self.previous_sources={};self.arbitrary_heap_reads=[]
 def api_return(self,a,raw,b,returned,details):
  assert b['symbol']in ['_CFRelease','_free'];returned=self.outcome['void_result64'];r=super().api_return(a,raw,b,returned,details);self.known.update(['x'+str(j)for j in range(18)]+['x30','nzcv']);return r
 def preflight(self,i):
  if not super().preflight(i):return False
  from capstone.arm64_const import ARM64_OP_MEM
  from capture_daemon_object_clock import memory_width
  o=next((x for x in i.operands if x.type==ARM64_OP_MEM),None)
  if o is not None:
   a=self.address(i,o);n=memory_width(i)
   if i.mnemonic.startswith(('ldr','ldur','ldp'))and P<=a<a+n<=P+SIZE and not all(x in self.defined for x in range(a,a+n)):return self.stop('before_undefined_owned_read',{'address':hex(a),'size_bytes':n})or False
  return True
 def code(self,u,a,n,d):
  self.flush();i=next(self.dec.disasm(IMAGE.read(a,4),a));reads,writes=register_access(i);missing=[i.reg_name(r)for r in reads if i.reg_name(r)not in ['wzr','xzr']and key(i.reg_name(r))not in self.known]
  if missing:return self.stop('before_undefined_GPR',{'instruction':i.mnemonic+' '+i.op_str,'registers':missing})
  super().code(u,a,n,d)
  if self.reason is None:self.known.update(key(i.reg_name(r))for r in writes)
 def run(self,limit=300000):
  start=0x100bb1620;self.ensure(start);self.u.emu_start(start,0,count=limit);self.flush()
  if self.reason is None:self.stop('source_visit_limit')
  assert not self.arbitrary_heap_reads
  cache=int(self.context['cache_owner_address'],16);D=self.F+0x3c30
  return {'identity_case_index':self.context['identity_case_index'],'parent_context_sha256':hashlib.sha256(json.dumps(self.context,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'configuration':self.outcome,'entry_PC':hex(start),'entry_SP':hex(self.F),'entry_defined_GPRs':self.context['entry_defined_GPRs'],'steps':self.steps,'events':self.events,'API_models':self.api,'edges':self.edges,'boundary':self.boundary,'source_pool':self.source_pool,'used_fixups':[hex(a)for a in sorted(self.fix)],'message_hex':self.message.hex(),'cache_owner':hex(cache),'cache_defined_mask36':[cache+j in self.defined for j in range(36)],'cache_hex36':bytes(self.u.mem_read(cache,36)).hex(),'destination_hex64':bytes(self.u.mem_read(D,64)).hex(),'destination_defined_mask64':[D+j in self.defined for j in range(64)],'allocated_owners':{hex(a):n for a,n in self.allocated.items()},'native_target_executed':False,'full_goal_complete':False}

def outcomes():
 for pattern,flags,retval in [(0xa5,0x50000000,0),(0x5a,0xa0000000,(1<<64)-1)]:yield {'clobber_pattern':pattern,'NZCV_after':flags,'void_result64':retval}
def packed(t):
 b=json.dumps(t,separators=(',',':')).encode();return {'identity_case_index':t['identity_case_index'],'configuration':t['configuration'],'source_visits':len(t['steps']),'payload_sha256':hashlib.sha256(b).hexdigest(),'payload_zlib_base64':base64.b64encode(zlib.compress(b,9)).decode(),'native_target_executed':False,'full_goal_complete':False}
def main():
 contexts=json.loads((ROOT/'daemon_cache_publication_context.json').read_text())['contexts'];rows=[]
 for j,c in enumerate(contexts):
  for cfg in outcomes():rows.append(packed(Run(c,cfg).run()))
  if j%24==23:print(json.dumps({'contexts_finished':j+1,'cases':len(rows),'source_visits':sum(r['source_visits']for r in rows)}),flush=True)
 assert len(rows)==576
 deps=['daemon_cache_publication_context.json','probe_daemon_identity_cache.py','probe_daemon_cache36.py','probe_daemon_object_initialization.py','daemon_digest_output_access.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'new_port_emission_established':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_cache_publication_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(r['source_visits']for r in rows)}),flush=True)
if __name__=='__main__':main()
