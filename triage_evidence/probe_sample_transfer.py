#!/usr/bin/env python3
"""Original metadata-result/data prefixes; stop before every crypto operation.

Private state/descriptor/heap/copy models only. Four metadata bytes are declared
synthetic input. No task mapping, native I/O, crypto, IPC or IDB action executes.
"""
import hashlib,json,struct
from pathlib import Path
from unicorn import arm64_const as ar
from kext_port_tools import ROOT,SOURCE,IMAGE,CS
from probe_sample_caller import case
from probe_sample_state import State,STACK,ARENA
SIZE_READ=0xfffffe000a509a60
SAMPLES_READ=0xfffffe000a509ab0;GLOBAL_BUFFER=0x7b00000000;GLOBAL_CAPACITY=81920;CACHED_BYTES=0xfffffe000ccc7848
CRYPTO={0xfffffe000a509fe8:'samples_descriptor_bridge',0xfffffe000a508534:'descriptor_wrapper',0xfffffe000a508484:'global_buffer_wrapper',0xfffffe000a5083d8:'shared_buffer_wrapper',0xfffffe000a5081b0:'copied_buffer_wrapper',0xfffffe000a5086a0:'cbc_helper'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class Transfer(State):
 def __init__(self,c):
  super().__init__(c);self.metadata_models=[];self.sample_models=[];self.crypto_boundaries=[];self.global_reads=[];self.global_known=bytearray(GLOBAL_CAPACITY);self.u.mem_map(GLOBAL_BUFFER,GLOBAL_CAPACITY);self.u.mem_write(GLOBAL_BUFFER,bytes([0xcd])*GLOBAL_CAPACITY);self.initial_cached_bytes_hex=bytes(self.u.mem_read(CACHED_BYTES,8)).hex();self.u.mem_write(CACHED_BYTES,struct.pack('<Q',GLOBAL_BUFFER));raw=bytearray(self.header_fixture);raw[0]=c['header_byte0'];self.header_fixture=bytes(raw);self.u.mem_write(self.header,self.header_fixture)
 def hook(self,u,a,n,d):
  if self.reason:return
  if 0xfffffe000a6247a4<=a<0xfffffe000a626648:
   if a not in self.decoded:self.decoded[a]=next(CS.disasm(IMAGE.read(a,4),a))
   ins=self.decoded[a]
   if ins.mnemonic=='blraa':
    target=self.reg(int(ins.op_str.split(',')[0][1:]))
    if target==SIZE_READ:
     self.flush();offset=self.reg(0);assert offset%4==0 and self.reg(1)==self.obj+0xc4 and self.reg(2)==4;index=offset//4;assert index<len(self.case['sample_words32'])
     returns=self.case['metadata_returns64'];result=self.case['metadata_return64']if returns is None else returns[index];word=self.case['sample_words32'][index];payload=word.to_bytes(4,'little');written=min(result&0xffffffff,4);dest=self.obj+0xc4;before=bytes(u.mem_read(dest,4));u.mem_write(dest,payload[:written]);self.known[dest-STACK:dest-STACK+written]=b'\1'*written
     obs={'pc':hex(a),'target':hex(target),'source_visit_index':len(self.visits),'registers8':[hex(self.reg(j))for j in range(8)],'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'metadata_index':index,'result64':hex(result),'declared_word32':hex(word),'written_bytes':written,'before_hex':before.hex(),'after_hex':bytes(u.mem_read(dest,4)).hex(),'target_executed':False};self.metadata_models.append(obs);raw=IMAGE.read(a,4);assert bytes(u.mem_read(a,4))==raw;self.pool[a]=raw;self.visits.append(a)
     if self.case['metadata_clobber']:
      for j in range(1,18):self.setreg(j,0xb4b4000000000000+j)
      u.reg_write(ar.UC_ARM64_REG_NZCV,0xf0000000)
     self.setreg(0,result);self.setreg(30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
    if target==SAMPLES_READ and self.case['model_sample_reads']:
     self.flush();offset,dest,length=[self.reg(j)for j in range(3)];assert length<=8192;assert ARENA<=dest<dest+length<=ARENA+8192 or GLOBAL_BUFFER<=dest<dest+length<=GLOBAL_BUFFER+GLOBAL_CAPACITY
     phase='tail'if a==0xfffffe000a625f48 else'bulk';assert a in[0xfffffe000a625f48,0xfffffe000a62602c]
     configured=self.case[phase+'_return64'];result=length if configured is None else configured;written=min(result&0xffffffff,length);data=bytes((offset+i+0x21)&255 for i in range(written));before=bytes(u.mem_read(dest,written));u.mem_write(dest,data)
     if ARENA<=dest<ARENA+8192:self.known[dest-STACK:dest-STACK+written]=b'\1'*written
     else:off=dest-GLOBAL_BUFFER;self.global_known[off:off+written]=b'\1'*written
     self.sample_models.append({'pc':hex(a),'target':hex(target),'phase':phase,'source_visit_index':len(self.visits),'registers8':[hex(self.reg(j))for j in range(8)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'result64':hex(result),'written_bytes':written,'payload_hex':data.hex(),'before_hex':before.hex(),'target_executed':False});raw=IMAGE.read(a,4);assert bytes(u.mem_read(a,4))==raw;self.pool[a]=raw;self.visits.append(a);self.setreg(0,result);self.setreg(30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
    if target in CRYPTO:
     self.flush();self.crypto_boundaries.append({'pc':hex(a),'target':hex(target),'role':CRYPTO[target],'source_visit_index':len(self.visits),'registers8':[hex(self.reg(j))for j in range(8)],'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'target_executed':False});return self.stop('before_crypto_call',pc=hex(a),target=hex(target))
  return super().hook(u,a,n,d)
 def read(self,u,access,a,n,v,d):
  super().read(u,access,a,n,v,d)
  if GLOBAL_BUFFER<=a<a+n<=GLOBAL_BUFFER+GLOBAL_CAPACITY:
   known=all(self.global_known[a-GLOBAL_BUFFER:a-GLOBAL_BUFFER+n]);self.global_reads.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'offset':a-GLOBAL_BUFFER,'size_bytes':n,'defined':known,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
   if not known:return self.stop('undefined_global_buffer_read',pc=hex(u.reg_read(ar.UC_ARM64_REG_PC)),offset=a-GLOBAL_BUFFER,size_bytes=n)
 def run(self):
  r=super().run();prefix=next((i for i,v in enumerate(self.global_known)if not v),GLOBAL_CAPACITY);known=self.known[ARENA-STACK:ARENA-STACK+8192];workspace_prefix=next((i for i,v in enumerate(known)if not v),8192);r['scope']=__doc__;r.update(metadata_models=self.metadata_models,sample_read_models=self.sample_models,crypto_boundaries=self.crypto_boundaries,global_buffer_fixture={'pointer_cell':hex(CACHED_BYTES),'prior_cell_hex':self.initial_cached_bytes_hex,'declared_pointer':hex(GLOBAL_BUFFER),'capacity_bytes':GLOBAL_CAPACITY,'native_initializer_executed':False},global_buffer_reads=self.global_reads,global_defined_prefix_bytes=prefix,global_defined_prefix_hex=bytes(self.u.mem_read(GLOBAL_BUFFER,prefix)).hex(),workspace_defined_prefix_bytes=workspace_prefix,workspace_defined_prefix_hex=bytes(self.u.mem_read(ARENA,workspace_prefix)).hex());return r
def make(word=16,result=4,op=0,mode=1,flag=0):
 c=case(1);c['modeled_results'].update(initialize=0,complete=0);c.update(header_byte0=op,header_byte1=mode,header_byte38=flag,object_fill_byte=0xa5,workspace_result64=ARENA,sample_word32=word,sample_words32=[word],metadata_return64=result,metadata_returns64=None,metadata_clobber=False,model_sample_reads=True,tail_return64=None,bulk_return64=None);return c
def cases():
 for word in[0,1,15,16,17,31,32,8191,8192,8193,0xffffffff]:
  for result in[0,3,4,0x100000004]:
   for op in[0,1,255]:yield make(word,result,op)
 for mode in[0,2,3,255]:
  for flag in[0,1]:
   for word in[15,16,17,8192,8193]:yield make(word,4,0,mode,flag)
 for word in[16,8192,8193]:
  for op in[0,1]:
   c=make(word,4,op);c['metadata_clobber']=True;yield c
 for phase,result in[('tail',0),('tail',15),('tail',0x100000010),('bulk',0),('bulk',15),('bulk',0x100000010)]:
  c=make(16);c[phase+'_return64']=result;yield c
 for words in[[16,16],[17,32],[1,16],[15,16],[4096,4096],[4096,4097],[4096,4112],[8192,16],[8193,16],[15,8193],[1,8193],[0,0],[0,16],[16,0],[16,16,16],[32,16,48]]:
  c=make(words[0]);c.update(sample_words32=words,element_count32=len(words),sample_length64=sum(words));yield c
 c=make(16);c.update(sample_words32=[16,16],element_count32=2,sample_length64=32,metadata_returns64=[4,0]);yield c
def main():
 rows=[];pool={}
 for c in cases():q=Transfer(c);r=q.run();rows.append(r);pool.update(q.pool)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in['probe_sample_state.py','probe_sample_caller.py','probe_kext_close.py','sample_state_contracts.json']},'cases':rows,'source_instructions':[{'ea':hex(a),'bytes_hex':b.hex(),'mnemonic':next(CS.disasm(b,a)).mnemonic,'operands':next(CS.disasm(b,a)).op_str}for a,b in sorted(pool.items())],'native_target_executed':False,'crypto_operation_executed':False,'full_goal_complete':False};(ROOT/'sample_transfer_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'stops':{s:sum(r['stop_reason']==s for r in rows)for s in sorted({r['stop_reason']for r in rows})},'crypto_targets':{s:sum(any(e['target']==s for e in r['crypto_boundaries'])for r in rows)for s in sorted({e['target']for r in rows for e in r['crypto_boundaries']})}}),flush=True)
if __name__=='__main__':main()
