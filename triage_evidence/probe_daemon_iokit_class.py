#!/usr/bin/env python3
"""Original IOMainPort/class decoder/matching prefix plus object/query chain.

Entry follows the unexecuted lock helper. External results are explicit models;
class source is original-file fixup-backed data. No native API or kernel code.
O(B+C*(V+E+J*F)) time,O(B+C*(V+E)+F+4096J) space; abstract PAC.
"""
import hashlib,json,struct,itertools
from pathlib import Path
from unicorn import arm64_const as ar
from probe_daemon_iokit_objects import Objects,cases as object_cases,P,TASK,GUARD,API,IMPS,STATE,DICT
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,POOL,TABLE
from daemon_import_bindings import binding
ENTRY=0x100461c30;DECODE=0x10040b5e0;DECODE_END=0x10040b7d4;NAME=b'com_apple_driver_FairPlayIOKit\0'
RANGES=[(ENTRY,0x100461cec),(DECODE,0x10040b83c),(0x1004616a8,0x1004616d0)]
NEW_IMPS={'IOKit/_IOMainPort':0x7c007400,'IOKit/_IOServiceMatching':0x7c007500}
class Matching(Objects):
 def __init__(self,c):
  super().__init__(c);self.prefix_models=[];self.objects_entry=None;self.class_call_snapshot=None;self.decoder_only=c.get('decoder_only',False)
  remove={self.F+0x38,self.F+0x40,self.F+0x7c};rows=[e for e in self.initial if int(e['address'],16)in remove];self.initial=[e for e in self.initial if int(e['address'],16)not in remove]
  for e in rows:
   a=int(e['address'],16);n=len(bytes.fromhex(e['bytes_hex']));self.u.mem_write(a,b'\xa5'*n);self.known[a-P:a-P+n]=bytes(n);self.prov[a-P:a-P+n]=bytes(n)
  for j,v in[(19,P+0x2000),(12,0x100f4e290),(13,0x100e99800),(23,0x1010c4000),(25,0x1010c4670),(28,0x597a)]:self.set(j,v)
  if self.decoder_only:
   self.set(19,0x101031ea0);self.set(25,0x100fc4130);self.set(28,c['decoder_W28'])
 def page(self,a):
  pg=a&~4095
  if pg in self.pages:return
  raw=bytearray(IMAGE.read(pg,4096));self.u.mem_map(pg,4096);self.pages.add(pg)
  for at,r in FIXUPS.items():
   if pg<=at<pg+4096:
    t=r['target'];v=TASK+0x7bf13863 if at==0x1010a39c8 else GUARD if t=='libSystem/___stack_chk_guard'else API if t=='IOKit/_IOConnectCallStructMethod'else NEW_IMPS[t]if t in NEW_IMPS else IMPS[t]if t in IMPS else t if isinstance(t,int)else 0x7c100000;raw[at-pg:at-pg+8]=struct.pack('<Q',v)
  self.u.mem_write(pg,bytes(raw))
 def prefix_call(self,a):
  main=a==0x100461cc4;slot=0x1010a0988 if main else 0x1010a0c28;div=0x6240 if main else 0x83b;assert self.reg(8)==NEW_IMPS[FIXUPS[slot]['target']]and self.reg(17)==div;params=[self.reg(j)for j in range(8)];writes=[];name='main_port'if main else'matching_dictionary'
  if main:
   assert params[:2]==[0,self.F+0x7c];result=self.c['prefix']['main_status']
   if result==0:writes=[(self.F+0x7c,struct.pack('<I',self.io['main_port']))]
  else:
   assert params[0]==self.F+0x89;self.class_call_snapshot=self.snapshot(params[0],31);assert self.class_call_snapshot['bytes_hex']==NAME.hex()and self.class_call_snapshot['known_mask_hex']=='01'*31;result=DICT if self.c['prefix']['matching_nonnull']else 0
  self.visit(a);out=[]
  for at,raw in writes:self.u.mem_write(at,raw);self.known[at-P:at-P+len(raw)]=b'\1'*len(raw);self.prov[at-P:at-P+len(raw)]=b'\2'*len(raw);out.append({'address':hex(at),'bytes_hex':raw.hex()})
  self.prefix_models.append({'pc':hex(a),'source_visit_index':self.seq-1,'name':name,'binding':binding(slot),'registers8':[hex(x)for x in params],'returned_value':hex(result),'modeled_writes':out,'native_target_executed':False});self.set(0,result)
  for j in range(1,18):self.set(j,0xf000000000000000+j*0x1111)
  self.u.reg_write(ar.UC_ARM64_REG_NZCV,0xf0000000);self.set(30,a+4);self.u.reg_write(ar.UC_ARM64_REG_PC,a+4)
 def code(self,u,a,n,d):
  self.flush()
  if self.decoder_only and a==DECODE_END:return self.stop_at(a,'before_decoder_followup_and_API')
  if a==0x10062fb74:return self.stop_at(a,'before_main_port_error_continuation')
  if a==0x1003f94ec:self.objects_entry={'pc':hex(a),'source_visit_index':self.seq,'registers31':[hex(self.reg(j))for j in range(31)]}
  if a in[0x100461cc4,0x10040b814]:return self.prefix_call(a)
  if not any(x<=a<a+4<=z for x,z in RANGES):return super().code(u,a,n,d)
  ins=next(self.dec.disasm(IMAGE.read(a,4),a));assert ins.mnemonic not in['bl','blr','blraa','br','ret','retab','svc','hvc','smc'];self.visit(a)
  if ins.mnemonic=='braa':
   target=self.reg(int(ins.op_str.split(',',1)[0][1:]));assert any(x<=target<z for x,z in RANGES)or target in[0x10062fb74,0x1003f94ec,0x100383b00];self.edges.append({'pc':hex(a),'source_visit_index':self.seq-1,'target':hex(target),'modifier16':hex(self.reg(17))});return u.reg_write(ar.UC_ARM64_REG_PC,target)
 def run(self):
  start=DECODE if self.decoder_only else ENTRY;self.page(start);self.u.emu_start(start,0,count=5000);self.flush();assert self.reason in['before_decoder_followup_and_API','before_main_port_error_continuation','before_matching_error_continuation','before_open_error_continuation','before_common_cleanup_unknown_pointer'];mask=bytearray(24);events=[]
  for row in self.image_initial_fixtures:
   a=int(row['address'],16)
   for j in range(a,a+len(bytes.fromhex(row['bytes_hex']))):
    if STATE<=j<STATE+24:mask[j-STATE]=3
  for m in self.io_models:
   for e in m['modeled_writes']:events.append((m['source_visit_index'],int(e['address'],16),len(bytes.fromhex(e['bytes_hex'])),2))
  for e in self.writes:events.append((e['source_visit_index'],int(e['address'],16),e['size_bytes'],1))
  for ix,a,n,p in sorted(events):
   for j in range(a,a+n):
    if STATE<=j<STATE+24:mask[j-STATE]=p
  return {'input':self.c,'frame_SP':hex(self.F),'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial_fixtures,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'IOKit_models':self.io_models,'prefix_models':self.prefix_models,'source_edges':self.edges,'source_fixup_reads':self.fixups,'objects_entry':self.objects_entry,'query_entry':self.query_entry,'preceding_query_boundary':self.query_boundary,'boundary':self.boundary,'helper_call':self.helper_call,'class_buffer':self.snapshot(self.F+0x89,31),'class_call_snapshot':self.class_call_snapshot,'main_port_cell':self.snapshot(self.F+0x7c,4),'saved_input_and_tables':self.snapshot(self.F+0x38,24),'query_words':self.snapshot(self.F+0x64,12),'iterator_cell':self.snapshot(self.F+0x68,4),'connection_saved_pointer':self.snapshot(self.F+8,8),'returned_size':self.snapshot(self.F+0x70,8),'query_state_record':self.snapshot(self.record,20),'record_before_helper':self.record_before_call,'fallback_record':getattr(self,'fallback_record',None),'state_cache':{'address':hex(STATE),'size_bytes':24,'bytes_hex':bytes(self.u.mem_read(STATE,24)).hex(),'provenance_mask_hex':mask.hex()},'fallback_calls':self.fallback_calls,'fallback_input_record':self.fallback_input_record,'fallback_access_record':self.fallback_access_record,'cache_before_fallback':self.cache_before_fallback,'fallback_returned':self.fallback_returned,'state_before_final_marker':self.state_before_final_marker,'helper_returned':self.helper_returned,'native_target_executed':False,'native_port_identity_proved':False,'full_goal_complete':False}

def cases():
 for x in object_cases():
  c=json.loads(json.dumps(x));c['prefix']={'main_status':0,'matching_nonnull':True};yield c
 base=next(object_cases())
 for status,nonnull,placement,port in itertools.product([0,1,0xe00002c7,0xffffffff],[False,True],[0,0x100],[0,0xf0000027]):
  c=json.loads(json.dumps(base));c.update(placement=placement,class_case='prefix_status_controls',prefix={'main_status':status,'matching_nonnull':nonnull});c['IO']['main_port']=port;yield c

def decoder_cases():
 base=next(object_cases())
 for low,placement in itertools.product(range(256),[0,0x100]):
  c=json.loads(json.dumps(base));c.update(placement=placement,decoder_only=True,decoder_W28=0x5900|low);yield c

def main():
 rows=[]
 for kind,source in[('composed',cases()),('decoder',decoder_cases())]:
  out=[]
  for j,c in enumerate(source):
   f=Matching(c);out.append(f.run());del f
   if j%32==0:print(json.dumps({'kind':kind,'cases_completed':j+1}),flush=True)
  rows.append((kind,out))
 sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();obj={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['probe_daemon_iokit_objects.py','probe_daemon_query_fallback.py','probe_daemon_query_state.py','probe_daemon_iokit_census.py','daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt']},'source_sha256':sha(SOURCE),**{k+'_cases':v for k,v in rows},'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_iokit_class_profiles.json').write_text(json.dumps(obj,indent=2)+'\n');print(json.dumps({k:{'cases':len(v),'visits':sum(len(r['source_visits'])for r in v)}for k,v in rows}),flush=True)
if __name__=='__main__':main()
