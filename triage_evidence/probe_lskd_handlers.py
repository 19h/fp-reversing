#!/usr/bin/env python3
"""Original handler preparation and compact field lookup in guarded private memory.

Only inherited allocator register models; no model writes memory. Original
lookup/initializer instructions execute. Stop before random/stop-helper calls
or at field-search/response-initializer returns. O(C*(B+V+E)) time/space,
abstract PAC, 30000 visits/case. No native heap/API/crypto/IPC or complete handler.
"""
import gc,hashlib,json,struct
from pathlib import Path
from unicorn import arm64_const as ar
from kext_port_tools import ROOT,SOURCE,CS
from probe_lskd_consumer import Consumer,cases as consumer_cases
from probe_lskd_response import Response,RESPONSE
from probe_lskd_request import kernel,OBJECT
C=None
CALLS={0xfffffe000a55356c:('scalar_record',0xfffffe000a52f01c,32),0xfffffe000a51ff80:('scalar_record',0xfffffe000a52f01c,32),0xfffffe000a590af0:('scalar_record',0xfffffe000a52f01c,32),0xfffffe000a527134:('scalar_record',0xfffffe000a52f01c,32),0xfffffe000a525c60:('scalar_record',0xfffffe000a52f01c,32),0xfffffe000a592438:('scalar_record',0xfffffe000a52f01c,32),0xfffffe000a590dd4:('scalar_record',0xfffffe000a52f01c,32),0xfffffe000a59143c:('scalar_record',0xfffffe000a52f01c,32),0xfffffe000a5954bc:('span_record',0xfffffe000a549bf4,40),0xfffffe000a51c028:('response_initializer',0xfffffe000a547cd4,28),0xfffffe000a52f268:('generic_field_search',0xfffffe000a52eed4,40),0xfffffe000a549e04:('generic_field_search',0xfffffe000a52eed4,40)}
def contracts():
 global C
 if C is None:C=json.loads((ROOT/'lskd_handlers_contracts.json').read_text())
 return C
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class Handlers(Consumer):
 def __init__(self,c):
  super().__init__(c);self.in_handler=False;self.handler_entry=None;self.search_return=None;self.init_return=None;self.prepared_call=None
  for s in contracts()['spans']:
   if s['label']not in ['random_wrapper','random_stub']:self.ranges.append((int(s['start'],16),int(s['end'],16)))
  for j,d in enumerate(contracts()['additional_mutable_globals'],19):
   a=int(d['address'],16);v=int.from_bytes(bytes.fromhex(d['original8_hex']),'little')if c['global_fixture']=='original'else 0 if c['global_fixture']=='zero'else(0x12345678a5a50000+j*0x111111111)&((1<<64)-1);self.u.mem_write(a,struct.pack('<Q',v));self.allowed.append((a,a+8))
  if 'stream_fields'in c:
   packet=b''.join(struct.pack('>HH',tag,len(bytes.fromhex(data)))+bytes.fromhex(data)for tag,data in c['stream_fields']);assert len(packet)<=128;obj=bytearray(160);struct.pack_into('<4I',obj,0,1,c['operation32'],len(c['stream_fields']),len(packet));obj[16:16+len(packet)]=packet;struct.pack_into('<QII',obj,144,OBJECT+16,len(c['stream_fields']),len(packet));self.seed(OBJECT,obj);self.fixture_additions.append({'address':hex(OBJECT),'bytes_hex':obj.hex()})
 def code(self,u,a,n,d):
  self.flush()
  if self.selection and a in self.leaves and a!=int(contracts()['handlers'][0]['entry'],16):
   pass
  entries={int(h['entry'],16)for h in contracts()['handlers']}
  if self.selection and a in entries:
   self.in_handler=True;self.handler_entry={'pc':hex(a),'source_visit_index':self.seq,'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)],'request':self.snapshot(OBJECT,160),'response_before':self.snapshot(RESPONSE,160)}
  if self.in_handler:
   sp=u.reg_read(ar.UC_ARM64_REG_SP)
   if a in [0xfffffe000a52f26c,0xfffffe000a549e08]:
    g=sp+(0x20 if a==0xfffffe000a52f26c else 0x10);p=self.snapshot(g,40);raw=bytes.fromhex(p['bytes_hex']);lp,dp=struct.unpack_from('<QQ',raw,8);self.search_return={'pc':hex(a),'source_visit_index':self.seq,'SP':hex(sp),'record':p,'length_output':self.snapshot(lp,2),'pointer_output':self.snapshot(dp,8)};return self.stop(a,'field_search_return')
   if a==0xfffffe000a51c02c:
    self.init_return={'pc':hex(a),'source_visit_index':self.seq,'SP':hex(sp),'registers31':[hex(self.reg(j))for j in range(31)],'record':self.snapshot(0x63000080a8,28),'response':self.snapshot(RESPONSE,160)};return self.stop(a,'response_initializer_return')
   if a in [0xfffffe000a50fd10,0xfffffe000a531d60]:
    self.prepared_call={'pc':hex(a),'source_visit_index':self.seq,'SP':hex(sp),'target':hex(self.reg(8)),'registers31':[hex(self.reg(j))for j in range(31)]}
    if a==0xfffffe000a531d60:self.prepared_call['record']=self.snapshot(self.reg(0),12)
    return self.stop(a,'before_random_call'if a==0xfffffe000a50fd10 else'before_stop_helper')
   if a in CALLS:
    kind,target,size=CALLS[a];self.visit(a);assert self.reg(8)==target;self.calls.append({'kind':kind,'pc':hex(a),'target':hex(target),'source_visit_index':self.seq-1,'SP':hex(sp),'registers31':[hex(self.reg(j))for j in range(31)],'registers8':[hex(self.reg(j))for j in range(8)],'record':self.snapshot(self.reg(0),size),'target_executed_in_private_guest':True});self.setreg(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,target)
   return Response.code(self,u,a,n,d)
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r.pop('selected_operation_callee_executed');r.update(handler_entry=self.handler_entry,field_search_return=self.search_return,response_initializer_return=self.init_return,prepared_handler_call=self.prepared_call,source_handler_preparation_executed=self.in_handler,original_field_lookup_executed=self.search_return is not None,original_response_initializer_executed=self.init_return is not None,complete_business_handler_executed=False,random_backend_executed=False,stop_helper_executed=False);return r
def cases():
 for c in consumer_cases():yield {**c,**({'stream_fields':[],'stream_fixture_label':'empty'}if c['kind']=='execute'else{})}
 for op,tag in [(0x1b69,0x72),(0x1b5c,0x66)]:
  for label,fields in [('second',[(0x40,'01020304'),(tag,'1122334455667788')]),('absent',[(0x40,'01020304'),(0x41,'05060708')]),('duplicate',[(tag,'1122334455667788'),(tag,'8877665544332211')]),('zero_length',[(tag,'')])]:
   for glob in ['original','zero','declared_noise']:
    for placement in [0,0x100]:
     for location in ['adjacent','separated']:
      c=next(c for c in consumer_cases()if c['kind']=='execute'and c['operation32']==op);yield {**c,'global_fixture':glob,'placement':placement,'auxiliary_location':location,'stream_fields':fields,'stream_fixture_label':label}
def main():
 rows=[]
 for j,c in enumerate(cases()):
  f=Handlers(c);r=f.run();del f;rows.append(r)
  if j%16==0:gc.collect();print(json.dumps({'cases_completed':j+1}),flush=True)
 deps=['lskd_handlers_contracts.json','lskd_handlers_spec.py','probe_lskd_consumer.py','lskd_consumer_contracts.json','probe_lskd_response.py','lskd_response_contracts.json','probe_lskd_execute.py','lskd_execute_contracts.json','probe_lskd_fields.py','lskd_fields_contracts.json','probe_lskd_request.py','lskd_request_contracts.json','legacy_tlv_contracts.json','legacy_stack_contracts.json','probe_legacy_stack.py','kernel_native_reader.py','kext_port_tools.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'kernel_collection_sha256':kernel().sha256,'cases':rows,'native_target_executed':False,'complete_business_handler_executed':False,'random_backend_executed':False,'external_IPC_emission_proved':False,'full_goal_complete':False};(ROOT/'lskd_handlers_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
