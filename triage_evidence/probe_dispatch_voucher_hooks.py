#!/usr/bin/env python3
"""Original dispatch table installer and callbacks on exact kernel CF packets.
Mach/task and separate source-dispatch caller transfers remain contracts.
No native bootstrap, IPC, TSD or authenticated control transfer executes.
O(source+visits+RAM+journals) time/space; normal zero voucher names only.
"""
import json
from daemon_receive_tools import ROOT
from recover_dispatch_voucher_hooks import P,FLAGS,sha,CacheView,DISPATCH_INIT,DISPATCH_ADOPT,DISPATCH_REVERT
from probe_cf_receive_voucher import Consumer as Parent
from probe_cf_daemon_request import Probe as DispatchProbe
from probe_kernel_vm_mig import Probe as CPU,P as B,SIZE
from probe_rpc502_vm_handoff import compressed
DISPATCH_CLEAR=0x18553aa44;USER=B+0x1000
class ClearProbe(CPU):
 def __init__(self,src,j,k):
  super().__init__(CacheView(src),'selector',{'id':0});self.kind='original_dispatch_clear_zero_name';self.c={'kernel_producer':j};self.initial=[];self.image_initial=[];self.entry=DISPATCH_CLEAR;f=next(f for f in src['functions']if f['start']==hex(DISPATCH_CLEAR));self.allowed=[(DISPATCH_CLEAR,int(f['end'],16))];self.fixture(USER,bytes.fromhex(k['final_user8192_hex']));self.set(0,USER);self.entry_regs=[hex(self.reg(q))for q in range(31)]
 def run(self):
  r=super().run();r['final_user8192_hex']=bytes(self.u.mem_read(USER,8192)).hex();r['final_private_RAM']=compressed(bytes(self.u.mem_read(B,SIZE)));return r
class Consumer(Parent):
 def __init__(self,src,index,k):
  super().__init__(src,index,k,'published_null_callbacks');self.image=CacheView(src);self.c['table_mode']='original_libdispatch_table';self.kind='original_dispatch_voucher_hooks';self.entry=DISPATCH_INIT;self.set(0,0);self.entry_regs=[hex(self.reg(j))for j in range(31)]
 def code(self,u,a,n,d):
  self.flush()
  if a in(DISPATCH_INIT,DISPATCH_ADOPT,DISPATCH_REVERT):self.frames.append(self.frame(a))
  if a in(0x18553aad8,0x18553ab88):raise AssertionError('Unexpected TSD read on declared zero-voucher/unchanged-state path')
  return super().code(u,a,n,d)
if __name__=='__main__':
 src=json.loads((ROOT/(P+'_source.json')).read_text());prior=json.loads((ROOT/'cf_receive_voucher_profiles.json').read_text());rows=[];dispatch=[];clears=[];ds=json.loads((ROOT/'cf_daemon_request_source.json').read_text())
 for j,k in enumerate(prior['kernel_cases']):
  r=Consumer(src,j,k).run();rows.append(r);print('receive',j,len(r['source_visits']),r['final_user8192_hex'][:8],flush=True)
  supplied={**k,'final_user8192_hex':r['final_user8192_hex'],'final_OOL16384_hex':r['final_OOL16384_hex']};q=DispatchProbe(j,supplied,ds).run();q['CF_receive_case_index']=j;dispatch.append(q);print('dispatch',j,q['boundary']['kind'],len(q['source_visits']),flush=True)
  clear=ClearProbe(src,j,k).run();clears.append(clear);print('clear',j,len(clear['source_visits']),clear['final_user8192_hex'][:8],flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json','cf_receive_voucher_profiles.json','probe_cf_receive_voucher.py','probe_kernel_vm_mig.py','cf_daemon_request_source.json','probe_cf_daemon_request.py','recover_'+P+'.py']},'kernel_cases':prior['kernel_cases'],'cases':rows,'dispatch_cases':dispatch,'clear_cases':clears,**FLAGS};(ROOT/(P+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
