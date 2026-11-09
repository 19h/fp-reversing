#!/usr/bin/env python3
"""Operation selection, shared-frame preparation and eight original callers.

Primary source bytes, chained slots and declared classifier contexts only.
O(B+I+N) time/source space. No native target/API/crypto/IPC operation or IDB edit.
"""
import bisect,hashlib,json
from pathlib import Path
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,CS
from recover_kext_aes_handoff import function,starts
from recover_kext_cold_init import pointer
from recover_carrier_control import span
from lskd_consumer_spec import NODES,LEAVES,DEFAULT
TABLE=0xfffffe000846c420
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');catalog=starts(k,e);parents=set();spans=[];nodes=[]
 def add(label,a,z):
  row=span(k,a,z);assert IMAGE.read(a,z-a).hex()==row['bytes_hex'];ix=bisect.bisect_right(catalog,a)-1;assert z<=catalog[ix+1];parents.add(catalog[ix]);row.update(label=label,compiler_start=hex(catalog[ix]),compiler_end=hex(catalog[ix+1]));spans.append(row);return row
 add('shared_frame_prepare',0xfffffe000a59bf78,0xfffffe000a59c068)
 for n in NODES:
  a,z=int(n['start'],16),int(n['end'],16);s=add('node_'+n['label'],a,z);ar=add('arithmetic_'+n['label'],int(n['arithmetic_start'],16),int(n['table_load_pc'],16));last=s['instructions'][-1];assert last['ea']==n['branch_pc']and last['mnemonic']=='braa';modifier=next(int(i['operands'].split('#')[1],16)for i in reversed(s['instructions'])if i['mnemonic']=='mov'and i['operands'].startswith('x17, #'));edges=[]
  for outcome in['true','false']:
   ix=n[outcome+'_index'];assert 0<=ix<0xb00;p=pointer(k,TABLE+8*ix);assert p['authenticated']and int(p['diversity'],16)==modifier;edges.append({'condition_outcome':outcome,'index32':ix,'original_pointer':p})
  nodes.append({**n,'modifier16':hex(modifier),'edges':edges})
 for a in sorted({int(v,16)for v in LEAVES.values()}|{int(DEFAULT,16)}):add('leaf_'+hex(a)[2:],a,a+16)
 callers=[]
 for label,a,pc,operation,n,b in[('start',0xfffffe000a5053f4,0xfffffe000a50544c,0x1b59,0,0),('stop',0xfffffe000a505480,0xfffffe000a5054d8,0x1b5a,0,0),('query',0xfffffe000a50550c,0xfffffe000a505568,0x1b5b,0,0),('span',0xfffffe000a505638,0xfffffe000a5056dc,0x1b5c,1,8)]:
  f=function(k,e,a);assert IMAGE.read(a,int(f['end'],16)-a).hex()==f['bytes_hex'];callers.append({'label':label,'start':hex(a),'execution_call':hex(pc),'operation32':operation,'entry_limit32':n,'payload_budget32_fixture':b,'function':f,'symbols':k.symbols([a])[hex(a)]});assert callers[-1]['symbols']
 old=json.loads((ROOT/'lskd_fields_contracts.json').read_text());fs=[function(k,e,a)for a in sorted(parents)];symbols=k.symbols([int(f['start'],16)for f in fs]+[0xfffffe000a59bf78]+[int(v,16)for v in LEAVES.values()]);out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['lskd_consumer_spec.py','kernel_native_reader.py','kext_port_tools.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py','recover_carrier_control.py','lskd_response_contracts.json','lskd_fields_contracts.json','lskd_execute_contracts.json']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'functions':fs,'spans':spans,'nodes':nodes,'leaf_map':{hex(a):b for a,b in LEAVES.items()},'default_leaf':DEFAULT,'table_address':hex(TABLE),'additional_callers':callers,'prior_provider_callers':old['providers'],'exact_symbols':symbols,'decoded_context_selector32':0x3be,'native_target_executed':False,'operation_callee_executed':False,'external_IPC_emission_proved':False,'full_goal_complete':False};(ROOT/'lskd_consumer_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'compiler_envelopes':len(fs),'spans':len(spans),'decision_nodes':len(nodes),'selected_values':len(LEAVES),'additional_callers':len(callers)}),flush=True)
if __name__=='__main__':main()
