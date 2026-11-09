#!/usr/bin/env python3
"""Original continuation records, lock endpoints, cache roots and source windows.

O(B+I+S log F+256R) time, O(B+I) space. No target executes. Compiler
start envelopes are boundary metadata, not reconstructed source-level roles.
"""
import bisect,hashlib,json,struct
from pathlib import Path
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected,CS
from recover_kext_aes_handoff import starts
from recover_kext_cold_init import pointer
from recover_carrier_control import span
from lskd_continuations_spec import SPANS,GLOBALS,PURE_TARGETS
T=0xfffffe000846c420;P=0xfffffe00084716e0

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');cat=starts(k,e);ss=[]
 for row in SPANS:
  a,z=int(row['start'],16),int(row['end'],16);s=span(k,a,z);assert IMAGE.read(a,z-a).hex()==s['bytes_hex'];j=bisect.bisect_right(cat,a)-1;assert z<=cat[j+1];s.update(label=row['label'],compiler_start=hex(cat[j]),compiler_end=hex(cat[j+1]));ss.append(s)
 specs=[('cached_global_release',0x79171c0,0x7919bb0,0xca,-0x92,P,0,0xfffffe000ccc78a8),('write_api',0x79171c0,0x7919bb0,0xca,0x978,T,0,0xfffffe000a508d94),('unlock_api',0x79171c0,0x7919bb0,0xea,0xa01,T,0,0xfffffe000a508d9c),('free_api',0x7920c10,0x79170c0,0xaa,0x97b,T,0,0xfffffe000a508d84)]
 rules=[]
 for label,l,r,key,add,base,bias,target in specs:
  l|=0xfffffe0000000000;r|=0xfffffe0000000000;b=selected(l,r,key,add,base=base,bias=bias);assert int(b['target'],16)==target;b.update(label=label,base=hex(base),left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex(),original_pointer=pointer(k,int(b['slot'],16)));rules.append(b)
 apis=[]
 for label,a in[('write',0xfffffe000a508d94),('unlock',0xfffffe000a508d9c),('free',0xfffffe000a508d84)]:
  wrapper=span(k,a,a+8);stub=int(wrapper['instructions'][1]['operands'][1:],16);s=span(k,stub,stub+16);ins=list(CS.disasm(k.read(stub,16),stub));assert[ i.mnemonic for i in ins]==['adrp','add','ldr','braa'];page=int(ins[0].op_str.split('#')[1],16);offset=int(ins[1].op_str.split('#')[1],16);slot=page+offset;bind=pointer(k,slot);expected='_IORWLock'+{'write':'Write','unlock':'Unlock','free':'Free'}[label];assert any(x['name']==expected for x in k.symbols([int(bind['target'],16)])[bind['target']]);apis.append({'label':label,'wrapper':wrapper,'stub':s,'binding':bind,'exact_target_symbols':k.symbols([int(bind['target'],16)])[bind['target']]})
 aliases=[]
 for delta in[0,4,8,12,-4,-8,-12]:
  target=0xfffffe000ccc78a8+delta;found=[]
  for va,off,n in IMAGE.segments:
   data=IMAGE.data[off:off+n];at=data.find(struct.pack('<Q',target))
   while at>=0:found.append(va+at);at=data.find(struct.pack('<Q',target),at+1)
  aliases.extend({'bias_from_cell':delta,'pointer':pointer(k,a)}for a in found)
 slots=[pointer(k,T+8*i)for i in[0x2d2,0x8d7,0x2c7,0x1d3,0x1e0,0x52f,0x595]];addresses=PURE_TARGETS+[0xfffffe000ccc78a8,*GLOBALS,*[int(a['binding']['target'],16)for a in apis],*[int(a['wrapper']['start'],16)for a in apis]]
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['lskd_continuations_spec.py','kernel_native_reader.py','kext_port_tools.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py','recover_carrier_control.py']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'spans':ss,'additional_mutable_globals':[{'address':hex(a),'size_bytes':8,'original8_hex':k.read(a,8).hex()}for a in GLOBALS],'cached_RW_cell':{'address':'0xfffffe000ccc78a8','original8_hex':k.read(0xfffffe000ccc78a8,8).hex(),'runtime_value_known':False,'native_creation_lineage_known':False},'bounded_pointer_aliases':aliases,'pointer_alias_search_deltas':[0,4,8,12,-4,-8,-12],'bank_rules':rules,'lock_control_slots':slots,'lock_apis':apis,'exact_symbols':k.symbols(addresses),'native_target_executed':False,'native_synchronization_executed':False,'full_goal_complete':False};(ROOT/'lskd_continuations_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'bounded_source_spans':len(ss),'new_controller_cells':len(GLOBALS),'lock_api_bindings':len(apis),'bank_rules':len(rules)}),flush=True)
if __name__=='__main__':main()
