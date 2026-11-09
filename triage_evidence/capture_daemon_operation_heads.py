#!/usr/bin/env python3
"""Original-image record-head spans and bounded operation-literal census.
O(text words*four operations + retained source spans) time, O(census + spans)
space. Literal candidates alone do not establish callers or native admission.
"""
import bisect,json,struct
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,block
from daemon_output_base_dispatch import CS
from daemon_digest_output_access import key
from resolve_kernel_collection_interfaces import commands
from recover_daemon_iokit_census import text_section
from capture_daemon_record720 import sha
SPECS=[(0x8799a4f1,0x100501bdc,0x100501c04),(0x8f7506ee,0x1005eb7bc,0x1005eb7e8),(0xa70e6eb4,0x100592ebc,0x100592ee0),(0xad952088,0x1004666ec,0x1004666fc)]
def function_starts():
 raw=SOURCE.read_bytes();cs=list(commands(raw,0));base=next(struct.unpack_from('<Q',raw,o+24)[0]for o,c,n in cs if c==0x19 and raw[o+8:o+24].rstrip(b'\0')==b'__TEXT');o,c,n=next(x for x in cs if x[1]==0x26);fo,nb=struct.unpack_from('<II',raw,o+8);data=raw[fo:fo+nb];cur=base;value=shift=0;starts=[]
 for b in data:
  value|=(b&127)<<shift
  if b&128:shift+=7;continue
  if value==0:break
  cur+=value;starts.append(cur);value=shift=0
 assert len(starts)==1005 and starts==sorted(set(starts));return starts,{'command':'LC_FUNCTION_STARTS','file_offset':fo,'size_bytes':nb,'entry_count':len(starts),'bytes_hex':data.hex()}
def normalized(a,n):
 data=bytearray(IMAGE.read(a,n))
 for at,r in FIXUPS.items():
  if a<=at<at+8<=a+n:assert isinstance(r['target'],int);data[at-a:at-a+8]=r['target'].to_bytes(8,'little')
 return bytes(data)
def projection(pc,stop,outputs,inputs):
 live={key(n)for n in outputs};rows=[]
 for i in reversed(list(CS.disasm(IMAGE.read(stop,pc-stop),stop))):
  rr,ww=i.regs_access();written={key(i.reg_name(r))for r in ww}
  if live&written:
   assert not any(o.type==3 for o in i.operands),(hex(i.address),i.mnemonic,i.op_str);rows.append({'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex()});live-=written;live|={key(i.reg_name(r))for r in rr}
   if live<=inputs:break
 assert live<=inputs,(hex(pc),live);rows.reverse();return rows,sorted(live)
def capture():
 a,n=text_section();data=IMAGE.read(a,n);hits={op:[]for op,_,_ in SPECS}
 for j in range(0,n-4,4):
  first,second=struct.unpack_from('<II',data,j)
  if first&0xffe00000!=0x52800000 or second&0xffe00000!=0x72a00000 or first&31!=second&31:continue
  value=((first>>5)&65535)|(((second>>5)&65535)<<16)
  if value in hits:hits[value].append(a+j)
 paths=json.loads((ROOT/'daemon_core_dispatch_symbolic.json').read_text());rows=[];starts,starts_source=function_starts();mig=[]
 for tab in json.loads((ROOT/'daemon_mig_tables.json').read_text())[:2]:
  a=int(tab['header'],16);assert normalized(a,32).hex()==tab['header_hex'];assert struct.unpack_from('<II',IMAGE.read(a,16),8)==(tab['start'],tab['end_exclusive'])
  for r in tab['routines']:
   descriptor=int(r['descriptor'],16);stub=int(r['stub'],16);assert normalized(descriptor,40).hex()==r['descriptor_hex']and FIXUPS[descriptor+8]['target']==stub;ix=bisect.bisect_left(starts,stub);assert starts[ix]==stub
   for i in CS.disasm(IMAGE.read(stub,starts[ix+1]-stub),stub):
    if i.mnemonic=='bl':mig.append({'request_ID':r['request_id'],'table_header':tab['header'],'descriptor':r['descriptor'],'stub':r['stub'],'call_PC':hex(i.address),'wrapper':hex(i.operands[0].imm),'original_call_bytes_hex':bytes(i.bytes).hex(),'descriptor_slot':hex(descriptor+8),'original_descriptor_word_hex':IMAGE.read(descriptor+8,8).hex()})
 for op,entry,frontier in SPECS:
  parent=next(j for j,p in enumerate(paths['paths'])if p['operation_sample']==hex(op));assert paths['paths'][parent]['boundary']['pc']==hex(frontier)
  candidates=[]
  for pc in hits[op]:
   ix=bisect.bisect_right(starts,pc)-1;lo,hi=starts[ix:ix+2];c={'pc':hex(pc),'register':'w'+str(struct.unpack_from('<I',IMAGE.read(pc,4))[0]&31),'context_start':hex(pc-48),'context_bytes_hex':IMAGE.read(pc-48,160).hex(),'containing_function_start':hex(lo),'next_function_start':hex(hi),'MIG_links':[m for m in mig if m['wrapper']==hex(lo)]};ins=list(CS.disasm(IMAGE.read(pc,40),pc));store=next((i for i in ins if i.mnemonic=='stp'and i.reg_name(i.operands[0].reg).startswith('w')and i.reg_name(i.operands[2].mem.base)=='fp'),None)
   # Capstone may render the base as x29 instead of fp.
   if store is None:store=next((i for i in ins if i.mnemonic=='stp'and i.reg_name(i.operands[0].reg).startswith('w')and i.reg_name(i.operands[2].mem.base)=='x29'),None)
   if store is not None:
    tagreg=store.reg_name(store.operands[0].reg);opreg=store.reg_name(store.operands[1].reg);proj,live=projection(store.address,lo,[tagreg,opreg],{'x29','x19'}if op==0xa70e6eb4 else{'x29'});c['record_constructor']={'store_PC':hex(store.address),'store_bytes_hex':bytes(store.bytes).hex(),'tag_register':tagreg,'operation_register':opreg,'record_relative_to_FP_bytes':store.operands[2].mem.disp-8,'projection':proj,'live_inputs':live,'decoded_tag_contract':'u32(incoming_W19 + 0x1D7B)'if op==0xa70e6eb4 else'0x6CF4'}
   candidates.append(c)
  rows.append({'operation32':hex(op),'handler_entry':hex(entry),'parent_path_index':parent,'first_input_PC':hex(frontier),'head':block(entry,0x800),'literal_candidates':candidates})
 return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_core_dispatch_symbolic.json','daemon_receive_tools.py','recover_daemon_iokit_census.py','daemon_mig_tables.json']},'text_census':{'start':hex(text_section()[0]),'size_bytes':n,'aligned_pairs_checked':(n-4)//4,'scope':'Adjacent MOVZ Wn low16; MOVK same Wn high16, shift16. Computed/nonadjacent/X-register/non-text materializations excluded.'},'function_starts_source':starts_source,'handlers':rows,'native_target_executed':False,'idb_mutated':False,'new_port_emission_established':False,'full_goal_complete':False}
if __name__=='__main__':
 r=capture();(ROOT/'daemon_operation_heads_source.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps([{'operation':x['operation32'],'head_end':x['head']['end'],'literal_PCs':[v['pc']for v in x['literal_candidates']]}for x in r['handlers']]),flush=True)
