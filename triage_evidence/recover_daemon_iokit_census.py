#!/usr/bin/env python3
"""Bounded daemon modifier census, query22/23 source and kext counterpart contracts.

O(B+I+256R+F) time/space. LC_FUNCTION_STARTS gives shared envelopes, not
semantic function bounds. No native IOKit, Mach, query provider or IDB mutation.
"""
import hashlib,json,struct,bisect
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,TABLE,selected,verify_original_fixups,qword
from daemon_import_bindings import binding
from recover_rpc502_parser_ownership import starts
from kernel_native_reader import Kernel
from recover_carrier_control import span
from recover_kext_cold_init import pointer
from recover_kext_aes_handoff import function
from kext_port_tools import IMAGE as KIMAGE,SOURCE as KSOURCE
from resolve_kernel_collection_interfaces import commands
SPANS=[('query22',0x100364398,0x100364470),('query22_failure_clear',0x100628754,0x10062876c),('query23',0x1004ba914,0x1004baa18),('query23_success',0x100332734,0x10033274c),('query23_failure_clear',0x1004d6be4,0x1004d6c10)]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def native(name,a,z):
 raw=IMAGE.read(a,z-a);return {'label':name,'start':hex(a),'end':hex(z),'bytes_hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)]}
def text_section():
 for at,cmd,n in commands(IMAGE.data,0):
  if cmd!=0x19:continue
  for j in range(struct.unpack_from('<I',IMAGE.data,at+64)[0]):
   p=at+72+80*j;name=IMAGE.data[p:p+16].split(b'\0')[0].decode()
   if name=='__text':
    a,n=struct.unpack_from('<QQ',IMAGE.data,p+32);return a,n
 raise AssertionError('no __text')
def census():
 a,n=text_section();raw=IMAGE.read(a,n);pattern=bytes.fromhex('914d8fd211093fd7');pos=0;rows=[];bounds,meta=starts()
 while True:
  pos=raw.find(pattern,pos)
  if pos<0:break
  if pos%4==0:
   pc=a+pos+4;start=max(a,pc-0x90);s=native('candidate',start,pc+4);j=bisect.bisect_right(bounds,pc)-1;selectors=[i for i in s['instructions']if i['mnemonic']=='mov'and i['operands'].startswith('w1, #')];s.update(call_PC=hex(pc),literal_W1_candidate=None if not selectors else selectors[-1]['operands'].split('#')[1],compiler_envelope_start=hex(bounds[j]),compiler_envelope_end=hex(bounds[j+1]),target_proved_by_modifier=False);rows.append(s)
  pos+=1
 return {'text_address':hex(a),'text_size_bytes':n,'text_sha256':hashlib.sha256(raw).hexdigest(),'exact_pattern_hex':pattern.hex(),'candidates':rows,'scope':'Aligned exact MOVZ X17,#7a6c;BLRAA X8,X17 pattern only. Other registers/forms and computed modifiers/selectors are outside this census.','LC_FUNCTION_STARTS':meta,'compiler_start_count':len(bounds)}
def main():
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');cc=census();assert len(cc['candidates'])==24;spans=[native(*r)for r in SPANS];banks=[]
 for name,l,r,key,add in[('query22',0x100e99a00,0x100f4e390,0x6d,0xcc1a),('query23',0x101031da0,0x100e99900,0x86,0xcc92)]:
  b=selected(l,r,key,add,TABLE,0);assert b['target']=='IOKit/_IOConnectCallStructMethod';b.update(label=name,left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex());banks.append(b)
 slots=[0x1010a44b0,0x1010a4a58,0x101083aa0,0x101083af0,0x101063000,0x10104f638,0x10104f728,0x10106d450];ptr=verify_original_fixups(slots);collision=[{'address':hex(a),**r}for a,r in FIXUPS.items()if 'div=0x7A6C 'in r['line']];assert len(collision)==4
 q=[];kspans=[]
 for sel,method,start,end,off,core in[(22,'ucGetVersion',0xfffffe000a5050c8,0xfffffe000a505120,0x8c0,0xfffffe000a5a299c),(23,'ucGetProtocolCapabilities',0xfffffe000a505120,0xfffffe000a505178,0x8c8,0xfffffe000a5a49d8)]:
  descriptor=pointer(k,0xfffffe000846b770+(sel-1)*8);record=int(descriptor['target'],16);fields=struct.unpack('<6Q',KIMAGE.read(record,48));assert fields[3:]==(3,0,4)and fields[1]==start;provider=pointer(k,0xfffffe000846b8d0+off);stub=function(k,e,int(provider['target'],16));assert stub['instructions'][-1]['operands']=='#'+hex(core);s=span(k,start,end);s['label']=method;kspans.append(s);s=span(k,core,core+0x60);s['label']=method+'_core_prefix';kspans.append(s)
  q.append({'selector':sel,'method':method,'descriptor_pointer':descriptor,'descriptor_original48_hex':k.read(record,48).hex(),'descriptor_normalized_fields6':[hex(v)for v in fields],'method_pointer':pointer(k,record+8),'provider_slot':provider,'provider_stub':stub,'core_target':hex(core),'core_return_value_known':False})
 live=json.loads((ROOT/'daemon_iokit_census_live_ida.json').read_text());matched=[]
 for row in live['open_code']['results']:
  for ins in row['instructions']:
   raw=bytes.fromhex(ins['bytes']);assert IMAGE.read(int(ins['address'],16),len(raw))==raw;matched.append({'PC':ins['address'],'size_bytes':len(raw)})
 for row in live['bank_bytes']:
  if row['address']=='0x1010a0640':assert int.from_bytes(bytes.fromhex(row['hex']),'little')==0x1010ca388
  else:assert IMAGE.read(int(row['address'],16),len(bytes.fromhex(row['hex']))).hex()==row['hex']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt','recover_rpc502_parser_ownership.py','kernel_native_reader.py','recover_carrier_control.py','recover_kext_cold_init.py','recover_kext_aes_handoff.py','daemon_iokit_census_live_ida.json']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'kext_sha256':sha(KSOURCE),'census':cc,'spans':spans,'bank_rules':banks,'original_fixup_records':ptr,'API_binding':binding(0x1010a0640),'modifier_collision_pointers':collision,'query23_root_values':[hex(qword(a))for a in slots[:2]],'kext_query_contracts':q,'kext_spans':kspans,'exact_kext_symbols':k.symbols([0xfffffe000846b8c0,*[int(x['provider_slot']['target'],16)for x in q],*[int(s['start'],16)for s in kspans]]) ,'live_IDB_source_rows_matched':matched,'source_entry_premises':{'W21':'0x9376','X24_TABLE':hex(TABLE),'SP8_connection_output_pointer':'fixture','SP10_left_bank':'0x100e99a00','SP28_right_bank':'0x100f4e390','normal_native_open_or_table_reachability_proved':False},'actual_selector18_caller_established':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_iokit_census_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'syntactic_candidates':24,'source_spans':len(spans),'banks':2,'kext_queries':2,'live_IDB_instruction_rows_matched':len(matched)}),flush=True)
if __name__=='__main__':main()
