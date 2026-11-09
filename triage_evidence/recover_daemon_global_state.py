#!/usr/bin/env python3
"""Recover self-image section, source blocks and encoded window interfaces.
O(image bytes+source bytes+512 bank inputs) time, O(image+source rows) space.
"""
import json,struct,hashlib
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,POOL,selected,verify_original_fixups
from resolve_kernel_collection_interfaces import commands
SPANS=[('section_publication',0x10031ed34,0x10031ed64),('section_size_publication',0x1003875a0,0x1003875bc),('range_prekey',0x1003f1390,0x1003f15e0),('floor_log2',0x1003f15e0,0x1003f176c),('range_split',0x1003f176c,0x1003f17b0),('span_codec_part1',0x1003f17f8,0x1003f1820),('span_codec_part2',0x1003f182c,0x1003f1844),('span_destination',0x1003f1844,0x1003f1854),('selection_offset',0x1003f1854,0x1003f1898),('offset_codec',0x1003f18cc,0x1003f18e0),('offset_destination',0x1003f18ec,0x1003f18fc),('window_address_codec',0x1003f18fc,0x1003f19e0),('window_mask_codec',0x1003f19e0,0x1003f19fc),('complete_window_block',0x1003f1390,0x1003f19fc)]
def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 spans=[]
 for label,a,z in SPANS:
  raw=IMAGE.read(a,z-a);ins=list(CS.disasm(raw,a));assert sum(i.size for i in ins)==len(raw);spans.append({'label':label,'start':hex(a),'end':hex(z),'bytes_hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins]})
 sections=[]
 for at,cmd,size in commands(IMAGE.data,0):
  if cmd!=0x19:continue
  count=struct.unpack_from('<I',IMAGE.data,at+64)[0]
  for j in range(count):
   off=at+72+j*80;name,segment=struct.unpack_from('<16s16s',IMAGE.data,off);addr,n=struct.unpack_from('<QQ',IMAGE.data,off+32)
   if name.rstrip(b'\0')==b'__text':sections.append({'section':name.rstrip(b'\0').decode(),'segment':segment.rstrip(b'\0').decode(),'header_file_offset':hex(off),'segment_command_file_offset':hex(at),'address':hex(addr),'size_bytes':n,'size_hex':hex(n),'end':hex(addr+n),'header_bytes_hex':IMAGE.data[off:off+80].hex()})
 assert len(sections)==1 and sections[0]['address']=='0x100001058'and sections[0]['size_hex']=='0xe297a8'
 banks=[selected(0x100e99700,0x100f4e190,0x56,0x10a,base=POOL,bias=-0x46e390be),selected(0x101031da0,0x100e99900,0xa,0xb4,base=POOL,bias=-0x2a9ae63e)];assert [b['target']for b in banks]==['0x1010b70d8','0x1010b83a0'];fixups=verify_original_fixups([int(b['slot'],16)for b in banks])
 ida=json.loads((ROOT/'daemon_global_state_live_ida.json').read_text());payload=[v['text']for v in ida['content']if v['type']=='text'and '[assist:tool-output]'in v['text']];rows=0;unique={}
 if payload:
  data=json.loads(payload[0].split('[assist:tool-output]\n',1)[1].split('\n[/assist:tool-output]',1)[0])
  for result in data['results']:
   for row in result['instructions']:
    a=int(row['address'],16);raw=bytes.fromhex(row['bytes']);assert IMAGE.read(a,len(raw))==raw;rows+=1;unique[a]=row
 else:assert ida.get('isError')and 'matching authenticated bridge worker is unavailable'in ida['content'][0]['text']
 S=sections[0]['size_bytes'];v=S-16;n=v.bit_length()-1;L=1<<min(n,15);mask=(v-L)&~0xfff;bits=[j for j in range(64)if mask>>j&1];offsets=sorted(sum(((q>>k)&1)<<bit for k,bit in enumerate(bits))for q in range(1<<len(bits)))
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{name:sha(ROOT/name)for name in ['daemon_global_state_lift.py','daemon_global_state_live_ida.json','daemon_buffer_consumer_profiles.json','daemon_global_state_observations.json','daemon_receive_tools.py','daemon_receive_fixups.txt']},'source_sha256':sha(SOURCE),'spans':spans,'text_section':sections[0],'bank_rules':banks,'source_fixups':fixups,'live_IDB_available':bool(payload),'live_IDB_rows_matched':rows,'unique_live_IDB_rows_matched':len(unique),'codecs':{'span_add64':'0x00e2c06c277e3e38','offset_xor64':'0x34936dc72afd2f98','address_xor64':'0x12af5504870a589f','mask_xor64':'0xfff0c012a7a730ec','intermediate_offset_xor64':'0xaca72517860a6000','range_prekey_xor64':'0x840204b3d6b78667'},'current_image_window':{'v':hex(v),'floor_log2':n,'window_length_bytes':L,'span_delta':hex((1<<n)-(1<<15)),'offset_mask':hex(mask),'selected_Q_bits':bits,'possible_offsets_hex':[hex(a)for a in offsets],'possible_offset_count':len(offsets),'native_distribution_claimed':False},'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_global_state_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'source_spans':len(spans),'fixups':len(fixups['records']),'IDB_rows':rows,'unique_IDB_rows':len(unique),'text_section':sections[0]['address'],'size':S,'possible_offsets':len(offsets)}),flush=True)
if __name__=='__main__':main()
