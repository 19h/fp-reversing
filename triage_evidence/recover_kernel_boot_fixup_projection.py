#!/usr/bin/env python3
"""Original boot fixup metadata and page-exact logical projection.
O(collection + fixups + source bytes) time/space; no native execution.
"""
import json,struct
from collections import Counter,defaultdict
from hashlib import sha256
from kernel_native_reader import Kernel
from kernel_vm_mig_tools import Image
from resolve_kernel_collection_interfaces import commands
from recover_kernel_boot_environment_publication import capture
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import sha
P='kernel_boot_fixup_projection';BOOT=0xfffffe000c66058c;HEAD=0xfffffe000c660948;END=0xfffffe000c660a14;FAIL=0xfffffe000c660a04;BANK=0xfffffe0007004000
SCOPE='Original boot fixup source relations, independent full-corpus chain decoding and page-exact logical targets. Eight cross-page fixups corrected in a separate view; prior artifacts preserved. Source prefix/finite cuts and corrected-reader signing rechecks do not constitute full boot execution or native PAC.'
def address(k,off):
 s=next(s for s in k.root['segments'] if s['file_offset']<=off<s['file_offset']+s['file_size']);return s['address']+off-s['file_offset']
def chains(k):
 command=next(at for at,c,n in commands(k.data,0) if c==0x80000034);off,length=struct.unpack_from('<II',k.data,command+8);version,start,imports,symbols,count,fmt,symfmt=struct.unpack_from('<7I',k.data,off);assert version==count==0;starts=off+start;segments=struct.unpack_from('<I',k.data,starts)[0];assert segments==len(k.root['segments'])
 for segment in range(segments):
  delta=struct.unpack_from('<I',k.data,starts+4+4*segment)[0]
  if not delta:continue
  info=starts+delta;size,page_size,pointer_format,vmoff,max_valid,pages=struct.unpack_from('<IHHQIH',k.data,info);assert pointer_format==8 and info+size<=off+length;seg=k.root['segments'][segment];assert seg['address']==BANK+vmoff
  for page in range(pages):
   start=struct.unpack_from('<H',k.data,info+22+2*page)[0]
   if start==0xffff:continue
   assert not start&0x8000 and start<page_size
   at=seg['file_offset']+page*page_size+start;rows=[];limit=seg['file_offset']+(page+1)*page_size
   while True:
    assert at<limit and at+8<=seg['file_offset']+seg['file_size'];word=struct.unpack_from('<Q',k.data,at)[0];cache=(word>>30)&3;assert cache==0;slot=address(k,at);target=(BANK+(word&0x3fffffff))&((1<<64)-1);div=(word>>32)&0xffff;adiv=(word>>48)&1;auth=word>>63;key=(word>>49)&3;modifier=div if not adiv else (slot if div==0 else (slot&0xffffffffffff)|(div<<48));step=((word>>51)&0xfff)*4
    rows.append({'file_offset':at,'slot':slot,'raw':word,'target':target,'auth':auth,'key':key,'address_diversity':adiv,'diversity':div,'modifier':modifier if auth else 0,'step':step})
    if not step:break
    at+=step
   yield {'segment_index':segment,'segment_name':seg['name'],'page_index':page,'page_size_bytes':page_size,'start_offset':start,'metadata_address':hex(address(k,info)),'rows':rows}
def digest(rows):
 h=sha256()
 for r in rows:h.update(struct.pack('<QQQQIBBB',r['slot'],r['raw'],r['target'],r['modifier'],r['step'],r['auth'],r['key'],r['address_diversity']))
 return h.hexdigest()
class CorrectedImage(Image):
 def __init__(self,base=None):
  if base is None:super().__init__()
  else:self.__dict__.update(base.__dict__)
  self.incoming=defaultdict(list)
  for pg,rows in list(self.pages.items()):
   for a,row in rows:
    if (a&4095)+8>4096:self.incoming[pg+4096].append((a,row))
 def logical_page(self,pg):
  raw=bytearray(self.k.read(pg,4096))
  for a,row in [*self.pages.get(pg,[]),*self.incoming.get(pg,[])]:
   lo,hi=max(a,pg),min(a+8,pg+4096);target=int(row['target'],16).to_bytes(8,'little');raw[lo-pg:hi-pg]=target[lo-a:hi-a]
  assert len(raw)==4096;return bytes(raw)
def build():
 k=Kernel();receipts=[];counts=Counter();cross=[];samples=[];slot_ranges=[]
 for chain in chains(k):
  rows=chain.pop('rows');receipts.append({**chain,'pointer_count':len(rows),'first_slot':hex(rows[0]['slot']),'last_slot':hex(rows[-1]['slot']),'ordered_records_sha256':digest(rows)});counts['fixups']+=len(rows)
  for r in rows:
   counts['auth'+str(r['auth'])]+=1;counts['cache_level0']+=1
   if r['auth']:counts['key'+str(r['key'])]+=1;counts['address_diversity'+str(r['address_diversity'])]+=1
   slot_ranges.append(r['slot'])
   if r['slot']&4095>4088:cross.append({k:(hex(v) if k in ['file_offset','slot','raw','target','modifier'] else v) for k,v in r.items()})
   if len(samples)<4 or r['auth'] and r['key']==2 and not any(x['auth'] and x['key']==2 for x in samples):samples.append(r)
 ordered=sorted(slot_ranges);assert len(set(ordered))==len(ordered) and all(b-a>=8 for a,b in zip(ordered,ordered[1:]));counts['chain_pages']=len(receipts);counts['cross_4KiB_fixups']=len(cross);counts['affected_4KiB_pages']=len({p for r in cross for p in [int(r['slot'],16)&~4095,(int(r['slot'],16)&~4095)+4096]})
 functions=[capture(k,BOOT),capture(k,0xfffffe000c6626e4)];command=next(at for at,c,n in commands(k.data,0) if c==0x80000034);off,size=struct.unpack_from('<II',k.data,command+8)
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'kernel_collection_sha256':k.sha256,'functions':functions,'metadata':{'command_file_offset':hex(command),'data_file_offset':hex(off),'data_address':hex(address(k,off)),'bytes_hex':k.data[off:off+size].hex()},'chain_page_receipts':receipts,'cross_page_fixups':cross,'source_CPU_samples':samples,'ordered_fixup_record_format':'Little-endian Q slot,Q raw,Q logical_target,Q effective_modifier,I next_step_bytes,B auth,B key,B address_diversity; modifier zero for unauthenticated words.','verified_counts':dict(counts),'fixup_slots_nonoverlapping':True,'prior_artifacts_unchanged':True,'native_target_executed':False}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
