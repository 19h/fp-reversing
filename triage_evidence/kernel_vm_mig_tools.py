#!/usr/bin/env python3
"""Original KC subsystem metadata and deterministic pre-startup hash model.
No target execution. O(collection bytes + fixups + routines + collisions)
time, O(collection + fixups + 1031 hash entries) space.
"""
import struct
from collections import defaultdict
from kernel_native_reader import Kernel
from resolve_kernel_collection_interfaces import chained_rebases
REGISTRY=0xfffffe000ca87018;SUBSYSTEM=0xfffffe0007e68088;ROUTINES=SUBSYSTEM+0x20
HASH=0xfffffe0007e5cab8;SLOTS=1031;MAXPROBE=0xfffffe0007e62b60;COUNT=0xfffffe0007f13f60
INIT=0xfffffe000c62a46c;SELECTOR=0xfffffe000bd8b33c;STUB=0xfffffe000bd8b18c
DISPATCH=0xfffffe000bcf4154;LEAF=0xfffffe000bdc1ec0;CONVERT=0xfffffe000bcfae94;RELEASE=0xfffffe000bdcade0
NDR=0xfffffe000ca92798
class Image:
 def __init__(self):
  self.k=Kernel();self.base,self.rebases,self.meta=chained_rebases(self.k.data);self.pages=defaultdict(list)
  for off,row in self.meta.items():
   s=next(s for s in self.k.root['segments']if s['file_offset']<=off< s['file_offset']+s['file_size']);a=s['address']+off-s['file_offset'];self.pages[a&~4095].append((a,row))
 def offset(self,a):
  s=next(s for s in self.k.root['segments']if s['address']<=a<s['address']+s['file_size']);return s['file_offset']+a-s['address']
 def pointer(self,a):
  o=self.offset(a);assert o in self.meta;return{'slot':hex(a),'file_offset':hex(o),**self.meta[o]}
 def logical_page(self,a):
  raw=bytearray(self.k.read(a,4096))
  for at,row in self.pages[a]:raw[at-a:at-a+8]=int(row['target'],16).to_bytes(8,'little')
  return bytes(raw)
 def subsystems(self):
  rows=[]
  for j in range(20):
   p=self.pointer(REGISTRY+8*j);a=int(p['target'],16);start,end,maximum=struct.unpack('<3I',self.k.read(a+8,12));assert start and end>=start and end-start<512 and maximum<=0x3fbc;records=[]
   for index in range(end-start):
    at=a+0x20+32*index;word=self.k.read(at+8,8);stub=self.pointer(at+8)if word!=bytes(8)else None;arity,field14,descriptors,reply=struct.unpack('<4I',self.k.read(at+0x10,16))
    if stub:assert int(stub['target'],16)in self.k.starts and reply
    records.append({'id':start+index,'index':index,'address':hex(at),'bytes_hex':self.k.read(at,32).hex(),'stub':stub,'arity_word10':arity,'word14':field14,'reply_descriptor_word18':descriptors,'reply_size_word1c':reply})
   rows.append({'registry_index':j,'registry_pointer':p,'address':hex(a),'selector':self.pointer(a),'start':start,'end':end,'maximum':maximum,'header_bytes_hex':self.k.read(a,32).hex(),'routines':records})
  assert rows[0]['address']==hex(SUBSYSTEM)and(rows[0]['start'],rows[0]['end'])==(4800,4830);return rows
 def hash_model(self,subsystems):
  assert self.k.read(HASH,SLOTS*24)==bytes(SLOTS*24)and self.k.read(MAXPROBE,4)==bytes(4)and self.k.read(COUNT,4)==bytes(4);table=[None]*SLOTS;maximum=0;insertions=[]
  for sub in subsystems:
   for routine in sub['routines']:
    if routine['stub']is None:continue
    mid=routine['id'];index=mid%SLOTS;probe=1
    while table[index]is not None:
     assert table[index]['id']!=mid and probe<SLOTS;index=(index+1)%SLOTS;probe+=1
    record={'id':mid,'index':index,'address':hex(HASH+24*index),'stub':routine['stub'],'reply_size':routine['reply_size_word1c'],'reply_descriptors':routine['reply_descriptor_word18'],'policy_word4':0xffffffff,'probe_count':probe};table[index]=record;insertions.append(record);maximum=max(maximum,probe)
  return {'table':table,'insertions':insertions,'maximum_probe':maximum,'inserted_count':len(insertions),'final_count_word':len(insertions)+32,'empty_initial_image_is_a_private_premise':True,'native_initialization_attested':False}
