#!/usr/bin/env python3
"""Static source SSA with explicit little-endian forwarding of private-frame bytes."""
import re
from validate_daemon_mode_one_word_schedule import Engine as Parent
from validate_daemon_existing_scalar_reader import bv
from validate_daemon_list_output import split
class FrameSSA(Parent):
 def __init__(self,name,regs=None,presets=None,loads=None):
  super().__init__({**{j:'Z'+str(j)for j in range(31)},'sp':'K',**(regs or{})},{},namespace=name+'_',frame_cells=None)
  self.byte_cells={};self.initial=[];self.frame_reads=[];self.frame_writes=[];self.external=[];self.decl={};self.loaded=0;self.supplied_loads=loads or{};self.cuts=[]
  for off,(value,w)in(presets or{}).items():self.save(off,value,w,'entry premise')
 def save(self,off,value,w,origin):
  assert w in[8,32,64]
  for j in range(w//8):self.byte_cells[off+j]=(f'((_ extract {j*8+7} {j*8}) {value})',origin)
 def loadframe(self,off,w):
  missing=[j for j in range(w//8)if off+j not in self.byte_cells]
  if missing:
   name=f'IF_{off:x}_{w}';assert name not in self.decl;self.decl[name]=w;self.initial.append({'frame_offset':off,'width_bits':w,'symbol':name,'new_byte_offsets':[off+j for j in missing]})
   for j in missing:self.byte_cells[off+j]=(f'((_ extract {j*8+7} {j*8}) {name})','entry input')
  parts=[self.byte_cells[off+j][0]for j in reversed(range(w//8))];value=parts[0]
  for part in parts[1:]:value=f'(concat {value} {part})'
  return value
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   m=i['mnemonic'];p=split(i['operands']);w=8 if m in['ldrb','strb']else 32 if p[0].startswith('w')else 64;off=None
   if m in['ldr','ldrb','str','strb']:
    match=re.fullmatch(r'\[sp(?:, #(0x[0-9a-f]+))?\]',p[1]);off=int(match[1],16)if match and match[1]else 0 if match else None
    if m in['ldr','ldrb']:
     if off is not None:
      value=self.loadframe(off,w);self.frame_reads.append({'site':i['ea'],'frame_offset':off,'width_bits':w,'value':value,'origins':[self.byte_cells[off+j][1]for j in range(w//8)]})
     else:
      value='L'+str(self.loaded);self.loaded+=1
      if i['ea']in self.supplied_loads:value,bits=self.supplied_loads[i['ea']];assert bits==w
      else:self.decl[value]=w
      self.external.append({'site':i['ea'],'symbol_or_value':value,'width_bits':w,'supplied_from_original_image':i['ea']in self.supplied_loads})
     self.loads[i['ea']]=(value,w)
   if m=='neg':self.put(p[0],f'(bvneg {self.get(p[1],w)})');self.sites.append(i['ea'])
   elif m=='extr':
    n=int(p[3][1:],0);assert 0<=n<w;self.put(p[0],f'((_ extract {w-1} 0) (bvlshr (concat {self.get(p[1],w)} {self.get(p[2],w)}) {bv(n,2*w)}))');self.sites.append(i['ea'])
   elif m=='adrp':self.put(p[0],bv(int(p[1][1:],0)));self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
   if off is not None and m in['str','strb']:
    value=self.stores[-1]['value'];self.save(off,value,w,i['ea']);self.frame_writes.append({'site':i['ea'],'frame_offset':off,'width_bits':w,'value':value})
  return self
 def record_full(self):
  return {**self.record(),'source_SSA':self.prefix(),'declarations':self.decl,'initial_frame_inputs':self.initial,'frame_reads':self.frame_reads,'frame_writes':self.frame_writes,'external_reads':self.external,'final_registers':self.r,'final_frame_bytes':self.byte_cells,'source_cuts':self.cuts}
def lookup(values,expr,w=8):
 out=bv(values[-1],w)
 for j in reversed(range(len(values)-1)):out=f'(ite (= {expr} {bv(j,w)}) {bv(values[j],w)} {out})'
 return out
