#!/usr/bin/env python3
"""Private original host-slot/send-reference/no-senders components and kext import.
O(visits+RAM+effects), O(image+RAM+journals). Locks/PAC and environmental objects
remain explicit premises; no native rights, notifications or allocator operations.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kernel_vm_mig import Probe as CPU,P,SIZE,SP,HALT
from probe_rpc502_vm_handoff import compressed,decode
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
PREFIX='kernel_send_right_lifecycle';PORT=P+0x83000;PORT2=P+0x83800;NOTIFY=P+0xc0000;THREAD=P+0x2c000;OUT=P+0x16000;HOST=0xfffffe000cad0238;META=P+0x9c000;METABASE=META-(((P+0x68000)>>10)&0xffffffff0)
ENTRIES={'host_priv':0xfffffe000bcf27ac,'acquire':0xfffffe000bcf258c,'release':0xfffffe000bcd0448}
def qregs(u):return[hex(u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]
def port_bytes(refs=3,send=2,active=True,request=0,sonce=0):
 b=bytearray(144);struct.pack_into('<II',b,0,1|(0x100 if active else 0),refs);struct.pack_into('<Q',b,0x50,request);struct.pack_into('<III',b,0x84,7,send,sonce);return bytes(b)
class Probe(CPU):
 def __init__(self,im,c,src,parent=None,index=None,kext=None,acquired=None):
  super().__init__(im,'selector',{'id':0});self.kind='send_right_lifecycle';self.c=c;self.initial=[];self.entry=ENTRIES[c['phase']];self.allowed=[(int(f['start'],16),int(f['end'],16))for f in src['functions']];self.auth=[];self.frames=[];self.transfer=None;self.imports=[];self.entryQ=None;self.returnpc=HALT;self.packet=None
  if kext is not None:
   self.transfer={'path':'kext_vm_copyout_bridge_profiles.json','case':7,**kext['final_private_RAM']};self.u.mem_write(P,decode(self.transfer))
   for e in kext['final_image_globals']:self.image_fixture(int(e['address'],16),bytes.fromhex(e['bytes_hex']),'Exact existing kext release-frontier globals')
   for j,x in enumerate(kext['boundary']['registers31']):self.set(j,int(x,16))
   self.u.reg_write(ar.UC_ARM64_REG_SP,int(kext['boundary']['SP'],16));self.u.reg_write(ar.UC_ARM64_REG_NZCV,int(kext['boundary']['NZCV'],16));self.returnpc=self.reg(30)
   for j,x in enumerate(kext['final_Q_registers32']):self.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),int(x,16))
   self.entryQ=kext['final_Q_registers32'];b=bytes.fromhex(acquired['final_ports144_hex'][hex(PORT)]);self.fixture(PORT,b);self.imports.append({'address':hex(PORT),'bytes_hex':b.hex(),'producer_case':1,'reason':'Exact source-produced acquired-port object replaces opaque port placeholder'})
  elif parent is not None:
   self.transfer={'path':PREFIX+'_profiles.json','case':index,**parent['final_private_RAM']};self.u.mem_write(P,decode(self.transfer))
   for e in parent['final_image_globals']:self.image_fixture(int(e['address'],16),bytes.fromhex(e['bytes_hex']),'Exact previous component final-global transfer')
  else:
   for a,b in[(PORT,port_bytes(c.get('refs',3),c.get('send',2),c.get('active',True),NOTIFY if c.get('notification')else 0)),(PORT2,port_bytes(5,1)),(NOTIFY,port_bytes(2,0,c.get('notify_active',True),sonce=1)),(OUT,b'\xa5'*8),(THREAD+0x518,struct.pack('<I',0x1234))]:self.fixture(a,b)
  self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,THREAD)
  for a in[PORT,PORT2,NOTIFY]:self.fixture(METABASE+((a>>10)&0xffffffff0),struct.pack('<H',0x16))
  self.image_fixture(0xfffffe0007e66e50,struct.pack('<QQ',P,P+SIZE),'Declared valid object arena bounds');self.image_fixture(0xfffffe0007e66f00,struct.pack('<Q',METABASE),'Declared zone metadata index base')
  if parent is None and kext is None:
   for a,b in[(HOST+8,bytes(8)),(HOST+0x10+17*8,struct.pack('<Q',0 if c.get('empty_slot')else PORT)),(HOST+0x10+34*8,struct.pack('<Q',PORT2)),(0xfffffe000cb0bc50,bytes(4))]:self.image_fixture(a,b,'Declared host slots, unlocked host and zero lock policy word')
  if kext is None:
   if c['phase']=='acquire':
    for j,x in enumerate([HOST,0xffffffff,c.get('slot',17),OUT]):self.set(j,x)
   elif c['phase']=='release':self.set(0,c.get('port',PORT))
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entrySP=hex(self.u.reg_read(ar.UC_ARM64_REG_SP));self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def image_fixture(self,a,b,why):self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':why})
 def write(self,u,t,a,n,v,d):
  assert P<=a<a+n<=P+SIZE or HOST+8<=a<a+n<=HOST+16,(hex(a),n)
  e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e)
 def code(self,u,a,n,d):
  self.flush()
  if a==self.returnpc:return self.stop('returned_to_actual_caller'if self.returnpc!=HALT else'returned')
  if a in[0xfffffe000c6340d8,0xfffffe000c641fa8,0xfffffe000c629ddc,0xfffffe000bcc922c]:return self.stop('before_validation_or_final_retirement')
  if a==0xfffffe000bcf55dc:
   self.packet={'address':hex(self.reg(0)),'bytes44_hex':bytes(u.mem_read(self.reg(0),44)).hex(),'arguments5':[hex(self.reg(j))for j in range(5)],'call_site':hex(self.reg(30)-4)};return self.stop('before_notification_send')
  if a in[0xfffffe000bd0aecc,0xfffffe000bd0ab18]:return self.model(a,'port_lock_model'if a==0xfffffe000bd0aecc else'port_unlock_model',0)
  if a in ENTRIES.values()or a in[0xfffffe000bcd00bc,0xfffffe000bcc8f4c,0xfffffe000bcce494]:self.frames.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments4':[hex(self.reg(j))for j in range(4)]})
  if any(x<=a<z for x,z in self.allowed):
   raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a))
   if i.mnemonic=='autda':
    assert raw==self.image.k.read(a,4);self.auth.append({'pc':hex(a),'pointer':hex(self.reg(16)),'modifier':hex(self.reg(17))});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
   if i.mnemonic=='brk':return self.stop('before_original_trap',{'immediate':i.op_str})
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=10000);self.flush();assert self.reason is not None,self.visits[-2:];self.ensure(HOST+8,8)
  addresses=list(dict.fromkeys((int(e['address'],16),len(e['bytes_hex'])//2)for e in self.image_initial))
  return{'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':self.entrySP,'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'entry_Q_registers32':self.entryQ,'final_Q_registers32':qregs(self.u),'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'initial_state_transfer':self.transfer,'port_object_imports':self.imports,'private_system_register_fixtures':[{'register':'TPIDR_EL1','value':hex(THREAD)}],'logical_data_authentication':self.auth,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'entry_frames':self.frames,'boundary':self.boundary,'notification_packet':self.packet,'final_ports144_hex':{hex(a):bytes(self.u.mem_read(a,144)).hex()for a in[PORT,PORT2,NOTIFY]},'output_name_or_pointer_u64':int.from_bytes(bytes(self.u.mem_read(OUT,8)),'little'),'final_host_lock8_hex':bytes(self.u.mem_read(HOST+8,8)).hex(),'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),'final_image_globals':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()}for a,n in addresses],**{k:False for k in FLAGS}}
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());rows=[]
 def add(c,parent=None,index=None,**kw):
  r=Probe(im,c,src,parent,index,**kw).run();rows.append(r);print(json.dumps({'case':len(rows)-1,'config':c,'visits':len(r['source_visits']),'boundary':r['boundary']['kind']}),flush=True)
 add({'phase':'host_priv'});add({'phase':'acquire','slot':17});add({'phase':'release'},rows[1],1);add({'phase':'acquire','slot':34});add({'phase':'release','port':PORT2},rows[3],3)
 add({'phase':'acquire','slot':17,'empty_slot':True});add({'phase':'acquire','slot':0});add({'phase':'acquire','slot':37});add({'phase':'release','port':0});add({'phase':'release','port':(1<<64)-1})
 add({'phase':'release','send':1});add({'phase':'release','send':1,'notification':True});add({'phase':'release','send':1,'notification':True,'notify_active':False});add({'phase':'release','send':1,'refs':1,'active':False});add({'phase':'release','send':1,'refs':2,'active':False});add({'phase':'release','send':0});add({'phase':'release','send':1,'refs':0})
 add({'phase':'acquire','slot':17,'send':0xfffffffe});add({'phase':'release'},rows[17],17);add({'phase':'acquire','slot':17,'send':0x7fffffff});add({'phase':'acquire','slot':17,'send':0xffffffff})
 kext=json.loads((ROOT/'kext_vm_copyout_bridge_profiles.json').read_text())['cases'][7];add({'phase':'release','kext_caller_import':True},kext=kext,acquired=rows[1])
 deps=[PREFIX+'_source.json','kext_vm_copyout_bridge_profiles.json','probe_kernel_vm_mig.py','probe_rpc502_vm_handoff.py','kernel_vm_mig_tools.py','recover_kernel_send_right_lifecycle.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'cases':rows,**{k:False for k in FLAGS}};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
