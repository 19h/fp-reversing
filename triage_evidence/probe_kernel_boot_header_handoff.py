#!/usr/bin/env python3
"""Private cold-entry, original tagged lists/copies and root consumers.
O(visits + journals + RAM) time/space. Hardware/callback contracts explicit.
"""
import json,struct
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
from probe_rpc502_vm_handoff import compressed,decode
import recover_kernel_boot_header_handoff as R
import probe_kernel_sptm_boot_inputs as B
P=B.P;SIZE=B.SIZE;SP=B.SP;HALT=B.HALT;BOOTARGS=P+0x3c000;STACK0=0xfffffe000cbb4000;STACK1=0xfffffe000cbbc000
NEW_LEAVES={R.PREINIT:'declared_self_relocator_no_RAM_effect',**{a:'declared_early_feature_callback_no_RAM_effect' for a in R.CALLBACK_TARGETS},
 0xfffffe000c621194:'declared_vector_registration_no_RAM_effect',0xfffffe000c47cce0:'declared_early_helper_no_RAM_effect'}

def header(c):
 raw=bytearray((j*29+7)&255 for j in range(0x358));struct.pack_into('<Q',raw,0,B.MAGIC if not c.get('bad_magic') else B.MAGIC^1)
 raw[0x1a0:0x2a0]=B.boot_record(c);struct.pack_into('<Q',raw,0x1d8,B.ROOTPA);struct.pack_into('<I',raw,0x68,c['count'])
 for off,fmt,value in [(0x330,'Q',0x1122334455667788),(0x338,'I',0x33445566),(0x340,'Q',0x2233445566778899),(0x348,'I',0x44556677)]:struct.pack_into('<'+fmt,raw,off,value)
 return bytes(raw)

def bootargs(c):
 raw=bytearray((j*17+3)&255 for j in range(0x480));struct.pack_into('<Q',raw,0x60,c.get('DT_base',0x12345000));struct.pack_into('<I',raw,0x68,c.get('DT_size',0x2345));return bytes(raw)

class Probe(B.Probe):
 def __init__(self,image,c,phase,parent=None,mutate=None):
  new=phase in ['dispatch','cold','handoff'];super().__init__(image,c,'loader' if parent is None and new else 'root' if new else phase,parent,mutate)
  self.phase=phase;self.system=[];self.envelopes=[];self.copy_entries=[];self.callback_entries=[];self.stackbanks={0:SP,1:P+0xec000};self.spsel=0
  e=json.loads(read(ROOT/(R.P+'_checks.json')));self.allowed=[(int(f['start'],16),int(f['end'],16)) for f in e['functions']]
  if new:
   if parent is None:
    self.fixture(B.HEADER,header(c));self.fixture(BOOTARGS,bootargs(c))
    self.image_fixture(R.ARGS_DEST,bytes([0x5a])*0x7d8,'Declared poisoned pre-copy destination; original copy is the sole new root/header producer')
    self.image_fixture(R.B.C.BOOTROOT,bytes(8),'Declared initially absent root; later original header copy supplies it')
    self.image_fixture(R.DEVICE_PTR,bytes(8),'Declared unpublished copied-header pointer')
    for at,n in [(0xfffffe0007f8b508,32),(0xfffffe0007ef9168,8),(0xfffffe0007e6d9b8,8),(0xfffffe0007e6d148,8),(0xfffffe000ca93df8,1)]:self.image_fixture(at,R.logical(image,at,n),'Original auxiliary publication fields')
    self.image_fixture(STACK0-16384,bytes([0xa5])*16384,'Declared boot-stack backing; native owner/admission unproved')
    self.image_fixture(R.RECORDS,R.logical(image,R.RECORDS,R.RECORD_END-R.RECORDS),'Original link records with exact logical chained fixups')
    for row in e['link_owner_blocks']:self.image_fixture(int(row['address'],16),bytes.fromhex(row['logical24_hex']),'Original tagged-list owner state with logical fixups')
   if phase=='handoff':
    self.entry=R.COLD+0x68;self.finish_PC=R.MAIN+0xb4;self.set(26,BOOTARGS);self.set(27,B.HEADER);self.u.reg_write(ar.UC_ARM64_REG_SP,STACK0)
   else:
    self.entry=R.ENTRY;self.finish_PC=-1
    self.set(0,c.get('entry_mode',0));self.set(1,BOOTARGS);self.set(2,B.HEADER)
  self.entry_sp=self.u.reg_read(ar.UC_ARM64_REG_SP);self.entry_regs=[hex(self.reg(j)) for j in range(31)];self.before=bytes(self.u.mem_read(P,SIZE))
 def code(self,u,a,n,d):
  self.flush()
  if self.phase=='dispatch' and a in [R.COLD,R.SECONDARY,0xfffffe000c660000,0xfffffe000bc9bbdc]:return self.stop('entry_dispatch_boundary')
  if self.phase=='cold' and a in [R.COLD+0x5c,R.COLD+0x64]:return self.stop('before_original_selector15_opaque_word')
  if a in NEW_LEAVES:
   if a in R.CALLBACK_TARGETS:self.callback_entries.append({'PC':hex(a),'arguments2':[hex(self.reg(j)) for j in range(2)],'modifier_X17':hex(self.reg(17)),'source_visit_index':len(self.visits)})
   return self.model(a,NEW_LEAVES[a],0)
  if a==R.COPY:self.copy_entries.append({'PC':hex(a),'arguments3':[hex(self.reg(j)) for j in range(3)],'return_PC':hex(self.reg(30)),'source_visit_index':len(self.visits)})
  if any(lo<=a<hi for lo,hi in self.allowed):
   raw=bytes(u.mem_read(a,4));dec=list(self.image.k.cs.disasm(raw,a))
   if not dec:return self.stop('before_uncalled_opaque_word')
   i=dec[0]
   if i.mnemonic in ['msr','isb','dsb','ic']:
    row={'PC':hex(a),'source_visit_index':len(self.visits),'mnemonic':i.mnemonic,'operands':i.op_str,'SP_before':hex(u.reg_read(ar.UC_ARM64_REG_SP))}
    if i.mnemonic=='msr' and i.op_str.startswith('spsel'):
     target=int(i.op_str.rsplit('#',1)[1],0);self.stackbanks[self.spsel]=u.reg_read(ar.UC_ARM64_REG_SP);self.spsel=target;u.reg_write(ar.UC_ARM64_REG_SP,self.stackbanks[target])
    elif i.mnemonic=='msr' and i.op_str in ['tpidr_el1, xzr']:u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,0)
    else:assert i.mnemonic in ['isb','dsb','ic'] or i.op_str in ['tpidr_el0, xzr','tpidrro_el0, xzr','vbar_el1, x9'],i.op_str
    row['SP_after']=hex(u.reg_read(ar.UC_ARM64_REG_SP));self.system.append(row);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
   if i.mnemonic in ['blraa','paciza','xpaci']:
    row={'pc':hex(a),'mnemonic':i.mnemonic,'source_visit_index':len(self.visits),'registers31':[hex(self.reg(j)) for j in range(31)]};self.envelopes.append(row);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
    if i.mnemonic=='blraa':self.set(30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,self.reg(int(i.op_str.split(',')[0][1:])))
    else:u.reg_write(ar.UC_ARM64_REG_PC,a+4)
    return
  return super().code(u,a,n,d)
 def run(self):
  out=super().run();out['entry_SP']=hex(self.entry_sp);out['logical_boot_system_effects']=self.system;out['logical_envelopes']=self.envelopes
  out['original_copy_entries']=self.copy_entries;out['early_callback_entries']=self.callback_entries
  out['boot_stack_model']={'bank0_entry':hex(SP),'bank1_entry':hex(P+0xec000),'entry_selection':0,'native_hardware_executed':False}
  return out

def oracle(row):
 phase=row['phase'];c=row['configuration'];checks=[]
 if phase not in ['dispatch','cold','handoff']:return B.oracle(row)
 b=row['boundary'];regs=list(map(lambda v:int(v,16),b['registers31']));wanted={}
 for f in row['initial_image_fixtures']:
  a=int(f['address'],16)
  for j,x in enumerate(bytes.fromhex(f['bytes_hex'])):wanted[a+j]=x
 def put(a,raw):
  assert all(a+j in wanted for j in range(len(raw))),(hex(a),len(raw))
  for j,x in enumerate(raw):wanted[a+j]=x
 def value(a,n):return int.from_bytes(bytes(wanted[a+j] for j in range(n)),'little')
 def check(label,p):assert p,(label,phase,c,b);checks.append(label)
 if phase=='dispatch':
  mode=c['entry_mode'];target=0xfffffe000c660000 if mode==4 else 0xfffffe000bc9bbdc if mode==5 else R.COLD if mode==0 else R.SECONDARY
  check('collection_mode_dispatch_target_matches_unsigned_equalities',b['pc']==hex(target))
  if mode==4:put(0xfffffe000ca93df8,bytes([B.HEADER&255]));check('mode4_retains_only_low8_of_X2_and_forwards_X1',regs[0]==BOOTARGS)
  elif mode==5:check('mode5_forwards_X1_X2_as_X0_X1',regs[:2]==[BOOTARGS,B.HEADER])
  else:check('ordinary_mode_preserves_external_inputs_after_thread_register_clears',regs[0]==mode and regs[1:3]==[BOOTARGS,B.HEADER])
 elif phase=='cold':
  base=c.get('DT_base',0x12345000);size=c.get('DT_size',0x2345);overflow=base+size>=(1<<64)
  if overflow:
   check('device_tree_addition_carry_stops_before_original_diagnostic_without_linking',b['kind']=='before_original_diagnostic' and not row['early_callback_entries'])
  else:
   for off,n,v in [(0x508,8,base),(0x510,8,size),(0x518,8,base+size),(0x520,4,int(base!=0))]:put(0xfffffe0007f8b000+off,v.to_bytes(n,'little'))
   for at in reversed(range(R.RECORDS,R.RECORD_END,16)):
    tagged=value(at+8,8);owner=tagged&~3;old=value(owner+8,8);put(at+8,((tagged&3)|old).to_bytes(8,'little'));put(owner+8,at.to_bytes(8,'little'));put(owner+4,((value(owner+4,4)+1)&0xffffffff).to_bytes(4,'little'))
   check('four_original_authenticated_callback_targets_receive_header_plus6c_and_modifier2abe',len(row['early_callback_entries'])==4 and [e['PC'] for e in row['early_callback_entries']]==list(map(hex,R.CALLBACK_TARGETS)) and all(int(e['arguments2'][0],16)==BOOTARGS+0x6c and int(e['modifier_X17'],16)==0x2abe for e in row['early_callback_entries']))
   if c.get('bad_magic'):check('original_header_magic_failure_stops_before_WFE_after_early_initialization',b['pc']=='0xfffffe000c66057c')
   else:
    raw=header(c)
    for src,dst,n,minimum in B.published_fields():
     if c['version']>=minimum:put(R.B.GLOBALS+dst,raw[0x1a0+src:0x1a0+src+n])
    if c['version']>=7:put(R.B.C.T.TRANSPORT_FLAG,bytes([c['flag']]))
    put(R.B.GLOBALS,bytes([1]));flag=value(R.B.C.T.TRANSPORT_FLAG,1)
    check('cold_entry_reaches_original_selector15_boundary_with_source_published_flag',b['pc']==hex(R.COLD+(0x64 if flag else 0x5c)) and regs[16]==15)
    check('cold_entry_preserves_external_bootargs_header_in_nonvolatile_registers',regs[26:28]==[BOOTARGS,B.HEADER] and int(b['SP'],16)==STACK0)
 elif phase=='handoff':
  initial=decode(row['initial_private_RAM']);args=initial[BOOTARGS-P:BOOTARGS-P+0x480];h=initial[B.HEADER-P:B.HEADER-P+0x358]
  put(R.ARGS_DEST,args);put(R.HEADER_DEST,h);put(0xfffffe0007ef9168,R.ARGS_DEST.to_bytes(8,'little'));put(R.DEVICE_PTR,R.HEADER_DEST.to_bytes(8,'little'))
  put(0xfffffe0007e6d9b8,h[0x198:0x1a0]);put(0xfffffe0007e6d148,h[0x18:0x20])
  check('two_original_memcpy_calls_copy_complete_bootargs_and_shared_header',[(list(map(lambda v:int(v,16),e['arguments3'])),e['return_PC']) for e in row['original_copy_entries']]==[([R.ARGS_DEST,BOOTARGS,0x480],hex(R.MAIN+0x74)),([R.HEADER_DEST,B.HEADER,0x358],hex(R.MAIN+0x94))])
  check('bulk_header_copy_supplies_physical_root_and_publishes_same_device_structure',value(R.B.C.BOOTROOT,8)==B.ROOTPA and value(R.DEVICE_PTR,8)==R.HEADER_DEST and b['pc']==hex(R.MAIN+0xb4))
  check('original_tail_handoff_supplies_entry_X1_X2_to_main_X0_X1',regs[19]==R.ARGS_DEST and regs[21]==R.HEADER_DEST and [m['symbol'] for m in row['API_models']]==[NEW_LEAVES[0xfffffe000c621194],NEW_LEAVES[0xfffffe000c47cce0]])
 matches=[]
 for rowg in row['final_image_globals']:
  at=int(rowg['address'],16);raw=bytes.fromhex(rowg['bytes_hex'])
  if STACK0-16384<=at<STACK0:continue
  matches.append(raw==bytes(wanted[at+j] for j in range(len(raw))))
 check('all_tracked_nonstack_image_bytes_match_independent_byte_formulas',all(matches))
 before=decode(row['initial_private_RAM']);after=decode(row['final_private_RAM']);check('all_private_RAM_is_preserved_by_boot_image_stack_execution',before==after)
 return checks
