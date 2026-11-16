#!/usr/bin/env python3
"""Independent logging formulas, prior-frontier custody and full CPU replay.
Linear journals/RAM; interval sorting O(N log N). No probe executor import.
"""
import json
from hashlib import sha256
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read,sha
from replay_kernel_boot_cpu_identity import pages,get,put
from replay_kernel_tunable_batch_execution import hydrate,publication_row
from probe_rpc502_vm_handoff import decode as uncompress
from replay_kernel_vm_mig import Replay as Core
import replay_kernel_longterm_bootstrap_execution as B
import recover_kernel_early_logging_execution as R

GROUPS=B.GROUPS+['timer_image_globals']
def prior_row(row):
 c=row['early_logging_join_checkpoint'];end=c['before_visit'];out=dict(row);out['source_visits']=row['source_visits'][:end]
 for k in ['source_reads','source_writes']:out[k]=[v for v in row[k] if v['source_visit_index']<end]
 for k,field in [('API_models','before_source_visit_index'),('logical_effects','before_visit'),('original_call_entries','source_visit_index'),('original_API_entries','before_visit'),('callback_entries','before_visit')]:out[k]=[v for v in row[k] if v[field]<end]
 for k in ['original_API_returns','callback_returns']:out[k]=[v for v in row[k] if v['before_visit']<end]
 memory=pages(hydrate(row)['initial_image_pages']);intervals=[]
 for k in GROUPS:
  for v in c[k]:a=int(v['address'],16);raw=bytes.fromhex(v['bytes_hex']);put(memory,a,len(raw),raw);intervals.append((a,a+len(raw)))
 merged=[]
 for a,z in sorted(intervals):
  if merged and a<=merged[-1][1]:lo,hi=merged.pop();merged.append((lo,max(hi,z)))
  else:merged.append((a,z))
 returned={v['entry_index'] for v in out['original_API_returns']};out.update(final_private_RAM=c['private_RAM'],final_image_globals=[{'address':hex(a),'bytes_hex':get(memory,a,z-a).hex()} for a,z in merged],final_system=c['system'],final_vectors=c['vectors'],final_page_sha256=c['mapped_page_sha256'],unfinished_API_entry_indices=[j for j in range(len(out['original_API_entries'])) if j not in returned],boundary={'pc':c['PC'],'kind':'before_unestablished_logging_system_register','detail':None,'registers31':c['registers31'],'SP':c['SP'],'NZCV':c['NZCV']},logging_system_register_frontier={'PC':hex(R.MRS),'operands':'x8, daif','register':'daif'},longterm_initializer_returned=False,logging_frontier_reached=True,original_printf_calls=[v for v in row['original_printf_calls'] if v['before_visit']<end]);return out

def preservation(row,im):
 old=hydrate(json.loads(read(ROOT/(R.B.P+'_audit.json')))['components'][2],im);new=prior_row(hydrate(row,im));keys=['source_visits','source_reads','source_writes','API_models','logical_effects','original_call_entries','original_API_entries','original_API_returns','callback_entries','callback_returns','final_private_RAM','final_image_globals','final_vectors','final_system','boundary','original_printf_calls','unfinished_API_entry_indices'];assert all(old[k]==new[k] for k in keys),[k for k in keys if old[k]!=new[k]]
 wanted=old['final_page_sha256'];actual=new['final_page_sha256'];assert wanted.keys()<=actual.keys() and all(actual[p]==h for p,h in wanted.items())
 for p in actual.keys()-wanted.keys():assert actual[p]==sha256(im.logical_page(int(p,16))).hexdigest()
 return {'prior_audit_sha256':sha(ROOT/(R.B.P+'_audit.json')),'compared_fields':keys,'exact_match':True,'known_original_page_hashes_exact_match':True,'additional_original_page_bytes':4096*len(actual.keys()-wanted.keys()),'call_frame_epochs':0,'new_callback_result_models':0}

def oracle(row,e):
 row=hydrate(row);prior=B.oracle(prior_row(row),json.loads(read(ROOT/(R.B.P+'_checks.json'))));c=row['early_logging_join_checkpoint'];end=c['before_visit'];memory=pages(row['initial_image_pages']);checks=[]
 for k in GROUPS+['logging_image_globals']:
  for r in c[k]:raw=bytes.fromhex(r['bytes_hex']);put(memory,int(r['address'],16),len(raw),raw)
 before_private=uncompress(c['private_RAM']);P=B.P
 for j in range(0,len(before_private),4096):memory[P+j]=bytearray(before_private[j:j+4096])
 def u(a,n):return int.from_bytes(get(memory,a,n),'little')
 def w(a,n,v):put(memory,a,n,v&((1<<(8*n))-1))
 def ok(label,p):assert p,('early_logging_contract',label);checks.append(label)
 thread=row['final_system']['tpidr_el1'];lock=0xfffffe000cad0108;ring=0xfffffe000cb2fe28;header=0xfffffe000caa3070;clock=u(0xfffffe000ca8c000,4);micro=u(0xfffffe000ca8c004,4);stamp=int(c['registers31'][21],16);seconds=stamp//clock;fraction=(stamp%clock)//micro
 expected=(f'[{seconds:5d}.{fraction:06d}]: '+f'Longterm timer threshold: {prior["longterm_u32"]} ms\n').encode('ascii');chars=bytes(v['character_u32'] for v in row['original_character_calls']);ok('exact_timestamp_and_diagnostic_character_stream',chars==expected)
 ok('one_proved_join_no_DAIF_value',len(row['proved_logging_joins'])==1 and row['proved_logging_joins'][0]['phase_u32']==3 and not row['proved_logging_joins'][0]['DAIF_value_supplied'] and 'daif' not in row['initial_system'] and 'daif' not in row['final_system'])
 ok('ring_header_admission',u(header+4,4)==131072 and u(header+8,4)==0 and u(header+16,8)==ring and len(expected)<131072)
 ok('uncontended_ticket_and_preemption_entry',u(lock+8,4)==0x144 and u(thread+0x1c8,4)==0)
 w(lock+8,4,0x01010144);w(lock+12,4,0);w(thread+0x1c8,4,0);w(header+8,4,len(expected));put(memory,ring,len(expected),expected);w(0xfffffe000caab110,1,1);w(0xfffffe000cbe9ec0,8,u(0xfffffe000cbe9ec0,8)+1)
 global_bytes=0
 for r in row['final_image_globals']:
  a=int(r['address'],16);raw=bytes.fromhex(r['bytes_hex']);ok('whole_global_'+r['address'],get(memory,a,len(raw))==raw);global_bytes+=len(raw)
 calls=row['original_logging_entries'];returns=row['original_logging_returns'];ok('logging_entry_sequence',[int(v['PC'],16) for v in calls]==[R.C.B.LOCK,R.TIMESTAMP,R.C.CORE,R.C.FORMAT,R.C.CORE,R.C.UNLOCK,R.C.WAKE]);ok('all_seven_logging_calls_return',sorted(v['entry_index'] for v in returns)==list(range(7)) and not row['unfinished_logging_entry_indices'])
 ok('all_character_callbacks_have_lock_preemption_count1',all(v['preemption_u32']==1 for v in row['original_character_calls']))
 stores=[v for v in row['source_writes'] if v['source_visit_index']>=end and v['pc']=='0xfffffe000c2ffdd4'];ok('every_ring_byte_has_original_store',len(stores)==len(expected) and all(v['address']==hex(ring+j) and v['size_bytes']==1 and v['after_hex']==bytes([ch]).hex() for j,(v,ch) in enumerate(zip(stores,expected))))
 preempt=[v for v in row['source_writes'] if v['source_visit_index']>=end and int(v['address'],16)==thread+0x1c8];ok('original_preemption_increment_and_decrement',[v['after_hex'] for v in preempt]==['01000000','00000000'])
 b=row['boundary'];ok('stop_before_unestablished_configuration_read',b['pc']=='0xfffffe000c48fc98' and b['kind']=='before_unestablished_logging_configuration_dereference' and b['detail']=={'pointer_slot':'0xfffffe0007f8b528','pointer_X8':'0xa5a5a5a5a5a5a5a5','field_offset_bytes':12,'read_width_bytes':4})
 ok('system_state_unchanged',row['final_system']==c['system']);ok('no_new_leaf_model',row['API_models']==prior_row(row)['API_models']);ok('1029_original_callbacks_preserved',len(row['callback_entries'])==len(row['callback_returns'])==1029)
 touched=[v for v in row['source_writes'] if v['source_visit_index']>=end];outside=[v for v in touched if not P<=int(v['address'],16)<P+len(before_private)];ok('all_nonprivate_writes_declared',all(any(int(r['address'],16)<=int(v['address'],16)<int(v['address'],16)+v['size_bytes']<=int(r['address'],16)+len(bytes.fromhex(r['bytes_hex'])) for r in row['final_image_globals']) for v in outside))
 slot=0xfffffe0007f8b528;origin_writes=[v for v in row['source_writes'] if int(v['address'],16)<=slot<int(v['address'],16)+v['size_bytes']];fixtures=[v for v in row['initial_image_fixtures'] if int(v['address'],16)<=slot<slot+8<=int(v['address'],16)+len(bytes.fromhex(v['bytes_hex']))]
 origin={'slot':hex(slot),'original_collection_bytes_hex':'0000000000000000','last_source_write':origin_writes[-1] if origin_writes else None,'initial_covering_fixtures':fixtures,'value_at_join':hex(u(slot,8)),'native_configuration_object':'unknown'}
 return {'checks':checks,'prior_longterm_contracts':prior,'expected_character_text':expected.decode('ascii'),'timestamp_ticks':stamp,'frequency_u32':clock,'microsecond_divisor_u32':micro,'timestamp_seconds':seconds,'timestamp_fraction':fraction,'characters':len(expected),'whole_global_bytes_compared':global_bytes,'configuration_pointer_origin':origin,'logging_returned':False,'native_console_emission_established':False}

class Replay(B.Replay):
 def __init__(self,image,row):super().__init__(image,row);self.logging_entries=[];self.logging_returns=[];self.logging_active=[];self.character_calls=[];self.joined=False
 def code(self,u,a,n,d):
  self.finish()
  if self.seq==len(self.p['source_visits']):return super().code(u,a,n,d)
  if a==R.MRS:
   c=self.p['early_logging_join_checkpoint'];self.composition_checkpoint(c)
   for k in ['lock_image_globals','timer_image_globals','logging_image_globals']:
    for v in c[k]:raw=bytes.fromhex(v['bytes_hex']);assert bytes(u.mem_read(int(v['address'],16),len(raw)))==raw;self.counts['whole_logging_checkpoint_bytes_checked']+=len(raw)
   phase=int.from_bytes(u.mem_read(R.C.PHASE,4),'little');assert phase<19 and not self.joined and 'daif' not in self.system
   for lo,hi in [(R.C.START,R.C.START+16),(R.C.SECOND,R.C.JOIN)]:assert bytes(u.mem_read(lo,hi-lo))==self.image.k.read(lo,hi-lo)
   raw=bytes(u.mem_read(a,4));assert raw.hex()=='28423bd5' and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()}
   event={'PC':hex(a),'kind':'source_proved_early_logging_join','before_visit':self.seq,'system_before':dict(self.system),'system_after':dict(self.system),'proof_audit_sha256':sha(ROOT/(R.C.P+'_audit.json')),'phase_address':hex(R.C.PHASE),'phase_bytes_hex':phase.to_bytes(4,'little').hex(),'phase_u32':phase,'join_PC':hex(R.JOIN),'contracted_original_words':9,'DAIF_value_supplied':False};assert self.p['proved_logging_joins']==[event] and event==self.p['logical_effects'][len(self.logical)];self.logical.append(event);self.seq+=1;self.joined=True;self.counts['source_visits_checked']+=1;self.counts['proved_block_transitions_checked']+=1;self.counts['contracted_original_words_checked']+=9
   for j,value in [(8,0xfffffe0007f34000),(9,phase),(24,1)]:u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),value)
   u.reg_write(ar.UC_ARM64_REG_NZCV,0x80000000);u.reg_write(ar.UC_ARM64_REG_PC,R.JOIN);return
  while self.logging_active and self.logging_entries[self.logging_active[-1]]['return_PC']==hex(a) and self.logging_entries[self.logging_active[-1]]['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP)):
   index=self.logging_active.pop();self.logging_returns.append({'entry_index':index,'before_visit':self.seq,'return_X0':hex(self.reg(0))})
  if self.joined and a in [R.C.B.LOCK,R.C.UNLOCK,R.TIMESTAMP,R.C.FORMAT,R.C.CORE,R.C.WAKE,R.C.B.PRINTF]:
   e={'PC':hex(a),'before_visit':self.seq,'arguments6':[hex(self.reg(j)) for j in range(6)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'return_PC':hex(self.reg(30)),'preemption_u32':int.from_bytes(u.mem_read(self.system['tpidr_el1']+0x1c8,4),'little')};self.logging_active.append(len(self.logging_entries));self.logging_entries.append(e)
  if self.joined and a==R.C.PUTC:self.character_calls.append({'PC':hex(a),'before_visit':self.seq,'character_u32':self.reg(0)&0xffffffff,'context':hex(self.reg(1)),'preemption_u32':int.from_bytes(u.mem_read(self.system['tpidr_el1']+0x1c8,4),'little'),'return_PC':hex(self.reg(30))})
  if self.joined and R.C.CORE<=a<0xfffffe000bd15408:
   raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a))
   if i.mnemonic=='blraa':
    assert i.op_str=='x21, x17' and self.reg(21)==R.C.PUTC and self.reg(17)==0xae56 and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()}
    event={'PC':hex(a),'kind':'blraa','scope':'original_formatter_character_callback','operands':i.op_str,'before_visit':self.seq,'system_before':dict(self.system),'system_after':dict(self.system),'target':hex(self.reg(21)),'modifier_X17':hex(self.reg(17)),'argument_X0':hex(self.reg(0)),'context_X1':hex(self.reg(1))};assert event==self.p['logical_effects'][len(self.logical)];self.logical.append(event);self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits_checked']+=1;self.counts['original_formatter_callback_edges_checked']+=1;u.reg_write(ar.UC_ARM64_REG_X30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,self.reg(21));return
  return super().code(u,a,n,d)
 def run(self):
  result=super().run();assert self.joined and self.logging_entries==self.p['original_logging_entries'] and self.logging_returns==self.p['original_logging_returns'] and self.logging_active==self.p['unfinished_logging_entry_indices'] and self.character_calls==self.p['original_character_calls'];return result
