#!/usr/bin/env python3
"""Original pre-allocation classifier and marker provenance; native entry unknown.
O(text bytes+retained source visits+fixups+256*bank rules) time/space.
"""
import json,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,TABLE,POOL,FIXUPS,selected,block
from recover_daemon_object_creation import span,sha
from recover_daemon_descriptor_producers import verify_used_fixups
from recover_daemon_context_lock import ida_output
from recover_daemon_iokit_census import text_section
from replay_daemon_descriptor_producers import unpack

def literal_pairs(mod):
 a,n=text_section();raw=IMAGE.read(a,n);rows=[]
 for j,(w,)in enumerate(struct.iter_unpack('<I',raw)):
  if w!=0xd2800000|(mod<<5)|17:continue
  pc=a+j*4;ii=list(CS.disasm(IMAGE.read(pc+4,4),pc+4))
  if not ii or ii[0].mnemonic!='braa':continue
  for at in range(pc-4,pc-0x4000,-4):
   ins=list(CS.disasm(IMAGE.read(at,4),at))
   if ins and ins[0].mnemonic in ['braa','br','b','ret','retab','retaa']:break
  else:raise AssertionError(hex(pc))
  rows.append({'modifier_pc':hex(pc),'branch_pc':hex(pc+4),'branch_operands':ii[0].op_str,'preceding_terminal_start':hex(at+4),'preceding_terminal_caveat':'This is a byte-order boundary, not proof that every edge enters at this start.','span':span('literal_'+hex(pc),at+4,pc+8)})
 return rows
def main():
 census=literal_pairs(0x156);assert len(census)==18
 specs=[('setup',0x100aee5c8,0x100aee670),('first_classifier',0x100b67258,0x100b672f4),('second_classifier',0x100b6de10,0x100b6deb0),('marker_resolver',0x1009d03e4,0x1009d0458),('saved_target',0x1009d02ac,0x1009d02b4),('saved_target_branch',0x1009d0770,0x1009d0780),('callback_zero',0x100b280c8,0x100b28100),('callback_trampoline',0x100c02f3c,0x100c02f44),('common_frame_epoch',0x1009d02b0,0x1009d0780)]
 specs.extend([('frame_save',0x100a035f0,0x100a03618),('counter_resolver',0x1009d0328,0x1009d0354)])
 spans=[span(n,a,z)for n,a,z in specs]
 source=json.loads((ROOT/'daemon_object_consumers_profiles.json').read_text());retained=[];first=None
 for j,row in enumerate(source['cases']):
  t=unpack(row);regs={'x'+str(k):{'hex':int(v,16).to_bytes(8,'little').hex()}for k,v in enumerate(t['initial_registers'])};F=int(t['initial_SP'],16);events=[];before={}
  for st in t['steps']:
   pc=st['pc']
   if pc in ['0x1009d03e4','0x1009d077c','0x10064ffbc','0x100c02f3c']:before[pc]=regs.copy()
   if pc in ['0x1009d0350','0x1009d0454','0x1009d02b0','0x10064ffc8']:events.append({'pc':pc,'events':st['events']})
   regs.update(st['registers_after'])
  assert before['0x10064ffbc']['x22']=={'hex':'1708000000000000'}
  assert before['0x100c02f3c']['x19']=={'hex':'a453b30001000000'}
  retained.append({'case_index':j,'initial_SP':hex(F),'source_configuration':row['configuration'],'events':events,'removal_gate_W22':'0x817','removal_callback':'0x100b353a4','common_end_registers':before['0x1009d077c']})
  if first is None:first=before['0x1009d03e4']
 bank=selected(0x100fc4130,0x101031ea0,0xbb,0x10ce,POOL,0xffffffffd2d67dc9);assert bank['target']=='0x1010c8254'
 resetbank=selected(0x100fc4130,0x101031ea0,0xa3,0x1226,POOL,0xffffffff93b856c6);assert resetbank['target']=='0x1010c8238'
 indices=[0x49d,0x49c,0x8e79,0x8e91,0x621b,0xadd1,0x9bd7,0x7e9,0x817,0x40c7];slots=[{'index':hex(i),'slot':hex(TABLE+8*i),'fixup':FIXUPS[TABLE+8*i]}for i in indices];fix={int(x['slot'],16)for x in slots}|{int(bank['slot'],16)}
 fix.add(int(resetbank['slot'],16));live=[];r=json.loads((ROOT/'daemon_creation_predecessors_ida_bytes.json').read_text());assert not r.get('isError')
 for x in ida_output(r)['results']:
  a=int(x['address'],16);b=bytes.fromhex(x['bytes']);assert IMAGE.read(a,len(b))==b
  for i in x['instructions']:assert IMAGE.read(int(i['address'],16),len(bytes.fromhex(i['bytes'])))==bytes.fromhex(i['bytes'])
  live.append({'start':hex(a),'size_bytes':len(b),'display_rows':len(x['instructions']),'partial_macro_rows':sum(len(bytes.fromhex(i['bytes']))<i['size']for i in x['instructions']if 'size'in i),'undecoded_byte_rows':sum('size'not in i for i in x['instructions'])})
 cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;epoch=[]
 for i in cs.disasm(IMAGE.read(0x1009d02b4,0x1009d0774-0x1009d02b4),0x1009d02b4):
  if i.mnemonic.startswith('st'):
   assert i.mnemonic=='str'and len(i.operands)==2 and i.reg_name(i.operands[1].mem.base)=='sp',hex(i.address);o=i.operands[1].mem.disp;n=4 if i.reg_name(i.operands[0].reg).startswith('w')else 8;assert not(o<0x2a70 and 0x2a68<o+n);epoch.append({'pc':hex(i.address),'offset':hex(o),'size_bytes':n})
 marker_gap=[]
 for i in cs.disasm(IMAGE.read(0x1009d0408,0x40),0x1009d0408):
  assert not any(i.reg_name(v)in ['x15','w15']for v in i.regs_access()[1]);marker_gap.append(hex(i.address))
 raw=SOURCE.read_bytes();off=32;sections=[]
 for _ in range(struct.unpack_from('<I',raw,16)[0]):
  cmd,sz=struct.unpack_from('<II',raw,off)
  if cmd==0x19:
   for k in range(struct.unpack_from('<I',raw,off+64)[0]):
    at=off+72+80*k;sec,seg,va,nb,fo,al,rel,nrel,flags=struct.unpack_from('<16s16sQQ5I',raw,at)
    if va<=0x1010c8254<va+nb:sections.append({'section':sec.rstrip(b'\0').decode(),'segment':seg.rstrip(b'\0').decode(),'start':hex(va),'size_bytes':nb,'flags':hex(flags),'marker_offset':hex(0x1010c8254-va)})
  off+=sz
 assert len(sections)==1
 deps=['daemon_object_consumers_profiles.json','daemon_creation_predecessors_ida_bytes.json','daemon_object_creation_contracts.json','daemon_receive_fixups.txt']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'spans':spans,'literal_0156_census':census,'marker_bank256':bank,'banks_exhaustive256':[bank,resetbank],'marker_section':sections[0],'original_fixups':verify_used_fixups(fix),'slots':slots,'retained_source_contexts':retained,'isolated_marker_initial_registers':first,'frame_target_epoch_stores':epoch,'marker_X15_preserved_gap_opcodes':marker_gap,'live_IDB_matches':live,'correction':{'report':'daemon_object_creation_report.md','previous_claim':'Executed removal gate W22=40C7','journal_verified':'Executed removal gate W22=0817; callback B353A4. 40C7 is a source-proof fixture.','prior_producers_and_journals_modified':False},'native_entry':'unknown','native_marker_values':'unknown','native_field_meaning':'unknown','native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_creation_predecessors_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'literal_0156_pairs':len(census),'retained_contexts':len(retained),'fixups':len(fix),'IDB_bytes':sum(x['size_bytes']for x in live)}),flush=True)
if __name__=='__main__':main()
