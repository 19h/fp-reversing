#!/usr/bin/env python3
"""Original dead-load liveness, two branches and first arena allocator ABI.
O(source bytes+instructions+256+F) time/space; no target code executes.
"""
import hashlib,json
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE,selected,verify_original_fixups
from recover_daemon_iokit_census import native
from daemon_import_bindings import binding
RANGES=[('flag_gate',0x1003308a0,0x1003308e4),('unknown_loads',0x1003b5724,0x1003b57d4),('phase_gate',0x1003c24b8,0x1003c24e4),('allocation_prefix',0x10032a464,0x10032a4ec)]
PATH=[(a,z)for _,a,z in RANGES[1:]]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def regkey(n):return 'x'+n[1:]if n.startswith('w')else n
def liveness():
 cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;ins=[i for a,z in PATH for i in cs.disasm(IMAGE.read(a,z-a),a)];rows=[]
 for definition,reg,kill in [(0x1003b5738,'x10',0x10032a4bc),(0x1003b573c,'x0',0x10032a4dc)]:
  k=next(j for j,i in enumerate(ins)if i.address==definition);interval=[]
  for i in ins[k+1:]:
   reads,writes=i.regs_access();r=[regkey(i.reg_name(x))for x in reads];w=[regkey(i.reg_name(x))for x in writes];assert reg not in r,(reg,hex(i.address));assert i.mnemonic not in ['bl','blr','blraa','svc','hvc','smc'];interval.append({'pc':hex(i.address),'reads':r,'writes':w})
   if reg in w:assert i.address==kill;break
  else:raise AssertionError('no full-register kill')
  rows.append({'load_pc':hex(definition),'register':reg,'kill_pc':hex(kill),'intervening_reads_of_loaded_register':0,'includes_kill':True,'instructions':interval,'scope':'W0/W10 writes zero-extend and kill the complete corresponding X register. Source path and absence of earlier calls are part of certificate.'})
 return rows
def main():
 spans=[native(n,a,z)for n,a,z in RANGES];bank=selected(0x100e99700,0x100f4e190,0x56,0xcbf9,TABLE,0);bank['base']=hex(TABLE)
 fix=verify_original_fixups([int(bank['slot'],16)])
 live=json.loads((ROOT/'daemon_arena_entry_live_ida.json').read_text())
 for x in live['instructions']:assert IMAGE.read(int(x['address'],16),len(bytes.fromhex(x['bytes'])))==bytes.fromhex(x['bytes'])
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in ['daemon_receive_tools.py','daemon_receive_fixups.txt','recover_daemon_iokit_census.py','daemon_import_bindings.py','daemon_arena_entry_live_ida.json','daemon_frame_entry_contracts.json']},'source_sha256':sha(SOURCE),'spans':spans,'source_path_ranges':[[hex(a),hex(z)]for a,z in PATH],'liveness':liveness(),'malloc_bank':bank,'allocator_binding':binding(int(bank['slot'],16)),'allocator_fixup':fix,'live_IDB_source_rows_matched':len(live['instructions']),'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_arena_entry_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'spans':len(spans),'liveness_certificates':len(out['liveness']),'bank_target':bank['target'],'IDB_rows':len(live['instructions'])}),flush=True)
if __name__=='__main__':main()
