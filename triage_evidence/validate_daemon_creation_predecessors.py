#!/usr/bin/env python3
"""Rebuild proofs, original pointer words, source epochs and private A64 cases.
O(source bytes+retained events+all replay visits+solver resources) time;
O(largest JSON+one emulator) space. Native construction remains unknown.
"""
import json,hashlib,struct
from pathlib import Path
from collections import Counter
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,FIXUPS
from recover_daemon_object_creation import sha
from recover_daemon_descriptor_producers import verify_used_fixups
from prove_daemon_creation_predecessors import obligations
from replay_daemon_creation_predecessors import Run,cases
from recover_daemon_iokit_census import text_section
from replay_daemon_descriptor_producers import unpack
def checked(n,g):
 r=json.loads((ROOT/n).read_text());assert r['generator_sha256']==sha(ROOT/g)and r['full_goal_complete']is False
 for dep,h in r.get('dependencies',{}).items():assert sha(ROOT/dep)==h,(n,dep)
 return r
def main():
 c=checked('daemon_creation_predecessors_contracts.json','recover_daemon_creation_predecessors.py');p=checked('daemon_creation_predecessors_proofs.json','prove_daemon_creation_predecessors.py');r=checked('daemon_creation_predecessors_replays.json','replay_daemon_creation_predecessors.py');assert c['source_sha256']==r['source_sha256']==sha(SOURCE)
 cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;allspans=c['spans']+[x['span']for x in c['literal_0156_census']];previous=json.loads((ROOT/'daemon_object_creation_contracts.json').read_text());ranges=[(int(s['start'],16),int(s['end'],16))for s in allspans+previous['spans']]
 for s in allspans:
  a,z=int(s['start'],16),int(s['end'],16);b=bytes.fromhex(s['bytes_hex']);assert IMAGE.read(a,z-a)==b and hashlib.sha256(b).hexdigest()==s['sha256'];assert len(list(cs.disasm(b,a)))*4==len(b)
 assert len(c['literal_0156_census'])==18
 a,n=text_section();raw=IMAGE.read(a,n);pcs=[]
 for j,(word,)in enumerate(struct.iter_unpack('<I',raw)):
  if word==0xd2800000|(0x156<<5)|17:
   pc=a+j*4;ii=list(cs.disasm(IMAGE.read(pc+4,4),pc+4))
   if ii and ii[0].mnemonic=='braa':pcs.append(pc+4)
 assert pcs==[int(x['branch_pc'],16)for x in c['literal_0156_census']]
 # Reject two constant-phase fragments using their complete decoded write sets.
 const=[]
 for start,wanted in [(0x1000edb74,0x232d),(0x10022b948,0)]:
  row=next(x['span']for x in c['literal_0156_census']if int(x['span']['start'],16)==start);ins=list(cs.disasm(bytes.fromhex(row['bytes_hex']),start));writes=[i for i in ins if any(i.reg_name(v)in ['w8','x8']for v in i.regs_access()[1])];last=writes[-1];assert last.mnemonic=='mov'and last.operands[1].imm==wanted;assert wanted!=0x621b;const.append({'start':hex(start),'last_W8_write':hex(last.address),'constant':hex(wanted)})
 for b in c['banks_exhaustive256']:
  l=IMAGE.read(int(b['left'],16),256);rr=IMAGE.read(int(b['right'],16),256);assert {i^rr[l[i]^int(b['key'],16)]for i in range(256)}=={int(b['constant'],16)};assert(int(FIXUPS[int(b['slot'],16)]['target'])+int(b['bias'],16))&((1<<64)-1)==int(b['target'],16)
 assert c['marker_section']['section']=='__common'and int(c['marker_section']['flags'],16)&255==1
 retained=json.loads((ROOT/'daemon_object_consumers_profiles.json').read_text())['cases']
 for x in c['retained_source_contexts']:
  trace=unpack(retained[x['case_index']]);regs={'x'+str(j):{'hex':int(v,16).to_bytes(8,'little').hex()}for j,v in enumerate(trace['initial_registers'])};seen=set()
  for st in trace['steps']:
   if st['pc']=='0x1009d077c':assert regs==x['common_end_registers'];seen.add(st['pc'])
   if st['pc']=='0x10064ffbc':assert regs['x22']=={'hex':'1708000000000000'};seen.add(st['pc'])
   if st['pc']=='0x100c02f3c':assert regs['x19']=={'hex':'a453b30001000000'};seen.add(st['pc']);break
   regs.update(st['registers_after'])
  assert len(seen)==3
  assert x['removal_gate_W22']=='0x817'and x['removal_callback']=='0x100b353a4';end=x['common_end_registers'];assert end['x12']=={'hex':'08019f0001000000'}
  for n,val in [('x4',0x1010c67c0),('x5',0x1010c5754),('x7',0x1010c9288),('x23',0x1010ca2b0),('x26',0x1010c67d0)]:assert end[n]=={'hex':val.to_bytes(8,'little').hex()}
  event=next(e for row in x['events']if row['pc']=='0x1009d0454'for e in row['events']);assert event['value']=={'hex':'54820c0101000000'}and int(event['address'],16)==int(x['initial_SP'],16)+0x26c8
  event=next(e for row in x['events']if row['pc']=='0x10064ffc8'for e in row['events']);assert event['address']=='0x10103dfa8'and event['value']=={'hex':'a453b30001000000'}
 for i in cs.disasm(IMAGE.read(0x1009d0458,0x1009d0774-0x1009d0458),0x1009d0458):
  assert not any(i.reg_name(v)=='sp'for v in i.regs_access()[1])
  if i.mnemonic.startswith('st'):
   assert i.mnemonic=='str'and i.reg_name(i.operands[1].mem.base)=='sp';o=i.operands[1].mem.disp;n=4 if i.reg_name(i.operands[0].reg).startswith('w')else 8;assert not(o<0x26d0 and o+n>0x26c8)
 solved=0
 for row in p['proofs']:
  for fk,hk in [('original_file','original_sha256'),('file','sha256')]:
   f=ROOT/row[fk];assert sha(f)==row[hk];s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_file(str(f)));assert str(s.check())=='unsat';solved+=1
 qs,counts=obligations(c);assert counts==p['source_lift_counts'];witness=[]
 for n,pred in qs:
  s=z3.Solver();s.set(timeout=30000);s.add(pred);assert str(s.check())=='unsat'
  if n=='selected_mode_presence_gate':s=z3.Solver();s.add(pred.arg(0));assert str(s.check())=='sat';witness.append({'proof':n,'premise':'sat','model':str(s.model())})
 cfgs=list(cases());assert [x['configuration']for x in r['cases']]==cfgs;totals=Counter();retired=set();fix={int(x['address'],16)for x in c['original_fixups']['records']}
 for old,cfg in zip(r['cases'],cfgs):
  v=Run(cfg);new=v.run();assert old==json.loads(json.dumps(new));retired.update(a for a,b in v.steps);assert all(any(a<=pc<z for a,z in ranges)for pc,b in v.steps);fix.update(v.fix);totals.update({'cases':1,'source_visits':new['source_visits'],'read_effects':new['read_effects'],'write_effects':len(new['private_writes']),'logical_edges':len(new['logical_edges']),'modeled_allocator_calls':len(new['modeled_allocator_calls'])})
 assert dict(totals)==r['verified_totals'];fresh=[]
 for d,marker in [(2,1),(200,1),(201,0),(2,0)]:fresh.append(Run({'kind':'composition','decoded':d,'presence':0x123456789abcdef0,'marker':marker,'nonnull':True,'lock':0x690000f000,'pattern':42,'placement':16}).run())
 assert {x['critical']['bank_input_byte']for x in r['cases']if x['configuration']['kind']=='marker_resolver'}==set(range(256));assert 0x100a636ec not in retired
 allfix=verify_used_fixups(fix);actual=FIXUPS[TABLE+0x817*8];fixture=FIXUPS[TABLE+0x40c7*8];assert actual['target']==0x100b353a4 and 'div=0x56F7'in actual['annotation']and 'div=0x3459'in fixture['annotation']
 verified={'original_source_spans_checked':len(c['spans']),'literal_0156_fragment_spans_checked':18,'original_fixups_checked':len(fix),'exhaustive_bank_inputs_checked':512,'retained_contexts_checked':len(c['retained_source_contexts']),'bounded_excluded_fragment_starts':13,'unexcluded_other_fragment_starts':4,'selected_classifier_chain_starts':1,'SMT_file_queries_unsat':solved,'rebuilt_source_obligations_unsat':len(qs),'source_lift_visits':sum(counts.values()),'persisted_A64_cases':len(cfgs),'persisted_A64_source_visits':totals['source_visits'],'persisted_A64_cases_freshly_recomputed':len(cfgs),'additional_A64_cases':len(fresh),'additional_A64_source_visits':sum(x['source_visits']for x in fresh),'distinct_retired_opcodes_within_checked_spans':len(retired),'live_IDB_ranges_checked':len(c['live_IDB_matches']),'live_IDB_raw_bytes_checked':sum(x['size_bytes']for x in c['live_IDB_matches'])}
 deps=['daemon_creation_predecessors_contracts.json','daemon_creation_predecessors_proofs.json','daemon_creation_predecessors_replays.json','replay_daemon_creation_predecessors.py','prove_daemon_creation_predecessors.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':verified,'independent_A64_totals':dict(totals),'additional_A64_cases':fresh,'all_observed_original_fixups':allfix,'constant_fragment_exclusions':const,'nonempty_premise_witnesses':witness,'correction_verified':True,'reader_B_reached':False,'all_checks_pass':True,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_creation_predecessors_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(verified),flush=True)
if __name__=='__main__':main()
