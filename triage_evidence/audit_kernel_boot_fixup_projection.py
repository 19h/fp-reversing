#!/usr/bin/env python3
"""Boot fixup source relations, complete corpus projection and scoped replay.
Linear corpus/page/journal work; SMT search separate, 30 s/query.
"""
import json,struct
from hashlib import sha256
from collections import Counter
import z3
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_kernel_timeout_execution import Model as Parent
from audit_kernel_mapping_context import DEC
from lskd_values_symbolic import resize
import recover_kernel_boot_fixup_projection as R
import probe_kernel_boot_fixup_projection as CPU
from replay_kernel_boot_fixup_projection import oracle,Replay
SIGNS={key:z3.Function('BFP_sign_'+key+'64',z3.BitVecSort(64),z3.BitVecSort(64),z3.BitVecSort(64)) for key in ['IA','IB','DA','DB']}
class Model(Parent):
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   key={'pacia1716':'IA','pacib1716':'IB','pacda':'DA','pacdb':'DB'}.get(i.mnemonic)
   if key:
    if self.next is not None:self.edge_checks.append(self.next==i.address)
    self.next=resize(i.address+4,64);self.pc=i.address;self.visited.add(i.address);self.count+=1
    if i.mnemonic in ['pacda','pacdb']:assert i.op_str=='x17, x16'
    self.write('x17',SIGNS[key](self.read('x17'),self.read('x16')));continue
   old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one');self.e,self.c=old_e,old_c
  return self
def source_proofs(e):
 proofs=[];coverage=[];B=0x6900000000
 def fresh():v=Model(e);v.regions=[(B,4096)];return v
 def cut(v,a,b,linked=False):
  f=next(f for f in e['functions'] if int(f['start'],16)<=a<b<=int(f['end'],16));off=a-int(f['start'],16);v.e=v.c={'spans':[{'label':'cut','start':hex(a),'bytes_hex':bytes.fromhex(f['bytes'])[off:off+b-a].hex()}]};return v.run('cut') if linked else v.enter('cut')
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad));s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label);s.add(*v.bindings_for([*common,counter]),counter);result=s.check();assert result==z3.unsat,(label,str(result),s.reason_unknown());proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True,'PAC_semantics':'Four uninterpreted key-specific signing functions; native keys/signatures unknown.'});coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instructions':v.count});print('proved',label,flush=True)
 fmt,word,base,value,modifier,slot=z3.BitVecs('BFP_format64 BFP_word64 BFP_base64 BFP_value64 BFP_modifier64 BFP_slot64',64)
 v=fresh();v.seed('x16',fmt);cut(v,R.HEAD,0xfffffe000c660958);low=z3.Extract(15,0,fmt);prove('only_low16_formats8_or11_enter_pointer_load',v,v.next!=z3.If(z3.Or(low==8,low==11),resize(0xfffffe000c660958,64),resize(R.FAIL,64)))
 bases=z3.BitVecs('BFP_cache0 BFP_cache1 BFP_cache2 BFP_cache3',64);v=fresh();v.seed('x0',B+512);v.seed('x12',B);v.setmem(B+512,8,word)
 for j,b in enumerate(bases):v.setmem(B+8*j,8,b)
 cut(v,0xfffffe000c660958,0xfffffe000c660968);level=z3.Extract(31,30,word);selected=z3.If(level==0,bases[0],z3.If(level==1,bases[1],z3.If(level==2,bases[2],bases[3])));prove('raw_low32_cache_level_selects_base_and_zero_base_exits',v,z3.Or(v.read('x1')!=word,v.read('x16')!=selected,v.next!=z3.If(selected==0,resize(R.FAIL,64),resize(0xfffffe000c660968,64))))
 v=fresh();v.seed('x1',word);v.seed('x16',base);cut(v,0xfffffe000c660968,0xfffffe000c660974);prove('target_is_base_plus_low30_and_auth_bit_selects_signing',v,z3.Or(v.read('x17')!=base+(word&0x3fffffff),v.next!=z3.If(z3.Extract(63,63,word)==1,resize(0xfffffe000c6609b0,64),resize(0xfffffe000c660974,64))))
 v=fresh();v.seed('x1',word);v.seed('x0',slot);cut(v,0xfffffe000c6609b0,0xfffffe000c6609d0);div=z3.ZeroExt(48,z3.Extract(47,32,word));expected=z3.If(z3.Extract(48,48,word)==0,div,z3.If(div==0,slot,(slot&0xffffffffffff)|(div<<48)));prove('auth_modifier_blends_diversity_and_slot_only_when_address_diversity_set',v,z3.Or(v.read('x16')!=expected,v.read('x2')!=z3.ZeroExt(62,z3.Extract(50,49,word))))
 for key,name in enumerate(['IA','IB','DA','DB']):
  v=fresh();v.seed('x2',key);v.seed('x16',modifier);v.seed('x17',value);cut(v,0xfffffe000c6609d0,0xfffffe000c6609d8)
  if key==0:cut(v,0xfffffe000c6609d8,0xfffffe000c6609e4,True)
  elif key==1:cut(v,0xfffffe000c6609d8,0xfffffe000c6609dc,True);cut(v,0xfffffe000c6609f4,0xfffffe000c6609fc,True)
  elif key==2:cut(v,0xfffffe000c6609e4,0xfffffe000c6609f4,True)
  else:cut(v,0xfffffe000c6609e4,0xfffffe000c6609ec,True);cut(v,0xfffffe000c6609fc,0xfffffe000c660a04,True)
  prove('key'+str(key)+'_uses_'+name+'_and_rejoins_store',v,z3.Or(v.read('x17')!=SIGNS[name](value,modifier),v.read('x16')!=modifier,v.next!=0xfffffe000c660974))
 for fmt_value in [8,11]:
  for nonzero in [False,True]:
   v=fresh();v.seed('x0',B+512);v.seed('x13',B+256);v.seed('x1',word);v.seed('x17',value);v.setmem(B+262,2,fmt_value);cut(v,0xfffffe000c660974,0xfffffe000c660984 if fmt_value==11 else 0xfffffe000c66098c)
   if fmt_value==8:cut(v,0xfffffe000c66098c,0xfffffe000c6609a0 if nonzero else 0xfffffe000c660994,True)
   else:cut(v,0xfffffe000c6609a0,0xfffffe000c6609b0 if nonzero else 0xfffffe000c6609a8,True)
   next_field=z3.ZeroExt(52,z3.Extract(62,51,word));stride=4 if fmt_value==8 else 1;prove('format'+str(fmt_value)+'_'+('next' if nonzero else 'end')+'_stores_value_and_uses_exact_step',v,z3.Or(v.load(B+512,8)!=value,v.read('x0')!=(B+512+next_field*stride if nonzero else resize(B+512,64)),v.next!=(R.HEAD if nonzero else R.END)),[next_field!=0 if nonzero else next_field==0])
 v=fresh();v.seed('x19',base);v.seed('x20',value);cut(v,0xfffffe000c660a48,0xfffffe000c660a58);prove('boot_tail_calls_kind1_publisher_with_header_and_slide',v,z3.Or(v.read('x0')!=1,v.read('x1')!=value,v.read('x2')!=base,v.next!=0xfffffe000c6626e4,v.read('x30')!=0xfffffe000c660a58))
 return proofs,coverage
def full_projection(im,e):
 corrected=R.CorrectedImage(im);pages={};counts=Counter();receipt=[];seen=set();cross=[]
 for chain in R.chains(im.k):
  rows=chain.pop('rows');receipt.append({**chain,'pointer_count':len(rows),'first_slot':hex(rows[0]['slot']),'last_slot':hex(rows[-1]['slot']),'ordered_records_sha256':R.digest(rows)})
  for r in rows:
   off=r['file_offset'];old=im.meta[off];assert int(old['raw'],16)==r['raw'] and int(old['target'],16)==r['target'] and old['auth']==r['auth'] and old['key']==r['key'] and old['address_diversity']==r['address_diversity'] and int(old['diversity'],16)==r['diversity'] and old['format']==8;assert off not in seen;seen.add(off);counts['independently_matched_fixups']+=1
   a=r['slot'];out=r['target'].to_bytes(8,'little')
   for j,b in enumerate(out):
    pg=(a+j)&~4095
    if pg not in pages:pages[pg]=bytearray(im.k.read(pg,4096))
    pages[pg][(a+j)&4095]=b
 assert seen==set(im.meta) and receipt==e['chain_page_receipts'];receipts=[];differences=[]
 for pg,raw in sorted(pages.items()):
  want=bytes(raw);actual=corrected.logical_page(pg);old=im.logical_page(pg);assert actual==want and len(actual)==4096
  row={'address':hex(pg),'raw_sha256':sha256(im.k.read(pg,4096)).hexdigest(),'corrected_sha256':sha256(actual).hexdigest(),'legacy_sha256':sha256(old).hexdigest(),'legacy_size_bytes':len(old),'byte_exact_independent_projection':True};receipts.append(row)
  if old!=actual:differences.append(row)
 affected={int(r['slot'],16)&~4095 for r in e['cross_page_fixups']};affected|={p+4096 for p in list(affected)};assert {int(r['address'],16) for r in differences}==affected
 controls=[]
 for r in e['cross_page_fixups']:
  a=int(r['slot'],16);pg=a&~4095;old=im.logical_page(pg)[a-pg:4096]+im.logical_page(pg+4096)[:4];new=corrected.logical_page(pg)[a-pg:4096]+corrected.logical_page(pg+4096)[:4];assert new==int(r['target'],16).to_bytes(8,'little') and old!=new and len(im.logical_page(pg))==4100;controls.append({'slot':hex(a),'legacy_joined_bytes_hex':old.hex(),'corrected_joined_bytes_hex':new.hex(),'legacy_first_page_size_bytes':4100,'legacy_projection_rejected':True})
 return corrected,{'independent_counts':dict(counts),'page_receipts':receipts,'changed_legacy_pages':differences,'boundary_regression_controls':controls,'all_metadata_matches_independent_decoder':True}
def corrected_signing_rechecks(im,e):
 import probe_kernel_initializer_pointer_signing as C
 from replay_kernel_initializer_pointer_signing import oracle as signing_oracle,Replay as SigningReplay
 old=json.loads(read(ROOT/'kernel_initializer_pointer_signing_audit.json'));source=json.loads(read(ROOT/'kernel_initializer_pointer_signing_checks.json'));rows=[];totals=Counter();tails=[(int(r['slot'],16)+4,4) for r in e['cross_page_fixups']]
 for index,(prior,c) in enumerate(zip(old['components'],C.configurations())):
  row=C.Probe(im,source,c).run();fields=set(row)-{'final_page_sha256'};assert all(row[k]==prior[k] for k in fields);assert signing_oracle(im,row)==prior['independent_oracle'];result=SigningReplay(im,row).run();totals.update(result);changes={pg:{'old':prior['final_page_sha256'][pg],'corrected':h} for pg,h in row['final_page_sha256'].items() if prior['final_page_sha256'][pg]!=h};assert row['final_page_sha256'].keys()==prior['final_page_sha256'].keys()
  assert not any(int(v['address'],16)<a+n and a<int(v['address'],16)+v['size_bytes'] for kind in ['source_reads','source_writes'] for v in row[kind] for a,n in tails)
  rows.append({'prior_component_index':index,'label':c['label'],'all_source_journals_registers_private_RAM_and_PAC_events_identical':True,'independent_oracle_identical':True,'final_page_hash_changes':changes,'corrected_tail_bytes_read_or_written':0,'independent_replay':result})
 assert len(rows)==len(old['components'])==29 and [i for i,r in enumerate(rows) if r['final_page_hash_changes']]==[0] and set(rows[0]['final_page_hash_changes'])=={'0xfffffe0008391000'}
 current=json.loads(read(ROOT/'kernel_early_logging_execution_audit.json'));affected={hex(int(r['slot'],16)&~4095) for r in e['cross_page_fixups']};affected|={hex(int(p,16)+4096) for p in list(affected)};assert not any(set(c['final_page_sha256'])&affected for c in current['components'])
 return {'prior_signing_audit_sha256':sha(ROOT/'kernel_initializer_pointer_signing_audit.json'),'prior_signing_checks_sha256':sha(ROOT/'kernel_initializer_pointer_signing_checks.json'),'cases':rows,'independent_replay_totals':dict(totals),'current_continuous_logging_audit_sha256':sha(ROOT/'kernel_early_logging_execution_audit.json'),'current_continuous_logging_affected_mapped_pages':0,'scope':'Only the 29 retained signing cases and current continuous logging case; no universal historical consumer audit.'}
def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,coverage=source_proofs(e);im=Image();corrected,projection=full_projection(im,e);components=[];totals=Counter()
 for c in CPU.cases(e):
  row=CPU.Probe(im.k,e,c).run();row['independent_oracle']=oracle(row,e);row['independent_replay']=Replay(im.k,row).run();totals.update(row['independent_replay']);components.append(row)
 controls=[]
 for pc in [0xfffffe000c660974,0xfffffe000c660994]:
  row=CPU.Probe(im.k,e,CPU.cases(e)[1],pc).run();assert all(row[k]==components[1][k] for k in ['configuration','initial_registers31','initial_private_sha256'])
  try:oracle(row,e)
  except AssertionError as error:rejection=list(error.args[0])
  else:raise AssertionError(('changed_source_accepted',hex(pc)))
  controls.append({'source_word_mutated_to_NOP':hex(pc),'all_initial_fields_match':True,'oracle_rejection':rejection,'configuration':row['configuration']})
 rechecks=corrected_signing_rechecks(corrected,e);stats={'source_queries_unsat':len(proofs),'proof_instruction_instances':sum(c['instructions'] for c in coverage),'proof_distinct_PCs':len({p for c in coverage for p in c['PCs']}),'CPU_cases':len(components),'CPU_source_visits':sum(len(c['source_visits']) for c in components),'semantic_assertions':sum(len(c['independent_oracle']['checks']) for c in components),'fixups_checked':projection['independent_counts']['independently_matched_fixups'],'projected_4KiB_pages':len(projection['page_receipts']),'legacy_changed_pages':len(projection['changed_legacy_pages']),'boundary_controls':len(projection['boundary_regression_controls']),'changed_source_controls':len(controls),'corrected_signing_cases':len(rechecks['cases']),'full_boot_executions':0,'native_target_executions':0,'continuous_startup_visits_added':0}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_boot_fixup_projection.py'),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'legacy_reader_sha256':sha(ROOT/'kernel_vm_mig_tools.py'),'scope':R.SCOPE,'source_proofs':proofs,'proof_coverage':coverage,'full_corpus_projection':projection,'components':components,'negative_source_controls':controls,'corrected_signing_rechecks':rechecks,'independent_totals':stats,'independent_replay_totals':dict(totals),'prior_published_artifacts_unchanged':True,'native_target_executed':False,'full_goal_complete':False}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
