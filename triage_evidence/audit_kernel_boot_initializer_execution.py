#!/usr/bin/env python3
"""Full boot execution, local source obligations and independent image oracle.
O(source/memory events + collection/fixups/pages/symbols) time and bounded
receipt/page/index storage. SMT search separate, 30 s/query. Logical PAC only.
"""
import json,struct
from collections import Counter
from hashlib import sha256
import z3
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from resolve_kernel_collection_interfaces import commands
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_kernel_boot_fixup_projection import Model,source_proofs as fixup_proofs
from lskd_values_symbolic import resize
import recover_kernel_boot_fixup_projection as FIX
import recover_kernel_boot_initializer_execution as R
import probe_kernel_boot_initializer_execution as CPU
import replay_kernel_boot_initializer_execution as REPLAY

def source_proofs(e):
 proofs,coverage=fixup_proofs(e);B=0x6b00000000
 def fresh():v=Model(e);v.regions=[(B,4096)];return v
 def cut(v,a,b,linked=False):
  f=next(f for f in e['functions'] if int(f['start'],16)<=a<b<=int(f['end'],16));off=a-int(f['start'],16);v.e=v.c={'spans':[{'label':'cut','start':hex(a),'bytes_hex':bytes.fromhex(f['bytes'])[off:off+b-a].hex()}]};return v.run('cut') if linked else v.enter('cut')
 def prove(label,v,bad):
  common=v.owned();counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad));s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label);s.add(*v.bindings_for([*common,counter]),counter);assert s.check()==z3.unsat,(label,s.reason_unknown());proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV'});coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instructions':v.count});print('proved',label,flush=True)
 value,slide=z3.BitVecs('BE_value64 BE_slide64',64)
 for label,start,base_reg,slide_reg,offset in [('root_segment',0xfffffe000c660f44,'x24','x25',24),('root_section',0xfffffe000c660f60,'x9','x25',32),('fileset_entry',0xfffffe000c660ee4,'x24','x25',8),('child_segment',0xfffffe000c660db0,'x10','x1',24),('child_section',0xfffffe000c660dcc,'x7','x1',32),('nlist_value',0xfffffe000c660e50,'x12','x1',8)]:
  v=fresh();v.seed(base_reg,B);v.seed(slide_reg,slide);v.setmem(B+offset,8,value);cut(v,start,start+12);prove(label+'_adds_slide_modulo64',v,v.load(B+offset,8)!=value+slide)
 v=fresh();kind=z3.BitVec('BE_n_type8',8);v.seed('x12',B);v.setmem(B+4,1,kind);cut(v,0xfffffe000c660e44,0xfffffe000c660e50);prove('nlist_unsigned_type_above31_skips_value_store',v,v.next!=z3.If(z3.UGT(kind,31),resize(0xfffffe000c660e20,64),resize(0xfffffe000c660e50,64)))
 v=fresh();prot=z3.BitVec('BE_maxprot32',32);v.seed('x24',B);v.setmem(B+56,4,prot);cut(v,0xfffffe000c6610e8,0xfffffe000c6610f0);prove('range_writable_mask_uses_maxprot_at56',v,z3.Or(v.read('w11')!=prot,v.read('w12')!=(prot&2)))
 v=fresh();mode=z3.BitVec('BE_mode32',32);v.seed('w19',mode);cut(v,0xfffffe000c660f1c,0xfffffe000c660f20);prove('mode_bit0_skips_child_call_but_enters_fileset_slide_store',v,v.next!=z3.If(mode&1!=0,resize(0xfffffe000c660ee4,64),resize(0xfffffe000c660f20,64)))
 regs=['x23','x27','x21','x0','x28','x26','x20'];offsets=[8,16,24,32,40,160,168];stores={0xfffffe000c661180,0xfffffe000c661190,0xfffffe000c661198,0xfffffe000c6611a4,0xfffffe000c6611b4,0xfffffe000c6611bc,0xfffffe000c6611c4}
 for enabled in [True,False]:
  v=fresh();v.seed('sp',B+2048);v.seed('x29',B+2048+144);values=z3.BitVecs(' '.join('BE_out'+str(j)+'_64' for j in range(7)),64)
  for j,(reg,off,val) in enumerate(zip(regs,offsets,values)):v.seed(reg,val);v.setmem(B+2048+off,8,B+128*j if enabled else 0);v.setmem(B+128*j,8,~val)
  first=True
  for pc in range(0xfffffe000c661178,0xfffffe000c6611c8,4):
   if not enabled and pc in stores:continue
   cut(v,pc,pc+4,not first);first=False
  prove('seven_'+('nonnull_outputs_store_selected_u64s' if enabled else 'null_outputs_preserve_destination_sentinels'),v,z3.Or(v.next!=0xfffffe000c6611c8,*[v.load(B+128*j,8)!=(val if enabled else ~val) for j,val in enumerate(values)]))
 return proofs,coverage

def image_oracle(im,e,row):
 expected=[{'address':r['address'],'value':r['value']} for r in e['expected_global_words']];assert row['published_global_words']==expected
 assert row['boundary']=={'PC':hex(CPU.HALT),'returned':True} and row['final_SP']==row['initial_SP']==hex(CPU.SP)
 assert row['initial_registers31'][19:30]==row['final_registers31'][19:30]
 assert im.k.read(0xfffffe000cacb000,8)==bytes(8)
 calls=row['original_call_entries'];counts=Counter(c['PC'] for c in calls);assert counts=={hex(R.BOOT):1,hex(R.SET):1,hex(R.RANGES):1,hex(R.CHILD):362}
 setter=next(c for c in calls if c['PC']==hex(R.SET));assert setter['arguments8'][:3]==['0x1',hex(R.HEADER),'0x0'] and setter['return_PC']=='0xfffffe000c660a58'
 ranges=next(c for c in calls if c['PC']==hex(R.RANGES));assert ranges['arguments8']==[hex(R.HEADER),'0x0','0x0',*[hex(a) for a in R.GLOBALS[4:]],'0x0'] and ranges['return_PC']=='0xfffffe000c660a90'
 corpus=sha256();fixups=0;chain_receipts=[]
 for chain in FIX.chains(im.k):
  rows=chain.pop('rows');chain_receipts.append({**chain,'pointer_count':len(rows),'first_slot':hex(rows[0]['slot']),'last_slot':hex(rows[-1]['slot']),'ordered_records_sha256':FIX.digest(rows)})
  for r in rows:corpus.update(struct.pack('<QQQQIBBB',r['slot'],r['raw'],r['target'],r['modifier'],r['step'],r['auth'],r['key'],r['address_diversity']));fixups+=1
 previous=json.loads(read(ROOT/'kernel_boot_fixup_projection_checks.json'));assert chain_receipts==previous['chain_page_receipts'];assert corpus.hexdigest()==row['stream_sha256']['fixups'] and fixups==row['fixups_stored']==1036413
 children=[];slide_counts=Counter();child_calls=[c for c in calls if c['PC']==hex(R.CHILD)];child_index=0
 for at,cmd,size in commands(im.k.data,0):
  if cmd==0x19:slide_counts['0xfffffe000c660f4c']+=1;slide_counts['0xfffffe000c660f68']+=struct.unpack_from('<I',im.k.data,at+64)[0]
  if cmd!=0x80000035:continue
  va,off=struct.unpack_from('<QQ',im.k.data,at+8);call=child_calls[child_index];child_index+=1;assert call['arguments8'][:2]==[hex(va),'0x0'] and call['return_PC']=='0xfffffe000c660f34';slide_counts['0xfffffe000c660eec']+=1;segments=sections=0;symtab=linkedit=None
  for ca,cc,cs in commands(im.k.data,off):
   if cc==0x19:
    segments+=1;sections+=struct.unpack_from('<I',im.k.data,ca+64)[0]
    if im.k.data[ca+8:ca+24].split(b'\0')[0]==b'__LINKEDIT':linkedit=ca
   if cc==2:symtab=ca
  slide_counts['0xfffffe000c660db8']+=segments;slide_counts['0xfffffe000c660dd4']+=sections;symbols=admitted=0
  if symtab is not None and linkedit is not None:
   symoff,symbols=struct.unpack_from('<II',im.k.data,symtab+8);vm=struct.unpack_from('<Q',im.k.data,linkedit+24)[0];fo=struct.unpack_from('<Q',im.k.data,linkedit+40)[0];base=vm+symoff-fo;types=im.k.read(base,16*symbols);admitted=sum(types[16*j+4]<=31 for j in range(symbols));slide_counts['0xfffffe000c660e58']+=admitted
  children.append({'header':hex(va),'segments':segments,'sections':sections,'symbols':symbols,'n_type_le31':admitted})
 assert len(children)==len(child_calls)==362
 for pc,n in slide_counts.items():assert row['write_PC_counts'][pc]==n,(pc,n)
 assert sum(slide_counts.values())==511000
 previous_pages=json.loads(read(ROOT/'kernel_boot_fixup_projection_audit.json'))['full_corpus_projection']['page_receipts'];assert {r['address'] for r in previous_pages}<=row['final_page_sha256'].keys()
 corrected=FIX.CorrectedImage(im);changed=[]
 for address,actual in row['final_page_sha256'].items():
  pg=int(address,16);raw=bytearray(corrected.logical_page(pg));before=sha256(raw).hexdigest()
  for r in e['expected_global_words']:
   a=int(r['address'],16)
   if pg<=a<a+8<=pg+4096:raw[a-pg:a-pg+8]=int(r['value'],16).to_bytes(8,'little')
  assert sha256(raw).hexdigest()==actual,('final_page_projection',address)
  if before!=actual:changed.append(address)
 assert changed==['0xfffffe0007e6d000','0xfffffe0007f8b000']
 return {'complete_fixup_stream_matches_independent_decode':True,'fixup_stream_sha256':corpus.hexdigest(),'chain_receipts_rechecked':len(chain_receipts),'fixups_checked':fixups,'original_children':children,'zero_slide_store_PC_counts':dict(slide_counts),'zero_slide_stores':sum(slide_counts.values()),'all_final_pages_match_corrected_projection_plus_globals':True,'mapped_pages_checked':len(row['final_page_sha256']),'mapped_bytes_checked':4096*len(row['final_page_sha256']),'fixup_projection_pages_included':len(previous_pages),'pages_changed_by_globals':changed,'published_global_bytes':64,'callee_saved_X19_through_X29_SP_and_return_checked':True,'raw_stack_guard_zero_checked':True}

def controls(im,e):
 out=[]
 for label,pc,wanted in [('omit_fixup_store',0xfffffe000c660974,'fixup_store_not_executed'),('omit_format8_step_shift',0xfffffe000c660994,'wrong_chain_slot')]:
  p=CPU.Probe(im,e,pc);initial=[hex(p.reg(j)) for j in range(31)];private=sha256(bytes(p.u.mem_read(CPU.P,CPU.SIZE))).hexdigest()
  try:p.run()
  except AssertionError as exc:rejection=list(exc.args[0]);assert rejection[0]==wanted
  else:raise AssertionError(('changed_source_accepted',hex(pc)))
  out.append({'label':label,'source_word_mutated_to_NOP':hex(pc),'original_bytes_hex':im.k.read(pc,4).hex(),'replacement_bytes_hex':'1f2003d5','initial_registers31':initial,'initial_SP':hex(CPU.SP),'initial_NZCV':'0x0','initial_private_sha256':private,'all_other_image_bytes_raw':True,'source_visits':p.visits,'fixups_stored':p.fixups,'rejection':rejection,'stream_sha256':{n:h.hexdigest() for n,h in p.streams.items()}});print('control_rejected',label,flush=True)
 return out

def audit(current_receipts=None):
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,coverage=source_proofs(e);im=Image()
 if current_receipts is None:row=CPU.Probe(im,e).run();replay=REPLAY.Replay(im.k,e,row).run()
 else:row,replay=current_receipts
 oracle=image_oracle(im,e,row);negative=controls(im,e)
 for c in negative:
  for key in ['initial_registers31','initial_SP','initial_NZCV','initial_private_sha256']:assert c[key]==row[key]
 assert replay=={'source_visits_checked':row['source_visits'],'reads_checked':row['source_reads'],'writes_checked':row['source_writes'],'fixup_stores_checked':row['fixups_stored'],'stream_digests_checked':5,'private_bytes_checked':CPU.SIZE,'mapped_image_bytes_checked':4096*len(row['final_page_sha256']),'all_GPR_SP_NZCV_and_call_entries_checked':True}
 totals={'source_queries_unsat':len(proofs),'proof_instruction_instances':sum(c['instructions'] for c in coverage),'proof_distinct_PCs':len({p for c in coverage for p in c['PCs']}),'full_private_boot_executions':1,'source_visits':row['source_visits'],'executed_source_PCs':len(row['source_visit_counts']),'source_reads':row['source_reads'],'source_writes':row['source_writes'],'fixup_stores':row['fixups_stored'],'zero_slide_stores':oracle['zero_slide_stores'],'published_global_words':8,'original_call_entries':len(row['original_call_entries']),'mapped_image_pages':len(row['final_page_sha256']),'changed_source_controls':len(negative),'loop_contractions':0,'native_target_executions':0,'continuous_startup_visits_added':0}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(REPLAY.__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'scope':R.SCOPE,'kernel_collection_sha256':e['kernel_collection_sha256'],'source_proofs':proofs,'proof_coverage':coverage,'component':row,'independent_image_oracle':oracle,'negative_source_controls':negative,'independent_totals':totals,'independent_replay_totals':replay,'executed_function_coverage':[{'start':f['start'],'captured_words':len(f['instructions']),'executed_unique_PCs':len({i['ea'] for i in f['instructions']}&row['source_visit_counts'].keys())} for f in e['functions']],'prior_continuous_startup_case_unchanged':True,'native_target_executed':False,'hardware_PAC_executed':False,'full_goal_complete':False}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True);print(json.dumps(a['independent_replay_totals']),flush=True)
