#!/usr/bin/env python3
"""Compose actual schema output with shared-holder and private lookup ABI.
Linear selected-instruction/query DAG construction; SMT search separately bounded.
"""
import copy,json
import z3
from kext_port_tools import ROOT,TABLE,qword,IMAGE
from lskd_values_symbolic import mem,resize
from verify_daemon_reader_record_payloads_publication import read,sha
import audit_userclient_schema_scalar as Parent
import recover_userclient_schema_registry as R
H=Parent.H;DEC=Parent.DEC;Publication=Parent.Publication;Schema=Parent.Schema
SUCCESS=Parent.SUCCESS;TOKEN=Parent.TOKEN;PHASE=Parent.PHASE
HOLDER=0xfffffe000ccceac0;KEY_BIAS=0x1ee45f68039f9913

def caller_pre(record):return((resize(0x262f54b973ed0b34,64)-(record|0x262f54b973ed0b34))+(record|0xd9d0ab468c12f4cb))^0x35a8f293ff58d679
def decoder_pre(record):return(((record|0x8be454d92cc693a0)-(record|0x741bab26d3396c5f))+0x741bab26d3396c5f)^0x679c0d0c5f8cb112
def codec(record):return decoder_pre(record)*0x8c229611
class Model(Parent.Model):
 def __init__(self,e):
  self.registry_receipt=e;self.registry_bank_reads=0;self.registry_controller_reads=0;self.registry_bank_rewrites=[];self.packet_codec_rewrites=[];self.header_owned=False
  combined=copy.deepcopy(e);combined['source']['spans']=e['scalar_source']['spans']+e['source']['spans'];super().__init__(combined)
  self.holder=z3.BitVec('RG_holder64',64);self.capacity=z3.BitVec('RG_capacity32',32);self.entries=z3.BitVec('RG_entries64',64);c=self.common
  for off,x in [(0xa50,0xfffffe0007941f60),(0xa58,0xfffffe000794a0d0),(0x9f8,0xfffffe0007949ed0),(0x9f0,0xfffffe000792fec0)]:mem(self,c['F']+off,8,x)
  self.seed('x16',c['S']+0x968);self.run('registry_packet_roots').run('registry_flag_root').run('registry_payload_root').run('registry_index_root').run('registry_default_status')
 def owned(self):
  out=super().owned()
  if self.header_owned:
   g=self.holder;c=self.common;out.extend([g!=0,z3.ULE(g,resize((1<<64)-17,64))]);extents=[(c['F'],resize(0x10f0,64)),(c['C'],resize(0x1000,64)),(c['S'],resize(0x4000,64)),(c['H'],resize(16,64)),(c['J'],resize(32,64)),(c['Z'],z3.ZeroExt(32,c['L'])+10)]
   if self.with_span:extents.append((c['P'],z3.ZeroExt(32,c['L'])))
   for a,n in extents:out.append(z3.Or(z3.ULE(g+16,a),z3.ULE(a+n,g)))
   for a,off,n in IMAGE.segments:out.append(z3.Or(z3.ULE(g+16,resize(a,64)),z3.ULE(resize(a+n,64),g)))
  return out
 def address(self,i,o):
  if i.writeback:
   assert i.address==0xfffffe000a65ac58;a=z3.simplify(self.read(i.reg_name(o.mem.base))+o.mem.disp);self.write(i.reg_name(o.mem.base),a);return a
  return super().address(i,o)
 def write(self,name,v):
  if self.pc==0xfffffe000a65b498 and name=='x13':
   record=self.read('x23');pre=self.values[(0xfffffe000a65b48c,'x13')];assert z3.simplify(pre).eq(z3.simplify(caller_pre(record))),'packet caller pre-key source shape';assert z3.simplify(v).eq(z3.simplify(pre*0x8c229611))and z3.simplify(self.read('w14')).as_long()==0x8c229611,'packet multiplier source shape'
   self.packet_codec_rewrites.append({'source_PC':hex(self.pc),'lemma':'universal_caller_decoder_pre_multiply_equality','source_shape_checked':True});v=z3.simplify(codec(record))
  super().write(name,v)
 def load(self,a,n):
  if self.pc in [0xfffffe000a65ac10,0xfffffe000a65ac18,0xfffffe000a65acb0,0xfffffe000a65acb8,0xfffffe000a65b4dc,0xfffffe000a65b4e4]:
   assert n==4;self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.address_checks.append(a==(0xfffffe000ccc30d0 if self.pc in [0xfffffe000a65ac10,0xfffffe000a65acb0,0xfffffe000a65b4dc]else 0xfffffe000ccc32f8));self.registry_controller_reads+=1;return z3.BitVec('RG_controller_'+str(self.registry_controller_reads),32)
  for name,(lp,rp,pp)in R.BANK_PCS.items():
   rule=next(q for q in self.registry_receipt['registry_bank_rules']if q['name']==name);left,right=int(rule['left'],16),int(rule['right'],16)
   if self.pc==lp:
    assert n==1;self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.registry_input=z3.Extract(7,0,a-left);self.registry_bank_reads+=1;self.registry_byte=z3.BitVec('RG_bank_'+str(self.registry_bank_reads),8);self.address_checks.append(a==left+z3.ZeroExt(56,self.registry_input));return self.registry_byte
   if self.pc==rp:
    assert n==1;self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.address_checks.append(a==right+z3.ZeroExt(56,self.registry_byte^int(rule['key'],16)));self.registry_bank_rewrites.append({'source_PC':hex(self.pc),'rule':name,'certified_inputs':256});return self.registry_input^int(rule['constant'],16)
   if self.pc==pp:
    assert n==8;self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.address_checks.append(a==int(rule['slot'],16));return resize(int(rule['original_pointer']['target'],16),64)
  if self.pc==0xfffffe000a65ac58:
   assert n==8;self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.address_checks.append(a==HOLDER);return self.holder
  if self.pc in R.BRANCHES:
   assert n==8;self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});js=R.BRANCHES[self.pc];self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in js]));out=resize(0,64)
   for j in js:out=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),out)
   return out
  return super().load(a,n)
 def run(self,label,take=None):
  original=self.e;row=next(s for s in original['source']['spans']if s['label']==label);skip=None
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.address==skip:continue
   self.pc=i.address;self.visited.add(i.address)
   if i.address in R.RETAGS:
    assert i.mnemonic=='b.eq'and i.operands[0].imm&((1<<64)-1)==i.address+8;self.guards.append(self.condition('eq'));skip=R.RETAGS[i.address];self.count+=1
   elif i.address in R.DIRECT:
    m,t=R.DIRECT[i.address];assert i.mnemonic==m and i.operands[0].imm&((1<<64)-1)==t;cond=self.condition(m[2:]);self.direct.append({'pc':i.address,'condition':cond,'next_PC':z3.If(cond,resize(t,64),resize(i.address+4,64))});self.count+=1
    if take is not None:self.guards.append(cond if take else z3.Not(cond))
   elif i.mnemonic=='blraa':
    self.write('x30',resize(i.address+4,64));self.edges.append({'pc':i.address,'target':self.read(i.reg_name(i.operands[0].reg)),'modifier':self.read(i.reg_name(i.operands[1].reg)),'pending_call':True});self.count+=1
   else:
    self.e={'source':{'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}};super().run('one',take);self.e=original
  self.e=original;return self

def prepared(e,kind='u32'):
 v=Model(e)
 for label in Parent.H.PATH:v.run(label)
 if kind=='u32':v.run('primary_gate',False).run('u32_gate');v.extra.append(v.common['L']==4);v.run('u32_request').run('length_bridge').run('word_writer')
 elif kind=='u64':v.run('primary_gate',True).run('secondary_gate',True).run('u64_gate');v.extra.append(v.common['L']==8);v.run('u64_request').run('u64_writer')
 else:
  v.run('primary_gate',True).run('secondary_gate',False).run('span_gate',False).run('span_length')
  if kind=='span_zero':v.extra.append(v.common['L']==0)
  else:v.extra.extend([v.common['L']!=0,v.counter==1]);v.with_span=True;v.run('span_request');v.seed('x10',v.counter);v.run('span_copy')
 v.publication_store_start=len(v.stores);Publication.finish(v);v.extra.extend([z3.ZeroExt(32,v.common['N'])==z3.ZeroExt(32,v.common['L'])+10,v.common['D']==Parent.Parent.KEY]);v.schema_store_start=len(v.stores);Schema.finish(v);v.search_store_start=len(v.stores)
 v.run('search_nonnull').run('search_node').run('node_decode_prepare').run('word_bridge_read').run('decode_word').run('tag_match').run('search_result').run('search_callback').run('schema_search_return');Parent.Parent.matched(v);v.scalar_store_start=len(v.stores);return v

def scalar_finished(e,kind='u32'):
 v=Parent.header(prepared(e,kind)).run('schema_type_gate',kind!='u32')
 if kind=='u32':v.run('schema_scalar_request').run('schema_length_bridge').run('decode_word').run('schema_scalar_return').run('schema_commit_entry')
 else:v.run('schema_other_type')
 v.run('schema_commit_cursor')
 if kind=='u32':v.run('schema_scalar_output')
 return v.run('schema_caller_return').run('schema_caller_status')
def holder_requested(e):
 v=scalar_finished(e);v.registry_store_start=len(v.stores);return v.run('registry_request').run('registry_holder')
def ready_consumer(e):
 v=holder_requested(e);v.extra.append(v.holder!=0);return v.run('registry_resume').run('registry_return').run('registry_scalar')
def lookup_requested(e):
 v=ready_consumer(e);v.header_owned=True;mem(v,v.holder+4,4,v.capacity);mem(v,v.holder+8,8,v.entries);return v.run('registry_lookup_entry').run('registry_lookup_header').run('registry_lookup_record').run('registry_lookup_call')

def packet_bad(v):
 c=v.common;record=c['S']+0x968;k=codec(record);shape=resize(0x652019cc00000000,64)|z3.ZeroExt(32,c['V']^0x6a48ac59)
 return z3.Or(H.cell(v,record,8)+k!=shape,H.cell(v,record+8,8)!=c['S']+0x10,H.cell(v,record+0x10,8)!=c['S']+0xa28,H.cell(v,record+0x20,8)!=v.entries,H.cell(v,record+0x28,4)-resize(k,32)!=0x541,(H.cell(v,record+0x2c,4)^resize(k,32))-0x4f950919!=v.capacity,H.cell(v,c['C']+0x30,8)!=0xfffffe000a636854,H.cell(v,c['C']+0x680,8)!=0xfffffe000a65b5f8,H.cell(v,c['S']+0xa28,4)!=0,v.read('x19')!=c['C']+0x440,v.read('x0')!=record,v.read('x30')!=0xfffffe000a65b530,Publication.edge(v,0xfffffe000a5ae354,0x6a0f))
def record_preserved(v):
 c=v.common;end=c['Z']+z3.ZeroExt(32,c['L'])+10
 return z3.Or(H.cell(v,c['S']+0xbc4,4)!=c['V'],H.cell(v,c['F']+0xaa8,8)!=14,H.cell(v,c['H'],8)!=c['J'],H.cell(v,c['H']+8,8)!=c['J'],H.cell(v,c['J']+0x18,8)!=c['Z'],*[z3.Not(z3.Or(z3.ULE(q['address']+q['size_bytes'],c['Z']),z3.ULE(end,q['address'])))for q in v.stores[v.registry_store_start:]])
def source_obligations(e):
 out=[];visited=set()
 def prove(name,v,bad):
  premises=[]if v is None else v.owned()+v.guards+v.extra
  p=z3.SolverFor('QF_BV');p.set(timeout=60000);p.add(*premises);r=p.check();assert r==z3.sat,(name,'premises',str(r),p.reason_unknown())
  s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises,z3.simplify(z3.Or(bad,*([]if v is None else[z3.Not(q)for q in v.address_checks]))));query=s.to_smt2();r=s.check();assert r==z3.unsat,(name,str(r),s.reason_unknown())
  out.append({'name':name,'result':'unsat','premises_nonvacuous':True,'query':query,'lifted_instruction_instances':0 if v is None else v.count,'packet_codec_source_shape_checks':[]if v is None else copy.deepcopy(v.packet_codec_rewrites),'registry_bank_rewrites':[]if v is None else copy.deepcopy(v.registry_bank_rewrites),'new_independent_controller_reads':0 if v is None else v.registry_controller_reads,'new_independent_bank_bytes':0 if v is None else v.registry_bank_reads})
  if v is not None:visited.update(v.visited)
  print('proved '+name,flush=True)
 p=z3.BitVec('RG_any_record64',64);prove('universal_caller_decoder_pre_multiply_equality',None,caller_pre(p)!=decoder_pre(p))
 v=Model(e);v.seed('x0',p);v.run('registry_lookup_codec');prove('actual_helper_codec_matches_original_decoder_formula',v,z3.Or(v.values[(0xfffffe000a5ae408,'x9')]!=decoder_pre(p),v.read('x13')!=codec(p)))
 v=Model(e);c=v.common;prove('original_roots_private_record_alias_and_default_status',v,z3.Or(H.cell(v,c['F']+0x658,8)!=c['S']+0x10,H.cell(v,c['F']+0x610,8)!=c['C']+0x440,H.cell(v,c['F']+0x940,8)!=c['S']+0xa28,H.cell(v,c['F']+0x998,8)!=c['S']+0x968,H.cell(v,c['F']+0x6f0,8)!=((c['S']+0x968)|0xd9d0ab468c12f4cb),H.cell(v,c['F']+0x9ec,4)!=0xce515bb2))
 v=holder_requested(e);c=v.common;prove('actual_schema_u32_success_requests_same_global_holder_with_own_callback',v,z3.Or(record_preserved(v),H.cell(v,c['F']+0x9e0,8)!=HOLDER,v.read('x19')!=0xfffffe000a6367b4,v.read('x22')!=v.holder,Publication.edge(v,z3.If(v.holder==0,resize(0xfffffe000a65ac84,64),resize(0xfffffe000a65affc,64)),0xa830)))
 v=ready_consumer(e);c=v.common;prove('ready_holder_returns_to_exact_scalar_consumer_and_lookup_arguments',v,z3.Or(record_preserved(v),v.read('w8')!=(c['V']^SUCCESS),v.read('w10')!=0x128,v.read('w23')!=0x160,v.read('x9')!=c['S']+0x10,v.read('x19')!=c['C']+0x440,Publication.edge(v,0xfffffe000a65b16c,0x44f9)))
 cut=Model(e);c=cut.common;status=z3.BitVec('RG_saved_status32',32)
 for reg,x in [('x7',TABLE),('w1',PHASE),('w3',TOKEN),('x22',cut.holder)]:cut.seed(reg,x)
 mem(cut,c['F']+0x9ec,4,status);cut.run('registry_return');prove('all_holder64_saved_status32_caller_return_gate',cut,z3.Or(cut.read('w23')!=status,Publication.edge(cut,z3.If(cut.holder==0,resize(0xfffffe000a641c1c,64),resize(0xfffffe000a6367fc,64)),0xd4c)))
 v=lookup_requested(e);c=v.common;record=c['S']+0x968;writes=[q for q in v.stores if q['pc']in [0xfffffe000a65b4c4,0xfffffe000a65b4c8,0xfffffe000a65b4d0,0xfffffe000a65b4d8]];assert len(writes)==6 and sum(q['size_bytes']for q in writes)==40
 gap=[z3.Not(z3.Or(z3.ULE(q['address']+q['size_bytes'],record+0x18),z3.ULE(record+0x20,q['address'])))for q in v.stores[v.registry_store_start:]]
 prove('complete_actual_u32_to_token541_packet_and_pending_lookup_call',v,z3.Or(packet_bad(v),record_preserved(v),*gap));models={'u32':v}
 v=holder_requested(e);v.extra.append(v.holder==0);v.run('registry_allocate');prove('null_holder_requests_original_typed_allocation_and_keeps_schema_callback',v,z3.Or(record_preserved(v),v.read('x0')!=0xfffffe000847b960,v.read('x19')!=0xfffffe000a6367b4,v.read('x30')!=0xfffffe000a65ad54,Publication.edge(v,0xfffffe000c4ba154,0xd0c8)))
 cut=Model(e);c=cut.common
 for reg,x in [('x7',TABLE),('x2',c['C']),('w3',TOKEN),('w20',0x5df),('w23',0x160),('x22',cut.holder)]:cut.seed(reg,x)
 cut.run('registry_lookup_header');prove('all_holder64_private_header_gate_clears_index_and_saves_trampoline',cut,z3.Or(H.cell(cut,c['S']+0xa28,4)!=0,H.cell(cut,c['C']+0x680,8)!=0xfffffe000a65b5f8,Publication.edge(cut,z3.If(cut.holder==0,resize(0xfffffe000a65b5ec,64),resize(0xfffffe000a65b408,64)),0xbe19)))
 cut=Model(e);c=cut.common
 for reg,x in [('x7',TABLE),('x4',c['S']),('w24',0x25),('w23',status)]:cut.seed(reg,x)
 cut.run('registry_error_status');prove('all_error_status32_publication_and_original_cleanup_request',cut,z3.Or(H.cell(cut,c['S']+0x1c,4)!=status,cut.read('w25')!=TOKEN,cut.read('x19')!=c['C']+0x418,Publication.edge(cut,0xfffffe000a66229c,0xb23e)))
 for kind in ['u64','span_zero','span_nonzero']:
  v=scalar_finished(e,kind);v.registry_store_start=len(v.stores);v.run('registry_error_status');c=v.common
  prove(kind+'_actual_scalar_type_error_is_published_before_cleanup',v,z3.Or(H.cell(v,c['S']+0x1c,4)!=Parent.TYPE_ERROR,H.cell(v,c['S']+0xbc4,4)!=0,H.cell(v,c['F']+0xaa8,8)!=z3.ZeroExt(32,c['L'])+10,Publication.edge(v,0xfffffe000a66229c,0xb23e)));models[kind]=v
 captured={int(i['pc'],16)for s in e['source']['spans']for i in s['instructions']};assert captured<=visited,captured-visited
 return out,models,len(visited&captured)

def bindings_and_premises(v,values):
 b=Parent.Parent.bindings(v,values);premises=[z3.simplify(z3.substitute(q,*b))for q in v.owned()+v.guards+v.extra+v.address_checks]
 s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises);assert s.check()==z3.sat
 return b,premises

def evaluations(e,models):
 rows=[]
 for r in e['predecessor_states']:
  kind,values=Parent.Parent.values_for(r);old=values['D'];values['D']=Parent.Parent.KEY;v=models[kind];c=v.common;b,premises=bindings_and_premises(v,values);fields=Parent.projected_fields(v,values);bad=[]
  if kind=='u32':
   packet=values['S']+0x968;k=H.numeric(codec(c['S']+0x968),b)
   fields.extend([('F',0x9e0,8,HOLDER),('C',0x30,8,0xfffffe000a636854),('C',0x680,8,0xfffffe000a65b5f8),('S',0xa28,4,0),('F',0x658,8,values['S']+0x10),('F',0x610,8,values['C']+0x440),('F',0x940,8,values['S']+0xa28),('F',0x998,8,packet),('F',0x6f0,8,packet|0xd9d0ab468c12f4cb),('F',0x9ec,4,0xce515bb2),('S',0x970,8,values['S']+0x10),('S',0x978,8,values['S']+0xa28),('S',0x990,4,(k+0x541)&0xffffffff)])
   shape=0x652019cc00000000|(values['V']^0x6a48ac59);assert H.numeric(H.cell(v,c['S']+0x968,8)+codec(c['S']+0x968),b)==shape;bad.append(packet_bad(v));target=0xfffffe000a5ae354;modifier=0x6a0f;symbolic_fields=2;derived_key=hex(KEY_BIAS+values['V'])
  else:
   fields.append(('S',0x1c,4,Parent.TYPE_ERROR));bad.append(H.cell(v,c['S']+0x1c,4)!=Parent.TYPE_ERROR);target=0xfffffe000a66229c;modifier=0xb23e;symbolic_fields=0;derived_key=None
  for root,off,n,want in fields:assert H.numeric(H.cell(v,c[root]+off,n),b)==want
  assert H.numeric(v.edges[-1]['target'],b)==target and H.numeric(v.edges[-1]['modifier'],b)==modifier
  bad.append(Publication.edge(v,target,modifier));s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises,z3.simplify(z3.substitute(z3.Or(*bad),*b)));assert s.check()==z3.unsat
  rows.append({'predecessor_case_index':r['predecessor_case_index'],'domain':kind,'evaluation_kind':'derived_key_substitution','original_raw_tag32':hex(old),'raw_tag32':hex(values['D']),'numeric_fields_checked':len(fields)+(1 if kind=='u32'else 0),'symbolic_environment_fields_checked':symbolic_fields,'environment_premises_nonvacuous':True,'conditional_environment_query_unsat':True,'native_holder_values_supplied':0,'native_capacity_values_supplied':0,'native_entries_values_supplied':0,'derived_lookup_key64':derived_key,'final_target':hex(target),'pending_call':kind=='u32','new_independent_controller_reads':v.registry_controller_reads,'new_independent_bank_bytes':v.registry_bank_reads,'packet_codec_source_shape_checks':copy.deepcopy(v.packet_codec_rewrites),'all_storage_branch_and_lookup_premises_checked':True,'missing_cells_bound_to_concrete_values':0,'continuous_guest_extended':False,'native_target_executed':False,'all_checks_pass':True})
 return rows

def adid_field_certificate(e,models):
 r=next(r for r in e['predecessor_states']if Parent.Parent.values_for(r)[0]=='u32');_,values=Parent.Parent.values_for(r);values.update(D=Parent.Parent.KEY,U=0x9777,L=4,V=0,N=14);v=models['u32'];b,premises=bindings_and_premises(v,values);field=e['adid_evidence']['packets'][0]['field_record_hex'];assert field=='fa83411297770000000400000000';actual=bytes(H.numeric(H.cell(v,v.common['Z']+j,1),b)for j in range(14));assert actual==bytes(x^H.py_mask(values['Z']+j)for j,x in enumerate(bytes.fromhex(field)))
 s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises,z3.simplify(z3.substitute(packet_bad(v),*b)));assert s.check()==z3.unsat
 assert H.numeric(H.cell(v,v.common['S']+0xbc4,4),b)==0 and H.numeric(v.edges[-1]['target'],b)==0xfffffe000a5ae354
 return {'source_predecessor_case_index':r['predecessor_case_index'],'synthetic_tag_and_scalar_substitution':True,'raw_record_hex':field,'protected_record_hex':actual.hex(),'protected_record_bytes_checked':14,'matches_all_twelve_frozen_ADID_field_records':all(p['field_record_hex']==field for p in e['adid_evidence']['packets']),'decoded_output32':0,'derived_lookup_key64':hex(KEY_BIAS),'pending_lookup_target':'0xfffffe000a5ae354','lookup_modifier':'0x6a0f','lookup_record_size_bytes':48,'lookup_record_initialized_bytes':40,'native_holder_values_supplied':0,'native_capacity_values_supplied':0,'native_entries_values_supplied':0,'environment_premises_nonvacuous':True,'conditional_environment_query_unsat':True,'native_target_executed':False,'lookup_helper_executed':False,'whole_ADID_packet_parsed_by_kext':False,'transport_identity_established':False}

def negative_controls(e):
 rows=[]
 for pc in [0xfffffe000a63678c,0xfffffe000a635c54,0xfffffe000a65b4c8]:
  changed=copy.deepcopy(e);row=next(s for s in changed['source']['spans']if int(s['start'],16)<=pc<int(s['end_exclusive'],16));off=pc-int(row['start'],16);raw=bytearray.fromhex(row['bytes_hex']);old=bytes(raw[off:off+4]);word=int.from_bytes(old,'little')
  word=word^(1<<10)if pc==0xfffffe000a63678c else(word&~(0xfff<<10))|((0x14 if pc==0xfffffe000a635c54 else 3)<<10);replacement=word.to_bytes(4,'little');raw[off:off+4]=replacement;row['bytes_hex']=raw.hex()
  if pc==0xfffffe000a63678c:v=scalar_finished(changed).run('registry_request');bad=v.read('w8')!=0x37;stop='before_consuming_mutated_callback_index'
  elif pc==0xfffffe000a635c54:v=ready_consumer(changed);bad=v.read('x9')!=v.common['S']+0x10;stop='before_private_lookup_record_construction'
  else:
   v=lookup_requested(changed);store=next(q for q in reversed(v.stores)if q['pc']==pc);bad=store['address']!=v.common['S']+0x988;stop='at_pending_lookup_call_without_executing_it'
  premises=v.owned()+v.guards+v.extra+v.address_checks;p=z3.SolverFor('QF_BV');p.set(timeout=60000);p.add(*premises);assert p.check()==z3.sat
  s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises,bad);assert s.check()==z3.sat
  rows.append({'mutated_PC':hex(pc),'original_word_hex':old.hex(),'replacement_word_hex':replacement.hex(),'satisfiable_violation_query':s.to_smt2(),'stop_boundary':stop,'normal_oracle_rejected':True,'native_target_executed':False})
 return rows

def audit(e=None):
 e=e if e is not None else json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,models,covered=source_obligations(e);cases=evaluations(e,models);certificate=adid_field_certificate(e,models);controls=negative_controls(e);prior=[]
 selected={'userclient_schema_scalar_audit.json':['universal_word32_add_mask_sub_equals_xor','universal_type32_mask_xor_sub_add_equals_xor','u32_complete_same_node_header_body_output_cursor_and_caller'],'userclient_hash_table_lookup_audit.json':['original_record_codec_closed_form','token541_nonnull_array_decoder_contract','token541_null_array_failure_gate']}
 for filename,names in selected.items():
  old=json.loads(read(ROOT/filename))
  for name in names:
   p=next(q for q in old['source_proofs']if q.get('name',q.get('label'))==name);ctx=z3.Context();s=z3.SolverFor('QF_BV',ctx=ctx);s.set(timeout=120000);s.add(*z3.parse_smt2_string(p['query'],ctx=ctx));result=s.check();assert result==z3.unsat,(name,str(result),s.reason_unknown());prior.append({'name':name,'result':'unsat','source_audit':filename,'source_audit_sha256':sha(ROOT/filename)});print('rechecked '+name,flush=True)
 totals={'new_source_queries_unsat':len(proofs),'prior_source_queries_unsat':len(prior),'lifted_instruction_instances':sum(q['lifted_instruction_instances']for q in proofs),'new_source_words_covered':covered,'derived_key_substitution_projections':len(cases),'numeric_fields_checked':sum(q['numeric_fields_checked']for q in cases),'symbolic_environment_fields_checked':sum(q['symbolic_environment_fields_checked']for q in cases),'environment_premises_sat':len(cases)+1,'conditional_environment_queries_unsat':len(cases)+1,'additional_prefix_cells_reconstructed':sum(len(p['registry_additional_source_cells'])for p in e['predecessor_states']),'additional_prefix_bytes_reconstructed':sum(sum(q['size_bytes']for q in p['registry_additional_source_cells'])for p in e['predecessor_states']),'negative_source_controls':len(controls),'missing_cells_assigned_concrete_values':0,'native_holder_values_supplied':0,'native_capacity_values_supplied':0,'native_entries_values_supplied':0,'ready_composition_new_controller_reads':4,'ready_composition_new_bank_bytes':2,'null_allocation_new_controller_reads':4,'null_allocation_new_bank_bytes':3,'ADID_compatible_record_bytes_checked':14,'lookup_record_size_bytes':48,'lookup_record_initialized_bytes':40,'composed_domains':4}
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':e['scope'],'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],'source_proofs':proofs,'rechecked_prior_source_proofs':prior,'partial_state_evaluations':cases,'ADID_field_certificate':certificate,'negative_source_controls':controls,'independent_totals':totals,'conditional_schema_registry_request_established':True,'all_checks_pass':True,**{n:False for n in R.FALSE}}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
