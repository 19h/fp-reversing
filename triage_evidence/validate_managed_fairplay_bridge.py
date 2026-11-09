#!/usr/bin/env python3
"""Independent selected instruction/ABI checks and original-source recapture.
O(B+F+I) time/space; no target execution, emulation or message sending.
"""
import copy,json
from recover_managed_fairplay_bridge import ROOT,P,FLAGS,build,sha,h,instructions
def check(s):
 count=0
 def at(r,offset,mn,op):
  nonlocal count
  a=int(r['start'],16)+offset;q=next(i for i in r['instructions']if int(i['ea'],16)==a);assert(q['mnemonic'],q['operands'])==(mn,op),(hex(a),q,mn,op);count+=1
 def exact(r,a,mn,op):at(r,a-int(r['start'],16),mn,op)
 assert len(s['images'])==2 and s['AMS_uuid']=='1b464993-f0e2-3804-b412-a6cc8091798c'
 for im in s['images']:
  assert im['class_binding']['symbol']=='_OBJC_CLASS_$_AMSKeybag'and im['class_binding']['total_addend']==0 and im['class_binding']['library']==s['AMS_path']
  assert im['reference']['all_chain_memberships_and_targets_match']and im['reference']['fixups_compared']==im['fixup_count']
  assert len(im['selector_callers'])==4 and len(im['ranges'])==5 and len(im['selected_buffer_calls'])==9
  assert {r['containing_start']for r in im['selector_callers']}=={r['start']for r in im['ranges'][:4]}
  assert [r['selector']for r in im['stubs'][:2]]==['fairplayContextWithError:','sharedInstance']
  assert all(r['binding']['symbol']=='_objc_msgSend'for r in im['stubs'][:2])
  st={r['binding']['symbol']:r['address']for r in im['stubs'][2:]};small=im['ranges'][3];a=int(small['start'],16)
  spec=[(0x18,'mov','x19, x21'),(0x30,'ldr','x0, [x8, #0xa18]'),(0x34,'bl','#'+st['_objc_opt_self']),
    (0x38,'bl','#0x1004808e0'),(0x40,'bl','#'+st['_objc_retainAutoreleasedReturnValue']),
    (0x44,'mov','x22, x0'),(0x48,'str','xzr, [sp]'),(0x4c,'mov','x2, sp'),(0x50,'bl','#0x10047ddc0'),
    (0x54,'mov','x20, x0'),(0x58,'mov','x0, x22'),(0x5c,'bl','#'+st['_objc_release']),
    (0x60,'ldr','x22, [sp]'),(0x64,'cbz','x22, #'+hex(a+0x80)),(0x68,'mov','x21, x22'),
    (0x6c,'bl','#'+st['_swift_willThrow']),(0x70,'mov','x0, x22'),(0x74,'bl','#'+st['_objc_retain']),
    (0x78,'mov','x21, x22'),(0x80,'mov','x21, x19'),(0x9c,'mov','x0, x20'),(0xb0,'retab','')]
  for off,mn,op in spec:at(small,off,mn,op)
  helper=im['ranges'][4];assert helper['start']==im['buffer_adapter_entry']
  for off,mn,op in [(0x24,'str','x3, [sp, #8]'),(0x28,'str','w2, [sp, #0x14]'),(0x2c,'str','x1, [sp, #0x18]'),(0x30,'str','w0, [sp, #0x20]')]:at(helper,off,mn,op)
  for caller in im['ranges'][:3]:
   call=next(c for c in im['selector_callers']if c['containing_start']==caller['start']);site=int(call['site'],16)
   exact(caller,site-8,'str','xzr, [x19]');exact(caller,site-4,'mov','x2, x19');exact(caller,site,'bl','#0x10047ddc0');exact(caller,site+4,'mov','x21, x0');exact(caller,site+8,'mov','x0, x20');exact(caller,site+12,'bl','#'+st['_objc_release']);exact(caller,site+16,'ldr','x20, [x19]')
  for r in im['ranges']:assert h(bytes.fromhex(r['bytes']))==r['sha256']and instructions(bytes.fromhex(r['bytes']),int(r['start'],16))==r['instructions']
 ams={r['start']:r for r in s['AMS_ranges']};wrapper=ams['0x19c1ed14c'];getter=ams['0x19c6491c8'];ctx=ams['0x19c6000e4'];cid=ams['0x19c6006fc']
 for off,mn,op in [(0x10,'mov','x19, x2'),(0x14,'bl','#0x1a0025080'),(0x24,'bl','#0x1a00250a0'),(0x28,'mov','x19, x0'),(0x34,'mov','x0, x19')]:at(wrapper,off,mn,op)
 for off,mn,op in [(0,'mov','w2, #0x10'),(4,'mov','w3, #1'),(8,'b','#0x1a006bf90')]:at(getter,off,mn,op)
 at(cid,0,'ldr','w0, [x0, #8]');at(cid,4,'ret','')
 for a,mn,op in [(0x19c60011c,'ldr','w0, [x20, #8]!'),(0x19c600124,'bl','#0x19ca0d0e4'),(0x19c6002d4,'add','x1, sp, #0x20'),(0x19c6002d8,'mov','x0, #0'),(0x19c6002dc,'mov','x3, x20'),(0x19c6002e0,'bl','#0x19c9e12a0'),(0x19c600348,'ldr','w19, [x20]'),(0x19c600358,'ldr','w19, [x20]'),(0x19c600374,'mov','x0, x19')]:exact(ctx,a,mn,op)
 names={r['start']:[e['name']for e in r['original_names']]for r in s['AMS_ranges']};assert '-[AMSKeybag fairplayContextWithError:]'in names[wrapper['start']]and '-[AMSFairPlayContext fairplayContextIDWithError:]'in names[ctx['start']]
 assert '_OBJC_CLASS_$_AMSFairPlayContext'in[e['name']for e in s['AMS_classes']['AMSFairPlayContext']['original_names']]
 cs={r['address']:r for r in s['AMS_stubs']};assert cs['0x1a0025080']['selector']=='fairPlayContext'and cs['0x1a00250a0']['selector']=='fairplayContextIDWithError:'
 for a,name in [('0x1a006bf90','_objc_getProperty'),('0x1a006bec0','_objc_alloc_init'),('0x1a006b980','_dispatch_once')]:assert cs[a]['exact_export']['symbol']==name
 for obj in[s]:assert all(obj[k]is False for k in FLAGS)
 return count
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();n=check(s);bad=[]
 for name in ['class','selector','buffer_width','error_channel','context_width','property_offset','reference','effect']:
  a=copy.deepcopy(s)
  if name=='class':a['images'][0]['class_binding']['symbol']='_OBJC_CLASS_$_Unknown'
  elif name=='selector':a['images'][1]['stubs'][0]['selector']='unknown'
  elif name=='buffer_width':next(r for r in a['images'][0]['ranges'][4]['instructions']if r['operands']=='w0, [sp, #0x20]')['operands']='x0, [sp, #0x20]'
  elif name=='error_channel':next(r for r in a['images'][1]['ranges'][3]['instructions']if r['operands']=='x2, sp')['operands']='x2, xzr'
  elif name=='context_width':a['AMS_ranges'][-1]['instructions'][0]['operands']='x0, [x0, #8]'
  elif name=='property_offset':a['AMS_ranges'][4]['instructions'][0]['operands']='w2, #8'
  elif name=='reference':a['images'][0]['reference']['all_chain_memberships_and_targets_match']=False
  else:a['target_executed']=True
  try:check(a)
  except AssertionError:bad.append(name)
  else:raise AssertionError('Alteration accepted '+name)
 counts={**s['verified_source_counts'],'exact_instruction_assertions':n,'rejected_alterations':len(bad)}
 scope={'original_static_binaries':2,'original_cached_AMS':True,'native_target_instructions':0,'target_emulation':False,'opaque_adapter_body_semantics_unknown':True,'dynamic_dispatch_identity_unknown':True,'RPC700_receiver_unknown':True}
 o={'generator_sha256':sha(__file__),'dependencies':{'recover_'+P+'.py':sha(ROOT/('recover_'+P+'.py'))},'source_recapture_match':True,'verified_counts':counts,'static_scope':scope,'rejected_controls':bad,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(o,indent=2)+'\n');print(json.dumps(counts))
if __name__=='__main__':main()
