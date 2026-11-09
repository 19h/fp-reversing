#!/usr/bin/env python3
"""Static bit-vector and byte-array output contracts; no target execution."""
import copy,json,re,subprocess
from recover_daemon_output_publication import ROOT,P,FLAGS,CS,sha,h,build,FIXED,BLOCKS,EDGES,SPECS,SCOPE
PATTERNS='''
success_gate|mov|w8, #-0x2427
success_gate|mov|w9, #-0x2bae
success_gate|ldr|w6, [x10, #0xc54]
success_gate|ldr|x11, [sp, #0x16d0]
success_gate|mov|x12, #-0x48e3
success_gate|ldr|x19, [sp, #0x9d0]
success_gate|add|w8, w19, w8
success_gate|eor|x12, x8, x12
success_gate|add|x11, x12, x11
success_gate|str|x11, [sp, #0x16d0]
success_gate|cmp|w6, w11
success_gate|cset|w11, eq
success_gate|mov|w12, #0x832e
success_gate|mul|w11, w11, w12
success_gate|add|w9, w19, w9
success_gate|eor|w9, w11, w9
publish|ldr|x9, [sp, #0x70c8]
publish|ldr|x10, [sp, #0x1a30]
publish|str|x9, [x10]
publish|ldr|w9, [sp, #0x3928]
publish|ldr|x10, [sp, #0x7098]
publish|str|x9, [x10]
publish|mov|w6, #0xc651
publish|movk|w6, #0x8b3d, lsl #16
result_stage|str|w6, [x8, #0x4a4]
result_stage|ldr|x20, [sp, #0x1360]
result_stage|str|x20, [sp, #0x5f68]
terminal_gate|ldr|w6, [x9, #0x4a4]
terminal_gate|cmp|w6, w9
helper_input|ldr|x10, [sp, #0x79c8]
helper_input|str|x10, [sp, #0x9b8]
helper_input|add|x11, sp, #3, lsl #12
helper_input|add|x11, x11, #0x928
helper_input|add|x9, sp, #7, lsl #12
helper_input|add|x9, x9, #0xc8
helper_setup|str|x11, [sp, #0x2988]
helper_setup|ldr|x24, [sp, #0x16d0]
helper_setup|add|x8, sp, #0xc, lsl #12
helper_setup|add|x8, x8, #0x70
helper_setup|add|x0, x8, x24
helper_setup|add|x20, x0, #0x10
helper_setup|str|x9, [sp, #0x2d20]
helper_setup|mov|w1, #0
helper_setup|mov|w2, #0x10
helper_setup|mov|x0, x20
helper_setup|mov|w2, #0x20
helper_setup|str|xzr, [x9, #0x378]
helper_setup|str|w8, [sp, #0x1210]
helper_return|ldr|x10, [x10, #0x378]
helper_return|ldr|x11, [sp, #0x2d20]
helper_return|str|x10, [x11]
helper_return|ldr|w10, [sp, #0x1210]
helper_return|ldr|x11, [sp, #0x2988]
helper_return|str|w10, [x11]
helper_return|mov|w6, #0xc651
helper_return|movk|w6, #0x8b3d, lsl #16
nested_outputs|ldr|x21, [sp, #0x1c10]
nested_outputs|add|x19, sp, #1, lsl #12
nested_outputs|add|x19, x19, #0x210
nested_outputs|add|x8, sp, #8, lsl #12
nested_outputs|add|x8, x8, #0x378
fill_banks|ldr|x9, [x25, #0x4048]
fill_banks|str|x20, [sp, #0x5d0]
fill_banks|str|x11, [sp, #0x5d8]
'''

def verify(s):
 assert s['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'and s['static_scope']==SCOPE
 for n,f in s['fragments'].items():
  bb=bytes.fromhex(f['bytes']);a=int(f['start'],16);ii=list(CS.disasm(bb,a))
  assert len(bb)==int(f['end'],16)-a==4*len(ii)and h(bb)==f['sha256']
  assert f['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]
  if n in FIXED:assert(a,int(f['end'],16))==FIXED[n]
  else:assert a==BLOCKS[n]and ii[-1].mnemonic=='braa'
 assert set(s['fragments'])==set(FIXED)|set(BLOCKS)
 rows=[]
 for line in PATTERNS.strip().splitlines():
  n,mn,op=line.split('|');hits=[i for i in s['fragments'][n]['instructions']if(i['mnemonic'],i['operands'])==(mn,op)];assert hits,(n,mn,op);rows.extend({'role':n,**i}for i in hits)
 assert[(r['role'],r['source'],int(r['index'],16),int(r['target'],16))for r in s['branches']]==EDGES
 for r in s['branches']:
  w=int(r['pointer_word'],16);assert w>>63 and(w>>32&65535)==r['modifier_u16']and not(w>>48&1)and not(w>>49&3)
  assert int(r['slot'],16)==0x101039ef0+8*int(r['index'],16)
 for name,pair,key,add in SPECS:
  b=s['banks'][name];l,rr=bytes.fromhex(b['left_bytes']),bytes.fromhex(b['right_bytes']);vals=[i^rr[l[i]^key]for i in range(256)]
  assert vals==b['results_256']and len(set(vals))==1 and b['target']=='0x10046faf8'
  assert int(b['slot'],16)==0x101039ef0+8*(add+vals[0])and b['left']==hex(pair[0])and b['right']==hex(pair[1])
 for r in s['calls']:
  assert r['target']=='0x10046faf8'and r['slot']=='0x1010a03c8'and r['modifier_u16']==0xac7d
  ii=list(CS.disasm(bytes.fromhex(r['bytes']),int(r['site'],16)-4));assert[(i.mnemonic,i.op_str)for i in ii]==[('mov','x17, #0xac7d'),('blraa','x8, x17')]
 assert[len(r['hits'])for r in s['literal_census']['patterns']]==[10,2,1,0]
 for r in s['literal_census']['patterns']:
  assert r['mask']=='0xffffffe0'
  for f in r['hits']:
   bb=bytes.fromhex(f['bytes']);assert int.from_bytes(bb[:4],'little')&0xffffffe0==int(r['opcode'],16)and h(bb)==f['sha256']
 assert s['fixup_reference']['catalog_memberships_compared']==61737 and all(s[k]is False for k in FLAGS)
 return rows

def bv(v,w=64):return '#x'+format(v&((1<<w)-1),'0'+str(w//4)+'x')

def publication_query(s):
 """Translate only the original straight-line publication arithmetic to SMT SSA.
 Memory loads are named component inputs; no target code or request is executed.
 """
 regs={8:bv(0x48cd)};defs=[];stores=[];translated=[]
 def get(r):
  ix=int(r[1:]);e=regs[ix];return f'((_ extract 31 0) {e})'if r[0]=='w'else e
 def put(r,e):
  name='v'+str(len(defs));width=32 if r[0]=='w'else 64;defs.append(f'(define-fun {name} () (_ BitVec {width}) {e})')
  regs[int(r[1:])]=f'((_ zero_extend 32) {name})'if width==32 else name
 for i in s['fragments']['publish']['instructions']:
  a=int(i['ea'],16)
  if a>=0x1005828c0:break
  mn=i['mnemonic'];op=i['operands'];parts=op.split(', ');rd=parts[0];width=32 if rd.startswith('w')else 64
  if mn=='ldr':
   key=(rd,', '.join(parts[1:]));inputs={('x9','[sp, #0x70c8]'):'D',('x10','[sp, #0x1a30]'):'A',('w9','[sp, #0x3928]'):'N',('x10','[sp, #0x7098]'):'B'};put(rd,inputs[key])
  elif mn=='str':stores.append({'site':i['ea'],'value':get(rd),'address':get(parts[1].strip('[]')),'width_bits':width})
  elif mn=='mov':put(rd,bv(int(parts[1][1:],0),width))
  elif mn=='movk':
   imm=int(parts[1][1:],0);shift=int(parts[2].split('#')[1],0);mask=0xffff<<shift
   put(rd,f'(bvor (bvand {get(rd)} {bv(~mask,width)}) {bv(imm<<shift,width)})')
  elif mn in('add','eor','orr'):
   opmap={'add':'bvadd','eor':'bvxor','orr':'bvor'};put(rd,f'({opmap[mn]} {get(parts[1])} {get(parts[2])})')
  else:raise AssertionError((mn,op))
  translated.append(i['ea'])
 assert len(stores)==2 and stores[0]['width_bits']==stores[1]['width_bits']==64
 body='(declare-fun D () (_ BitVec 64)) (declare-fun N () (_ BitVec 32))\n(declare-fun A () (_ BitVec 64)) (declare-fun B () (_ BitVec 64))\n'+'\n'.join(defs)+'\n'
 body+='(assert (or '+f'(distinct {stores[0]["value"]} D) (distinct {stores[0]["address"]} A) '+f'(distinct {stores[1]["value"]} ((_ zero_extend 32) (bvxor N #x8b3dc651))) (distinct {stores[1]["address"]} B) (distinct {get("w19")} #x00006cf4)'+'))'
 return body,{'source_sites':translated,'SSA_definitions':len(defs),'stores':stores,'entry_W8':'0x48cd','load_inputs':{'D':'u64[K+70c8]','N':'u32[K+3928]','A':'u64[K+1a30]','B':'u64[K+7098]'}}

def byte_query():
 body='(declare-fun C () (_ BitVec 64)) (declare-fun D () (_ BitVec 64)) (declare-fun N () (_ BitVec 32))\n(declare-fun M () (Array (_ BitVec 64) (_ BitVec 8))) (declare-fun probe () (_ BitVec 64))\n(define-fun L () (_ BitVec 64) ((_ zero_extend 32) (bvxor N #x8b3dc651)))\n'
 expr='M';items=[]
 for off,value in[(0x408,'D'),(0x6e8,'L')]:
  for j in range(8):
   a=f'(bvadd C {bv(off+j)})';v=f'((_ extract {j*8+7} {j*8}) {value})';expr=f'(store {expr} {a} {v})';items.append((a,v))
 body+=f'(define-fun O () (Array (_ BitVec 64) (_ BitVec 8)) {expr})\n'
 claims=[f'(distinct (select O {a}) {v})'for a,v in items]
 claims.append('(and '+' '.join(f'(distinct probe {a})'for a,v in items)+' (distinct (select O probe) (select M probe)))')
 return body+'(assert (or '+' '.join(claims)+'))'

def helper_query():
 # Source-defined helper output aliases: K+2d20 -> K+70c8 and
 # K+2988 -> K+3928; values come from K+8378 (u64) / K+1210 (u32).
 body='(declare-fun K () (_ BitVec 64)) (declare-fun M () (Array (_ BitVec 64) (_ BitVec 8))) (declare-fun probe () (_ BitVec 64))\n'
 def addr(off):return f'(bvadd K {bv(off)})'
 def load(mem,off,count):
  parts=[f'(select {mem} {addr(off+j)})'for j in reversed(range(count))]
  expr=parts[-1]
  for p in reversed(parts[:-1]):expr=f'(concat {p} {expr})'
  return expr
 D=load('M',0x8378,8);N=load('M',0x1210,4);expr='M';written=[]
 for off,value,count in[(0x70c8,D,8),(0x3928,N,4)]:
  for j in range(count):expr=f'(store {expr} {addr(off+j)} ((_ extract {8*j+7} {8*j}) {value}))';written.append(addr(off+j))
 body+=f'(define-fun G () (Array (_ BitVec 64) (_ BitVec 8)) {expr})\n'
 claims=[f'(distinct {load("G",0x70c8,8)} {D})',f'(distinct {load("G",0x3928,4)} {N})',f'(distinct {load("G",0x8378,8)} {D})',f'(distinct {load("G",0x1210,4)} {N})']
 claims.append('(and '+' '.join(f'(distinct probe {a})'for a in written)+' (distinct (select G probe) (select M probe)))')
 return body+'(assert (or '+' '.join(claims)+'))'

def proofs(s):
 codec,translation=publication_query(s)
 qs=[('publication_original_SSA_all_pointer_and_length_bits',codec),
 ('success_gate_status_and_cursor_all32','''(declare-fun s () (_ BitVec 32)) (declare-fun cursor () (_ BitVec 64))
(define-fun w8 () (_ BitVec 32) (bvadd #x00006cf4 #xffffdbd9))
(define-fun delta () (_ BitVec 64) (bvxor ((_ zero_extend 32) w8) #xffffffffffffb71d))
(define-fun index () (_ BitVec 32) (bvxor (bvmul (ite (= s #x8b3dc651) #x00000001 #x00000000) #x0000832e) (bvadd #x00006cf4 #xffffd452)))
(assert (or (distinct w8 #x000048cd) (distinct (bvadd cursor delta) (bvsub cursor #x0000000000000030))
 (distinct index (ite (= s #x8b3dc651) #x0000c268 #x00004146))))'''),
 ('caller_pair_exact_bytes',byte_query()),
 ('helper_pair_width_and_forwarding',helper_query()),
 ('two_fill_extents_cover_48_bytes','''(declare-fun i () (_ BitVec 64))
(define-fun first () Bool (bvult i #x0000000000000010))
(define-fun second () Bool (and (bvuge i #x0000000000000010) (bvult i #x0000000000000030)))
(assert (or (distinct (or first second) (bvult i #x0000000000000030)) (and first second)))'''),
 ('common_result_staging_all32','''(declare-fun s () (_ BitVec 32))
(define-fun inner_ok () Bool (= s #x8b3dc651))
(define-fun staged () (_ BitVec 32) (ite inner_ok #x8b3dc651 s))
(define-fun outer_ok () Bool (= staged #x8b3dc651))
(define-fun L () (_ BitVec 32) (bvxor staged #x8b3dc651))
(assert (or (distinct staged s) (distinct inner_ok outer_ok) (distinct outer_ok (= L #x00000000))))''')]
 out=[]
 for name,body in qs:
  assert body.count('(')==body.count(')'),name
  q='(set-option :timeout 10000)\n(set-logic QF_AUFBV)\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,capture_output=True,text=True);assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr)
  out.append({'name':name,'query':q,'result':'unsat','scope':'Static component equations. Matching phase, valid owners/epochs, preserved helper/frame cells and normal helper returns are premises. Fill coverage is extent arithmetic, not a new all-input fill-function proof. No native heap/PAC/delivery or complete serialization is inferred.'})
 return {'queries':out,'publication_translation':translation}

def models():
 mask=(1<<64)-1;rows=[]
 for N in[0,1,0x7fff,0x10000,0x7fffffff,0x80000000,0xfffffffe,0xffffffff]:
  a=((N^0x327d5b04c58c3b05)+0xcd82a4fb3a73c4fb)&mask;b=((N^0xa835841070e0199b)+0x57ca7bef8f1fe665)&mask;c=((N^0x9a48df143e51e4cf)+0x65b720ebc1ae1b31)&mask
  out=((a^b^c)+0x8b3dc651)&mask;assert out==N^0x8b3dc651 and out<=0xffffffff
  for D in[0,1,0x100000000000,mask]:rows.append({'encoded_u32':hex(N),'pointer_u64':hex(D),'extent_u64':hex(out),'pointer_forwarded_unchanged':True})
 gate=[]
 for s in[0,0x74c29d69,0x74c29d85,0x8b3dc651,0xffffffff]:gate.append({'raw':hex(s),'publish':s==0x8b3dc651,'index':hex(0xc268 if s==0x8b3dc651 else 0x4146)})
 return {'publication_cases':rows,'gate_cases':gate,'scope':'Analyst-written integer boundary cases; pointer values carry no mapping/validity premise and are never passed to target code or APIs.'}

def alterations(s):
 def ins(q,n,ea,op):next(i for i in q['fragments'][n]['instructions']if i['ea']==ea).update(operands=op)
 changes=[('pointer_width',lambda q:ins(q,'publish','0x100582820','w9, [x10]')),
 ('encoded_length_width',lambda q:ins(q,'publish','0x100582824','x9, [sp, #0x3928]')),
 ('length_output_width',lambda q:ins(q,'publish','0x1005828bc','w9, [x10]')),
 ('cursor_direction',lambda q:ins(q,'success_gate','0x10059c7f4','x11, x11, x11')),
 ('success_branch',lambda q:q['branches'][0].update(target='0x1004de1d4')),
 ('helper_length_store',lambda q:ins(q,'helper_return','0x1007518c8','x10, [x11]')),
 ('fill_target',lambda q:q['banks']['zero16'].update(target='0x10046f89c')),
 ('native_claim',lambda q:q.update(native_peer_identity_proved=True))]
 out=[]
 for name,change in changes:
  q=copy.deepcopy(s);change(q)
  try:verify(q)
  except AssertionError:out.append({'alteration':name,'rejected':True})
  else:raise AssertionError('Accepted altered evidence '+name)
 return out

def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();rows=verify(s);pr=proofs(s);mm=models();neg=alterations(s)
 c={'generator_sha256':sha(__file__),'dependencies':{'recover_'+P+'.py':sha(ROOT/('recover_'+P+'.py'))},'source_recapture_match':True,'instruction_assertions':rows,'proofs':pr,'models':mm,'alterations':neg,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},
  'verified_counts':{**s['verified_source_counts'],'instruction_assertions':len(rows),'publication_instructions_translated':len(pr['publication_translation']['source_sites']),'publication_SSA_definitions':pr['publication_translation']['SSA_definitions'],'component_queries_unsat':len(pr['queries']),'publication_boundary_cases':len(mm['publication_cases']),'gate_cases':len(mm['gate_cases']),'rejected_evidence_alterations':len(neg)},'all_checks_pass':True,'static_scope':SCOPE,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(c['verified_counts']),flush=True)
if __name__=='__main__':main()
