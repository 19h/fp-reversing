(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun candidate_u64 () (_ BitVec 64))
(declare-fun dispatch_seed_u32 () (_ BitVec 32))
(assert
 (let ((?x50 (bvxor dispatch_seed_u32 (ite (= candidate_u64 (_ bv0 64)) (_ bv4054 32) (_ bv0 32)))))
(let ((?x31 (bvxor dispatch_seed_u32 (bvmul (ite (= (_ bv0 64) candidate_u64) (_ bv1 32) (_ bv0 32)) (_ bv4054 32)))))
(and (distinct ?x31 ?x50) true))))
(check-sat)
