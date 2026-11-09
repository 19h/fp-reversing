; benchmark generated from python API
(set-info :status unknown)
(declare-fun candidate_state32 () (_ BitVec 32))
(assert
 (let ((?x26 (bvxor candidate_state32 (bvadd (bvxor (bvadd candidate_state32 (_ bv160 32)) (_ bv2955273429 32)) (_ bv1339691775 32)))))
(and (bvult candidate_state32 (_ bv2648 32)) (and (distinct (= ?x26 (_ bv2228 32)) (= (bvand candidate_state32 (_ bv4294966881 32)) (_ bv2144 32))) true))))
(check-sat)
