; benchmark generated from python API
(set-info :status unknown)
(declare-fun consumer_payload64 () (_ BitVec 64))
(declare-fun consumer_first_index32 () (_ BitVec 32))
(assert
 (let ((?x27 (bvxor consumer_first_index32 (ite (= consumer_payload64 (_ bv0 64)) (_ bv46 32) (_ bv0 32)))))
(let ((?x22 (bvxor consumer_first_index32 (bvmul (_ bv46 32) (ite (= consumer_payload64 (_ bv0 64)) (_ bv1 32) (_ bv0 32))))))
(not (= ?x22 ?x27)))))
(check-sat)
