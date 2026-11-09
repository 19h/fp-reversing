; benchmark generated from python API
(set-info :status unknown)
(declare-fun attribute32 () (_ BitVec 32))
(assert
 (let ((?x19 (bvor (ite (= (bvand attribute32 (_ bv65536 32)) (_ bv0 32)) (_ bv2 32) (_ bv0 32)) (ite (= (bvand attribute32 (_ bv131072 32)) (_ bv0 32)) (_ bv64 32) (_ bv0 32)))))
(not (or (= ?x19 (_ bv0 32)) (= ?x19 (_ bv2 32)) (= ?x19 (_ bv64 32)) (= ?x19 (_ bv66 32))))))
(check-sat)
