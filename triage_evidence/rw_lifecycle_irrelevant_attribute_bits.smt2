; benchmark generated from python API
(set-info :status unknown)
(declare-fun alternate_attribute32 () (_ BitVec 32))
(declare-fun attribute32 () (_ BitVec 32))
(assert
 (let ((?x40 (bvor (ite (= (bvand alternate_attribute32 (_ bv65536 32)) (_ bv0 32)) (_ bv2 32) (_ bv0 32)) (ite (= (bvand alternate_attribute32 (_ bv131072 32)) (_ bv0 32)) (_ bv64 32) (_ bv0 32)))))
(let ((?x19 (bvor (ite (= (bvand attribute32 (_ bv65536 32)) (_ bv0 32)) (_ bv2 32) (_ bv0 32)) (ite (= (bvand attribute32 (_ bv131072 32)) (_ bv0 32)) (_ bv64 32) (_ bv0 32)))))
(and (distinct (= ?x19 ?x40) (= (bvand (bvxor attribute32 alternate_attribute32) (_ bv196608 32)) (_ bv0 32))) true))))
(check-sat)
