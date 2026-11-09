; benchmark generated from python API
(set-info :status unknown)
(declare-fun attribute32 () (_ BitVec 32))
(assert
 (let ((?x19 (bvor (ite (= (bvand attribute32 (_ bv65536 32)) (_ bv0 32)) (_ bv2 32) (_ bv0 32)) (ite (= (bvand attribute32 (_ bv131072 32)) (_ bv0 32)) (_ bv64 32) (_ bv0 32)))))
(let ((?x48 (bvshl ?x19 (_ bv16 32))))
(or (and (distinct (bvand ?x48 (_ bv851967 32)) (_ bv0 32)) true) (= ?x48 (_ bv3722305197 32))))))
(check-sat)
