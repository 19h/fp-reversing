; benchmark generated from python API
(set-info :status unknown)
(declare-fun lifetime_runtime_flag32 () (_ BitVec 32))
(assert
 (let (($x206 (= lifetime_runtime_flag32 (_ bv0 32))))
(let ((?x208 (ite $x206 (_ bv0 1) (_ bv1 1))))
(let ((?x211 (bvadd (_ bv4311981808 64) (concat (_ bv1297 56) ?x208 (_ bv0 2) ?x208 (_ bv0 4)))))
(and (and (distinct lifetime_runtime_flag32 (_ bv0 32)) true) (and (distinct ?x211 (_ bv4312313984 64)) true))))))
(check-sat)
