; benchmark generated from python API
(set-info :status unknown)
(declare-fun result32 () (_ BitVec 32))
(declare-fun selector32 () (_ BitVec 32))
(assert
 (let (($x323 (= result32 (_ bv0 32))))
(let ((?x325 (ite $x323 (_ bv1287 32) (_ bv1291 32))))
(let ((?x35 (ite (and (distinct result32 (_ bv0 32)) true) (bvxor (bvor (bvadd selector32 (_ bv561 32)) (_ bv1 32)) (_ bv1845 32)) (_ bv0 32))))
(let ((?x36 (bvxor selector32 ?x35)))
(let (($x322 (= selector32 (_ bv1287 32))))
(and $x322 (and (distinct ?x36 ?x325) true))))))))
(check-sat)
