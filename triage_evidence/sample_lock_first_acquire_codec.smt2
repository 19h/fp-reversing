; benchmark generated from python API
(set-info :status unknown)
(declare-fun record_low32 () (_ BitVec 32))
(assert
 (let ((?x14 (bvmul (bvxor record_low32 (_ bv1630773448 32)) (_ bv2228712307 32))))
(let ((?x43 (bvsub (bvsub (_ bv4294967294 32) (bvor record_low32 (_ bv2919006754 32))) (bvor (_ bv1375960541 32) (bvnot record_low32)))))
(let ((?x46 (bvmul (bvxor ?x43 (_ bv858840341 32)) (_ bv2228712307 32))))
(and (distinct ?x46 ?x14) true)))))
(check-sat)
