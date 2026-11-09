; benchmark generated from python API
(set-info :status unknown)
(declare-fun operation32 () (_ BitVec 32))
(assert
 (let (($x313 (= operation32 (_ bv7004 32))))
(let ((?x307 (ite $x313 (_ bv1646 32) (_ bv958 32))))
(let ((?x321 (bvnot ((_ extract 5 1) (bvmul (_ bv1488 32) (ite $x313 (_ bv1 32) (_ bv0 32)))))))
(let ((?x316 (bvmul (_ bv1488 32) (ite $x313 (_ bv1 32) (_ bv0 32)))))
(let ((?x309 ((_ extract 6 6) ?x316)))
(let ((?x319 (bvnot ((_ extract 9 7) ?x316))))
(let ((?x310 ((_ extract 31 10) ?x316)))
(let ((?x329 (concat ?x310 ?x319 ?x309 ?x321 (_ bv0 1))))
(not (= ?x329 ?x307)))))))))))
(check-sat)
