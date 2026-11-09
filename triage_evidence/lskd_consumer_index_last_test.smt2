; benchmark generated from python API
(set-info :status unknown)
(declare-fun operation32 () (_ BitVec 32))
(assert
 (let (($x416 (= operation32 (_ bv7022 32))))
(let ((?x425 (ite $x416 (_ bv996 32) (_ bv958 32))))
(let ((?x443 (bvnot ((_ extract 5 1) (bvmul (_ bv90 32) (ite $x416 (_ bv1 32) (_ bv0 32)))))))
(let ((?x399 (bvmul (_ bv90 32) (ite $x416 (_ bv1 32) (_ bv0 32)))))
(let ((?x412 ((_ extract 6 6) ?x399)))
(let ((?x441 (bvnot ((_ extract 9 7) ?x399))))
(let ((?x438 ((_ extract 31 10) ?x399)))
(let ((?x451 (concat ?x438 ?x441 ?x412 ?x443 (_ bv0 1))))
(not (= ?x451 ?x425)))))))))))
(check-sat)
