; benchmark generated from python API
(set-info :status unknown)
(declare-fun rw_init_status32 () (_ BitVec 32))
(assert
 (let (($x412 (= rw_init_status32 (_ bv12 32))))
(let ((?x390 (ite $x412 (_ bv28543 32) (_ bv15295 32))))
(let ((?x437 (concat ((_ extract 31 14) (bvmul (_ bv21696 32) (ite $x412 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 13 11) (bvmul (_ bv21696 32) (ite $x412 (_ bv1 32) (_ bv0 32))))) ((_ extract 10 10) (bvmul (_ bv21696 32) (ite $x412 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 9 7) (bvmul (_ bv21696 32) (ite $x412 (_ bv1 32) (_ bv0 32))))) ((_ extract 6 6) (bvmul (_ bv21696 32) (ite $x412 (_ bv1 32) (_ bv0 32)))) (_ bv63 6))))
(not (= ?x437 ?x390))))))
(check-sat)
