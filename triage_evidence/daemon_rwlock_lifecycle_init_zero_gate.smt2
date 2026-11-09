; benchmark generated from python API
(set-info :status unknown)
(declare-fun rw_init_status32 () (_ BitVec 32))
(assert
 (let (($x323 (= rw_init_status32 (_ bv0 32))))
(let ((?x285 (ite $x323 (_ bv27331 32) (_ bv15295 32))))
(let ((?x355 (concat ((_ extract 31 14) (bvmul (_ bv20860 32) (ite $x323 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 13 11) (bvmul (_ bv20860 32) (ite $x323 (_ bv1 32) (_ bv0 32))))) ((_ extract 10 10) (bvmul (_ bv20860 32) (ite $x323 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 9 7) (bvmul (_ bv20860 32) (ite $x323 (_ bv1 32) (_ bv0 32))))) ((_ extract 6 6) (bvmul (_ bv20860 32) (ite $x323 (_ bv1 32) (_ bv0 32)))) (bvnot (bvmul (_ bv60 6) (ite $x323 (_ bv1 6) (_ bv0 6)))))))
(not (= ?x355 ?x285))))))
(check-sat)
