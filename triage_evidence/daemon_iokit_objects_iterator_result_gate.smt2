; benchmark generated from python API
(set-info :status unknown)
(declare-fun service32 () (_ BitVec 32))
(assert
 (let (($x117 (= service32 (_ bv0 32))))
(let ((?x111 (ite $x117 (_ bv28257 32) (_ bv28178 32))))
(let ((?x144 (concat ((_ extract 31 15) (bvmul (_ bv115 32) (ite $x117 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 14 13) (bvmul (_ bv115 32) (ite $x117 (_ bv1 32) (_ bv0 32))))) ((_ extract 12 12) (bvmul (_ bv115 32) (ite $x117 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 11 9) (bvmul (_ bv115 32) (ite $x117 (_ bv1 32) (_ bv0 32))))) ((_ extract 8 5) (bvmul (_ bv115 32) (ite $x117 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 4 4) (bvmul (_ bv115 32) (ite $x117 (_ bv1 32) (_ bv0 32))))) ((_ extract 3 2) (bvmul (_ bv115 32) (ite $x117 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 1 1) (bvmul (_ bv115 32) (ite $x117 (_ bv1 32) (_ bv0 32))))) (ite $x117 (_ bv1 1) (_ bv0 1)))))
(not (= ?x144 ?x111))))))
(check-sat)
