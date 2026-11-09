; benchmark generated from python API
(set-info :status unknown)
(declare-fun API_status32 () (_ BitVec 32))
(assert
 (let (($x67 (= API_status32 (_ bv0 32))))
(let ((?x61 (ite $x67 (_ bv46605 32) (_ bv46598 32))))
(let ((?x99 (concat ((_ extract 31 16) (bvmul (_ bv11 32) (ite $x67 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 15 15) (bvmul (_ bv11 32) (ite $x67 (_ bv1 32) (_ bv0 32))))) ((_ extract 14 14) (bvmul (_ bv11 32) (ite $x67 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 13 12) (bvmul (_ bv11 32) (ite $x67 (_ bv1 32) (_ bv0 32))))) ((_ extract 11 11) (bvmul (_ bv11 32) (ite $x67 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 10 9) (bvmul (_ bv11 32) (ite $x67 (_ bv1 32) (_ bv0 32))))) ((_ extract 8 3) (bvmul (_ bv11 32) (ite $x67 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 2 1) (bvmul (_ bv11 32) (ite $x67 (_ bv1 32) (_ bv0 32))))) (ite $x67 (_ bv1 1) (_ bv0 1)))))
(not (= ?x99 ?x61))))))
(check-sat)
