; benchmark generated from python API
(set-info :status unknown)
(declare-fun sync_pointer64 () (_ BitVec 64))
(assert
 (let (($x448 (= sync_pointer64 (_ bv0 64))))
(let ((?x398 (ite $x448 (_ bv24423 32) (_ bv22845 32))))
(let ((?x486 (concat ((_ extract 31 15) (bvmul (_ bv1626 32) (ite $x448 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 14 14) (bvmul (_ bv1626 32) (ite $x448 (_ bv1 32) (_ bv0 32))))) ((_ extract 13 13) (bvmul (_ bv1626 32) (ite $x448 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 12 11) (bvmul (_ bv1626 32) (ite $x448 (_ bv1 32) (_ bv0 32))))) ((_ extract 10 9) (bvmul (_ bv1626 32) (ite $x448 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 8 8) (bvmul (_ bv1626 32) (ite $x448 (_ bv1 32) (_ bv0 32))))) ((_ extract 7 6) (bvmul (_ bv1626 32) (ite $x448 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 5 2) (bvmul (_ bv1626 32) (ite $x448 (_ bv1 32) (_ bv0 32))))) ((_ extract 1 1) (bvmul (_ bv1626 32) (ite $x448 (_ bv1 32) (_ bv0 32)))) (_ bv1 1))))
(not (= ?x486 ?x398))))))
(check-sat)
