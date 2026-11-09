; benchmark generated from python API
(set-info :status unknown)
(declare-fun rw_heap64 () (_ BitVec 64))
(assert
 (let (($x146 (= rw_heap64 (_ bv0 64))))
(let ((?x207 (ite $x146 (_ bv22080 32) (_ bv22053 32))))
(let ((?x265 (concat ((_ extract 31 15) (bvmul (_ bv101 32) (ite $x146 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 14 14) (bvmul (_ bv101 32) (ite $x146 (_ bv1 32) (_ bv0 32))))) ((_ extract 13 13) (bvmul (_ bv101 32) (ite $x146 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 12 12) (bvmul (_ bv101 32) (ite $x146 (_ bv1 32) (_ bv0 32))))) ((_ extract 11 11) (bvmul (_ bv101 32) (ite $x146 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 10 9) (bvmul (_ bv101 32) (ite $x146 (_ bv1 32) (_ bv0 32))))) ((_ extract 8 6) (bvmul (_ bv101 32) (ite $x146 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 5 5) (bvmul (_ bv101 32) (ite $x146 (_ bv1 32) (_ bv0 32))))) ((_ extract 4 3) (bvmul (_ bv101 32) (ite $x146 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 2 2) (bvmul (_ bv101 32) (ite $x146 (_ bv1 32) (_ bv0 32))))) ((_ extract 1 1) (bvmul (_ bv101 32) (ite $x146 (_ bv1 32) (_ bv0 32)))) (ite $x146 (_ bv0 1) (_ bv1 1)))))
(not (= ?x265 ?x207))))))
(check-sat)
