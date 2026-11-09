; benchmark generated from python API
(set-info :status unknown)
(declare-fun query_capabilities32 () (_ BitVec 32))
(assert
 (let ((?x302 (ite (= query_capabilities32 (_ bv0 32)) (_ bv22780 32) (_ bv10071 32))))
(let ((?x166 (concat ((_ extract 30 30) query_capabilities32) (_ bv0 3) ((_ extract 26 26) query_capabilities32) (_ bv0 2) ((_ extract 23 23) query_capabilities32) (_ bv0 2) ((_ extract 20 20) query_capabilities32) (_ bv0 1) ((_ extract 18 17) query_capabilities32) (_ bv0 1) ((_ extract 15 15) query_capabilities32) (_ bv0 2) ((_ extract 12 12) query_capabilities32) (_ bv0 1) ((_ extract 10 4) query_capabilities32) (_ bv0 5))))
(let (($x276 (= query_capabilities32 ?x166)))
(let ((?x339 (concat ((_ extract 31 14) (bvmul (_ bv32683 32) (ite $x276 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 13 13) (bvmul (_ bv32683 32) (ite $x276 (_ bv1 32) (_ bv0 32))))) ((_ extract 12 11) (bvmul (_ bv32683 32) (ite $x276 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 10 8) (bvmul (_ bv32683 32) (ite $x276 (_ bv1 32) (_ bv0 32))))) ((_ extract 7 7) (bvmul (_ bv32683 32) (ite $x276 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 6 6) (bvmul (_ bv32683 32) (ite $x276 (_ bv1 32) (_ bv0 32))))) ((_ extract 5 5) (bvmul (_ bv32683 32) (ite $x276 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 4 4) (bvmul (_ bv32683 32) (ite $x276 (_ bv1 32) (_ bv0 32))))) ((_ extract 3 3) (bvmul (_ bv32683 32) (ite $x276 (_ bv1 32) (_ bv0 32)))) (bvnot (bvmul (_ bv3 3) (ite $x276 (_ bv1 3) (_ bv0 3)))))))
(not (= ?x339 ?x302)))))))
(check-sat)
