; benchmark generated from python API
(set-info :status unknown)
(declare-fun fallback_version32 () (_ BitVec 32))
(assert
 (let (($x477 (= ((_ extract 31 30) fallback_version32) (_ bv0 2))))
(let (($x647 (not $x477)))
(let (($x479 (and (or $x647 (bvule (_ bv45 6) ((_ extract 29 24) fallback_version32))) (not (= ((_ extract 31 24) fallback_version32) (_ bv45 8))))))
(let ((?x672 (concat ((_ extract 31 14) (bvmul (_ bv33 32) (ite $x479 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 13 13) (bvmul (_ bv33 32) (ite $x479 (_ bv1 32) (_ bv0 32))))) ((_ extract 12 11) (bvmul (_ bv33 32) (ite $x479 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 10 9) (bvmul (_ bv33 32) (ite $x479 (_ bv1 32) (_ bv0 32))))) ((_ extract 8 8) (bvmul (_ bv33 32) (ite $x479 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 7 7) (bvmul (_ bv33 32) (ite $x479 (_ bv1 32) (_ bv0 32))))) ((_ extract 6 5) (bvmul (_ bv33 32) (ite $x479 (_ bv1 32) (_ bv0 32)))) (bvnot ((_ extract 4 4) (bvmul (_ bv33 32) (ite $x479 (_ bv1 32) (_ bv0 32))))) ((_ extract 3 3) (bvmul (_ bv33 32) (ite $x479 (_ bv1 32) (_ bv0 32)))) (ite $x479 (_ bv6 3) (_ bv7 3)))))
(let (($x291 (not (= ?x672 (ite (= ((_ extract 31 24) fallback_version32) (_ bv46 8)) (_ bv9910 32) (_ bv9879 32))))))
(and (not (or $x647 (bvule (_ bv47 6) ((_ extract 29 24) fallback_version32)))) $x291)))))))
(check-sat)
