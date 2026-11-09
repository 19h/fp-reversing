; benchmark generated from python API
(set-info :status unknown)
(declare-fun fallback_version32 () (_ BitVec 32))
(assert
 (let (($x647 (not (= ((_ extract 31 30) fallback_version32) (_ bv0 2)))))
(let ((?x310 (bvadd (_ bv47 33) (concat (_ bv0 1) (bvadd (_ bv4294967249 32) (concat (_ bv0 24) ((_ extract 31 24) fallback_version32)))))))
(let ((?x312 ((_ extract 32 32) ?x310)))
(let ((?x371 (concat ((_ extract 31 15) (bvmul (_ bv163 32) (ite (= ?x312 (_ bv1 1)) (_ bv0 32) (_ bv1 32)))) (bvnot ((_ extract 14 13) (bvmul (_ bv163 32) (ite (= ?x312 (_ bv1 1)) (_ bv0 32) (_ bv1 32))))) ((_ extract 12 12) (bvmul (_ bv163 32) (ite (= ?x312 (_ bv1 1)) (_ bv0 32) (_ bv1 32)))) (bvnot ((_ extract 11 10) (bvmul (_ bv163 32) (ite (= ?x312 (_ bv1 1)) (_ bv0 32) (_ bv1 32))))) ((_ extract 9 9) (bvmul (_ bv163 32) (ite (= ?x312 (_ bv1 1)) (_ bv0 32) (_ bv1 32)))) (bvnot ((_ extract 8 8) (bvmul (_ bv163 32) (ite (= ?x312 (_ bv1 1)) (_ bv0 32) (_ bv1 32))))) ((_ extract 7 6) (bvmul (_ bv163 32) (ite (= ?x312 (_ bv1 1)) (_ bv0 32) (_ bv1 32)))) (bvnot ((_ extract 5 5) (bvmul (_ bv163 32) (ite (= ?x312 (_ bv1 1)) (_ bv0 32) (_ bv1 32))))) ((_ extract 4 3) (bvmul (_ bv163 32) (ite (= ?x312 (_ bv1 1)) (_ bv0 32) (_ bv1 32)))) (bvnot ((_ extract 2 2) (bvmul (_ bv163 32) (ite (= ?x312 (_ bv1 1)) (_ bv0 32) (_ bv1 32))))) ((_ extract 1 1) (bvmul (_ bv163 32) (ite (= ?x312 (_ bv1 1)) (_ bv0 32) (_ bv1 32)))) ?x312)))
(let (($x587 (= ?x371 (ite (or $x647 (bvule (_ bv47 6) ((_ extract 29 24) fallback_version32))) (_ bv28038 32) (_ bv27941 32)))))
(not $x587)))))))
(check-sat)
