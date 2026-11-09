; benchmark generated from python API
(set-info :status unknown)
(declare-fun output_selector32 () (_ BitVec 32))
(assert
 (let ((?x639 (bvnot (bvmul (_ bv6 3) (ite (= ((_ extract 7 0) output_selector32) (_ bv1 8)) (_ bv1 3) (_ bv0 3))))))
(let ((?x609 (bvmul (_ bv462 32) (ite (= ((_ extract 7 0) output_selector32) (_ bv1 8)) (_ bv1 32) (_ bv0 32)))))
(let ((?x630 ((_ extract 31 31) ?x609)))
(let ((?x616 (concat ?x630 ?x630 ?x630 ?x630 ?x630 ?x630 ?x630 ?x630 ?x630 ?x630 ?x630 ?x630 ?x630 ?x630 ?x630 ?x630 ?x630 ?x630 ?x630 ?x630 ?x630 ?x630 ?x630 ?x630 ?x630 ?x630 ?x630 ?x630 ?x630 ((_ extract 31 13) ?x609) (bvnot ((_ extract 12 11) ?x609)) ((_ extract 10 8) ?x609) (bvnot ((_ extract 7 6) ?x609)) ((_ extract 5 3) ?x609) ?x639 (_ bv0 3))))
(let ((?x581 (bvadd (_ bv4311981808 64) ?x616)))
(let (($x300 (and (distinct ?x581 (ite (= (bvand output_selector32 (_ bv255 32)) (_ bv1 32)) (_ bv4312033080 64) (_ bv4312032552 64))) true)))
(and true $x300))))))))
(check-sat)
