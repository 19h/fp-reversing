; benchmark generated from python API
(set-info :status unknown)
(declare-fun output_selector32 () (_ BitVec 32))
(assert
 (let ((?x256 (bvmul (_ bv9377 32) (ite (= ((_ extract 7 0) output_selector32) (_ bv2 8)) (_ bv1 32) (_ bv0 32)))))
(let ((?x72 ((_ extract 31 31) ?x256)))
(let ((?x165 (concat ?x72 ?x72 ?x72 ?x72 ?x72 ?x72 ?x72 ?x72 ?x72 ?x72 ?x72 ?x72 ?x72 ?x72 ?x72 ?x72 ?x72 ?x72 ?x72 ?x72 ?x72 ?x72 ?x72 ?x72 ?x72 ?x72 ?x72 ?x72 ?x72 ((_ extract 31 13) ?x256) (bvnot ((_ extract 12 11) ?x256)) ((_ extract 10 8) ?x256) (bvnot ((_ extract 7 6) ?x256)) ((_ extract 5 3) ?x256) (ite (= ((_ extract 7 0) output_selector32) (_ bv2 8)) (_ bv6 3) (_ bv7 3)) (_ bv0 3))))
(let (($x66 (= ?x165 (bvadd (_ bv18446744069397569808 64) (ite (= ((_ extract 7 0) output_selector32) (_ bv2 8)) (_ bv4312105504 64) (_ bv4312032552 64))))))
(not $x66))))))
(check-sat)
