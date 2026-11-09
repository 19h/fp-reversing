; benchmark generated from python API
(set-info :status unknown)
(assert
 (let ((?x63 ((_ extract 31 0) (_ bv1 64))))
(let ((?x91 ((_ extract 31 31) ?x63)))
(let ((?x86 (bvsub ?x63 ?x63)))
(let ((?x74 ((_ extract 31 31) ?x86)))
(or (= ?x74 (_ bv1 1)) (not (= ?x86 (_ bv0 32))) (not (bvuge ?x63 ?x63)) (and (and (distinct ?x91 ?x91) true) (and (distinct ?x74 ?x91) true))))))))
(check-sat)
