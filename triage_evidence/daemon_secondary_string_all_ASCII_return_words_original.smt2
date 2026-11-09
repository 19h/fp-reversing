; benchmark generated from python API
(set-info :status unknown)
(declare-fun string_conversion_return32 () (_ BitVec 32))
(assert
 (let (($x62 (= string_conversion_return32 (_ bv0 32))))
(let ((?x93 (ite $x62 (_ bv0 2) (_ bv1 2))))
(let ((?x99 (ite $x62 (_ bv0 1) (_ bv1 1))))
(and (distinct ((_ extract 31 0) (concat (_ bv357 58) ?x99 ?x93 (_ bv6 3))) (ite (and (distinct string_conversion_return32 (_ bv0 32)) true) (_ bv22894 32) (_ bv22854 32))) true)))))
(check-sat)
