; benchmark generated from python API
(set-info :status unknown)
(declare-fun string_conversion_return32 () (_ BitVec 32))
(assert
 (let (($x62 (= string_conversion_return32 (_ bv0 32))))
(let ((?x93 (ite $x62 (_ bv0 2) (_ bv1 2))))
(let ((?x99 (ite $x62 (_ bv0 1) (_ bv1 1))))
(not (= (concat (_ bv357 26) ?x99 ?x93 (_ bv6 3)) (ite $x62 (_ bv22854 32) (_ bv22894 32))))))))
(check-sat)
