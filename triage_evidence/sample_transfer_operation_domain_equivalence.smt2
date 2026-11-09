; benchmark generated from python API
(set-info :status unknown)
(declare-fun header_byte0 () (_ BitVec 8))
(assert
 (let (($x14 (= header_byte0 (_ bv0 8))))
(let (($x49 (or $x14 (= header_byte0 (_ bv1 8)))))
(and (distinct (= (ite $x14 (_ bv1 32) (_ bv0 32)) (bvxor ((_ zero_extend 24) header_byte0) (_ bv1 32))) $x49) true))))
(check-sat)
