; benchmark generated from python API
(set-info :status unknown)
(declare-fun request_header32 () (_ BitVec 32))
(assert
 (let (($x303 (= request_header32 (_ bv1 32))))
(let ((?x316 (ite $x303 (_ bv1672 32) (_ bv1676 32))))
(and (distinct ((_ extract 31 0) ((_ zero_extend 32) (concat (_ bv209 29) (ite $x303 (_ bv0 1) (_ bv1 1)) (_ bv0 2)))) ?x316) true))))
(check-sat)
