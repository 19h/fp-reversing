; benchmark generated from python API
(set-info :status unknown)
(declare-fun producer_pointer64 () (_ BitVec 64))
(assert
 (let (($x209 (= producer_pointer64 (_ bv0 64))))
(let ((?x211 (ite $x209 (_ bv0 32) (_ bv1 32))))
(and true (and (distinct ((_ extract 31 0) (concat (_ bv0 32) ?x211)) ?x211) true)))))
(check-sat)
