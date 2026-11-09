; benchmark generated from python API
(set-info :status unknown)
(declare-fun registry_word64 () (_ BitVec 64))
(assert
 (let (($x328 (= registry_word64 (_ bv0 64))))
(let ((?x373 (ite $x328 (_ bv31949 32) (_ bv31997 32))))
(not (= (concat (_ bv499 26) (ite $x328 (_ bv0 1) (_ bv1 1)) (ite $x328 (_ bv0 1) (_ bv1 1)) (_ bv13 4)) ?x373)))))
(check-sat)
