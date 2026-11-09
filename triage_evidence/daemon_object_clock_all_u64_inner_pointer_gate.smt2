; benchmark generated from python API
(set-info :status unknown)
(declare-fun clock_return64 () (_ BitVec 64))
(assert
 (let (($x150 (= clock_return64 (_ bv0 64))))
(let ((?x305 (ite $x150 (_ bv31949 32) (_ bv31997 32))))
(not (= (concat (_ bv499 26) (ite $x150 (_ bv0 1) (_ bv1 1)) (ite $x150 (_ bv0 1) (_ bv1 1)) (_ bv13 4)) ?x305)))))
(check-sat)
