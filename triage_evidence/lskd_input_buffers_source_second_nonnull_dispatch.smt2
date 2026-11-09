; benchmark generated from python API
(set-info :status unknown)
(declare-fun output_sized_region64 () (_ BitVec 64))
(assert
 (let ((?x85 (bvmul (_ bv8 32) (ite (= output_sized_region64 (_ bv0 64)) (_ bv1 32) (_ bv0 32)))))
(let ((?x89 ((_ extract 31 11) ?x85)))
(let (($x210 (and (= ((_ extract 3 2) ?x85) (_ bv0 2)) (= ((_ extract 6 6) ?x85) (_ bv0 1)) (= ((_ extract 9 8) ?x85) (_ bv0 2)) (= ?x89 (_ bv0 21)))))
(let (($x211 (not $x210)))
(let (($x72 (= output_sized_region64 (_ bv0 64))))
(let (($x201 (not $x72)))
(and $x201 $x211))))))))
(check-sat)
