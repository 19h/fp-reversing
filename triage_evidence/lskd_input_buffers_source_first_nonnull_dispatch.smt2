; benchmark generated from python API
(set-info :status unknown)
(declare-fun input_sized_region64 () (_ BitVec 64))
(assert
 (let ((?x32 (bvmul (_ bv54 32) (ite (= input_sized_region64 (_ bv0 64)) (_ bv1 32) (_ bv0 32)))))
(let ((?x39 ((_ extract 31 12) ?x32)))
(let ((?x41 ((_ extract 11 11) ?x32)))
(let (($x219 (= ?x41 (_ bv0 1))))
(let (($x222 (and (= (bvnot ((_ extract 4 1) ?x32)) (_ bv15 4)) (= ((_ extract 5 5) ?x32) (_ bv0 1)) (= (bvnot ((_ extract 7 6) ?x32)) (_ bv3 2)) (= ((_ extract 10 8) ?x32) (_ bv0 3)) $x219 (= ?x39 (_ bv0 20)))))
(let (($x223 (not $x222)))
(let (($x27 (= input_sized_region64 (_ bv0 64))))
(let (($x193 (not $x27)))
(and $x193 $x223))))))))))
(check-sat)
