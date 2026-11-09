; benchmark generated from python API
(set-info :status unknown)
(declare-fun life_count32 () (_ BitVec 32))
(assert
 (let (($x276 (= life_count32 (_ bv0 32))))
(let ((?x274 (ite $x276 (_ bv33296 32) (_ bv33307 32))))
(let ((?x297 (bvmul (_ bv11 4) (ite $x276 (_ bv0 4) (_ bv1 4)))))
(let ((?x281 (bvmul (_ bv11 32) (ite $x276 (_ bv0 32) (_ bv1 32)))))
(let ((?x282 ((_ extract 8 5) ?x281)))
(let ((?x285 ((_ extract 14 10) ?x281)))
(let ((?x286 ((_ extract 31 16) ?x281)))
(not (= (concat ?x286 (_ bv1 1) ?x285 (_ bv1 1) ?x282 (_ bv1 1) ?x297) ?x274))))))))))
(check-sat)
