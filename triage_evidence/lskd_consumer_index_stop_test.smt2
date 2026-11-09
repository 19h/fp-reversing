; benchmark generated from python API
(set-info :status unknown)
(declare-fun operation32 () (_ BitVec 32))
(assert
 (let (($x266 (bvsle (_ bv7003 32) operation32)))
(let ((?x760 (ite $x266 (_ bv2289 32) (_ bv2297 32))))
(let ((?x294 (bvmul (_ bv8 32) (ite $x266 (_ bv0 32) (_ bv1 32)))))
(let ((?x280 ((_ extract 3 1) ?x294)))
(let ((?x287 ((_ extract 10 8) ?x294)))
(let ((?x242 ((_ extract 31 12) ?x294)))
(let ((?x286 (concat ?x242 (_ bv1 1) ?x287 (_ bv15 4) ?x280 (_ bv1 1))))
(not (= ?x286 ?x760))))))))))
(check-sat)
