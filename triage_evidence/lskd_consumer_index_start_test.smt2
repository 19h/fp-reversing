; benchmark generated from python API
(set-info :status unknown)
(declare-fun operation32 () (_ BitVec 32))
(assert
 (let (($x283 (= operation32 (_ bv7001 32))))
(let ((?x245 (ite $x283 (_ bv1683 32) (_ bv507 32))))
(let ((?x269 (bvmul (_ bv1896 32) (ite $x283 (_ bv1 32) (_ bv0 32)))))
(let ((?x268 ((_ extract 2 2) ?x269)))
(let ((?x247 (bvnot ((_ extract 8 3) ?x269))))
(let ((?x256 ((_ extract 31 9) ?x269)))
(let ((?x189 (concat ?x256 ?x247 ?x268 (_ bv3 2))))
(not (= ?x189 ?x245))))))))))
(check-sat)
