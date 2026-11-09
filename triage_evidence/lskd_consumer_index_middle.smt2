; benchmark generated from python API
(set-info :status unknown)
(declare-fun operation32 () (_ BitVec 32))
(assert
 (let (($x174 (bvsle (_ bv7015 32) operation32)))
(let ((?x191 (ite $x174 (_ bv0 1) (_ bv1 1))))
(let ((?x177 (bvmul (_ bv2005 32) (ite $x174 (_ bv1 32) (_ bv0 32)))))
(let ((?x162 ((_ extract 3 1) ?x177)))
(let ((?x179 (bvnot ((_ extract 9 4) ?x177))))
(let ((?x176 ((_ extract 31 10) ?x177)))
(let ((?x192 (concat ?x176 ?x179 ?x162 ?x191)))
(not (= ?x192 (ite $x174 (_ bv1060 32) (_ bv1009 32))))))))))))
(check-sat)
