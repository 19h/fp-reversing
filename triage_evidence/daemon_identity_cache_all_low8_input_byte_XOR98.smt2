; benchmark generated from python API
(set-info :status unknown)
(declare-fun identity_return64 () (_ BitVec 64))
(assert
 (let ((?x399 (concat (bvnot ((_ extract 7 7) identity_return64)) ((_ extract 6 5) identity_return64) (bvnot ((_ extract 4 3) identity_return64)) ((_ extract 2 0) identity_return64))))
(let ((?x153 ((_ extract 7 0) identity_return64)))
(let ((?x303 (bvadd ?x153 (bvmul (_ bv255 8) (concat (_ bv0 2) ((_ extract 4 3) identity_return64) (_ bv0 4))))))
(not (= ?x303 (bvadd (_ bv104 8) ?x399)))))))
(check-sat)
