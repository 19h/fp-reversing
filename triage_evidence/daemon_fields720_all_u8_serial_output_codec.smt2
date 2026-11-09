; benchmark generated from python API
(set-info :status unknown)
(declare-fun fields_byte8 () (_ BitVec 8))
(assert
 (let ((?x122 ((_ extract 6 5) fields_byte8)))
(let ((?x353 (concat (bvnot ((_ extract 7 7) fields_byte8)) ?x122 (bvnot ((_ extract 4 3) fields_byte8)) ((_ extract 2 0) fields_byte8))))
(let ((?x564 (bvadd fields_byte8 (bvmul (_ bv255 8) (concat (_ bv0 2) ((_ extract 4 3) fields_byte8) (_ bv0 4))))))
(not (= ?x564 (bvadd (_ bv104 8) ?x353)))))))
(check-sat)
