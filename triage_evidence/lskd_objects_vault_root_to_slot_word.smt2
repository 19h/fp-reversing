; benchmark generated from python API
(set-info :status unknown)
(declare-fun objects_saved_index32 () (_ BitVec 32))
(assert
 (let ((?x72 ((_ extract 9 0) objects_saved_index32)))
(let ((?x389 (concat (_ bv0 4) ?x72)))
(let ((?x287 (bvmul (_ bv8 14) ?x389)))
(let ((?x360 (bvadd (_ bv8 14) ?x287)))
(let (($x30 (= ((_ extract 63 14) (bvadd (_ bv8 64) (bvmul (_ bv8 64) (concat (_ bv0 54) ?x72)))) (_ bv0 50))))
(let (($x352 (and $x30 (bvule ?x360 (_ bv8192 14)))))
(not $x352))))))))
(check-sat)
