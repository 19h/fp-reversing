; benchmark generated from python API
(set-info :status unknown)
(declare-fun callback_state64 () (_ BitVec 64))
(assert
 (let (($x273 (not (bvule (bvmul (_ bv16 64) (concat (_ bv0 60) ((_ extract 63 60) callback_state64))) (_ bv18446744073709551599 64)))))
(let (($x283 (bvule (bvadd (_ bv16 9) (bvmul (_ bv16 9) (concat (_ bv0 5) ((_ extract 63 60) callback_state64)))) (_ bv256 9))))
(let ((?x232 ((_ extract 63 9) (bvadd (_ bv16 64) (bvmul (_ bv16 64) (concat (_ bv0 60) ((_ extract 63 60) callback_state64)))))))
(or (not (and (= ?x232 (_ bv0 55)) $x283)) $x273)))))
(check-sat)
