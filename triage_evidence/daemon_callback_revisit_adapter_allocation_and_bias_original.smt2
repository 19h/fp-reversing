; benchmark generated from python API
(set-info :status unknown)
(declare-fun callback_temp64 () (_ BitVec 64))
(declare-fun callback_state64 () (_ BitVec 64))
(declare-fun callback_frame64 () (_ BitVec 64))
(assert
 (let ((?x29 (bvmul (_ bv16 64) (bvadd (bvlshr callback_state64 (_ bv60 64)) (_ bv1 64)))))
(let ((?x62 (concat (_ bv0 55) ((_ extract 8 4) (bvadd (_ bv31 32) (concat (_ bv0 24) ((_ extract 63 60) callback_state64) (_ bv0 4)))) (_ bv0 4))))
(let ((?x58 (bvmul (_ bv18446744073709551615 64) ?x62)))
(let ((?x59 (bvadd callback_frame64 ?x58)))
(let (($x37 (and (distinct ?x59 (bvsub callback_frame64 ?x29)) true)))
(let (($x43 (or $x37 $x37 (and (distinct (bvadd (_ bv18446744073709551440 64) callback_temp64) (bvsub callback_temp64 (_ bv176 64))) true))))
(and true $x43))))))))
(check-sat)
