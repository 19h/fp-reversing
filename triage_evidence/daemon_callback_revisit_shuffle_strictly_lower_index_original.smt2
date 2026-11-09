; benchmark generated from python API
(set-info :status unknown)
(declare-fun callback_shuffle_counter32 () (_ BitVec 32))
(declare-fun callback_seed32 () (_ BitVec 32))
(assert
 (let ((?x710 (bvadd callback_seed32 callback_shuffle_counter32)))
(let ((?x525 (bvurem (bvmul (bvxor ?x710 callback_seed32) (_ bv16777619 32)) callback_shuffle_counter32)))
(let (($x699 (and (bvuge callback_shuffle_counter32 (_ bv1 32)) (bvule callback_shuffle_counter32 (_ bv272 32)))))
(and $x699 (bvuge ?x525 callback_shuffle_counter32))))))
(check-sat)
