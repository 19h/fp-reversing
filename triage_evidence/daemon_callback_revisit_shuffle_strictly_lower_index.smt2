; benchmark generated from python API
(set-info :status unknown)
(declare-fun callback_shuffle_counter32 () (_ BitVec 32))
(declare-fun callback_seed32 () (_ BitVec 32))
(assert
 (let ((?x710 (bvadd callback_seed32 callback_shuffle_counter32)))
(let ((?x657 (bvurem_i (bvmul (_ bv16777619 32) (bvxor callback_seed32 ?x710)) callback_shuffle_counter32)))
(let (($x822 (bvule callback_shuffle_counter32 ?x657)))
(let (($x467 (bvule ((_ extract 8 0) callback_shuffle_counter32) (_ bv272 9))))
(let (($x781 (= ((_ extract 31 9) callback_shuffle_counter32) (_ bv0 23))))
(let (($x819 (or (not (= ((_ extract 31 1) callback_shuffle_counter32) (_ bv0 31))) (= ((_ extract 0 0) callback_shuffle_counter32) (_ bv1 1)))))
(and $x819 $x781 $x467 $x822))))))))
(check-sat)
