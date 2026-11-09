; benchmark generated from python API
(set-info :status unknown)
(declare-fun ctxlock_seal_word_index32 () (_ BitVec 32))
(declare-fun ctxlock_seal_seed32 () (_ BitVec 32))
(assert
 (let ((?x907 (bvadd ctxlock_seal_seed32 ctxlock_seal_word_index32)))
(let ((?x780 (bvmul (_ bv16777619 32) (bvxor ctxlock_seal_seed32 ?x907))))
(let ((?x770 (ite (= ctxlock_seal_word_index32 (_ bv0 32)) (_ bv0 32) (bvudiv_i ?x780 ctxlock_seal_word_index32))))
(let ((?x799 (bvadd ?x780 (bvmul (_ bv4294967295 32) (bvmul ctxlock_seal_word_index32 ?x770)))))
(let ((?x591 ((_ extract 31 0) (concat (_ bv0 32) ?x799))))
(let ((?x620 (bvurem (bvmul (bvxor ?x907 ctxlock_seal_seed32) (_ bv16777619 32)) ctxlock_seal_word_index32)))
(let (($x583 (and (bvuge ctxlock_seal_word_index32 (_ bv1 32)) (bvule ctxlock_seal_word_index32 (_ bv68 32)))))
(and $x583 (or (and (distinct ?x591 ?x620) true) (bvuge ?x591 ctxlock_seal_word_index32)))))))))))
(check-sat)
