; benchmark generated from python API
(set-info :status unknown)
(declare-fun aux_emit_saved_phase64 () (_ BitVec 64))
(assert
 (let ((?x160 ((_ extract 31 0) aux_emit_saved_phase64)))
(let (($x498 (= ?x160 (_ bv35505 32))))
(xor (= (bvsub ?x160 (_ bv17301 32)) (_ bv18204 32)) $x498))))
(check-sat)
