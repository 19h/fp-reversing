; benchmark generated from python API
(set-info :status unknown)
(declare-fun aux_emit_saved_phase64 () (_ BitVec 64))
(assert
 (let ((?x160 ((_ extract 31 0) aux_emit_saved_phase64)))
(let (($x438 (= ?x160 (_ bv27892 32))))
(xor (= (bvsub ?x160 (_ bv9688 32)) (_ bv18204 32)) $x438))))
(check-sat)
