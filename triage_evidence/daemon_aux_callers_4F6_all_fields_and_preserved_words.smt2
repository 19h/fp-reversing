; benchmark generated from python API
(set-info :status unknown)
(declare-fun aux_emit_saved_phase64 () (_ BitVec 64))
(assert
 (let ((?x160 ((_ extract 31 0) aux_emit_saved_phase64)))
(let ((?x217 (bvadd (_ bv4294957608 32) ?x160)))
(not (= (concat ((_ extract 31 2) ?x217) ((_ extract 1 0) aux_emit_saved_phase64)) ?x217)))))
(check-sat)
