; benchmark generated from python API
(set-info :status unknown)
(declare-fun aux_emit_saved_phase64 () (_ BitVec 64))
(assert
 (let ((?x160 ((_ extract 31 0) aux_emit_saved_phase64)))
(let ((?x390 (bvadd (_ bv4294949995 32) ?x160)))
(let (($x4436 (= (concat ((_ extract 31 2) ?x390) (bvadd (_ bv3 2) ((_ extract 1 0) aux_emit_saved_phase64))) ?x390)))
(not $x4436)))))
(check-sat)
