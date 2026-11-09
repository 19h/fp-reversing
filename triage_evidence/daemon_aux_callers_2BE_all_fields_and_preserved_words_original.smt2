; benchmark generated from python API
(set-info :status unknown)
(declare-fun aux_emit_old_result32 () (_ BitVec 32))
(declare-fun aux_emit_old_pad32 () (_ BitVec 32))
(declare-fun aux_emit_input_pointer64 () (_ BitVec 64))
(assert
 (let (($x114 (and (distinct aux_emit_old_result32 aux_emit_old_result32) true)))
(let (($x113 (and (distinct aux_emit_old_pad32 aux_emit_old_pad32) true)))
(let (($x100 (and (distinct aux_emit_input_pointer64 aux_emit_input_pointer64) true)))
(let (($x108 (and (distinct (_ bv18204 32) (bvxor ((_ extract 31 0) (_ bv3749402159 64)) (_ bv3749384499 32))) true)))
(or $x108 (and (distinct (bvsub ((_ extract 31 0) (_ bv2589073228 64)) (_ bv3749384499 32)) (_ bv3134656025 32)) true) $x100 $x113 $x114))))))
(check-sat)
