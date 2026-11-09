; benchmark generated from python API
(set-info :status unknown)
(declare-fun handoff_U64 () (_ BitVec 64))
(assert
 (let (($x134 (and (distinct handoff_U64 handoff_U64) true)))
(and true $x134)))
(check-sat)
