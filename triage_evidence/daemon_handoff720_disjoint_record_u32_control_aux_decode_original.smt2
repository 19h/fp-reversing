; benchmark generated from python API
(set-info :status unknown)
(declare-fun handoff_V32 () (_ BitVec 32))
(declare-fun handoff_U64 () (_ BitVec 64))
(declare-fun handoff_control32 () (_ BitVec 32))
(assert
 (let (($x134 (and (distinct handoff_U64 handoff_U64) true)))
(let (($x343 (or (and (distinct ((_ extract 31 0) (concat (_ bv0 32) handoff_control32)) handoff_control32) true) $x134 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) handoff_V32)) handoff_V32) true))))
(and true $x343))))
(check-sat)
