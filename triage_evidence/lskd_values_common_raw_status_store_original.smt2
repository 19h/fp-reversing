; benchmark generated from python API
(set-info :status unknown)
(declare-fun lookup_status32 () (_ BitVec 32))
(assert
 (let ((?x173 ((_ extract 31 0) ((_ zero_extend 32) lookup_status32))))
(and (distinct ?x173 lookup_status32) true)))
(check-sat)
