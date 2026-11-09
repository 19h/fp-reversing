; benchmark generated from python API
(set-info :status unknown)
(declare-fun clock_value32 () (_ BitVec 32))
(assert
 (let (($x125 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) clock_value32)) clock_value32) true)))
(or (and (distinct (_ bv4312568456 64) (_ bv4312568456 64)) true) $x125)))
(check-sat)
