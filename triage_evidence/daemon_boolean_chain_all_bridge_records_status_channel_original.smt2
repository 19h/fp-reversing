; benchmark generated from python API
(set-info :status unknown)
(declare-fun bool_chain_returned_raw_status32 () (_ BitVec 32))
(assert
 (let (($x190 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) bool_chain_returned_raw_status32)) bool_chain_returned_raw_status32) true)))
(or (and (distinct ((_ extract 31 0) ((_ zero_extend 32) ((_ extract 31 0) (_ bv2336081489 64)))) (_ bv2336081489 32)) true) $x190)))
(check-sat)
