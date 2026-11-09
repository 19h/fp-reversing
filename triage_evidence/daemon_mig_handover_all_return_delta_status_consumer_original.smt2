; benchmark generated from python API
(set-info :status unknown)
(declare-fun handover_return_status32 () (_ BitVec 32))
(declare-fun handover_return_delta64 () (_ BitVec 64))
(assert
 (let (($x351 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) handover_return_status32)) handover_return_status32) true)))
(let ((?x349 (bvadd (_ bv446676922928 64) handover_return_delta64)))
(or (and (distinct ?x349 ?x349) true) $x351))))
(check-sat)
