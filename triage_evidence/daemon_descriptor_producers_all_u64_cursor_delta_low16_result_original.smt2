; benchmark generated from python API
(set-info :status unknown)
(declare-fun producer_counter64 () (_ BitVec 64))
(declare-fun producer_cursor64 () (_ BitVec 64))
(assert
 (let ((?x360 (bvshl ((_ zero_extend 48) ((_ extract 15 0) (bvsub producer_cursor64 producer_counter64))) (_ bv4 64))))
(let ((?x379 ((_ extract 15 0) producer_counter64)))
(let ((?x382 (bvmul (_ bv65535 16) ?x379)))
(let ((?x375 ((_ extract 15 0) producer_cursor64)))
(let ((?x383 (bvadd ?x375 ?x382)))
(let ((?x397 (concat (_ bv0 44) ?x383 (_ bv0 4))))
(and true (and (distinct ?x397 ?x360) true)))))))))
(check-sat)
