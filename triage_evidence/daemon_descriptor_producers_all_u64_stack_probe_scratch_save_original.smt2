; benchmark generated from python API
(set-info :status unknown)
(declare-fun producer_SP64 () (_ BitVec 64))
(declare-fun producer_B64 () (_ BitVec 64))
(declare-fun producer_A64 () (_ BitVec 64))
(assert
 (let (($x523 (or (and (distinct producer_A64 producer_A64) true) (and (distinct producer_B64 producer_B64) true) (and (distinct producer_SP64 producer_SP64) true))))
(and true $x523)))
(check-sat)
