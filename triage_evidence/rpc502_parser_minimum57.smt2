(set-option :timeout 30000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun length32 () (_ BitVec 32))
(assert
 (and (distinct (bvult (bvsub length32 (_ bv57 32)) (_ bv4294967239 32)) (bvuge length32 (_ bv57 32))) true))
(check-sat)
