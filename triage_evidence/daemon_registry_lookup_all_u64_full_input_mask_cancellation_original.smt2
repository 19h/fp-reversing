; benchmark generated from python API
(set-info :status unknown)
(declare-fun registry_word64 () (_ BitVec 64))
(assert
 (let ((?x71 (bvxor registry_word64 (_ bv10995706271387654296 64))))
(and true (and (distinct (bvxor (bvxor ?x71 (_ bv16409013220067847612 64)) (_ bv16409013220067847612 64)) ?x71) true))))
(check-sat)
