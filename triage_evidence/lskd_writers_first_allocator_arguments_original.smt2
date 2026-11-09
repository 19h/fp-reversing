; benchmark generated from python API
(set-info :status unknown)
(assert
 (or (and (distinct ((_ zero_extend 32) (_ bv16384 32)) (_ bv16384 64)) true) (and (distinct ((_ zero_extend 32) (_ bv64 32)) (_ bv64 64)) true) (and (distinct (_ bv16320 64) (_ bv16320 64)) true)))
(check-sat)
