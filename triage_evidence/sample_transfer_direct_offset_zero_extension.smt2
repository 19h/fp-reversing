; benchmark generated from python API
(set-info :status unknown)
(declare-fun offset32 () (_ BitVec 32))
(assert
 (let ((?x43 ((_ zero_extend 32) offset32)))
(and (distinct (bvand ?x43 (_ bv4294967295 64)) ?x43) true)))
(check-sat)
