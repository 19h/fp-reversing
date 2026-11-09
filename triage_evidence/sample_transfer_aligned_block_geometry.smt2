; benchmark generated from python API
(set-info :status unknown)
(declare-fun size32 () (_ BitVec 32))
(assert
 (let ((?x10 ((_ zero_extend 32) size32)))
(let ((?x12 (bvand ?x10 (_ bv4294967280 64))))
(and (distinct ?x12 (bvshl (bvlshr ?x10 (_ bv4 64)) (_ bv4 64))) true))))
(check-sat)
