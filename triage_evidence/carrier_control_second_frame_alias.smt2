; benchmark generated from python API
(set-info :status unknown)
(declare-fun entry_SP64 () (_ BitVec 64))
(assert
 (and (distinct (bvsub (bvadd (bvsub entry_SP64 (_ bv96 64)) (_ bv80 64)) (_ bv232 64)) (bvadd (bvsub (bvsub entry_SP64 (_ bv96 64)) (_ bv1536 64)) (_ bv1384 64))) true))
(check-sat)
