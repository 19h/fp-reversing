; benchmark generated from python API
(set-info :status unknown)
(declare-fun entry_SP64 () (_ BitVec 64))
(assert
 (and (distinct (bvsub (bvadd (bvsub entry_SP64 (_ bv128 64)) (_ bv112 64)) (_ bv232 64)) (bvadd (bvsub (bvsub entry_SP64 (_ bv128 64)) (_ bv4208 64)) (_ bv4088 64))) true))
(check-sat)
