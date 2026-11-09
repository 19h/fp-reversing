; benchmark generated from python API
(set-info :status unknown)
(declare-fun result64 () (_ BitVec 64))
(assert
 (and (distinct (ite (= ((_ extract 31 0) result64) (_ bv0 32)) (_ bv0 32) (_ bv4294925268 32)) (ite (= (bvand result64 (_ bv4294967295 64)) (_ bv0 64)) (_ bv0 32) (_ bv4294925268 32))) true))
(check-sat)
