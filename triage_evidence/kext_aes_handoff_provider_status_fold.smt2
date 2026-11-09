; benchmark generated from python API
(set-info :status unknown)
(declare-fun input64 () (_ BitVec 64))
(assert
 (and (distinct (ite (= ((_ extract 31 0) input64) (_ bv0 32)) (_ bv0 64) (_ bv4294967274 64)) (ite (= (bvand input64 (_ bv4294967295 64)) (_ bv0 64)) (_ bv0 64) (_ bv4294967274 64))) true))
(check-sat)
