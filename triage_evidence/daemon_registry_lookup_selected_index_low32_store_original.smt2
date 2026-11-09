; benchmark generated from python API
(set-info :status unknown)
(declare-fun registry_j64 () (_ BitVec 64))
(assert
 (and true (and (distinct ((_ extract 31 0) registry_j64) ((_ extract 31 0) registry_j64)) true)))
(check-sat)
