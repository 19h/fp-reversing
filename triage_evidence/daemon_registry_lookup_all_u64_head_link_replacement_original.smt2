; benchmark generated from python API
(set-info :status unknown)
(declare-fun registry_word64 () (_ BitVec 64))
(assert
 (and true (and (distinct registry_word64 registry_word64) true)))
(check-sat)
