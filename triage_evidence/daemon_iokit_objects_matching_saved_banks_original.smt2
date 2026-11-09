; benchmark generated from python API
(set-info :status unknown)
(declare-fun matching_dictionary64 () (_ BitVec 64))
(assert
 (let (($x16 (and (distinct matching_dictionary64 matching_dictionary64) true)))
(or $x16 (and (distinct (_ bv4311948960 64) (_ bv4311948960 64)) true) (and (distinct (_ bv4311499056 64) (_ bv4311499056 64)) true))))
(check-sat)
