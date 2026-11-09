; benchmark generated from python API
(set-info :status unknown)
(declare-fun reader_rootB64 () (_ BitVec 64))
(declare-fun reader_rootA64 () (_ BitVec 64))
(assert
 (let (($x416 (or (and (distinct reader_rootA64 reader_rootA64) true) (and (distinct reader_rootB64 reader_rootB64) true))))
(and true $x416)))
(check-sat)
