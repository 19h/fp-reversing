; benchmark generated from python API
(set-info :status unknown)
(declare-fun publication_return64 () (_ BitVec 64))
(assert
 (let (($x18 (and (distinct publication_return64 publication_return64) true)))
(and true (or $x18 $x18))))
(check-sat)
