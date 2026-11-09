; benchmark generated from python API
(set-info :status unknown)
(declare-fun cache36_return64 () (_ BitVec 64))
(assert
 (let (($x52 (and (distinct (_ bv65182 64) (_ bv65182 64)) true)))
(let (($x15 (and (distinct (_ bv0 64) (_ bv0 64)) true)))
(let (($x18 (and (distinct cache36_return64 cache36_return64) true)))
(or $x18 (and (distinct (_ bv4312472344 64) (_ bv4312472344 64)) true) $x15 $x52)))))
(check-sat)
