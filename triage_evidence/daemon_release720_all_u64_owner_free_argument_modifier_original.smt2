; benchmark generated from python API
(set-info :status unknown)
(declare-fun release_pointer64 () (_ BitVec 64))
(assert
 (let (($x122 (and (distinct release_pointer64 release_pointer64) true)))
(and true (or $x122 (and (distinct (_ bv18082 64) (_ bv18082 64)) true)))))
(check-sat)
