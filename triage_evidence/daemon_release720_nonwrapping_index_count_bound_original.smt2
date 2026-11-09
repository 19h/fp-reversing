; benchmark generated from python API
(set-info :status unknown)
(declare-fun release_count32 () (_ BitVec 32))
(declare-fun release_index32 () (_ BitVec 32))
(assert
 (let (($x561 (bvule (bvadd release_index32 (_ bv1 32)) release_count32)))
(and (and (distinct release_index32 (_ bv4294967295 32)) true) (and (distinct $x561 (bvult release_index32 release_count32)) true))))
(check-sat)
