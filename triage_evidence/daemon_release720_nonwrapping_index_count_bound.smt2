; benchmark generated from python API
(set-info :status unknown)
(declare-fun release_count32 () (_ BitVec 32))
(declare-fun release_index32 () (_ BitVec 32))
(assert
 (let (($x1063 (= (bvule release_count32 release_index32) (bvule (bvadd (_ bv1 32) release_index32) release_count32))))
(let (($x529 (= release_index32 (_ bv4294967295 32))))
(let (($x818 (not $x529)))
(and $x818 $x1063)))))
(check-sat)
