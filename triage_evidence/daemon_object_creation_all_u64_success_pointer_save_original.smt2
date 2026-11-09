; benchmark generated from python API
(set-info :status unknown)
(declare-fun creation_marker_phase64 () (_ BitVec 64))
(declare-fun creation_return64 () (_ BitVec 64))
(assert
 (let (($x271 (and (distinct (_ bv0 64) (_ bv0 64)) true)))
(let (($x116 (and (distinct creation_marker_phase64 creation_marker_phase64) true)))
(let (($x241 (and (distinct creation_return64 creation_return64) true)))
(and true (or $x241 $x116 $x271))))))
(check-sat)
