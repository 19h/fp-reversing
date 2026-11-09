; benchmark generated from python API
(set-info :status unknown)
(declare-fun creation_marker_phase64 () (_ BitVec 64))
(assert
 (let (($x116 (and (distinct creation_marker_phase64 creation_marker_phase64) true)))
(let (($x126 (or (and (distinct ((_ extract 31 0) (_ bv2452 64)) (_ bv2452 32)) true) (and (distinct ((_ extract 31 0) (_ bv41882 64)) (_ bv41882 32)) true) $x116)))
(and true $x126))))
(check-sat)
