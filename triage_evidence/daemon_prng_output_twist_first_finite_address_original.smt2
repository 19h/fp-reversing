; benchmark generated from python API
(set-info :status unknown)
(declare-fun out_frame64 () (_ BitVec 64))
(declare-fun out_next32 () (_ BitVec 32))
(declare-fun out_twist_offset64 () (_ BitVec 64))
(assert
 (let ((?x734 (bvadd (_ bv1752 64) out_frame64 (concat (_ bv0 61) ((_ extract 0 0) out_next32) (_ bv0 2)))))
(let (($x788 (and (and (distinct ?x734 (bvadd out_frame64 (_ bv1752 64))) true) (and (distinct ?x734 (bvadd out_frame64 (_ bv1756 64))) true))))
(let (($x492 (= (bvand out_twist_offset64 (_ bv3 64)) (_ bv0 64))))
(let (($x27 (and (= (bvand out_frame64 (_ bv15 64)) (_ bv0 64)) (bvuge out_frame64 (_ bv429496729600 64)) (bvule out_frame64 (_ bv429496792096 64)))))
(let (($x681 (and $x27 $x492 (bvule out_twist_offset64 (_ bv904 64)))))
(and $x681 $x788)))))))
(check-sat)
