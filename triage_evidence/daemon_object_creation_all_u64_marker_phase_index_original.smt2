; benchmark generated from python API
(set-info :status unknown)
(declare-fun creation_marker_phase64 () (_ BitVec 64))
(assert
 (let (($x111 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) (bvadd (_ bv20703 32) ((_ extract 31 0) creation_marker_phase64)))) (bvadd ((_ extract 31 0) creation_marker_phase64) (_ bv20703 32))) true)))
(and true (or $x111 (and (distinct ((_ extract 7 0) ((_ extract 31 0) (_ bv1 64))) (_ bv1 8)) true)))))
(check-sat)
