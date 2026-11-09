; benchmark generated from python API
(set-info :status unknown)
(declare-fun rb_trailer_size32 () (_ BitVec 32))
(declare-fun rb_trailer_type32 () (_ BitVec 32))
(assert
 (let (($x12 (and (bvuge ((_ extract 31 0) (concat (_ bv0 32) rb_trailer_size32)) (_ bv31 32)) (not (= (bvsub ((_ extract 31 0) (concat (_ bv0 32) rb_trailer_size32)) (_ bv31 32)) (_ bv0 32))))))
(let (($x360 (and (distinct (and (= ((_ extract 31 0) (concat (_ bv0 32) rb_trailer_type32)) (_ bv0 32)) $x12) (and (= rb_trailer_type32 (_ bv0 32)) (bvugt rb_trailer_size32 (_ bv31 32)))) true)))
(or (and (distinct (_ bv433792024656 64) (_ bv433792024656 64)) true) $x360))))
(check-sat)
