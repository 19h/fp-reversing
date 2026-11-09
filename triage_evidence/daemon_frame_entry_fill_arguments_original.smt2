; benchmark generated from python API
(set-info :status unknown)
(declare-fun frame_SP64 () (_ BitVec 64))
(assert
 (let ((?x138 (bvadd frame_SP64 (_ bv1776 64))))
(let ((?x252 (bvadd (_ bv1776 64) frame_SP64)))
(let (($x88 (and (distinct ?x252 ?x138) true)))
(or $x88 $x88 (and (distinct ((_ zero_extend 32) (_ bv0 32)) (_ bv0 64)) true) (and (distinct ((_ zero_extend 32) (_ bv1024 32)) (_ bv1024 64)) true) (and (distinct (_ bv44157 64) (_ bv44157 64)) true))))))
(check-sat)
