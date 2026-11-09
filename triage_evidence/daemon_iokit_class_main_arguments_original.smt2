; benchmark generated from python API
(set-info :status unknown)
(declare-fun class_frame64 () (_ BitVec 64))
(assert
 (or (and (distinct ((_ zero_extend 32) (_ bv0 32)) (_ bv0 64)) true) (and (distinct (bvadd (_ bv124 64) class_frame64) (bvadd class_frame64 (_ bv124 64))) true) (and (distinct (_ bv25152 64) (_ bv25152 64)) true)))
(check-sat)
