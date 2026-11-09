; benchmark generated from python API
(set-info :status unknown)
(declare-fun class_frame64 () (_ BitVec 64))
(assert
 (or (and (distinct (bvadd (_ bv137 64) class_frame64) (bvadd class_frame64 (_ bv137 64))) true) (and (distinct (_ bv2107 64) (_ bv2107 64)) true)))
(check-sat)
