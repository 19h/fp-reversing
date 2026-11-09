; benchmark generated from python API
(set-info :status unknown)
(declare-fun life_frame64 () (_ BitVec 64))
(assert
 (let (($x25 (or (and (distinct ((_ extract 31 0) (_ bv18204 64)) (_ bv18204 32)) true) (and (distinct (bvadd (_ bv10864 64) life_frame64) (bvadd life_frame64 (_ bv10864 64))) true))))
(and true $x25)))
(check-sat)
