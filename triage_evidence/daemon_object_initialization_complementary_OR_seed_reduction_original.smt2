; benchmark generated from python API
(set-info :status unknown)
(declare-fun init_mba64 () (_ BitVec 64))
(assert
 (let (($x1180 (and (distinct (bvadd (bvsub (bvor init_mba64 (_ bv1994676127346907220 64)) (bvor init_mba64 (_ bv16452067946362644395 64))) (_ bv16452067946362644395 64)) (bvxor init_mba64 (_ bv1994676127346907220 64))) true)))
(and true $x1180)))
(check-sat)
