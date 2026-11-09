; benchmark generated from python API
(set-info :status unknown)
(declare-fun init_mba64 () (_ BitVec 64))
(assert
 (let (($x460 (and (distinct (bvadd (bvsub (bvor (bvshl init_mba64 (_ bv1 64)) (_ bv9629527145532668144 64)) init_mba64) (_ bv4408608464088441736 64)) (bvadd (bvadd (bvxor init_mba64 (_ bv4814763572766334072 64)) (_ bv4814763572766334072 64)) (_ bv4408608464088441736 64))) true)))
(and true $x460)))
(check-sat)
