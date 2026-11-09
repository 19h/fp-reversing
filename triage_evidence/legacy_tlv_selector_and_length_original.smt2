; benchmark generated from python API
(set-info :status unknown)
(declare-fun shared_inner_key32 () (_ BitVec 32))
(assert
 (let ((?x1930 (bvadd ((_ zero_extend 16) (bvsub (_ bv26121 16) ((_ extract 15 0) shared_inner_key32))) shared_inner_key32)))
(let ((?x1871 (bvadd (bvsub (bvadd shared_inner_key32 (_ bv3359316967 32)) shared_inner_key32) (_ bv935650877 32))))
(let (($x1212 (and (distinct (bvxor (bvxor ?x1871 shared_inner_key32) shared_inner_key32) (_ bv548 32)) true)))
(or $x1212 (and (distinct ((_ extract 15 0) (bvsub ?x1930 (_ bv26113 32))) (_ bv8 16)) true))))))
(check-sat)
