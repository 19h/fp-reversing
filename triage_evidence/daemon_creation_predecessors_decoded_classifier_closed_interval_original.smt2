; benchmark generated from python API
(set-info :status unknown)
(declare-fun pred_raw32 () (_ BitVec 32))
(assert
 (let ((?x12 (bvxor pred_raw32 (_ bv2336081489 32))))
(let (($x371 (bvuge ?x12 (_ bv2 32))))
(let (($x301 (and (distinct (and (bvult ?x12 (_ bv201 32)) (bvult (bvsub ?x12 (_ bv2 32)) (_ bv4294967294 32))) (and $x371 (bvule ?x12 (_ bv200 32)))) true)))
(and true $x301)))))
(check-sat)
