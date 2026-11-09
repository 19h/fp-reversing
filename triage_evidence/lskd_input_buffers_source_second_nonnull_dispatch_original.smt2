; benchmark generated from python API
(set-info :status unknown)
(declare-fun output_sized_region64 () (_ BitVec 64))
(assert
 (let ((?x85 (bvmul (_ bv8 32) (ite (= output_sized_region64 (_ bv0 64)) (_ bv1 32) (_ bv0 32)))))
(let ((?x82 ((_ extract 3 2) ?x85)))
(let ((?x86 ((_ extract 6 6) ?x85)))
(let ((?x88 ((_ extract 9 8) ?x85)))
(let ((?x89 ((_ extract 31 11) ?x85)))
(let ((?x90 (concat ?x89 (_ bv1 1) ?x88 (_ bv1 1) ?x86 (_ bv3 2) ?x82 (_ bv3 2))))
(and (and (distinct output_sized_region64 (_ bv0 64)) true) (and (distinct ((_ extract 31 0) ((_ zero_extend 32) ?x90)) (_ bv1203 32)) true)))))))))
(check-sat)
