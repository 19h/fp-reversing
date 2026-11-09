; benchmark generated from python API
(set-info :status unknown)
(declare-fun output_selector32 () (_ BitVec 32))
(assert
 (let (($x504 (and (distinct (_ bv468151500800 64) (_ bv468151500800 64)) true)))
(let (($x151 (or $x504 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) output_selector32)) output_selector32) true) (and (distinct (_ bv4312326672 64) (_ bv4312326672 64)) true))))
(and true $x151))))
(check-sat)
