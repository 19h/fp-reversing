; benchmark generated from python API
(set-info :status unknown)
(declare-fun out_record64 () (_ BitVec 64))
(assert
 (let (($x163 (and (distinct (bvxor (bvmul (bvmul (bvxor out_record64 (_ bv9383277678722142141 64)) (_ bv3354844327 64)) (_ bv16986958209167198999 64)) (_ bv9383277678722142141 64)) out_record64) true)))
(and true $x163)))
(check-sat)
