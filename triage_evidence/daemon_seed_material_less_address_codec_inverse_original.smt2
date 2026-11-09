; benchmark generated from python API
(set-info :status unknown)
(declare-fun less_record64 () (_ BitVec 64))
(assert
 (let (($x66 (and (distinct (bvxor (bvmul (bvmul (bvxor less_record64 (_ bv106391012430238306 64)) (_ bv3122700023 64)) (_ bv1160544141792084679 64)) (_ bv106391012430238306 64)) less_record64) true)))
(and true $x66)))
(check-sat)
