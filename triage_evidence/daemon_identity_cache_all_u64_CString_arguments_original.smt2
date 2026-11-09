; benchmark generated from python API
(set-info :status unknown)
(declare-fun identity_B64 () (_ BitVec 64))
(declare-fun identity_A64 () (_ BitVec 64))
(declare-fun identity_return64 () (_ BitVec 64))
(assert
 (let (($x10 (and (distinct (_ bv134217984 64) (_ bv134217984 64)) true)))
(let (($x18 (and (distinct identity_A64 identity_A64) true)))
(let (($x24 (and (distinct identity_return64 identity_return64) true)))
(or $x24 $x18 (and (distinct identity_B64 identity_B64) true) $x10 (and (distinct (_ bv29192 64) (_ bv29192 64)) true))))))
(check-sat)
