; benchmark generated from python API
(set-info :status unknown)
(declare-fun frame_C64 () (_ BitVec 64))
(declare-fun frame_I64 () (_ BitVec 64))
(assert
 (let (($x187 (and (distinct ((_ extract 31 0) (_ bv64 64)) (_ bv64 32)) true)))
(let (($x186 (and (distinct ((_ extract 31 0) (_ bv41809 64)) (_ bv41809 32)) true)))
(let (($x49 (and (distinct frame_C64 frame_C64) true)))
(let (($x167 (and (distinct frame_I64 frame_I64) true)))
(and true (or $x167 $x49 $x186 $x187)))))))
(check-sat)
