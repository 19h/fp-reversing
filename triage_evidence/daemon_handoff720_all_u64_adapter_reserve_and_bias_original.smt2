; benchmark generated from python API
(set-info :status unknown)
(declare-fun handoff_cursor64 () (_ BitVec 64))
(declare-fun handoff_result64 () (_ BitVec 64))
(declare-fun handoff_SP64 () (_ BitVec 64))
(assert
 (let ((?x356 (bvadd (_ bv18446744073709551440 64) handoff_cursor64)))
(let ((?x281 (bvmul (_ bv16 64) (bvadd (bvlshr handoff_result64 (_ bv60 64)) (_ bv1 64)))))
(let ((?x392 (concat (_ bv0 55) ((_ extract 8 4) (bvadd (_ bv31 32) (concat (_ bv0 24) ((_ extract 63 60) handoff_result64) (_ bv0 4)))) (_ bv0 4))))
(let ((?x390 (bvmul (_ bv18446744073709551615 64) ?x392)))
(let ((?x384 (bvadd handoff_SP64 ?x390)))
(let (($x383 (and (distinct ?x384 (bvsub handoff_SP64 ?x281)) true)))
(and true (or $x383 $x383 $x383 (and (distinct ?x356 (bvsub handoff_cursor64 (_ bv176 64))) true))))))))))
(check-sat)
