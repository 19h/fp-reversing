; benchmark generated from python API
(set-info :status unknown)
(declare-fun output_word32 () (_ BitVec 32))
(declare-fun output_root64 () (_ BitVec 64))
(assert
 (let (($x562 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) output_word32)) output_word32) true)))
(let (($x620 (and (distinct output_root64 output_root64) true)))
(and true (or $x620 $x562 (and (distinct ((_ extract 7 0) (_ bv0 32)) (_ bv0 8)) true))))))
(check-sat)
