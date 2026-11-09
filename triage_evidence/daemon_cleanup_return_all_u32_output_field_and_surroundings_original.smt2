; benchmark generated from python API
(set-info :status unknown)
(declare-fun cleanup_output_word32 () (_ BitVec 32))
(assert
 (let (($x47 (and (distinct (_ bv171 8) (_ bv171 8)) true)))
(let (($x43 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) cleanup_output_word32)) cleanup_output_word32) true)))
(or $x43 $x47 $x47 $x47 $x47 $x47 $x47 $x47 $x47 $x47 $x47 $x47 $x47 $x47 $x47 $x47 $x47 $x47 $x47 $x47 $x47 $x47 $x47 $x47 $x47 $x47 $x47 $x47 $x47))))
(check-sat)
