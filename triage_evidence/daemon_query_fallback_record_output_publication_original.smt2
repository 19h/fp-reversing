; benchmark generated from python API
(set-info :status unknown)
(declare-fun fallback_record64 () (_ BitVec 64))
(declare-fun fallback_helper_SP64 () (_ BitVec 64))
(declare-fun fallback_output_marker32 () (_ BitVec 32))
(assert
 (let (($x618 (and (distinct (bvadd (_ bv16 64) fallback_helper_SP64) (bvadd fallback_helper_SP64 (_ bv16 64))) true)))
(let (($x613 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) fallback_output_marker32)) fallback_output_marker32) true)))
(or $x613 $x618 (and (distinct fallback_record64 fallback_record64) true)))))
(check-sat)
