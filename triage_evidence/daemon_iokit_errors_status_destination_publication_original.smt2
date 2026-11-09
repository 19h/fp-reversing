; benchmark generated from python API
(set-info :status unknown)
(declare-fun error_helper_SP64 () (_ BitVec 64))
(declare-fun error_value32 () (_ BitVec 32))
(assert
 (let (($x1368 (and (distinct (bvadd (_ bv16 64) error_helper_SP64) (bvadd error_helper_SP64 (_ bv16 64))) true)))
(or (and (distinct ((_ extract 31 0) ((_ zero_extend 32) error_value32)) error_value32) true) $x1368)))
(check-sat)
