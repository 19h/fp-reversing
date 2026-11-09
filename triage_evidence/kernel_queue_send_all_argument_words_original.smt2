; benchmark generated from python API
(set-info :status unknown)
(declare-fun qs_options64 () (_ BitVec 64))
(declare-fun qs_message64 () (_ BitVec 64))
(declare-fun qs_queue64 () (_ BitVec 64))
(assert
 (let (($x17 (and (distinct qs_message64 qs_message64) true)))
(or (and (distinct (bvadd (_ bv18446744073709551576 64) qs_queue64) (bvsub qs_queue64 (_ bv40 64))) true) (and (distinct qs_queue64 qs_queue64) true) $x17 (and (distinct qs_options64 qs_options64) true))))
(check-sat)
