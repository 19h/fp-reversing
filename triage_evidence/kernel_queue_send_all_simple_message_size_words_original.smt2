; benchmark generated from python API
(set-info :status unknown)
(declare-fun qs_header_size32 () (_ BitVec 32))
(assert
 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) (bvadd (_ bv4294967288 32) qs_header_size32))) (bvsub qs_header_size32 (_ bv8 32))) true))
(check-sat)
