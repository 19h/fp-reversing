; benchmark generated from python API
(set-info :status unknown)
(declare-fun byte_cursor32 () (_ BitVec 32))
(declare-fun entry_count32 () (_ BitVec 32))
(assert
 (let (($x883 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (bvadd (_ bv12 32) byte_cursor32))) (bvadd byte_cursor32 (_ bv12 32))) true)))
(let (($x3201 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (bvadd (_ bv1 32) entry_count32))) (bvadd entry_count32 (_ bv1 32))) true)))
(or $x3201 $x883))))
(check-sat)
