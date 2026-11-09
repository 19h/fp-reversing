; benchmark generated from python API
(set-info :status unknown)
(declare-fun completion_remaining64 () (_ BitVec 64))
(assert
 (let (($x211 (and (distinct (_ bv4311981808 64) (_ bv4311981808 64)) true)))
(let (($x610 (and (distinct ((_ extract 31 0) (_ bv64501 64)) (_ bv64501 32)) true)))
(let (($x601 (and (distinct ((_ extract 31 0) (_ bv152 64)) (_ bv152 32)) true)))
(let (($x292 (and (distinct (_ bv468151566336 64) (_ bv468151566336 64)) true)))
(let (($x888 (and (distinct (_ bv468151631872 64) (_ bv468151631872 64)) true)))
(let (($x145 (bvuge completion_remaining64 (_ bv1 64))))
(let (($x682 (and $x145 (bvule completion_remaining64 (_ bv4294967295 64)))))
(and $x682 (or $x888 $x292 $x601 $x610 (and (distinct ((_ extract 31 0) (_ bv26007 64)) (_ bv26007 32)) true) $x211))))))))))
(check-sat)
