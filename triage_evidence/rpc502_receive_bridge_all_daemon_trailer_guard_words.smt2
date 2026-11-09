; benchmark generated from python API
(set-info :status unknown)
(declare-fun rb_trailer_size32 () (_ BitVec 32))
(declare-fun rb_trailer_type32 () (_ BitVec 32))
(assert
 (let (($x842 (not (= ((_ extract 31 5) rb_trailer_size32) (_ bv0 27)))))
(let (($x362 (= rb_trailer_type32 (_ bv0 32))))
(let (($x1696 (and $x362 (or $x842 (= ((_ extract 4 0) rb_trailer_size32) (_ bv31 5))) (not (= rb_trailer_size32 (_ bv31 32))))))
(not (= $x1696 (and $x362 $x842)))))))
(check-sat)
