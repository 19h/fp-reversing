; benchmark generated from python API
(set-info :status unknown)
(declare-fun qs_count16 () (_ BitVec 16))
(assert
 (let (($x73 (not (bvuge ((_ extract 31 0) ((_ zero_extend 32) ((_ zero_extend 16) qs_count16))) ((_ extract 31 0) (_ bv65534 64))))))
(let (($x75 (bvule qs_count16 (_ bv65533 16))))
(let (($x58 (= (bvsub ((_ extract 31 0) ((_ zero_extend 32) ((_ zero_extend 16) qs_count16))) ((_ extract 31 0) (_ bv65533 64))) (_ bv0 32))))
(let (($x67 (not (bvuge ((_ extract 31 0) ((_ zero_extend 32) ((_ zero_extend 16) qs_count16))) ((_ extract 31 0) (_ bv65533 64))))))
(or (and (distinct (or $x67 $x58) $x75) true) (and (distinct $x73 (bvult qs_count16 (_ bv65534 16))) true)))))))
(check-sat)
