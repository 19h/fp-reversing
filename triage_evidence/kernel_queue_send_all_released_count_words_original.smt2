; benchmark generated from python API
(set-info :status unknown)
(declare-fun qs_count16 () (_ BitVec 16))
(declare-fun qs_limit16 () (_ BitVec 16))
(assert
 (let ((?x480 ((_ extract 31 0) (concat (_ bv0 32) (bvadd (_ bv4294967295 32) (concat (_ bv0 16) qs_count16))))))
(let ((?x486 (bvand ?x480 (_ bv65535 32))))
(let ((?x30 ((_ extract 31 0) (concat (_ bv0 48) qs_limit16))))
(let (($x499 (and (distinct (or (not (bvuge ?x30 ?x486)) (= (bvsub ?x30 ?x486) (_ bv0 32))) (bvule qs_limit16 (bvsub qs_count16 (_ bv1 16)))) true)))
(or (and (distinct ((_ extract 15 0) ?x480) (bvsub qs_count16 (_ bv1 16))) true) $x499))))))
(check-sat)
