; benchmark generated from python API
(set-info :status unknown)
(declare-fun qr_count16 () (_ BitVec 16))
(declare-fun qr_limit16 () (_ BitVec 16))
(assert
 (let ((?x601 ((_ extract 31 0) (concat (_ bv0 32) (bvadd (_ bv4294967295 32) (concat (_ bv0 16) qr_count16))))))
(let ((?x596 (bvand ?x601 (_ bv65535 32))))
(let ((?x597 ((_ extract 31 0) (concat (_ bv0 48) qr_limit16))))
(let (($x621 (and (distinct (or (not (bvuge ?x597 ?x596)) (= (bvsub ?x597 ?x596) (_ bv0 32))) (bvule qr_limit16 (bvsub qr_count16 (_ bv1 16)))) true)))
(or (and (distinct ((_ extract 15 0) ?x601) (bvsub qr_count16 (_ bv1 16))) true) $x621))))))
(check-sat)
