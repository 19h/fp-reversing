; benchmark generated from python API
(set-info :status unknown)
(declare-fun consumer_buffer64 () (_ BitVec 64))
(declare-fun consumer_frame64 () (_ BitVec 64))
(declare-fun consumer_record64 () (_ BitVec 64))
(assert
 (let (($x29 (= (bvand consumer_buffer64 (_ bv3 64)) (_ bv0 64))))
(let (($x26 (and (= (bvand consumer_frame64 (_ bv15 64)) (_ bv0 64)) (bvuge consumer_frame64 (_ bv429496729600 64)) (bvule consumer_frame64 (_ bv429496792096 64)) (= consumer_record64 (bvadd consumer_frame64 (_ bv2808 64))))))
(and $x26 (and (distinct (= (_ bv0 64) (concat (_ bv0 62) ((_ extract 1 0) consumer_buffer64))) $x29) true)))))
(check-sat)
