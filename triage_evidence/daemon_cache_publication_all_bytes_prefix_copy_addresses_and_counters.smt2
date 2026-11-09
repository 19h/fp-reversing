; benchmark generated from python API
(set-info :status unknown)
(declare-fun publication_i64 () (_ BitVec 64))
(declare-fun publication_N64 () (_ BitVec 64))
(assert
 (let (($x6379 (not (= (concat (_ bv0 32) ((_ extract 31 0) publication_i64)) publication_i64))))
(let (($x5454 (not (bvule publication_N64 publication_i64))))
(let (($x5634 (bvule ((_ extract 4 0) publication_N64) (_ bv20 5))))
(let (($x5949 (= ((_ extract 63 5) publication_N64) (_ bv0 59))))
(let (($x5610 (or (not (= ((_ extract 63 1) publication_N64) (_ bv0 63))) (= ((_ extract 0 0) publication_N64) (_ bv1 1)))))
(and $x5610 $x5949 $x5634 $x5454 $x6379)))))))
(check-sat)
