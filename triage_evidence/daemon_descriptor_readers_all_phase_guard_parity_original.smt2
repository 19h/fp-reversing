; benchmark generated from python API
(set-info :status unknown)
(declare-fun reader_phase32 () (_ BitVec 32))
(assert
 (let ((?x316 (bvand reader_phase32 (_ bv1 32))))
(let ((?x350 (concat ((_ extract 31 16) reader_phase32) (bvnot ((_ extract 15 15) reader_phase32)) ((_ extract 14 12) reader_phase32) (bvnot ((_ extract 11 11) reader_phase32)) ((_ extract 10 10) reader_phase32) (bvnot ((_ extract 9 8) reader_phase32)) ((_ extract 7 6) reader_phase32) (bvnot ((_ extract 5 5) reader_phase32)) ((_ extract 4 4) reader_phase32) (bvnot ((_ extract 3 3) reader_phase32)) ((_ extract 2 0) reader_phase32))))
(let ((?x307 (bvmul (_ bv61 32) ?x350)))
(and true (and (distinct (bvand ((_ extract 31 0) (concat (_ bv0 32) ?x307)) (_ bv1 32)) ?x316) true))))))
(check-sat)
