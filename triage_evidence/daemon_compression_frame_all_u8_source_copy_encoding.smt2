; benchmark generated from python API
(set-info :status unknown)
(declare-fun frame_byte8 () (_ BitVec 8))
(assert
 (let ((?x332 (concat (bvnot ((_ extract 7 7) frame_byte8)) ((_ extract 6 5) frame_byte8) (bvnot ((_ extract 4 3) frame_byte8)) ((_ extract 2 0) frame_byte8))))
(let ((?x307 (bvadd frame_byte8 (bvmul (_ bv255 8) (concat (_ bv0 2) ((_ extract 4 3) frame_byte8) (_ bv0 4))))))
(not (= ?x307 (bvadd (_ bv104 8) ?x332))))))
(check-sat)
