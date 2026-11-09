; benchmark generated from python API
(set-info :status unknown)
(declare-fun aux_emit_frame_base64 () (_ BitVec 64))
(assert
 (let ((?x608 (bvnot ((_ extract 3 3) (bvadd (_ bv8 4) ((_ extract 3 0) aux_emit_frame_base64))))))
(let (($x4971 (= ?x608 (bvnot ((_ extract 3 3) (bvadd (_ bv4294967128 32) ((_ extract 31 0) aux_emit_frame_base64)))))))
(let ((?x440 ((_ extract 3 0) aux_emit_frame_base64)))
(let ((?x476 (bvadd (_ bv8 4) ?x440)))
(let ((?x610 ((_ extract 2 2) ?x476)))
(let (($x4366 (and (= ?x610 ((_ extract 2 2) (bvadd (_ bv4294967128 32) ((_ extract 31 0) aux_emit_frame_base64)))) $x4971)))
(let (($x4577 (not $x4366)))
(let (($x4378 (= ?x440 (_ bv0 4))))
(and $x4378 $x4577))))))))))
(check-sat)
