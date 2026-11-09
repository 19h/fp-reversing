; benchmark generated from python API
(set-info :status unknown)
(declare-fun aux_emit_frame_base64 () (_ BitVec 64))
(assert
 (let ((?x453 (bvnot ((_ extract 1 1) (bvadd (_ bv68792 32) ((_ extract 31 0) aux_emit_frame_base64))))))
(let (($x4550 (and (= ((_ extract 0 0) aux_emit_frame_base64) (_ bv0 1)) (= ?x453 (bvnot ((_ extract 1 1) aux_emit_frame_base64))) (= ((_ extract 2 2) (bvadd (_ bv68792 32) ((_ extract 31 0) aux_emit_frame_base64))) (_ bv0 1)))))
(let (($x4935 (not $x4550)))
(let ((?x440 ((_ extract 3 0) aux_emit_frame_base64)))
(let (($x4482 (= ?x440 (_ bv0 4))))
(and $x4482 $x4935)))))))
(check-sat)
