; benchmark generated from python API
(set-info :status unknown)
(declare-fun frame_N32 () (_ BitVec 32))
(declare-fun frame_H32 () (_ BitVec 32))
(assert
 (let ((?x61 (bvadd (_ bv64 32) (bvmul (_ bv4294967295 32) (concat (_ bv0 26) ((_ extract 5 0) frame_H32))))))
(let (($x331 (not (bvule ?x61 frame_N32))))
(let (($x339 (bvule (_ bv64 7) (bvadd ((_ extract 6 0) frame_N32) (concat (_ bv0 1) ((_ extract 5 0) frame_H32))))))
(let (($x328 (= ((_ extract 31 7) (bvadd frame_N32 (concat (_ bv0 26) ((_ extract 5 0) frame_H32)))) (_ bv0 25))))
(let (($x315 (or (not $x328) $x339)))
(and $x315 $x331)))))))
(check-sat)
