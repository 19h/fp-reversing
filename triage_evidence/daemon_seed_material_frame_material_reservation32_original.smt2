; benchmark generated from python API
(set-info :status unknown)
(declare-fun material_old_frame_cursor64 () (_ BitVec 64))
(declare-fun material_frame64 () (_ BitVec 64))
(assert
 (let (($x897 (and (distinct (bvadd (_ bv32 64) material_old_frame_cursor64) (bvadd material_old_frame_cursor64 (_ bv32 64))) true)))
(let (($x1070 (and (distinct (bvadd (_ bv1632 64) material_frame64 material_old_frame_cursor64) (bvadd (bvadd material_frame64 (_ bv1632 64)) material_old_frame_cursor64)) true)))
(let (($x31 (bvule material_frame64 (_ bv18446744073709548575 64))))
(let (($x29 (bvuge material_frame64 (_ bv8589934592 64))))
(let (($x27 (= (bvand material_frame64 (_ bv15 64)) (_ bv0 64))))
(let (($x360 (and $x27 $x29 $x31)))
(and $x360 (or $x1070 $x1070 $x897)))))))))
(check-sat)
