; benchmark generated from python API
(set-info :status unknown)
(declare-fun out_frame_cursor64 () (_ BitVec 64))
(declare-fun out_data64 () (_ BitVec 64))
(declare-fun out_byte_offset32 () (_ BitVec 32))
(declare-fun out_owner64 () (_ BitVec 64))
(declare-fun out_frame64 () (_ BitVec 64))
(assert
 (let ((?x917 (bvadd out_data64 ((_ zero_extend 32) out_byte_offset32))))
(let (($x1213 (bvule out_owner64 (_ bv18446744073709461615 64))))
(let (($x27 (and (= (bvand out_frame64 (_ bv15 64)) (_ bv0 64)) (bvuge out_frame64 (_ bv429496729600 64)) (bvule out_frame64 (_ bv429496792096 64)))))
(let (($x859 (and $x27 (bvuge out_owner64 (_ bv433791696896 64)) $x1213 (bvuge out_data64 out_owner64) (bvule out_data64 (bvadd out_owner64 (_ bv89996 64))) (bvuge ?x917 out_owner64) (bvule ?x917 (bvadd out_owner64 (_ bv89996 64))) (bvuge ?x917 out_data64))))
(and $x859 (and (distinct out_frame_cursor64 out_frame_cursor64) true)))))))
(check-sat)
