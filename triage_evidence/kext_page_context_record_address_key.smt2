(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun record_pointer64 () (_ BitVec 64))
(assert
 (let ((?x231 ((_ zero_extend 32) (bvor (bvand ((_ extract 31 0) ((_ zero_extend 32) (_ bv50003 32))) (_ bv65535 32)) (bvshl (_ bv63614 32) (_ bv16 32))))))
(let ((?x218 (bvor (bvand (bvor (bvand (_ bv45832 64) (_ bv18446744069414649855 64)) (bvshl (_ bv62369 64) (_ bv16 64))) (_ bv18446462603027808255 64)) (bvshl (_ bv3958 64) (_ bv32 64)))))
(let ((?x203 (bvor (bvand (bvor (bvand (_ bv30790 64) (_ bv18446744069414649855 64)) (bvshl (_ bv9302 64) (_ bv16 64))) (_ bv18446462603027808255 64)) (bvshl (_ bv36389 64) (_ bv32 64)))))
(let ((?x185 (bvor (bvand (bvor (bvand (_ bv3956 64) (_ bv18446744069414649855 64)) (bvshl (_ bv46931 64) (_ bv16 64))) (_ bv18446462603027808255 64)) (bvshl (_ bv58293 64) (_ bv32 64)))))
(let ((?x194 (bvor (bvor (bvand ?x185 (_ bv281474976710655 64)) (bvshl (_ bv46168 64) (_ bv48 64))) (bvshl record_pointer64 (_ bv1 64)))))
(let ((?x209 (bvadd (bvsub ?x194 record_pointer64) (bvor (bvand ?x203 (_ bv281474976710655 64)) (bvshl (_ bv9683 64) (_ bv48 64))))))
(let ((?x233 ((_ extract 31 0) (bvmul (bvxor ?x209 (bvor (bvand ?x218 (_ bv281474976710655 64)) (bvshl (_ bv53965 64) (_ bv48 64)))) ?x231))))
(and (distinct ?x233 (bvmul (bvxor ((_ extract 31 0) record_pointer64) (_ bv671626418 32)) (_ bv4169057107 32))) true)))))))))
(check-sat)
