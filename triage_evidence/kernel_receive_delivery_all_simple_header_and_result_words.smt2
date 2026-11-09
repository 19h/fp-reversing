; benchmark generated from python API
(set-info :status unknown)
(declare-fun rd_kernel_size32 () (_ BitVec 32))
(assert
 (let ((?x359 (bvadd (_ bv4294967288 32) rd_kernel_size32)))
(let (($x1541 (= (concat ((_ extract 31 8) ?x359) (bvadd (_ bv248 8) ((_ extract 7 0) rd_kernel_size32))) ?x359)))
(not $x1541))))
(check-sat)
