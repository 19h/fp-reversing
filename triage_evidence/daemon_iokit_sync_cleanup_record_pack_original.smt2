; benchmark generated from python API
(set-info :status unknown)
(declare-fun sync_shared_key32 () (_ BitVec 32))
(declare-fun sync_pointer64 () (_ BitVec 64))
(assert
 (let (($x252 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (bvadd (_ bv41619 32) (bvmul (_ bv2355619829 32) sync_shared_key32)))) (bvsub (_ bv41619 32) (bvmul sync_shared_key32 (_ bv1939347467 32)))) true)))
(let (($x147 (and (distinct sync_pointer64 sync_pointer64) true)))
(or $x147 $x252))))
(check-sat)
