; benchmark generated from python API
(set-info :status unknown)
(declare-fun record_address64 () (_ BitVec 64))
(assert
 (let ((?x31 (bvmul (bvxor record_address64 (_ bv3166686302010437418 64)) (_ bv3939039061 64))))
(let ((?x25 (bvadd (bvsub (bvor record_address64 (_ bv9575297181010848123 64)) (bvor record_address64 (_ bv8871446892698703492 64))) (_ bv8871446892698703492 64))))
(let ((?x28 (bvmul (bvxor ?x25 (_ bv12614615971758212689 64)) (_ bv3939039061 64))))
(let ((?x19 (bvxor (bvsub (bvor record_address64 (_ bv4957304250555390711 64)) (bvand record_address64 (_ bv4957304250555390711 64))) (_ bv8014636687119234525 64))))
(let ((?x21 (bvmul ?x19 (_ bv3939039061 64))))
(or (and (distinct ?x21 ?x31) true) (and (distinct ?x28 ?x31) true))))))))
(check-sat)
