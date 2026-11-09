; benchmark generated from python API
(set-info :status unknown)
(declare-fun inner_record_address32 () (_ BitVec 32))
(assert
 (let ((?x21 (bvsub (bvmul (_ bv2 32) (bvand inner_record_address32 (_ bv3205751888 32))) inner_record_address32)))
(let ((?x10 (bvsub (bvor (_ bv3321562874 32) (bvshl inner_record_address32 (_ bv1 32))) inner_record_address32)))
(and (distinct (bvmul (bvxor (bvadd ?x10 (_ bv486702211 32)) (_ bv2893376283 32)) (_ bv3485697751 32)) (bvmul (bvxor (bvadd ?x21 (_ bv1089215407 32)) (_ bv241497033 32)) (_ bv3485697751 32))) true))))
(check-sat)
