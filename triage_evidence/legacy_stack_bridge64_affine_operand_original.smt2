; benchmark generated from python API
(set-info :status unknown)
(declare-fun input_X2 () (_ BitVec 64))
(declare-fun operand_key64 () (_ BitVec 64))
(assert
 (let ((?x47 (bvxor (bvadd (bvmul input_X2 (_ bv789092719754401991 64)) (_ bv2571236323425771088 64)) operand_key64)))
(let ((?x52 (bvadd (bvmul (bvxor ?x47 operand_key64) (_ bv1796970430700218615 64)) (_ bv16690650033266063934 64))))
(and (distinct ?x52 (bvadd input_X2 (_ bv4912036738873915758 64))) true))))
(check-sat)
