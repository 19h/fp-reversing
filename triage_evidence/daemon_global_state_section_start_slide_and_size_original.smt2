; benchmark generated from python API
(set-info :status unknown)
(declare-fun window_section_size64 () (_ BitVec 64))
(declare-fun window_segment_vmaddr64 () (_ BitVec 64))
(declare-fun window_runtime_base64 () (_ BitVec 64))
(declare-fun window_section_addr64 () (_ BitVec 64))
(assert
 (let (($x19 (and (distinct window_section_size64 window_section_size64) true)))
(let ((?x32 (bvsub (bvadd window_section_addr64 window_runtime_base64) window_segment_vmaddr64)))
(let ((?x30 (bvmul (_ bv18446744073709551615 64) window_segment_vmaddr64)))
(let (($x18 (and (distinct (bvadd window_runtime_base64 window_section_addr64 ?x30) ?x32) true)))
(and true (or $x18 $x19)))))))
(check-sat)
