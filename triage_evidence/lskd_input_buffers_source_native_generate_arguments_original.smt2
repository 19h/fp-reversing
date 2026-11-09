; benchmark generated from python API
(set-info :status unknown)
(declare-fun native_destination64 () (_ BitVec 64))
(declare-fun native_chunk64 () (_ BitVec 64))
(declare-fun native_thread_field16 () (_ BitVec 16))
(declare-fun native_context64 () (_ BitVec 64))
(declare-fun native_generate_pointer64 () (_ BitVec 64))
(assert
 (let (($x131 (and (distinct ((_ zero_extend 32) ((_ zero_extend 16) native_thread_field16)) ((_ zero_extend 48) native_thread_field16)) true)))
(let (($x142 (and (distinct native_context64 native_context64) true)))
(or (and (distinct native_generate_pointer64 native_generate_pointer64) true) $x142 $x131 (and (distinct native_chunk64 native_chunk64) true) (and (distinct native_destination64 native_destination64) true)))))
(check-sat)
