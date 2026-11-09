	.build_version macos, 13, 0	sdk_version 27, 0
	.section	__TEXT,__text,regular,pure_instructions
	.globl	_probe_data_alloc               ; -- Begin function probe_data_alloc
	.p2align	2
_probe_data_alloc:                      ; @probe_data_alloc
	.cfi_startproc
; %bb.0:
	b	_IOMallocData
	.cfi_endproc
                                        ; -- End function
	.globl	_probe_data_free                ; -- Begin function probe_data_free
	.p2align	2
_probe_data_free:                       ; @probe_data_free
	.cfi_startproc
; %bb.0:
	b	_IOFreeData
	.cfi_endproc
                                        ; -- End function
.subsections_via_symbols
