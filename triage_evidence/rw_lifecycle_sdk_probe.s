	.build_version macos, 13, 0	sdk_version 27, 0
	.section	__TEXT,__text,regular,pure_instructions
	.globl	_rw_lifecycle_pointer_width     ; -- Begin function rw_lifecycle_pointer_width
	.p2align	2
_rw_lifecycle_pointer_width:            ; @rw_lifecycle_pointer_width
	.cfi_startproc
; %bb.0:
	mov	w0, #8                          ; =0x8
	ret
	.cfi_endproc
                                        ; -- End function
.subsections_via_symbols
