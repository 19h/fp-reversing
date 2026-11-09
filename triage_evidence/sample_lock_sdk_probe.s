	.build_version macos, 13, 0	sdk_version 27, 0
	.section	__TEXT,__text,regular,pure_instructions
	.globl	_sample_lock_pointer_widths     ; -- Begin function sample_lock_pointer_widths
	.p2align	2
_sample_lock_pointer_widths:            ; @sample_lock_pointer_widths
	.cfi_startproc
; %bb.0:
	mov	w0, #2056                       ; =0x808
	ret
	.cfi_endproc
                                        ; -- End function
.subsections_via_symbols
