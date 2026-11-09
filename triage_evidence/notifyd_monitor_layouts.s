	.build_version macos, 27, 2	sdk_version 27, 2
	.ptrauth_abi_version 0
	.ptrauth_abi_version 0
	.section	__TEXT,__text,regular,pure_instructions
	.globl	_source_selected_mask           ; -- Begin function source_selected_mask
	.p2align	2
_source_selected_mask:                  ; @source_selected_mask
	.cfi_startproc
; %bb.0:
	and	w8, w0, w1
	and	w0, w8, #0x3ff
	ret
	.cfi_endproc
                                        ; -- End function
.subsections_via_symbols
