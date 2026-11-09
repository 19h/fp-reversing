	.build_version macos, 27, 2	sdk_version 27, 2
	.ptrauth_abi_version 0
	.ptrauth_abi_version 0
	.section	__TEXT,__text,regular,pure_instructions
	.globl	_selected_parameter             ; -- Begin function selected_parameter
	.p2align	2
_selected_parameter:                    ; @selected_parameter
	.cfi_startproc
; %bb.0:
	ldr	w8, [x0, #28]
	mov	w9, #50769                      ; =0xc651
	movk	w9, #35645, lsl #16
	add	w8, w8, w1
	eor	w0, w8, w9
	ret
	.cfi_endproc
                                        ; -- End function
	.globl	_selected_extent                ; -- Begin function selected_extent
	.p2align	2
_selected_extent:                       ; @selected_extent
	.cfi_startproc
; %bb.0:
	ldr	w8, [x0, #8]
	eor	w8, w8, w1
	mov	w9, #34296                      ; =0x85f8
	movk	w9, #54556, lsl #16
	add	w0, w8, w9
	ret
	.cfi_endproc
                                        ; -- End function
.subsections_via_symbols
