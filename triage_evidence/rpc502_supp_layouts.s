	.build_version macos, 27, 2	sdk_version 27, 2
	.ptrauth_abi_version 0
	.ptrauth_abi_version 0
	.section	__TEXT,__text,regular,pure_instructions
	.globl	_supplemental_address_key       ; -- Begin function supplemental_address_key
	.p2align	2
_supplemental_address_key:              ; @supplemental_address_key
	.cfi_startproc
; %bb.0:
	mov	w8, #24596                      ; =0x6014
	movk	w8, #50902, lsl #16
	eor	w8, w0, w8
	mov	w9, #22831                      ; =0x592f
	movk	w9, #27526, lsl #16
	mul	w0, w8, w9
	ret
	.cfi_endproc
                                        ; -- End function
.subsections_via_symbols
