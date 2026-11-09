	.build_version macos, 27, 2	sdk_version 27, 2
	.ptrauth_abi_version 0
	.ptrauth_abi_version 0
	.section	__TEXT,__text,regular,pure_instructions
	.globl	_local_byte_codec               ; -- Begin function local_byte_codec
	.p2align	2
_local_byte_codec:                      ; @local_byte_codec
	.cfi_startproc
; %bb.0:
	lsl	w8, w0, #1
	and	w8, w8, #0x30
	sub	w8, w0, w8
	sub	w8, w8, #104
	and	w0, w8, #0xff
	ret
	.cfi_endproc
                                        ; -- End function
.subsections_via_symbols
