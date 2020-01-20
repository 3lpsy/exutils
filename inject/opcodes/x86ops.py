IX86_PUSHAD = b"\x60"
IX86_PUSHFD = b"\x9C"
IX86_POPAD = b"\x61"
IX86_NOP = b"\x90"

# unconditional jump/calls
IX86_JMP = b"\xe9"
IX86_JUMP = IX86_JMP

IX86_JMP_SHORT = b"\xeb"
IX86_JMP_FAR = b"\xea"
IX86_CALL = b"\xe8"

# unconditional jump/calls

IX86_JA = b"\x0f\x87"  # Jump if above
IX86_JNBE = IX86_JA  # Jump if not below or equal
IX86_JA_SHORT = b"\x77"  # Jump if above
IX86_JNBE_SHORT = IX86_JA_SHORT  # Jump if not below or equal

IX86_JAE = b"\x0f\x83"  # Jump if above or equal
IX86_JNB = IX86_JAE  # Jump if not below
IX86_JAE_SHORT = b"\x73"  # Jump if above or equal
IX86_JNB_SHORT = IX86_JAE_SHORT  # Jump if not below

IX86_JB = b"\x0f\x82"  # Jump if below
IX86_JBAE = IX86_JB  # Jump if not above or equal
IX86_JC = IX86_JB  # Jump if carry
IX86_JB_SHORT = b"\x72"  # Jump if below
IX86_JBAE_SHORT = IX86_JB_SHORT  # Jump if not above or equal
IX86_JC_SHORT = IX86_JB_SHORT  # Jump if carry

IX86_JBE = b"\x0f\x86"  # Jump if below or equal
IX86_JBZ = IX86_JBE  # Jump if ?
IX86_JBNA = IX86_JBE  # Jump if not above
IX86_JBE_SHORT = b"\x76"  # Jump if below or equal
IX86_JBZ_SHORT = IX86_JBE_SHORT  # Jump if ?
IX86_JBNA_SHORT = IX86_JBE_SHORT  # Jump if not above

IX86_JE = b"\x0f\x84"  # Jump if equal
IX86_JZ = IX86_JE  # Jump if zero
IX86_JE_SHORT = b"\x74"  # Jump if equal
IX86_JZ_SHORT = IX86_JE_SHORT  # Jump if zero

IX86_JG = b"\x0f\x8f"  # jump if greater
IX86_JNLE = IX86_JG  # Jump if not less or equal
IX86_JG_SHORT = b"\x7f"  # jump if greater
IX86_JNLE_SHORT = IX86_JG_SHORT  # Jump if not less or equal

IX86_JGE = b"\x0f\x8d"  # Jump if greater or equal
IX86_JNL = IX86_JGE  # Jump if not less than
IX86_JGE_SHORT = b"\x7d"  # Jump if greater or equal
IX86_JNL_SHORT = IX86_JGE_SHORT  # Jump if not less than

IX86_JL = b"\x0f\x8c"  # Jump if less
IX86_JNGE = IX86_JL  # Jump if not greater or equal
IX86_JL_SHORT = b"\x7c"  # Jump if less
IX86_JNGE_SHORT = IX86_JL_SHORT  # Jump if not greater or equal

IX86_JLE = b"\x0f\x8e"  # Jump if less or equal
IX86_JNG = IX86_JLE  # Jump if not greater
IX86_JLE_SHORT = b"\x7e"  # Jump if less or equal
IX86_JNG_SHORT = IX86_JLE_SHORT  # Jump if not greater

IX86_JNE = b"\x0f\x85"  # Jump if not equal
IX86_JNZ = IX86_JNE  # Jump if not zero
IX86_JNE_SHORT = b"\x75"  # Jump if not equal
IX86_JNZ_SHORT = IX86_JNE_SHORT  # Jump if not zero

IX86_JNO = b"\x0f\x81"  # Jump if not overflow
IX86_JNO_SHORT = b"\x71"  # Jump if not overflow

IX86_JNS = b"\x0f\x89"  # Jump if not sign
IX86_JNS_SHORT = b"\x79"  # Jump if not sign

IX86_JNP = b"\x0f\x8b"  # Jump if not parity
IX86_JPO = IX86_JNP  # Jump if parity odd
IX86_JNP_SHORT = b"\x7b"  # Jump if not parity
IX86_JPO_SHORT = IX86_JNP_SHORT  # Jump if parity odd

IX86_JO = b"\x0f\x80"  # Jump if overflow
IX86_JO_SHORT = b"\x70"  # Jump if overflow

IX86_JP = b"\x0f\x8a"  # Jump if parity
IX86_JPE = IX86_JP  # Jump if parity equal
IX86_JP_SHORT = b"\x7a"  # Jump if parity
IX86_JPE_SHORT = IX86_JP_SHORT  # Jump if parity equal

IX86_JS = b"\x0f\x88"  # Jump if sign
IX86_JS_SHORT = b"\x78"  # Jump if sign
