from enum import Enum
from inject.utils import byteslash
from inject.opcodes.x86ops import *
from inject.opcodes.x86lists import *


class X86OP(Enum):
    # conditional jmp/calls
    JA = IX86_JA
    JA_SHORT = IX86_JA_SHORT
    JNBE = IX86_JA
    JNBE_SHORT = IX86_JA_SHORT
    JAE = IX86_JAE
    JAE_SHORT = IX86_JAE_SHORT
    JNB = IX86_JAE
    JNB_SHORT = IX86_JAE_SHORT
    JB = IX86_JB
    JB_SHORT = IX86_JB_SHORT
    JBAE = IX86_JB
    JBAE_SHORT = IX86_JB_SHORT
    JC = IX86_JB
    JC_SHORT = IX86_JB_SHORT
    JBE = IX86_JBE
    JBE_SHORT = IX86_JBE_SHORT
    JBZ = IX86_JBE
    JBZ_SHORT = IX86_JBE_SHORT
    JBNA = IX86_JBE
    JBNA_SHORT = IX86_JBE_SHORT
    JE = IX86_JE
    JE_SHORT = IX86_JE_SHORT
    JZ = IX86_JE
    JZ_SHORT = IX86_JE_SHORT
    JG = IX86_JG
    JG_SHORT = IX86_JG_SHORT
    JNLE = IX86_JG
    JNLE_SHORT = IX86_JG_SHORT
    JGE = IX86_JGE
    JGE_SHORT = IX86_JGE_SHORT
    JNL = IX86_JGE
    JNL_SHORT = IX86_JGE_SHORT
    JL = IX86_JL
    JL_SHORT = IX86_JL_SHORT
    JNGE = IX86_JL
    JNGE_SHORT = IX86_JL_SHORT
    JLE = IX86_JLE
    JLE_SHORT = IX86_JLE_SHORT
    JNG = IX86_JLE
    JNG_SHORT = IX86_JLE_SHORT
    JNE = IX86_JNE
    JNE_SHORT = IX86_JNE_SHORT
    JNZ = IX86_JNE
    JNZ_SHORT = IX86_JNE_SHORT
    JNO = IX86_JNO
    JNO_SHORT = IX86_JNO_SHORT
    JNS = IX86_JNS
    JNS_SHORT = IX86_JNS_SHORT
    JNP = IX86_JNP
    JNP_SHORT = IX86_JNP_SHORT
    JPO = IX86_JNP
    JPO_SHORT = IX86_JNP_SHORT
    JO = IX86_JO
    JO_SHORT = IX86_JO_SHORT
    JP = IX86_JP
    JP_SHORT = IX86_JP_SHORT
    JPE = IX86_JP
    JPE_SHORT = IX86_JP_SHORT
    JS = IX86_JS
    JS_SHORT = IX86_JS_SHORT

    # unconditional jmp/calls
    CALL = IX86_CALL
    JMP = IX86_JMP
    JMP_SHORT = IX86_JMP_SHORT
    JMP_FAR = IX86_JMP_FAR

    PUSHAD = IX86_PUSHAD
    PUSHFD = IX86_PUSHFD
    POPAD = IX86_POPAD
    NOP = IX86_NOP

    def is_jmp_call(self):
        return self.name in IX86_CONDITIONAL_JMP_CALLS + IX86_UNCONDITIONAL_JMP_CALLS

    def is_conditional_jmp_call(self):
        return self.name in IX86_CONDITIONAL_JMP_CALLS

    def is_unconditional_jmp_call(self):
        return self.name in IX86_UNCONDITIONAL_JMP_CALLS

    def is_short(self):
        return self.name.endswith("_SHORT")

    def short(self):
        for name, member in type(self).__members__.items():
            if name == self.name + "_SHORT":
                return member
        raise Exception(f"No short alternative found for {str(self.name)}")

    @classmethod
    def knows_value(cls, val):
        for name, member in cls.__members__.items():
            if member.value == val:
                return True
        return False

    def deshort(self):
        for name, member in type(self).__members__.items():
            if name + "_SHORT" == self.name:
                return member
        raise Exception(f"No short alternative found for {str(self.name)}")

    def __str__(self):
        return byteslash(self.value)

    def __bytes__(self):
        return bytes(self.value)
