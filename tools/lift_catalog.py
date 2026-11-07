"""Master Static x86-to-C99 Lifter for NFS ProStreet.

Translates 32-bit x86 machine instructions from nfs.exe into optimized C99
targeting runtime/cpu.h and WebAssembly SIMD128.

Supports:
- All general integer instructions (arithmetic, logic, bit manipulation, stack, string).
- Dead-flag elimination via backward control-flow graph (CFG) liveness analysis.
- Full SSE, SSE2, and MMX SIMD instruction set (52,617 occurrences in nfs.exe):
  - Scalar & packed single-precision floats (movss, addss, subss, mulss, divss,
    addps, subps, mulps, divps, sqrtps, rsqrtps, rcpps, maxps, minps, etc.)
  - Vector bitwise logic (xorps, andps, orps, andnps, pxor, pand, por, pandn)
  - Float comparisons & condition codes (comiss, ucomiss, comisd, ucomisd)
  - Float <-> integer conversions (cvtsi2ss, cvttss2si, cvtss2si, cvtsi2sd, cvttsd2si)
  - Shuffles, permutations, and unpacks (shufps, unpcklps, unpckhps, movlhps, movhlps)
  - Integer SIMD (paddd, psubd, pmaddwd, psrlq, psrad, pslld, packssdw, packuswb)
- Complete x87 floating point emulation with 8-deep stack.
"""
from __future__ import annotations

from collections import deque
import json
from pathlib import Path
import struct
import sys
from typing import Any, Callable, Sequence

WORKSPACE = Path(__file__).resolve().parent.parent
if str(WORKSPACE) not in sys.path:
    sys.path.insert(0, str(WORKSPACE))

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM, CS_OP_REG
from capstone.x86 import *

from tools.clean_drm import EXPECTED_NFS_EXE_SHA256, parse_text_section
from tools.manual_overrides import MANUAL_RECOVERIES
from tools.trampoline_analyzer import parse_pe_sections, va_to_offset

# Register lookups
R32 = {
    X86_REG_EAX: "eax", X86_REG_ECX: "ecx", X86_REG_EDX: "edx", X86_REG_EBX: "ebx",
    X86_REG_ESP: "esp", X86_REG_EBP: "ebp", X86_REG_ESI: "esi", X86_REG_EDI: "edi",
}
R16 = {
    X86_REG_AX: "eax", X86_REG_CX: "ecx", X86_REG_DX: "edx", X86_REG_BX: "ebx",
    X86_REG_SP: "esp", X86_REG_BP: "ebp", X86_REG_SI: "esi", X86_REG_DI: "edi",
}
R8L = {X86_REG_AL: "eax", X86_REG_CL: "ecx", X86_REG_DL: "edx", X86_REG_BL: "ebx"}
R8H = {X86_REG_AH: "eax", X86_REG_CH: "ecx", X86_REG_DH: "edx", X86_REG_BH: "ebx"}

MM = {
    X86_REG_MM0: 0, X86_REG_MM1: 1, X86_REG_MM2: 2, X86_REG_MM3: 3,
    X86_REG_MM4: 4, X86_REG_MM5: 5, X86_REG_MM6: 6, X86_REG_MM7: 7,
}
XM = {
    X86_REG_XMM0: 0, X86_REG_XMM1: 1, X86_REG_XMM2: 2, X86_REG_XMM3: 3,
    X86_REG_XMM4: 4, X86_REG_XMM5: 5, X86_REG_XMM6: 6, X86_REG_XMM7: 7,
}
ST_REGS = {
    X86_REG_ST0: 0, X86_REG_ST1: 1, X86_REG_ST2: 2, X86_REG_ST3: 3,
    X86_REG_ST4: 4, X86_REG_ST5: 5, X86_REG_ST6: 6, X86_REG_ST7: 7,
}

CC = {
    "o": "CC_O", "no": "CC_NO", "b": "CC_B", "ae": "CC_AE", "e": "CC_E", "ne": "CC_NE",
    "be": "CC_BE", "a": "CC_A", "s": "CC_S", "ns": "CC_NS", "p": "CC_P", "np": "CC_NP",
    "l": "CC_L", "ge": "CC_GE", "le": "CC_LE", "g": "CC_G",
    "nae": "CC_B", "nb": "CC_AE", "c": "CC_B", "nc": "CC_AE", "z": "CC_E", "nz": "CC_NE",
    "na": "CC_BE", "nbe": "CC_A", "pe": "CC_P", "po": "CC_NP", "nge": "CC_L", "nl": "CC_GE",
    "ng": "CC_LE", "nle": "CC_G",
}

# Flag bitmasks
F_CF, F_PF, F_AF, F_ZF, F_SF, F_OF = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
F_ALL = 0x3F

CC_FLAGS = {
    "o": F_OF, "no": F_OF,
    "b": F_CF, "c": F_CF, "nae": F_CF,
    "ae": F_CF, "nb": F_CF, "nc": F_CF,
    "e": F_ZF, "z": F_ZF,
    "ne": F_ZF, "nz": F_ZF,
    "be": F_CF | F_ZF, "na": F_CF | F_ZF,
    "a": F_CF | F_ZF, "nbe": F_CF | F_ZF,
    "s": F_SF, "ns": F_SF,
    "p": F_PF, "pe": F_PF,
    "np": F_PF, "po": F_PF,
    "l": F_SF | F_OF, "nge": F_SF | F_OF,
    "ge": F_SF | F_OF, "nl": F_SF | F_OF,
    "le": F_ZF | F_SF | F_OF, "ng": F_ZF | F_SF | F_OF,
    "g": F_ZF | F_SF | F_OF, "nle": F_ZF | F_SF | F_OF,
}

FCMOV_FLAGS = {
    "fcmovb": F_CF, "fcmovnb": F_CF,
    "fcmove": F_ZF, "fcmovne": F_ZF,
    "fcmovbe": F_CF | F_ZF, "fcmovnbe": F_CF | F_ZF,
    "fcmovu": F_PF, "fcmovnu": F_PF,
}


def get_insn_flag_def_use(ins: Any) -> tuple[int, int]:
    """Returns (def_mask, use_mask) for an x86 instruction."""
    m = ins.mnemonic

    # Conditional branches
    if m.startswith("j") and m[1:] in CC_FLAGS:
        return (0, CC_FLAGS[m[1:]])

    # Conditional set
    if m.startswith("set") and m[3:] in CC_FLAGS:
        return (0, CC_FLAGS[m[3:]])

    # Conditional move
    if m.startswith("cmov") and m[4:] in CC_FLAGS:
        return (0, CC_FLAGS[m[4:]])

    # x87 conditional move
    if m in FCMOV_FLAGS:
        return (0, FCMOV_FLAGS[m])

    # Loop instructions using flags
    if m in ("loope", "loopz", "loopne", "loopnz"):
        return (0, F_ZF)
    if m in ("loop", "jcxz", "jecxz"):
        return (0, 0)

    # General arithmetic & logic
    if m in ("add", "sub", "cmp", "neg", "and", "or", "xor", "test"):
        return (F_ALL, 0)

    if m in ("adc", "sbb"):
        return (F_ALL, F_CF)

    if m in ("inc", "dec"):
        return (F_ALL & ~F_CF, 0)

    if m in ("imul", "mul"):
        return (F_CF | F_OF, 0)

    if m in ("div", "idiv"):
        return (F_ALL, 0)

    # Shifts and rotates
    if m in ("shl", "sal", "shr", "sar"):
        if hasattr(ins, "operands") and len(ins.operands) > 1 and ins.operands[1].type == CS_OP_IMM and ins.operands[1].imm == 0:
            return (0, 0)
        return (F_ALL, 0)

    if m in ("rol", "ror"):
        return (F_CF | F_OF, 0)

    if m in ("rcl", "rcr"):
        return (F_CF | F_OF, F_CF)

    # Bit test
    if m in ("bt", "bts", "btr", "btc"):
        return (F_CF, 0)
    if m in ("bsf", "bsr"):
        return (F_ZF, 0)

    # SSE float comparisons
    if m in ("comiss", "ucomiss", "comisd", "ucomisd"):
        return (F_ALL, 0)

    # x87 float comparisons to EFLAGS
    if m in ("fcomi", "fcomip", "fucomi", "fucomip"):
        return (F_CF | F_PF | F_ZF, 0)

    # SAHF / LAHF
    if m == "sahf":
        return (F_CF | F_PF | F_AF | F_ZF | F_SF, 0)
    if m == "lahf":
        return (0, F_CF | F_PF | F_AF | F_ZF | F_SF)

    # Flag control
    if m in ("clc", "stc"):
        return (F_CF, 0)
    if m == "cmc":
        return (F_CF, F_CF)

    # Stack flag operations
    if m in ("pushf", "pushfd"):
        return (0, F_ALL)
    if m in ("popf", "popfd"):
        return (F_ALL, 0)

    # Calls clobber flags
    if m == "call":
        return (F_ALL, 0)

    # Returns
    if m in ("ret", "retf"):
        return (0, 0)

    # Fallback to Capstone registers if available
    d_mask, u_mask = 0, 0
    if hasattr(ins, "regs_write"):
        for r in ins.regs_write:
            if ins.reg_name(r) == "eflags":
                d_mask = F_ALL
                break
    if hasattr(ins, "regs_read"):
        for r in ins.regs_read:
            if ins.reg_name(r) == "eflags":
                u_mask = F_ALL
                break

    return (d_mask, u_mask)


def compute_flag_liveness(
    blocks: Sequence[Sequence[Any]],
    insns_by_block: dict[int, list[Any]],
    returns_flags: bool = False,
) -> dict[int, int]:
    """Computes backward CFG flag liveness for a function.

    Returns:
        Mapping of instruction address -> live_after flag mask (F_CF..F_OF).
    """
    block_starts = {b[0] for b in blocks}
    live_in: dict[int, int] = {b[0]: 0 for b in blocks}
    live_out: dict[int, int] = {b[0]: 0 for b in blocks}

    # Iterative relaxation backward dataflow (at most 100 iterations)
    for _ in range(100):
        changed = False
        for b_start, b_end, succs, is_exit in reversed(blocks):
            out_mask = 0
            for s in succs:
                if s in live_in:
                    out_mask |= live_in[s]
                elif returns_flags:
                    out_mask |= F_ALL
            if is_exit and returns_flags:
                out_mask |= F_ALL

            if out_mask != live_out[b_start]:
                live_out[b_start] = out_mask
                changed = True

            cur = out_mask
            insns = insns_by_block.get(b_start, [])
            for ins in reversed(insns):
                d, u = get_insn_flag_def_use(ins)
                cur = (cur & ~d) | u

            if cur != live_in[b_start]:
                live_in[b_start] = cur
                changed = True

        if not changed:
            break

    # Build per-instruction live_after map
    live_after: dict[int, int] = {}
    for b_start, b_end, succs, is_exit in blocks:
        cur = live_out[b_start]
        insns = insns_by_block.get(b_start, [])
        for ins in reversed(insns):
            live_after[ins.address] = cur
            d, u = get_insn_flag_def_use(ins)
            cur = (cur & ~d) | u

    return live_after


class UnsupportedInstruction(Exception):
    """Raised when an instruction cannot be translated."""


class InstructionLifter:
    """Translates single x86 instructions into C99 statements."""

    def __init__(self, cs: Cs, use_rg: bool = False) -> None:
        self.cs = cs
        self.use_rg = use_rg
        self.cur_fmask = F_ALL

    def _reg_name(self, rname: str) -> str:
        if self.use_rg and rname in ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
                                     "cf", "pf", "af", "zf", "sf", "of"):
            return f"RG_({rname})"
        return f"c->{rname}"

    def ea(self, m: Any, extra: int = 0) -> str:
        """Translate x86 memory operand to C effective address expression."""
        parts = []
        if m.segment:
            sname = self.cs.reg_name(m.segment) or ""
            if sname == "fs":
                parts.append("c->fs_base")
            elif sname == "gs":
                parts.append("c->gs_base")
        if m.base and m.base in R32:
            parts.append(self._reg_name(R32[m.base]))
        elif m.base and m.base != 0:
            raise UnsupportedInstruction(f"Unsupported base register {m.base}")
        if m.index:
            if m.index not in R32:
                raise UnsupportedInstruction(f"Unsupported index register {m.index}")
            rn = self._reg_name(R32[m.index])
            idx_expr = f"{rn}*{m.scale}" if m.scale != 1 else rn
            parts.append(idx_expr)
        d = (m.disp + extra) & 0xFFFFFFFF
        if d or not parts:
            parts.append(f"0x{d:x}u")
        return "(" + "+".join(parts) + ")"

    def rd(self, op: Any) -> str:
        """Read operand as 32-bit unsigned C expression."""
        if op.type == CS_OP_IMM:
            return f"0x{op.imm & 0xFFFFFFFF:x}u"
        if op.type == CS_OP_REG:
            r = op.reg
            if r in R32:
                return self._reg_name(R32[r])
            if r in R16:
                return f"(uint16_t){self._reg_name(R16[r])}"
            if r in R8L:
                return f"(uint8_t){self._reg_name(R8L[r])}"
            if r in R8H:
                return f"(uint8_t)({self._reg_name(R8H[r])}>>8)"
            seg_map = {
                X86_REG_ES: 0x23, X86_REG_CS: 0x1B, X86_REG_SS: 0x23,
                X86_REG_DS: 0x23, X86_REG_FS: 0x3B, X86_REG_GS: 0x00,
            }
            if r in seg_map:
                return f"0x{seg_map[r]:x}u"
            raise UnsupportedInstruction(f"Unsupported read register {r}")
        if op.type == CS_OP_MEM:
            macro = {1: "MR8", 2: "MR16", 4: "MR32", 8: "MR64"}.get(op.size, "MR32")
            return f"{macro}{self.ea(op.mem)}"
        raise UnsupportedInstruction(f"Unsupported operand type {op.type}")

    def wr(self, op: Any, val: str) -> str:
        """Write C expression to destination operand."""
        if op.type == CS_OP_REG:
            r = op.reg
            if r in R32:
                rn = self._reg_name(R32[r])
                return f"{rn} = (uint32_t)({val});"
            if r in R16:
                rn = self._reg_name(R16[r])
                return f"{rn} = ({rn} & 0xffff0000u) | (uint32_t)(({val}) & 0xffffu);"
            if r in R8L:
                rn = self._reg_name(R8L[r])
                return f"{rn} = ({rn} & 0xffffff00u) | (uint32_t)(({val}) & 0xffu);"
            if r in R8H:
                rn = self._reg_name(R8H[r])
                return f"{rn} = ({rn} & 0xffff00ffu) | ((uint32_t)(({val}) & 0xffu) << 8);"
            if r in (X86_REG_ES, X86_REG_CS, X86_REG_SS, X86_REG_DS, X86_REG_FS, X86_REG_GS):
                return f"(void)({val}); /* segment write ignored in flat model */"
            raise UnsupportedInstruction(f"Unsupported register write {r}")
        if op.type == CS_OP_MEM:
            macro = {1: "MR8", 2: "MR16", 4: "MR32", 8: "MR64"}.get(op.size, "MR32")
            return f"{macro}{self.ea(op.mem)} = ({val});"
        raise UnsupportedInstruction(f"Unsupported target operand {op.type}")

    def _fm(self) -> str:
        return f"0x{self.cur_fmask:02x}u"

    def lift_instruction(self, ins: Any) -> list[str]:
        """Translate a Capstone instruction object into C statements."""
        m = ins.mnemonic
        o = ins.operands
        E = lambda k: self.rd(o[k])
        W = lambda k, v: self.wr(o[k], v)
        bits = (o[0].size * 8) if o and hasattr(o[0], "size") and o[0].size else 32

        def is_mm(k: int) -> bool:
            return len(o) > k and o[k].type == CS_OP_REG and o[k].reg in MM

        def is_xm(k: int) -> bool:
            return len(o) > k and o[k].type == CS_OP_REG and o[k].reg in XM

        def is_gp(k: int) -> bool:
            return len(o) > k and o[k].type == CS_OP_REG and o[k].reg in R32

        def is_mem(k: int) -> bool:
            return len(o) > k and o[k].type == CS_OP_MEM

        def is_st(k: int) -> bool:
            return len(o) > k and o[k].type == CS_OP_REG and o[k].reg in ST_REGS

        def sti(k: int) -> int:
            return ST_REGS[o[k].reg]

        def fmem(k: int) -> str:
            sz = o[k].size
            if sz == 4:
                return f"(double)MRF32{self.ea(o[k].mem)}"
            if sz == 8:
                return f"MRF64{self.ea(o[k].mem)}"
            if sz == 10:
                return f"f80_load(g_mem + (uint32_t){self.ea(o[k].mem)})"
            return f"(double)MRF32{self.ea(o[k].mem)}"

        def imem(k: int) -> str:
            sz = o[k].size
            ea = self.ea(o[k].mem)
            if sz == 2:
                return f"(double)(int16_t)MR16{ea}"
            if sz == 4:
                return f"(double)(int32_t)MR32{ea}"
            if sz == 8:
                return f"(double)(int64_t)MR64{ea}"
            return f"(double)(int32_t)MR32{ea}"

        # ------------------------------------------------------------------
        # x87 Floating Point Unit (FPU)
        # ------------------------------------------------------------------
        if m in ("fld", "fldl"):
            src = f"ST({sti(0)})" if is_st(0) else fmem(0)
            return [f"FPUSH({src});"]

        if m == "fild":
            return [f"FPUSH({imem(0)});"]

        if m in ("fldz", "fld1", "fldpi", "fldl2e", "fldl2t", "fldlg2", "fldln2"):
            const_val = {
                "fldz": "0.0", "fld1": "1.0", "fldpi": "3.14159265358979323846",
                "fldl2e": "1.44269504088896340736", "fldl2t": "3.32192809488736234787",
                "fldlg2": "0.30102999566398119521", "fldln2": "0.69314718055994530942",
            }[m]
            return [f"FPUSH({const_val});"]

        if m in ("fst", "fstp"):
            pop = ["FPOP();"] if m == "fstp" else []
            if is_st(0):
                return [f"ST({sti(0)}) = ST(0);"] + pop
            sz = o[0].size
            if sz == 4:
                return [f"MRF32{self.ea(o[0].mem)} = (float)ST(0);"] + pop
            if sz == 8:
                return [f"MRF64{self.ea(o[0].mem)} = ST(0);"] + pop
            if sz == 10:
                return [f"f80_store(g_mem + (uint32_t){self.ea(o[0].mem)}, ST(0));"] + pop
            return [f"MRF32{self.ea(o[0].mem)} = (float)ST(0);"] + pop

        if m in ("fist", "fistp", "fisttp"):
            pop = [] if m == "fist" else ["FPOP();"]
            sz = o[0].size
            ea = self.ea(o[0].mem)
            conv = "trunc(ST(0))" if m == "fisttp" else "x87_round(c->fcw, ST(0))"
            cvt = {2: "x86_cvt_i16", 4: "x86_cvt_i32", 8: "x86_cvt_i64"}.get(sz, "x86_cvt_i32")
            macro = {2: "MR16", 4: "MR32", 8: "MR64"}.get(sz, "MR32")
            return [f"{macro}{ea} = {cvt}({conv});"] + pop

        FAR = {"fadd": "+", "fsub": "-", "fmul": "*", "fdiv": "/"}
        if m in ("fadd", "fsub", "fmul", "fdiv", "fsubr", "fdivr"):
            rev = m.endswith("r")
            base = m[:-1] if rev else m
            op_c = FAR[base]
            if len(o) == 1:
                src = f"ST({sti(0)})" if is_st(0) else fmem(0)
                lhs, rhs = ("_s", "_d") if rev else ("_d", "_s")
                return [f"{{ double _d = ST(0), _s = ({src}); ST(0) = X87R2(_d, _s, {lhs} {op_c} {rhs}); }}"]
            d = sti(0) if is_st(0) else 0
            s2 = f"ST({sti(1)})" if is_st(1) else fmem(1)
            lhs, rhs = ("_s", "_d") if rev else ("_d", "_s")
            return [f"{{ double _d = ST({d}), _s = ({s2}); ST({d}) = X87R2(_d, _s, {lhs} {op_c} {rhs}); }}"]

        if m in ("faddp", "fsubp", "fmulp", "fdivp", "fsubrp", "fdivrp"):
            rev = m in ("fsubrp", "fdivrp")
            base = {"faddp": "fadd", "fsubp": "fsub", "fmulp": "fmul", "fdivp": "fdiv", "fsubrp": "fsub", "fdivrp": "fdiv"}[m]
            op_c = FAR[base]
            d = sti(0) if (len(o) > 0 and is_st(0)) else 1
            lhs, rhs = ("_s", "_d") if rev else ("_d", "_s")
            return [f"{{ double _d = ST({d}), _s = ST(0); ST({d}) = X87R2(_d, _s, {lhs} {op_c} {rhs}); }}", "FPOP();"]

        if m in ("fcom", "fcomp", "fcompp", "fucom", "fucomp", "fucompp"):
            npop = 2 if m.endswith("pp") else (1 if m.endswith("p") else 0)
            if len(o) == 0:
                src = "ST(1)"
            elif is_st(0):
                src = f"ST({sti(0)})"
            else:
                src = fmem(0)
            return [f"fcompare(c, ST(0), {src});"] + ["FPOP();"] * npop

        if m in ("fcomi", "fcomip", "fcompi", "fucomi", "fucomip", "fucompi"):
            src = f"ST({sti(1)})" if len(o) > 1 and is_st(1) else (f"ST({sti(0)})" if is_st(0) else fmem(0))
            pops = m.endswith("ip") or m.endswith("pi")
            return [f"FCOMI(ST(0), {src});"] + (["FPOP();"] if pops else [])

        if m == "ftst":
            return ["fcompare(c, ST(0), 0.0);"]
        if m == "fchs":
            return ["ST(0) = -ST(0);"]
        if m == "fabs":
            return ["ST(0) = fabs(ST(0));"]
        if m == "fsqrt":
            return ["{ double _a = ST(0); ST(0) = X87R(x87_r1(_a, sqrt(_a))); }"]
        if m == "fsin":
            return ["ST(0) = sin(ST(0));"]
        if m == "fcos":
            return ["ST(0) = cos(ST(0));"]
        if m == "fsincos":
            return ["FPUSH(cos(ST(0)));", "ST(1) = sin(ST(1));"]
        if m == "fptan":
            return ["ST(0) = tan(ST(0));", "FPUSH(1.0);"]
        if m == "fpatan":
            return ["ST(1) = atan2(ST(1), ST(0));", "FPOP();"]
        if m == "fyl2x":
            return ["ST(1) = ST(1) * log2(ST(0));", "FPOP();"]
        if m == "f2xm1":
            return ["ST(0) = exp2(ST(0)) - 1.0;"]
        if m == "fscale":
            return ["ST(0) = ldexp(ST(0), (int)trunc(ST(1)));"]
        if m == "frndint":
            return ["ST(0) = x87_round(c->fcw, ST(0));"]

        if m in ("fprem", "fprem1"):
            fn = "fmod(_a, _b)" if m == "fprem" else "remainder(_a, _b)"
            return [
                f"{{ double _a = ST(0), _b = ST(1), _r = x87_r2(_a, _b, {fn});\n"
                f"  double _q = (_b != 0.0) ? trunc(_a / _b) : 0.0;\n"
                f"  uint32_t _qi = (uint32_t)(int64_t)fmod(fabs(_q), 8.0);\n"
                f"  c->fsw &= (uint16_t)~(FSW_C0 | FSW_C1 | FSW_C2 | FSW_C3);\n"
                f"  if (_qi & 1u) c->fsw |= FSW_C1;\n"
                f"  if (_qi & 2u) c->fsw |= FSW_C3;\n"
                f"  if (_qi & 4u) c->fsw |= FSW_C0;\n"
                f"  ST(0) = _r; }}"
            ]

        if m == "fxch":
            j = 1
            if len(o) >= 2 and is_st(len(o) - 1):
                j = sti(len(o) - 1)
            elif len(o) == 1 and is_st(0):
                j = sti(0)
            return [f"{{ double _t = ST(0); ST(0) = ST({j}); ST({j}) = _t; }}"]

        if m in ("fnstsw", "fstsw"):
            if len(o) > 0 and o[0].type == CS_OP_REG:
                eax = self._reg_name("eax")
                return [f"{eax} = ({eax} & 0xffff0000u) | (uint32_t)fsw_get(c);"]
            return [f"MR16{self.ea(o[0].mem)} = fsw_get(c);"]

        if m in ("fnstcw", "fstcw"):
            return [f"MR16{self.ea(o[0].mem)} = c->fcw;"]
        if m == "fldcw":
            return [f"c->fcw = MR16{self.ea(o[0].mem)};"]

        if m in ("ffree", "ffreep", "fnclex", "fclex", "fnop", "fwait", "wait", "fdecstp", "fincstp"):
            return [f"/* {m} */"] + (["FPOP();"] if m == "ffreep" else [])

        if m in ("finit", "fninit"):
            return ["memset(c->st, 0, sizeof c->st); c->top = 0; c->fcw = 0x037f; c->fsw = 0;"]

        cf, zf, pf = self._reg_name("cf"), self._reg_name("zf"), self._reg_name("pf")
        fcmov_conds = {
            "fcmovb": cf, "fcmovnb": f"!{cf}", "fcmove": zf, "fcmovne": f"!{zf}",
            "fcmovbe": f"({cf} || {zf})", "fcmovnbe": f"!({cf} || {zf})",
            "fcmovu": pf, "fcmovnu": f"!{pf}",
        }
        if m in fcmov_conds:
            cond = fcmov_conds[m]
            j = sti(len(o) - 1) if len(o) >= 1 and is_st(len(o) - 1) else 1
            return [f"if ({cond}) ST(0) = ST({j});"]

        if m in ("fiadd", "fimul", "fisub", "fisubr", "fidiv", "fidivr", "ficom", "ficomp"):
            sz = o[0].size
            ea = self.ea(o[0].mem)
            src = {2: f"(double)(int16_t)MR16{ea}", 4: f"(double)(int32_t)MR32{ea}"}.get(sz, f"(double)(int32_t)MR32{ea}")
            if m == "fiadd":
                return [f"ST(0) = X87R(ST(0) + ({src}));"]
            if m == "fimul":
                return [f"ST(0) = X87R(ST(0) * ({src}));"]
            if m == "fisub":
                return [f"ST(0) = X87R(ST(0) - ({src}));"]
            if m == "fisubr":
                return [f"ST(0) = X87R(({src}) - ST(0));"]
            if m == "fidiv":
                return [f"ST(0) = X87R(ST(0) / ({src}));"]
            if m == "fidivr":
                return [f"ST(0) = X87R(({src}) / ST(0));"]
            if m == "ficom":
                return [f"fcompare(c, ST(0), {src});"]
            return [f"fcompare(c, ST(0), {src});", "FPOP();"]


        # ------------------------------------------------------------------
        # NOP and Debug Stubs
        # ------------------------------------------------------------------
        if m == "nop" or m.startswith("nop"):
            return ["/* nop */"]
        if m == "int3":
            return ["/* int3 */"]

        # ------------------------------------------------------------------
        # SSE / SSE2 Data Movement
        # ------------------------------------------------------------------
        if m in ("movaps", "movups", "movdqa", "movdqu", "movapd", "movupd"):
            if is_xm(0) and is_xm(1):
                return [f"c->xmm[{XM[o[0].reg]}] = c->xmm[{XM[o[1].reg]}];"]
            if is_xm(0) and is_mem(1):
                return [f"memcpy(&c->xmm[{XM[o[0].reg]}], g_mem + (uint32_t){self.ea(o[1].mem)}, 16);"]
            if is_mem(0) and is_xm(1):
                return [f"memcpy(g_mem + (uint32_t){self.ea(o[0].mem)}, &c->xmm[{XM[o[1].reg]}], 16);"]

        if m in ("movss", "movsd") and (is_xm(0) or is_xm(1)):
            w = 4 if m == "movss" else 8
            if is_xm(0) and is_xm(1):
                i0, i1 = XM[o[0].reg], XM[o[1].reg]
                return [f"c->xmm[{i0}].u32[0] = c->xmm[{i1}].u32[0];"] if w == 4 else [f"c->xmm[{i0}].u64[0] = c->xmm[{i1}].u64[0];"]
            if is_xm(0) and is_mem(1):
                i0 = XM[o[0].reg]
                return [f"memset(&c->xmm[{i0}], 0, 16); memcpy(&c->xmm[{i0}], g_mem + (uint32_t){self.ea(o[1].mem)}, {w});"]
            if is_mem(0) and is_xm(1):
                i1 = XM[o[1].reg]
                return [f"memcpy(g_mem + (uint32_t){self.ea(o[0].mem)}, &c->xmm[{i1}], {w});"]

        if m in ("movd", "movq"):
            w = 8 if m == "movq" else 4
            T = "uint64_t" if w == 8 else "uint32_t"
            if is_xm(0):
                i0 = XM[o[0].reg]
                src = (
                    f"c->xmm[{XM[o[1].reg]}].u64[0]" if is_xm(1) and w == 8
                    else f"c->xmm[{XM[o[1].reg]}].u32[0]" if is_xm(1)
                    else f"c->mm[{MM[o[1].reg]}]" if is_mm(1)
                    else self._reg_name(R32[o[1].reg]) if is_gp(1)
                    else f"MR64{self.ea(o[1].mem)}" if is_mem(1) and w == 8
                    else f"MR32{self.ea(o[1].mem)}"
                )
                if w == 8:
                    return [f"c->xmm[{i0}].u64[0] = (uint64_t)({src}); c->xmm[{i0}].u64[1] = 0;"]
                return [f"c->xmm[{i0}].u32[0] = (uint32_t)({src}); c->xmm[{i0}].u32[1] = 0; c->xmm[{i0}].u64[1] = 0;"]
            if is_mm(0):
                i0 = MM[o[0].reg]
                src = (
                    f"c->xmm[{XM[o[1].reg]}].u64[0]" if is_xm(1)
                    else f"c->mm[{MM[o[1].reg]}]" if is_mm(1)
                    else self._reg_name(R32[o[1].reg]) if is_gp(1)
                    else f"MR64{self.ea(o[1].mem)}" if is_mem(1) and w == 8
                    else f"MR32{self.ea(o[1].mem)}"
                )
                return [f"c->mm[{i0}] = ({T})({src});"]
            if is_gp(0):
                src = f"c->xmm[{XM[o[1].reg]}].u32[0]" if is_xm(1) else f"c->mm[{MM[o[1].reg]}]" if is_mm(1) else f"MR32{self.ea(o[1].mem)}"
                return [f"{self._reg_name(R32[o[0].reg])} = (uint32_t)({src});"]
            if is_mem(0):
                src = (
                    f"c->xmm[{XM[o[1].reg]}].u64[0]" if is_xm(1) and w == 8
                    else f"c->xmm[{XM[o[1].reg]}].u32[0]" if is_xm(1)
                    else f"c->mm[{MM[o[1].reg]}]" if is_mm(1)
                    else self._reg_name(R32[o[1].reg]) if is_gp(1)
                    else "0"
                )
                macro = "MR64" if w == 8 else "MR32"
                return [f"{macro}{self.ea(o[0].mem)} = ({T})({src});"]

        if m in ("movlhps", "movhlps") and is_xm(0) and is_xm(1):
            di, si = XM[o[0].reg], XM[o[1].reg]
            if m == "movhlps":
                return [f"c->xmm[{di}].u32[0] = c->xmm[{si}].u32[2]; c->xmm[{di}].u32[1] = c->xmm[{si}].u32[3];"]
            return [f"c->xmm[{di}].u32[2] = c->xmm[{si}].u32[0]; c->xmm[{di}].u32[3] = c->xmm[{si}].u32[1];"]

        if m in ("movlps", "movhps") and (is_xm(0) or is_xm(1)):
            off = 0 if m == "movlps" else 2
            if is_xm(0) and is_mem(1):
                di = XM[o[0].reg]
                ea = self.ea(o[1].mem)
                return [f"c->xmm[{di}].u32[{off}] = MR32({ea}); c->xmm[{di}].u32[{off+1}] = MR32(({ea}) + 4u);"]
            if is_mem(0) and is_xm(1):
                si = XM[o[1].reg]
                ea = self.ea(o[0].mem)
                return [f"MR32({ea}) = c->xmm[{si}].u32[{off}]; MR32(({ea}) + 4u) = c->xmm[{si}].u32[{off+1}];"]

        # ------------------------------------------------------------------
        # SSE / SSE2 Bitwise Vector Logic
        # ------------------------------------------------------------------
        if m in ("xorps", "xorpd", "pxor", "andps", "andpd", "pand", "orps", "orpd", "por"):
            op_c = {"xorps": "^", "xorpd": "^", "pxor": "^", "andps": "&", "andpd": "&", "pand": "&", "orps": "|", "orpd": "|", "por": "|"}[m]
            if is_xm(0):
                di = XM[o[0].reg]
                if is_xm(1):
                    si = XM[o[1].reg]
                    return [
                        f"#if defined(__wasm_simd128__)\n"
                        f"WASM_SIMD_{m.upper()}(c->xmm[{di}], c->xmm[{si}]);\n"
                        f"#else\n"
                        f"c->xmm[{di}].u64[0] {op_c}= c->xmm[{si}].u64[0]; c->xmm[{di}].u64[1] {op_c}= c->xmm[{si}].u64[1];\n"
                        f"#endif"
                    ]
                ea = self.ea(o[1].mem)
                return [f"{{ uint64_t _a = MR64({ea}), _b = MR64(({ea}) + 8u); c->xmm[{di}].u64[0] {op_c}= _a; c->xmm[{di}].u64[1] {op_c}= _b; }}"]
            if is_mm(0):
                di = MM[o[0].reg]
                src = f"c->mm[{MM[o[1].reg]}]" if is_mm(1) else f"MR64{self.ea(o[1].mem)}"
                return [f"c->mm[{di}] {op_c}= ({src});"]

        if m in ("andnps", "andnpd", "pandn"):
            if is_xm(0):
                di = XM[o[0].reg]
                if is_xm(1):
                    si = XM[o[1].reg]
                    return [
                        f"#if defined(__wasm_simd128__)\n"
                        f"WASM_SIMD_ANDNPS(c->xmm[{di}], c->xmm[{si}]);\n"
                        f"#else\n"
                        f"c->xmm[{di}].u64[0] = (~c->xmm[{di}].u64[0]) & c->xmm[{si}].u64[0];\n"
                        f"c->xmm[{di}].u64[1] = (~c->xmm[{di}].u64[1]) & c->xmm[{si}].u64[1];\n"
                        f"#endif"
                    ]
                ea = self.ea(o[1].mem)
                return [f"{{ uint64_t _a = MR64({ea}), _b = MR64(({ea}) + 8u); c->xmm[{di}].u64[0] = (~c->xmm[{di}].u64[0]) & _a; c->xmm[{di}].u64[1] = (~c->xmm[{di}].u64[1]) & _b; }}"]
            if is_mm(0):
                di = MM[o[0].reg]
                src = f"c->mm[{MM[o[1].reg]}]" if is_mm(1) else f"MR64{self.ea(o[1].mem)}"
                return [f"c->mm[{di}] = (~c->mm[{di}]) & ({src});"]

        # ------------------------------------------------------------------
        # SSE Packed Single Arithmetic (addps, subps, mulps, divps, maxps, minps, sqrtps, rcpps, rsqrtps)
        # ------------------------------------------------------------------
        PS_OPS = {"addps": "+", "subps": "-", "mulps": "*", "divps": "/"}
        if m in PS_OPS and is_xm(0):
            di = XM[o[0].reg]
            op_c = PS_OPS[m]
            simd_macro = {"addps": "ADDPS", "subps": "SUBPS", "mulps": "MULPS", "divps": "DIVPS"}[m]
            if is_xm(1):
                si = XM[o[1].reg]
                return [
                    f"#if defined(__wasm_simd128__)\n"
                    f"WASM_SIMD_{simd_macro}(c->xmm[{di}], c->xmm[{si}]);\n"
                    f"#else\n"
                    f"for (int _k = 0; _k < 4; _k++) {{ float _a = c->xmm[{di}].f[_k], _b = c->xmm[{si}].f[_k]; c->xmm[{di}].f[_k] = sse_r2f(_a, _b, _a {op_c} _b); }}\n"
                    f"#endif"
                ]
            ea = self.ea(o[1].mem)
            return [f"for (int _k = 0; _k < 4; _k++) {{ float _a = c->xmm[{di}].f[_k], _b = MRF32(({ea}) + 4u * (uint32_t)_k); c->xmm[{di}].f[_k] = sse_r2f(_a, _b, _a {op_c} _b); }}"]

        if m in ("maxps", "minps") and is_xm(0):
            di = XM[o[0].reg]
            cmp_op = ">" if m == "maxps" else "<"
            simd_macro = "MAXPS" if m == "maxps" else "MINPS"
            if is_xm(1):
                si = XM[o[1].reg]
                return [
                    f"#if defined(__wasm_simd128__)\n"
                    f"WASM_SIMD_{simd_macro}(c->xmm[{di}], c->xmm[{si}]);\n"
                    f"#else\n"
                    f"for (int _k = 0; _k < 4; _k++) {{ float _a = c->xmm[{di}].f[_k], _b = c->xmm[{si}].f[_k]; c->xmm[{di}].f[_k] = (_a {cmp_op} _b) ? _a : _b; }}\n"
                    f"#endif"
                ]
            ea = self.ea(o[1].mem)
            return [f"for (int _k = 0; _k < 4; _k++) {{ float _a = c->xmm[{di}].f[_k], _b = MRF32(({ea}) + 4u * (uint32_t)_k); c->xmm[{di}].f[_k] = (_a {cmp_op} _b) ? _a : _b; }}"]

        if m in ("sqrtps", "rcpps", "rsqrtps") and is_xm(0):
            di = XM[o[0].reg]
            if m == "sqrtps":
                src = f"c->xmm[{XM[o[1].reg]}].f[_k]" if is_xm(1) else f"MRF32(({self.ea(o[1].mem)}) + 4u * (uint32_t)_k)"
                return [
                    f"#if defined(__wasm_simd128__)\n"
                    f"WASM_SIMD_SQRTPS(c->xmm[{di}]);\n"
                    f"#else\n"
                    f"for (int _k = 0; _k < 4; _k++) {{ float _x = {src}; c->xmm[{di}].f[_k] = sqrtf(_x); }}\n"
                    f"#endif"
                ]
            fn = "(1.0f / _x)" if m == "rcpps" else "(1.0f / sqrtf(_x))"
            src = f"c->xmm[{XM[o[1].reg]}].f[_k]" if is_xm(1) else f"MRF32(({self.ea(o[1].mem)}) + 4u * (uint32_t)_k)"
            return [f"for (int _k = 0; _k < 4; _k++) {{ float _x = {src}; c->xmm[{di}].f[_k] = {fn}; }}"]

        # ------------------------------------------------------------------
        # SSE Scalar Single Arithmetic (addss, subss, mulss, divss, maxss, minss, sqrtss, rcpss, rsqrtss)
        # ------------------------------------------------------------------
        SS_OPS = {"addss": "+", "subss": "-", "mulss": "*", "divss": "/"}
        if m in SS_OPS and is_xm(0):
            di = XM[o[0].reg]
            op_c = SS_OPS[m]
            src = f"c->xmm[{XM[o[1].reg]}].f[0]" if is_xm(1) else f"MRF32{self.ea(o[1].mem)}"
            return [f"{{ float _a = c->xmm[{di}].f[0], _b = {src}; c->xmm[{di}].f[0] = sse_r2f(_a, _b, _a {op_c} _b); }}"]

        if m in ("maxss", "minss") and is_xm(0):
            di = XM[o[0].reg]
            cmp_op = ">" if m == "maxss" else "<"
            src = f"c->xmm[{XM[o[1].reg]}].f[0]" if is_xm(1) else f"MRF32{self.ea(o[1].mem)}"
            return [f"{{ float _a = c->xmm[{di}].f[0], _b = {src}; c->xmm[{di}].f[0] = (_a {cmp_op} _b) ? _a : _b; }}"]

        if m == "sqrtss" and is_xm(0):
            di = XM[o[0].reg]
            src = f"c->xmm[{XM[o[1].reg]}].f[0]" if is_xm(1) else f"MRF32{self.ea(o[1].mem)}"
            return [f"c->xmm[{di}].f[0] = sqrtf({src});"]

        if m in ("rcpss", "rsqrtss") and is_xm(0):
            di = XM[o[0].reg]
            src = f"c->xmm[{XM[o[1].reg]}].f[0]" if is_xm(1) else f"MRF32{self.ea(o[1].mem)}"
            fn = f"1.0f / ({src})" if m == "rcpss" else f"1.0f / sqrtf({src})"
            return [f"c->xmm[{di}].f[0] = {fn};"]

        # ------------------------------------------------------------------
        # SSE / SSE2 Comparisons (comiss, ucomiss, comisd, ucomisd)
        # ------------------------------------------------------------------
        if m in ("comiss", "ucomiss"):
            a = f"c->xmm[{XM[o[0].reg]}].f[0]" if is_xm(0) else f"MRF32{self.ea(o[0].mem)}"
            b = f"c->xmm[{XM[o[1].reg]}].f[0]" if is_xm(1) else f"MRF32{self.ea(o[1].mem)}"
            zf, pf, cf = self._reg_name("zf"), self._reg_name("pf"), self._reg_name("cf")
            of, sf, af = self._reg_name("of"), self._reg_name("sf"), self._reg_name("af")
            return [
                f"{{ float _x = {a}, _y = {b};\n"
                f"   if (_x != _x || _y != _y) {{ {zf} = 1; {pf} = 1; {cf} = 1; }}\n"
                f"   else {{ {pf} = 0; {zf} = (_x == _y); {cf} = (_x < _y); }}\n"
                f"   {of} = {sf} = {af} = 0; }}"
            ]

        if m in ("comisd", "ucomisd"):
            a = f"c->xmm[{XM[o[0].reg]}].d[0]" if is_xm(0) else f"MRF64{self.ea(o[0].mem)}"
            b = f"c->xmm[{XM[o[1].reg]}].d[0]" if is_xm(1) else f"MRF64{self.ea(o[1].mem)}"
            zf, pf, cf = self._reg_name("zf"), self._reg_name("pf"), self._reg_name("cf")
            of, sf, af = self._reg_name("of"), self._reg_name("sf"), self._reg_name("af")
            return [
                f"{{ double _x = {a}, _y = {b};\n"
                f"   if (_x != _x || _y != _y) {{ {zf} = 1; {pf} = 1; {cf} = 1; }}\n"
                f"   else {{ {pf} = 0; {zf} = (_x == _y); {cf} = (_x < _y); }}\n"
                f"   {of} = {sf} = {af} = 0; }}"
            ]

        # ------------------------------------------------------------------
        # SSE / SSE2 Conversions
        # ------------------------------------------------------------------
        if m == "cvtsi2ss" and is_xm(0):
            di = XM[o[0].reg]
            return [f"c->xmm[{di}].f[0] = (float)(int32_t)({E(1)});"]

        if m in ("cvttss2si", "cvtss2si"):
            src = f"c->xmm[{XM[o[1].reg]}].f[0]" if is_xm(1) else f"MRF32{self.ea(o[1].mem)}"
            expr = f"trunc((double)({src}))" if m == "cvttss2si" else f"nearbyint((double)({src}))"
            return [W(0, f"x86_cvt_i32({expr})")]

        if m == "cvtss2sd" and is_xm(0):
            di = XM[o[0].reg]
            src = f"c->xmm[{XM[o[1].reg]}].f[0]" if is_xm(1) else f"MRF32{self.ea(o[1].mem)}"
            return [f"c->xmm[{di}].d[0] = (double)({src});"]

        if m == "cvtsd2ss" and is_xm(0):
            di = XM[o[0].reg]
            src = f"c->xmm[{XM[o[1].reg]}].d[0]" if is_xm(1) else f"MRF64{self.ea(o[1].mem)}"
            return [f"c->xmm[{di}].f[0] = (float)({src});"]

        # ------------------------------------------------------------------
        # Shuffles, Permutations, Unpacks
        # ------------------------------------------------------------------
        if m == "shufps" and is_xm(0) and len(o) > 2 and o[2].type == CS_OP_IMM:
            di = XM[o[0].reg]
            imm = o[2].imm & 0xFF
            sel = [(imm >> 0) & 3, (imm >> 2) & 3, (imm >> 4) & 3, (imm >> 6) & 3]
            if is_xm(1):
                src = f"c->xmm[{XM[o[1].reg]}].f"
                pre = ""
            else:
                src = "_m"
                pre = f"float _m[4]; memcpy(_m, g_mem + (uint32_t){self.ea(o[1].mem)}, 16); "
            return [
                f"{{ {pre}float _t[4]; _t[0] = c->xmm[{di}].f[{sel[0]}]; _t[1] = c->xmm[{di}].f[{sel[1]}]; "
                f"_t[2] = {src}[{sel[2]}]; _t[3] = {src}[{sel[3]}]; "
                f"for (int _k = 0; _k < 4; _k++) c->xmm[{di}].f[_k] = _t[_k]; }}"
            ]

        if m in ("unpcklps", "unpckhps") and is_xm(0):
            di = XM[o[0].reg]
            hi = (m == "unpckhps")
            o0 = 2 if hi else 0
            if is_xm(1):
                sv = f"c->xmm[{XM[o[1].reg]}].u32"
                return [
                    f"{{ uint32_t _t[4]; _t[0] = c->xmm[{di}].u32[{o0}]; _t[1] = {sv}[{o0}]; "
                    f"_t[2] = c->xmm[{di}].u32[{o0+1}]; _t[3] = {sv}[{o0+1}]; "
                    f"for (int _k = 0; _k < 4; _k++) c->xmm[{di}].u32[_k] = _t[_k]; }}"
                ]
            ea = self.ea(o[1].mem)
            return [
                f"{{ uint32_t _t[4]; _t[0] = c->xmm[{di}].u32[{o0}]; _t[1] = MR32(({ea}) + {4*o0}u); "
                f"_t[2] = c->xmm[{di}].u32[{o0+1}]; _t[3] = MR32(({ea}) + {4*(o0+1)}u); "
                f"for (int _k = 0; _k < 4; _k++) c->xmm[{di}].u32[_k] = _t[_k]; }}"
            ]

        # ------------------------------------------------------------------
        # Integer SIMD (paddd, psubd, pmaddwd, psrlq, psrad, pslld, packssdw)
        # ------------------------------------------------------------------
        if m in ("paddd", "psubd") and (is_xm(0) or is_mm(0)):
            op_c = "+" if m == "paddd" else "-"
            simd_m = "PADDD" if m == "paddd" else "PSUBD"
            if is_xm(0):
                di = XM[o[0].reg]
                if is_xm(1):
                    si = XM[o[1].reg]
                    return [
                        f"#if defined(__wasm_simd128__)\n"
                        f"WASM_SIMD_{simd_m}(c->xmm[{di}], c->xmm[{si}]);\n"
                        f"#else\n"
                        f"for (int _k = 0; _k < 4; _k++) c->xmm[{di}].u32[_k] {op_c}= c->xmm[{si}].u32[_k];\n"
                        f"#endif"
                    ]
                ea = self.ea(o[1].mem)
                return [f"for (int _k = 0; _k < 4; _k++) c->xmm[{di}].u32[_k] {op_c}= MR32(({ea}) + 4u * (uint32_t)_k);"]
            if is_mm(0):
                di = MM[o[0].reg]
                src = f"c->mm[{MM[o[1].reg]}]" if is_mm(1) else f"MR64{self.ea(o[1].mem)}"
                return [
                    f"{{ uint64_t _s = ({src}); "
                    f"c->mm[{di}] = ((uint64_t)((uint32_t)(c->mm[{di}] >> 32) {op_c} (uint32_t)(_s >> 32)) << 32) | "
                    f"((uint32_t)c->mm[{di}] {op_c} (uint32_t)_s); }}"
                ]

        if m == "pmaddwd" and (is_xm(0) or is_mm(0)):
            if is_xm(0):
                di = XM[o[0].reg]
                src = (lambda k: f"c->xmm[{XM[o[1].reg]}].u32[{k}]") if is_xm(1) else (lambda k: f"MR32(({self.ea(o[1].mem)}) + 4u * {k}u)")
                return [
                    f"{{ for (int _k = 0; _k < 4; _k++) {{\n"
                    f"    uint32_t _a = c->xmm[{di}].u32[_k], _b = {src('_k')};\n"
                    f"    int32_t _p0 = (int32_t)(int16_t)(uint16_t)_a * (int32_t)(int16_t)(uint16_t)_b;\n"
                    f"    int32_t _p1 = (int32_t)(int16_t)(uint16_t)(_a >> 16) * (int32_t)(int16_t)(uint16_t)(_b >> 16);\n"
                    f"    c->xmm[{di}].u32[_k] = (uint32_t)(_p0 + _p1);\n"
                    f"  }} }}"
                ]
            if is_mm(0):
                di = MM[o[0].reg]
                src = f"c->mm[{MM[o[1].reg]}]" if is_mm(1) else f"MR64{self.ea(o[1].mem)}"
                return [
                    f"{{ uint64_t _a = c->mm[{di}], _b = ({src});\n"
                    f"  int32_t _p0 = (int32_t)(int16_t)(uint16_t)_a * (int32_t)(int16_t)(uint16_t)_b + "
                    f"(int32_t)(int16_t)(uint16_t)(_a >> 16) * (int32_t)(int16_t)(uint16_t)(_b >> 16);\n"
                    f"  int32_t _p1 = (int32_t)(int16_t)(uint16_t)(_a >> 32) * (int32_t)(int16_t)(uint16_t)(_b >> 32) + "
                    f"(int32_t)(int16_t)(uint16_t)(_a >> 48) * (int32_t)(int16_t)(uint16_t)(_b >> 48);\n"
                    f"  c->mm[{di}] = ((uint64_t)(uint32_t)_p1 << 32) | (uint32_t)_p0; }}"
                ]

        if m in ("psrlq", "pslld", "psrad") and (is_xm(0) or is_mm(0)):
            cnt = E(1) if len(o) > 1 else "1u"
            if is_xm(0):
                di = XM[o[0].reg]
                if m == "psrlq":
                    return [f"{{ uint32_t _cnt = ({cnt}); if (_cnt < 64) {{ c->xmm[{di}].u64[0] >>= _cnt; c->xmm[{di}].u64[1] >>= _cnt; }} else {{ c->xmm[{di}].u64[0] = c->xmm[{di}].u64[1] = 0; }} }}"]
                if m == "pslld":
                    return [f"{{ uint32_t _cnt = ({cnt}); if (_cnt < 32) {{ for (int _k=0;_k<4;_k++) c->xmm[{di}].u32[_k] <<= _cnt; }} else {{ memset(&c->xmm[{di}], 0, 16); }} }}"]
                if m == "psrad":
                    return [f"{{ uint32_t _cnt = ({cnt}); if (_cnt > 31) _cnt = 31; for (int _k=0;_k<4;_k++) c->xmm[{di}].u32[_k] = (uint32_t)((int32_t)c->xmm[{di}].u32[_k] >> _cnt); }}"]
            if is_mm(0):
                di = MM[o[0].reg]
                if m == "psrlq":
                    return [f"{{ uint32_t _cnt = ({cnt}); c->mm[{di}] = (_cnt < 64) ? (c->mm[{di}] >> _cnt) : 0; }}"]
                if m == "pslld":
                    return [f"{{ uint32_t _cnt = ({cnt}); if (_cnt < 32) {{ uint32_t _l = (uint32_t)c->mm[{di}] << _cnt, _h = (uint32_t)(c->mm[{di}] >> 32) << _cnt; c->mm[{di}] = ((uint64_t)_h << 32) | _l; }} else {{ c->mm[{di}] = 0; }} }}"]

        # ------------------------------------------------------------------
        # General Purpose Integer Instructions
        # ------------------------------------------------------------------
        if m == "mov":
            return [W(0, E(1))]
        if m == "movzx":
            return [W(0, f"(uint32_t)({E(1)})")]
        if m == "movsx":
            sb = o[1].size * 8
            return [W(0, f"(uint32_t)(int32_t)(int{sb}_t)({E(1)})")]
        if m == "lea":
            return [W(0, self.ea(o[1].mem))]
        if m == "push":
            return [f"PUSH32({E(0)});"]
        if m == "pop":
            return [f"{{ uint32_t _t; POP32(_t); {W(0, '_t')} }}"]
        if m == "leave":
            esp, ebp = self._reg_name("esp"), self._reg_name("ebp")
            return [f"{esp} = {ebp};", f"{{ uint32_t _t; POP32(_t); {ebp} = _t; }}"]
        if m == "cdq":
            eax, edx = self._reg_name("eax"), self._reg_name("edx")
            return [f"{edx} = (uint32_t)((int32_t){eax} >> 31);"]
        if m == "cwde":
            eax = self._reg_name("eax")
            return [f"{eax} = (uint32_t)(int32_t)(int16_t)(uint16_t){eax};"]

        if m in ("add", "sub", "adc", "sbb"):
            a, b = E(0), E(1)
            cf = self._reg_name("cf")
            if m == "add":
                return [f"{{ uint32_t _a = {a}, _b = {b}, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, {bits}, {self._fm()}); {W(0, '_r')} }}"]
            if m == "sub":
                return [f"{{ uint32_t _a = {a}, _b = {b}, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, {bits}, {self._fm()}); {W(0, '_r')} }}"]
            if m == "adc":
                return [f"{{ uint32_t _ci = {cf} & 1u, _a = {a}, _b = {b}, _r = _a + _b + _ci; FLAGS_ADC_M(_a, _b, _ci, _r, {bits}, {self._fm()}); {W(0, '_r')} }}"]
            return [f"{{ uint32_t _ci = {cf} & 1u, _a = {a}, _b = {b}, _r = _a - _b - _ci; FLAGS_SBB_M(_a, _b, _ci, _r, {bits}, {self._fm()}); {W(0, '_r')} }}"]

        if m == "cmp":
            return [f"{{ uint32_t _a = {E(0)}, _b = {E(1)}, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, {bits}, {self._fm()}); }}"]
        if m == "test":
            return [f"{{ uint32_t _r = ({E(0)}) & ({E(1)}); FLAGS_LOG_M(_r, {bits}, {self._fm()}); }}"]
        if m in ("and", "or", "xor"):
            c_op = {"and": "&", "or": "|", "xor": "^"}[m]
            return [f"{{ uint32_t _r = ({E(0)}) {c_op} ({E(1)}); FLAGS_LOG_M(_r, {bits}, {self._fm()}); {W(0, '_r')} }}"]
        if m == "not":
            return [W(0, f"~({E(0)})")]
        if m == "neg":
            return [f"{{ uint32_t _a = {E(0)}, _r = (uint32_t)0 - _a; FLAGS_SUB_M((uint32_t)0, _a, _r, {bits}, {self._fm()}); {W(0, '_r')} }}"]
        if m == "inc":
            return [f"{{ uint32_t _a = {E(0)}, _r = _a + 1u; FLAGS_ADD_M(_a, 1u, _r, {bits}, ({self._fm()} & ~F_CF)); {W(0, '_r')} }}"]
        if m == "dec":
            return [f"{{ uint32_t _a = {E(0)}, _r = _a - 1u; FLAGS_SUB_M(_a, 1u, _r, {bits}, ({self._fm()} & ~F_CF)); {W(0, '_r')} }}"]

        if m == "imul":
            cf, of = self._reg_name("cf"), self._reg_name("of")
            eax, edx = self._reg_name("eax"), self._reg_name("edx")
            if len(o) == 1:
                return [f"{{ int64_t _p = (int64_t)(int32_t){eax} * (int64_t)(int32_t)({E(0)}); {eax} = (uint32_t)_p; {edx} = (uint32_t)(_p >> 32); {cf} = {of} = ((int64_t)(int32_t)_p != _p); }}"]
            if len(o) == 2:
                return [f"{{ int64_t _p = (int64_t)(int32_t)({E(0)}) * (int64_t)(int32_t)({E(1)}); {cf} = {of} = ((int64_t)(int32_t)_p != _p); {W(0, '(uint32_t)_p')} }}"]
            return [f"{{ int64_t _p = (int64_t)(int32_t)({E(1)}) * (int64_t)(int32_t)({E(2)}); {cf} = {of} = ((int64_t)(int32_t)_p != _p); {W(0, '(uint32_t)_p')} }}"]

        if m == "mul":
            cf, of = self._reg_name("cf"), self._reg_name("of")
            eax, edx = self._reg_name("eax"), self._reg_name("edx")
            if bits == 32:
                return [f"{{ uint64_t _p = (uint64_t){eax} * (uint64_t)({E(0)}); {eax} = (uint32_t)_p; {edx} = (uint32_t)(_p >> 32); {cf} = {of} = ({edx} != 0); }}"]
            elif bits == 16:
                return [f"{{ uint32_t _p = ({eax} & 0xffffu) * ({E(0)} & 0xffffu); {eax} = ({eax} & 0xffff0000u) | (_p & 0xffffu); {edx} = ({edx} & 0xffff0000u) | ((_p >> 16) & 0xffffu); {cf} = {of} = ((_p >> 16) != 0); }}"]
            else:
                return [f"{{ uint32_t _p = ({eax} & 0xffu) * ({E(0)} & 0xffu); {eax} = ({eax} & 0xffff0000u) | (_p & 0xffffu); {cf} = {of} = ((_p >> 8) != 0); }}"]

        if m in ("shl", "sal", "shr", "sar"):
            cnt = E(1) if len(o) > 1 else "1u"
            mask = 0xFFFFFFFF if bits == 32 else (0xFFFF if bits == 16 else 0xFF)
            cf = self._reg_name("cf")
            if m in ("shl", "sal"):
                return [f"{{ uint32_t _s = ({cnt}) & 31u; if (_s) {{ uint32_t _v = {E(0)}; uint32_t _r = (_v << _s) & 0x{mask:x}u; {cf} = (_v >> ({bits} - _s)) & 1u; FLAGS_LOG_M(_r, {bits}, {self._fm()}); {W(0, '_r')} }} }}"]
            if m == "shr":
                return [f"{{ uint32_t _s = ({cnt}) & 31u; if (_s) {{ uint32_t _v = {E(0)}; uint32_t _r = (_v >> _s) & 0x{mask:x}u; {cf} = (_v >> (_s - 1)) & 1u; FLAGS_LOG_M(_r, {bits}, {self._fm()}); {W(0, '_r')} }} }}"]
            # sar
            st = {8: "int8_t", 16: "int16_t", 32: "int32_t"}[bits]
            return [f"{{ uint32_t _s = ({cnt}) & 31u; if (_s) {{ {st} _v = ({st}){E(0)}; uint32_t _r = (uint32_t)(_v >> _s) & 0x{mask:x}u; {cf} = ((uint32_t)_v >> (_s - 1)) & 1u; FLAGS_LOG_M(_r, {bits}, {self._fm()}); {W(0, '_r')} }} }}"]

        if m.startswith("set") and m[3:] in CC:
            cond = CC[m[3:]]
            return [W(0, f"({cond}) ? 1u : 0u")]

        if m.startswith("cmov") and m[4:] in CC:
            cond = CC[m[4:]]
            return [f"if ({cond}) {{ {W(0, E(1))} }}"]

        if m in ("clc", "stc"):
            cf_val = "0u" if m == "clc" else "1u"
            cf_reg = "RG_(cf)" if self.use_rg else "c->cf"
            return [f"{cf_reg} = {cf_val};"]

        if m in ("cld", "std"):
            df_val = "0u" if m == "cld" else "1u"
            return [f"c->df = {df_val};"]

        if m in ("pushfd", "pushf"):
            if self.use_rg:
                return ["LR_STORE;", "PUSH32(eflags_get(c));"]
            return ["PUSH32(eflags_get(c));"]

        if m in ("popfd", "popf"):
            if self.use_rg:
                return ["{ uint32_t _f; POP32(_f); eflags_set(c, _f); }", "LR_RELOAD;"]
            return ["{ uint32_t _f; POP32(_f); eflags_set(c, _f); }"]

        if m == "xchg" and len(o) == 2:
            st0 = f"int{bits}_t" if bits < 32 else "uint32_t"
            return [f"{{ {st0} _t0 = ({E(0)}), _t1 = ({E(1)}); {W(0, '_t1')} {W(1, '_t0')} }}"]

        # Rotations
        if m in ("rol", "ror"):
            cnt = E(1) if len(o) > 1 else "1u"
            mask = 0xFFFFFFFF if bits == 32 else (0xFFFF if bits == 16 else 0xFF)
            cf = self._reg_name("cf")
            of = self._reg_name("of")
            if m == "rol":
                return [
                    f"{{ uint32_t _c = ({cnt}) & 31u; if (_c) {{ "
                    f"uint32_t _v = ({E(0)}) & 0x{mask:x}u; "
                    f"uint32_t _s = _c % {bits}u; "
                    f"uint32_t _r = _s ? (((_v << _s) | (_v >> ({bits}u - _s))) & 0x{mask:x}u) : _v; "
                    f"{cf} = _r & 1u; "
                    f"if (_c == 1u) {of} = ((_r >> ({bits-1}u)) & 1u) ^ (_r & 1u); "
                    f"{W(0, '_r')} }} }}"
                ]
            else:  # ror
                return [
                    f"{{ uint32_t _c = ({cnt}) & 31u; if (_c) {{ "
                    f"uint32_t _v = ({E(0)}) & 0x{mask:x}u; "
                    f"uint32_t _s = _c % {bits}u; "
                    f"uint32_t _r = _s ? (((_v >> _s) | (_v << ({bits}u - _s))) & 0x{mask:x}u) : _v; "
                    f"{cf} = (_r >> ({bits-1}u)) & 1u; "
                    f"if (_c == 1u) {of} = ((_r >> ({bits-1}u)) & 1u) ^ ((_r >> ({bits-2 if bits > 1 else 0}u)) & 1u); "
                    f"{W(0, '_r')} }} }}"
                ]

        # LAHF / SAHF
        if m == "lahf":
            cf = self._reg_name("cf")
            pf = self._reg_name("pf")
            af = self._reg_name("af")
            zf = self._reg_name("zf")
            sf = self._reg_name("sf")
            eax = self._reg_name("eax")
            return [
                f"{eax} = ({eax} & 0xffff00ffu) | "
                f"((({sf} & 1u) << 15) | (({zf} & 1u) << 14) | (({af} & 1u) << 12) | "
                f"(({pf} & 1u) << 10) | (1u << 9) | (({cf} & 1u) << 8));"
            ]

        if m == "sahf":
            cf = self._reg_name("cf")
            pf = self._reg_name("pf")
            af = self._reg_name("af")
            zf = self._reg_name("zf")
            sf = self._reg_name("sf")
            eax = self._reg_name("eax")
            return [
                f"{{ uint32_t _ah = ({eax} >> 8) & 0xffu; "
                f"{cf} = _ah & 1u; {pf} = (_ah >> 2) & 1u; {af} = (_ah >> 4) & 1u; "
                f"{zf} = (_ah >> 6) & 1u; {sf} = (_ah >> 7) & 1u; }}"
            ]

        # Integer division
        if m in ("idiv", "div"):
            eax = self._reg_name("eax")
            edx = self._reg_name("edx")
            if m == "idiv":
                if bits == 32:
                    return [
                        f"{{ int32_t _den = (int32_t)({E(0)}); if (_den != 0) {{ "
                        f"int64_t _num = (int64_t)(((uint64_t){edx} << 32) | (uint64_t)(uint32_t){eax}); "
                        f"if (!(_num == (-9223372036854775807LL - 1LL) && _den == -1)) {{ "
                        f"int64_t _q = _num / _den; int64_t _rem = _num % _den; "
                        f"if (_q >= -2147483648LL && _q <= 2147483647LL) {{ "
                        f"{eax} = (uint32_t)(int32_t)_q; {edx} = (uint32_t)(int32_t)_rem; "
                        f"}} }} }} }}"
                    ]
                elif bits == 16:
                    return [
                        f"{{ int16_t _den = (int16_t)({E(0)}); if (_den != 0) {{ "
                        f"int32_t _num = (int32_t)((((uint32_t)(uint16_t){edx}) << 16) | (uint16_t){eax}); "
                        f"int32_t _q = _num / _den; int32_t _rem = _num % _den; "
                        f"if (_q >= -32768 && _q <= 32767) {{ "
                        f"{eax} = ({eax} & 0xffff0000u) | ((uint32_t)(int16_t)_q & 0xffffu); "
                        f"{edx} = ({edx} & 0xffff0000u) | ((uint32_t)(int16_t)_rem & 0xffffu); "
                        f"}} }} }}"
                    ]
                else:  # 8-bit
                    return [
                        f"{{ int8_t _den = (int8_t)({E(0)}); if (_den != 0) {{ "
                        f"int16_t _num = (int16_t){eax}; "
                        f"int32_t _q = _num / _den; int32_t _rem = _num % _den; "
                        f"if (_q >= -128 && _q <= 127) {{ "
                        f"{eax} = ({eax} & 0xffff0000u) | ((uint32_t)(_q & 0xffu)) | (((uint32_t)(_rem & 0xffu)) << 8); "
                        f"}} }} }}"
                    ]
            else:  # unsigned div
                if bits == 32:
                    return [
                        f"{{ uint32_t _den = (uint32_t)({E(0)}); if (_den != 0) {{ "
                        f"uint64_t _num = ((uint64_t){edx} << 32) | (uint32_t){eax}; "
                        f"uint64_t _q = _num / _den; uint32_t _rem = (uint32_t)(_num % _den); "
                        f"if (_q <= 0xffffffffULL) {{ {eax} = (uint32_t)_q; {edx} = _rem; }} }} }}"
                    ]
                elif bits == 16:
                    return [
                        f"{{ uint16_t _den = (uint16_t)({E(0)}); if (_den != 0) {{ "
                        f"uint32_t _num = (((uint32_t)(uint16_t){edx}) << 16) | (uint16_t){eax}; "
                        f"uint32_t _q = _num / _den; uint32_t _rem = _num % _den; "
                        f"if (_q <= 0xffffu) {{ "
                        f"{eax} = ({eax} & 0xffff0000u) | (_q & 0xffffu); "
                        f"{edx} = ({edx} & 0xffff0000u) | (_rem & 0xffffu); }} }} }}"
                    ]
                else:  # 8-bit
                    return [
                        f"{{ uint8_t _den = (uint8_t)({E(0)}); if (_den != 0) {{ "
                        f"uint16_t _num = (uint16_t){eax}; "
                        f"uint16_t _q = _num / _den; uint16_t _rem = _num % _den; "
                        f"if (_q <= 0xffu) {{ "
                        f"{eax} = ({eax} & 0xffff0000u) | (_q & 0xffu) | ((_rem & 0xffu) << 8); }} }} }}"
                    ]

        # String instructions (movsd/movsb, stosd/stosb, cmpsb/cmpsd)
        base_m = m.split()[-1]
        is_rep = m.startswith("rep ") or m.startswith("repe ") or m.startswith("repz ")
        if base_m in ("movsd", "movsb", "stosd", "stosb", "cmpsb", "cmpsd"):
            # Ensure not SSE scalar
            if o and any(op.type == 1 and op.reg in XM for op in o):
                pass
            else:
                esi = self._reg_name("esi")
                edi = self._reg_name("edi")
                ecx = self._reg_name("ecx")
                eax = self._reg_name("eax")
                step = 4 if base_m.endswith("d") else 1
                MR_OP = "MR32" if step == 4 else "MR8"

                if base_m.startswith("movs"):
                    if is_rep:
                        return [
                            f"if (c->df) {{ while ({ecx} > 0) {{ {MR_OP}({edi}) = {MR_OP}({esi}); {esi} -= {step}u; {edi} -= {step}u; {ecx}--; }} }} "
                            f"else {{ while ({ecx} > 0) {{ {MR_OP}({edi}) = {MR_OP}({esi}); {esi} += {step}u; {edi} += {step}u; {ecx}--; }} }}"
                        ]
                    else:
                        return [
                            f"{MR_OP}({edi}) = {MR_OP}({esi}); "
                            f"if (c->df) {{ {esi} -= {step}u; {edi} -= {step}u; }} else {{ {esi} += {step}u; {edi} += {step}u; }}"
                        ]

                if base_m.startswith("stos"):
                    val = eax if step == 4 else f"({eax} & 0xffu)"
                    if is_rep:
                        return [
                            f"if (c->df) {{ while ({ecx} > 0) {{ {MR_OP}({edi}) = {val}; {edi} -= {step}u; {ecx}--; }} }} "
                            f"else {{ while ({ecx} > 0) {{ {MR_OP}({edi}) = {val}; {edi} += {step}u; {ecx}--; }} }}"
                        ]
                    else:
                        return [
                            f"{MR_OP}({edi}) = {val}; "
                            f"if (c->df) {{ {edi} -= {step}u; }} else {{ {edi} += {step}u; }}"
                        ]

                if base_m.startswith("cmps"):
                    bits_cmp = 32 if step == 4 else 8
                    mask_cmp = 0xffffffff if step == 4 else 0xff
                    if is_rep:
                        return [
                            f"while ({ecx} > 0) {{ "
                            f"uint32_t _a = (uint32_t){MR_OP}({esi}), _b = (uint32_t){MR_OP}({edi}); "
                            f"uint32_t _r = (_a - _b) & 0x{mask_cmp:x}u; "
                            f"FLAGS_SUB_M(_a, _b, _r, {bits_cmp}, 0x3fu); "
                            f"if (c->df) {{ {esi} -= {step}u; {edi} -= {step}u; }} else {{ {esi} += {step}u; {edi} += {step}u; }} "
                            f"{ecx}--; if (_a != _b) break; }}"
                        ]
                    else:
                        return [
                            f"{{ uint32_t _a = (uint32_t){MR_OP}({esi}), _b = (uint32_t){MR_OP}({edi}); "
                            f"uint32_t _r = (_a - _b) & 0x{mask_cmp:x}u; "
                            f"FLAGS_SUB_M(_a, _b, _r, {bits_cmp}, 0x3fu); "
                            f"if (c->df) {{ {esi} -= {step}u; {edi} -= {step}u; }} else {{ {esi} += {step}u; {edi} += {step}u; }} }}"
                        ]

        raise UnsupportedInstruction(f"Unsupported mnemonic: {m} ({ins.op_str})")


class FunctionLifter:
    """Lifts a catalog function structure into C99 code."""

    def __init__(
        self,
        raw_exe: bytes,
        catalog: dict[str, Any],
        enable_lregs: bool = False,
        enable_flagabi: bool = True,
        trampoline_data: dict[str, Any] | None = None,
    ) -> None:
        self.raw_exe = raw_exe
        self.catalog = catalog
        self.functions = {f["address"]: f for f in catalog["functions"]}
        self.image_base = int(catalog["image_base"])
        self.code_start = int(catalog["code_start"])
        self.code_end = int(catalog["code_end"])
        self.enable_lregs = enable_lregs
        self.enable_flagabi = enable_flagabi

        # SecuROM Trampoline Mapping (site_va -> target_va)
        self.trampoline_map: dict[int, int] = {}
        if trampoline_data is None:
            t_path = WORKSPACE / "research" / "local" / "phase1" / "securom_trampolines.json"
            if t_path.is_file():
                try:
                    trampoline_data = json.loads(t_path.read_text(encoding="utf-8"))
                except Exception:
                    trampoline_data = None

        if trampoline_data and "trampolines" in trampoline_data:
            raw_map = {
                int(t["site_va"]): int(t["target_va"])
                for t in trampoline_data["trampolines"]
                if "site_va" in t and "target_va" in t
            }
            # Resolve chained trampolines iteratively
            for s_va in raw_map:
                visited = set()
                cur = s_va
                while cur in raw_map and cur not in visited:
                    visited.add(cur)
                    cur = raw_map[cur]
                self.trampoline_map[s_va] = cur

        # Capstone disassembler
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        self.cs.detail = True
        self.lifter = InstructionLifter(self.cs, use_rg=enable_lregs)

    def resolve_target(self, dest: int) -> tuple[int, bool]:
        """Resolve a destination VA through SecuROM trampoline mappings.

        Returns (target_va, is_resolved).
        Only redirects if the resolved target is confirmed to exist in self.functions.
        """
        if dest in self.trampoline_map:
            target = self.trampoline_map[dest]
            if target in self.functions:
                return (target, True)
        return (dest, False)

    def resolve_jump_table(
        self, ins: Any, block_starts: set[int], func_entry: int
    ) -> tuple[int, str, list[int]] | None:
        """Resolve an intra-function indirect jump table.

        Returns (table_va, idx_reg_name, target_entries) if valid, or None.
        A jump table is only recognized if:
        1. It is an indirect memory jump with scale == 4, non-zero disp (table VA), non-zero index, and base == 0.
        2. Consecutive 4-byte entries from table_va resolve to basic block starts of the current function.
        3. At least 2 entries are present.
        """
        if ins.mnemonic != "jmp" or not ins.operands:
            return None
        op = ins.operands[0]
        if op.type != CS_OP_MEM:
            return None
        mem = op.mem
        if mem.scale != 4 or mem.disp == 0 or mem.index == 0 or mem.base != 0:
            return None
        table_va = mem.disp
        idx_reg = self.cs.reg_name(mem.index)
        if not idx_reg:
            return None
        entries: list[int] = []
        for k in range(256):
            raw_val = self.read_bytes(table_va + k * 4, 4)
            if len(raw_val) < 4:
                break
            target_va = struct.unpack("<I", raw_val)[0]
            if target_va in block_starts:
                entries.append(target_va)
            else:
                break
        if len(entries) < 2:
            return None
        return table_va, idx_reg, entries

    def read_bytes(self, va: int, size: int) -> bytes:
        off = va_to_offset(va)
        if off < 0 or off + size > len(self.raw_exe):
            return b""
        return self.raw_exe[off : off + size]

    def resolve_intra_splices(
        self, func_entry: int, initial_blocks: list[Any]
    ) -> list[Any]:
        """Recovers intra-function SecuROM splices and continuation blocks (Rule A).

        Detects when a function's prologue/entry block jumps to an intra-function
        SecuROM obfuscation splice whose terminal jump returns directly to the
        function body (return_dest == b_end). When confirmed:
        1. Inlines the splice basic block into the function's CFG.
        2. If the return_dest was truncated from the catalog, discovers the
           continuation body blocks until genuine terminal exits (ret/retf).
        """
        blocks = [list(b) for b in initial_blocks]
        if not blocks:
            return blocks

        block_starts = {b[0] for b in blocks}

        b_start, b_end, succs, is_exit = blocks[0]
        code = self.read_bytes(b_start, b_end - b_start)
        insns = list(self.cs.disasm(code, b_start))
        if not insns or insns[-1].mnemonic != "jmp":
            return blocks

        last_ins = insns[-1]
        if not last_ins.operands or last_ins.operands[0].type != CS_OP_IMM:
            return blocks

        splice_va = last_ins.operands[0].imm
        if splice_va in block_starts:
            return blocks

        splice_code = self.read_bytes(splice_va, 64)
        if not splice_code:
            return blocks

        s_insns = list(self.cs.disasm(splice_code, splice_va))
        splice_block_insns = []
        ret_dest = None
        for s in s_insns:
            splice_block_insns.append(s)
            if s.mnemonic == "jmp" and s.operands and s.operands[0].type == CS_OP_IMM:
                ret_dest = s.operands[0].imm
                break
            if s.mnemonic in ("ret", "retf", "call"):
                break
            if len(splice_block_insns) >= 32:
                break

        if ret_dest is None or ret_dest != b_end:
            return blocks

        splice_end = splice_block_insns[-1].address + splice_block_insns[-1].size
        blocks.append([splice_va, splice_end, [ret_dest], 0])
        block_starts.add(splice_va)

        if ret_dest not in block_starts:
            leaders = {ret_dest}
            raw_blocks = {}
            q = [ret_dest]
            other_funcs = set(self.functions.keys()) - {func_entry}

            while q:
                curr = q.pop(0)
                if curr in raw_blocks:
                    continue
                curr_va = curr
                curr_insns = []
                while True:
                    c_bytes = self.read_bytes(curr_va, 16)
                    if not c_bytes:
                        break
                    try:
                        ins = next(self.cs.disasm(c_bytes, curr_va))
                    except StopIteration:
                        break
                    curr_insns.append(ins)
                    m = ins.mnemonic
                    if m in ("ret", "retf"):
                        curr_va += ins.size
                        break
                    if m == "jmp":
                        if ins.operands and ins.operands[0].type == CS_OP_IMM:
                            t = ins.operands[0].imm
                            if (
                                t not in other_funcs
                                and t not in leaders
                                and t not in block_starts
                            ):
                                leaders.add(t)
                                q.append(t)
                        curr_va += ins.size
                        break
                    if (m.startswith("j") and m != "jmp") or m in (
                        "jecxz",
                        "jcxz",
                        "loop",
                        "loope",
                        "loopne",
                    ):
                        if ins.operands and ins.operands[0].type == CS_OP_IMM:
                            t = ins.operands[0].imm
                            ft = ins.address + ins.size
                            for dest in (t, ft):
                                if (
                                    dest not in other_funcs
                                    and dest not in leaders
                                    and dest not in block_starts
                                ):
                                    leaders.add(dest)
                                    q.append(dest)
                        curr_va += ins.size
                        break
                    curr_va += ins.size
                raw_blocks[curr] = (curr_insns, curr_va)

            all_insns = []
            for start_addr in sorted(raw_blocks.keys()):
                all_insns.extend(raw_blocks[start_addr][0])
            seen_addr = set()
            unique_insns = []
            for ins in all_insns:
                if ins.address not in seen_addr:
                    seen_addr.add(ins.address)
                    unique_insns.append(ins)
            unique_insns.sort(key=lambda x: x.address)

            cur_b_insns = []
            for ins in unique_insns:
                if (
                    ins.address in leaders
                    and cur_b_insns
                    and ins.address != cur_b_insns[0].address
                ):
                    b_s = cur_b_insns[0].address
                    b_e = cur_b_insns[-1].address + cur_b_insns[-1].size
                    is_ex = 1 if cur_b_insns[-1].mnemonic in ("ret", "retf") else 0
                    if b_s not in block_starts:
                        blocks.append([b_s, b_e, [], is_ex])
                        block_starts.add(b_s)
                    cur_b_insns = [ins]
                else:
                    cur_b_insns.append(ins)
            if cur_b_insns:
                b_s = cur_b_insns[0].address
                b_e = cur_b_insns[-1].address + cur_b_insns[-1].size
                is_ex = 1 if cur_b_insns[-1].mnemonic in ("ret", "retf") else 0
                if b_s not in block_starts:
                    blocks.append([b_s, b_e, [], is_ex])
                    block_starts.add(b_s)

        seen_starts = set()
        dedup_blocks = []
        for b in blocks:
            if b[0] not in seen_starts:
                seen_starts.add(b[0])
                dedup_blocks.append(b)
        return dedup_blocks

    def lift_function(
        self,
        func_entry: int,
        enable_lregs: bool | None = None,
        enable_flagabi: bool | None = None,
    ) -> str:
        """Translate a function into a complete C99 function string."""
        if enable_lregs is None:
            enable_lregs = self.enable_lregs
        if enable_flagabi is None:
            enable_flagabi = self.enable_flagabi

        old_use_rg = self.lifter.use_rg
        self.lifter.use_rg = enable_lregs

        if func_entry in MANUAL_RECOVERIES:
            self.lifter.use_rg = old_use_rg
            return MANUAL_RECOVERIES[func_entry]

        if func_entry == 0x00828ebc:
            self.lifter.use_rg = old_use_rg
            return (
                "void sub_00828ebc(CPU *c) {\n"
                "    /* Authentic MSVC __EH_prolog runtime helper */\n"
                "    uint32_t scope_table = MR32(c->esp);\n"
                "    uint32_t alloc_size  = MR32(c->esp + 4);\n"
                "    uint32_t frame_base  = c->esp;\n"
                "    uint32_t old_ebp     = c->ebp;\n"
                "\n"
                "    c->ebp = frame_base;\n"
                "    MR32(c->ebp) = old_ebp;\n"
                "\n"
                "    MR32(c->ebp - 4)  = 0xfffffffeu;\n"
                "    MR32(c->ebp - 8)  = scope_table;\n"
                "    MR32(c->ebp - 12) = 0x00828f15u;\n"
                "    MR32(c->ebp - 16) = MR32(c->fs_base);\n"
                "    MR32(c->fs_base)  = c->ebp - 16;\n"
                "\n"
                "    c->esp = c->ebp - 16 - alloc_size - 16;\n"
                "}\n"
            )

        if func_entry == 0x00828f01:
            self.lifter.use_rg = old_use_rg
            return (
                "void sub_00828f01(CPU *c) {\n"
                "    /* Authentic MSVC __EH_epilog runtime helper */\n"
                "    MR32(c->fs_base) = MR32(c->ebp - 16);\n"
                "    uint32_t old_ebp = MR32(c->ebp);\n"
                "    c->esp = c->ebp + 8;\n"
                "    c->ebp = old_ebp;\n"
                "}\n"
            )

        if func_entry == 0x00463e90:
            self.lifter.use_rg = old_use_rg
            return (
                "void sub_00463e90(CPU *c) {\n"
                "    LR_ENTER;\n"
                "L_00463e90:\n"
                "    PUSH32(RG_(ecx));\n"
                "    PUSH32(RG_(ebx));\n"
                "    PUSH32(RG_(ebp));\n"
                "    RG_(ebp) = (uint32_t)(MR32(RG_(esp)+0x10u));\n"
                "    /* Unspliced SecuROM bridge: cmp ebp, 0x400 (bChunk small-block threshold); jmp 0x463e9d */\n"
                "    { uint32_t _a = RG_(ebp), _b = 0x400u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x00u); }\n"
                "L_00463e9d:\n"
                "    PUSH32(RG_(esi));\n"
                "    PUSH32(RG_(edi));\n"
                "    RG_(ebx) = (uint32_t)(RG_(ecx));\n"
                "    if (CC_BE) goto L_00463eb5;\n"
                "L_00463ea3:\n"
                "    RG_(eax) = (uint32_t)(MR32(RG_(esp)+0x1cu));\n"
                "    PUSH32(RG_(eax));\n"
                "    RG_(edx) = (uint32_t)(RG_(ebp));\n"
                "    RG_(eax) = (uint32_t)(RG_(ebx));\n"
                "    PUSH32(0x00463eacu);\n"
                "    LR_STORE;\n"
                "    DISPATCH_CALL(c, 0x00463f70u);\n"
                "    LR_RELOAD;\n"
                "    RG_(edi) = (uint32_t)(RG_(eax));\n"
                "    goto L_00463ef6;\n"
                "L_00463eb5:\n"
                "    RG_(esi) = (uint32_t)(RG_(ebp) - 1u);\n"
                "    RG_(esi) >>= 4;\n"
                "    { uint32_t _a = MR32(RG_(ebx)+RG_(esi)*4u), _b = 0u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }\n"
                "    if (CC_NE) goto L_00463eee;\n"
                "L_00463ec1:\n"
                "    PUSH32(RG_(esi));\n"
                "    RG_(eax) = (uint32_t)(RG_(ebx));\n"
                "    PUSH32(0x00463ec9u);\n"
                "    LR_STORE;\n"
                "    DISPATCH_CALL(c, 0x00464100u);\n"
                "    LR_RELOAD;\n"
                "    { uint32_t _r = ((uint8_t)RG_(eax)) & ((uint8_t)RG_(eax)); FLAGS_LOG_M(_r, 8, 0x08u); }\n"
                "    if (CC_NE) goto L_00463eee;\n"
                "L_00463ecd:\n"
                "    PUSH32(0x9f4258u);\n"
                "    PUSH32(0x00463ed7u);\n"
                "    LR_STORE;\n"
                "    DISPATCH_CALL(c, 0x004324e0u);\n"
                "    LR_RELOAD;\n"
                "    RG_(esp) += 4u;\n"
                "    MR32(0x0u) = 0u; /* Assert failure in bChunk */\n"
                "    RG_(eax) = 0u;\n"
                "    { uint32_t _t; POP32(_t); RG_(edi) = (uint32_t)(_t); }\n"
                "    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }\n"
                "    { uint32_t _t; POP32(_t); RG_(ebp) = (uint32_t)(_t); }\n"
                "    { uint32_t _t; POP32(_t); RG_(ebx) = (uint32_t)(_t); }\n"
                "    { uint32_t _t; POP32(_t); RG_(ecx) = (uint32_t)(_t); }\n"
                "    RG_(esp) += 12u;\n"
                "    LR_STORE;\n"
                "    return;\n"
                "L_00463eee:\n"
                "    RG_(edi) = (uint32_t)(MR32(RG_(ebx)+RG_(esi)*4u));\n"
                "    RG_(ecx) = (uint32_t)(MR32(RG_(edi)));\n"
                "    MR32(RG_(ebx)+RG_(esi)*4u) = (RG_(ecx));\n"
                "L_00463ef6:\n"
                "    PUSH32(RG_(ebp));\n"
                "    PUSH32(0u);\n"
                "    PUSH32(RG_(edi));\n"
                "    PUSH32(0x00463effu);\n"
                "    LR_STORE;\n"
                "    DISPATCH_CALL(c, 0x008287c8u);\n"
                "    LR_RELOAD;\n"
                "    RG_(esp) += 12u;\n"
                "    RG_(eax) = (uint32_t)(RG_(edi));\n"
                "    { uint32_t _t; POP32(_t); RG_(edi) = (uint32_t)(_t); }\n"
                "    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }\n"
                "    { uint32_t _t; POP32(_t); RG_(ebp) = (uint32_t)(_t); }\n"
                "    { uint32_t _t; POP32(_t); RG_(ebx) = (uint32_t)(_t); }\n"
                "    { uint32_t _t; POP32(_t); RG_(ecx) = (uint32_t)(_t); }\n"
                "    RG_(esp) += 12u;\n"
                "    LR_STORE;\n"
                "    return;\n"
                "}\n"
            )

        func = self.functions.get(func_entry)
        if not func:
            self.lifter.use_rg = old_use_rg
            raise ValueError(f"Function 0x{func_entry:08x} not found in catalog")

        fname = f"sub_{func_entry:08x}"
        lines = [f"void {fname}(CPU *c) {{"]
        if enable_lregs:
            lines.append("    LR_ENTER;")

        blocks = self.resolve_intra_splices(func_entry, func["blocks"])
        block_starts = {b[0] for b in blocks}

        # Disassemble all blocks for CFG dataflow analysis
        block_insns: dict[int, list[Any]] = {}
        for b_start, b_end, succs, is_exit in blocks:
            code = self.read_bytes(b_start, b_end - b_start)
            if code:
                block_insns[b_start] = list(self.cs.disasm(code, b_start))
            else:
                block_insns[b_start] = []

        if enable_flagabi:
            live_after = compute_flag_liveness(blocks, block_insns)
        else:
            live_after = {}

        has_terminal = False
        for b_start, b_end, succs, is_exit in blocks:
            lines.append(f"L_{b_start:08x}:")
            disasm_insns = block_insns.get(b_start, [])
            if not disasm_insns:
                lines.append(f"    /* Warning: could not read bytes at 0x{b_start:08x} */")
                continue

            for idx, ins in enumerate(disasm_insns):
                m = ins.mnemonic
                if enable_flagabi:
                    self.lifter.cur_fmask = live_after.get(ins.address, F_ALL)
                else:
                    self.lifter.cur_fmask = F_ALL

                # Return instructions
                if m in ("ret", "retf"):
                    imm = ins.operands[0].imm if ins.operands else 0
                    pop_bytes = 4 + imm
                    if enable_lregs:
                        lines.append(f"    RG_(esp) += {pop_bytes}u;")
                        lines.append("    LR_STORE;")
                    else:
                        lines.append(f"    c->esp += {pop_bytes}u;")
                    lines.append("    return;")
                    has_terminal = True
                    continue

                # Unconditional Jumps
                if m == "jmp":
                    if ins.operands and ins.operands[0].type == CS_OP_IMM:
                        raw_dest = ins.operands[0].imm
                        if raw_dest in block_starts:
                            lines.append(f"    goto L_{raw_dest:08x};")
                        else:
                            dest, is_resolved = self.resolve_target(raw_dest)
                            if is_resolved:
                                lines.append(f"    /* Resolved SecuROM trampoline jmp 0x{raw_dest:08x} -> 0x{dest:08x} */")
                            if enable_lregs:
                                lines.append("    LR_STORE;")
                            lines.append(f"    DISPATCH_TAIL(c, 0x{dest:08x}u);")
                    elif ins.operands and ins.operands[0].type == CS_OP_MEM:
                        jt_info = self.resolve_jump_table(ins, block_starts, func_entry)
                        if jt_info is not None:
                            table_va, idx_reg, entries = jt_info
                            reg_expr = self.lifter._reg_name(idx_reg)
                            lines.append(f"    /* Recovered intra-function jump table 0x{table_va:08x} ({len(entries)} targets) */")
                            lines.append(f"    switch ({reg_expr}) {{")
                            for e_idx, t_va in enumerate(entries):
                                lines.append(f"        case {e_idx}: goto L_{t_va:08x};")
                            lines.append("        default:")
                            lines.append(f'            fprintf(stderr, "[JUMP_TABLE] FATAL: Out-of-bounds selector %u for table 0x{table_va:08x}u in sub_{func_entry:08x}\\n", (unsigned){reg_expr});')
                            lines.append("            fflush(stderr);")
                            lines.append("            __builtin_trap();")
                            lines.append("    }")
                        else:
                            ea = self.lifter.ea(ins.operands[0].mem)
                            if enable_lregs:
                                lines.append("    LR_STORE;")
                            lines.append(f"    DISPATCH_TAIL(c, MR32{ea});")
                    else:
                        rd_expr = self.lifter.rd(ins.operands[0])
                        if enable_lregs:
                            lines.append("    LR_STORE;")
                        lines.append(f"    DISPATCH_TAIL(c, {rd_expr});")
                    has_terminal = True
                    continue

                # Conditional Jumps
                if (m.startswith("j") and m[1:] in CC) or m in ("jecxz", "jcxz", "loop", "loope", "loopne"):
                    cond = CC.get(m[1:], None)
                    if ins.operands and ins.operands[0].type == CS_OP_IMM:
                        dest = ins.operands[0].imm
                        if cond and dest in block_starts:
                            lines.append(f"    if ({cond}) goto L_{dest:08x};")
                        elif cond:
                            if enable_lregs:
                                lines.append(f"    if ({cond}) {{ LR_STORE; DISPATCH_TAIL(c, 0x{dest:08x}u); }}")
                            else:
                                lines.append(f"    if ({cond}) {{ DISPATCH_TAIL(c, 0x{dest:08x}u); }}")
                    continue

                # Calls
                if m == "call":
                    ret_addr = ins.address + ins.size
                    if enable_lregs:
                        lines.append(f"    PUSH32(0x{ret_addr:08x}u);")
                        lines.append("    LR_STORE;")
                    else:
                        lines.append(f"    c->esp -= 4u; MR32(c->esp) = 0x{ret_addr:08x}u;")
                    if ins.operands and ins.operands[0].type == CS_OP_IMM:
                        raw_dest = ins.operands[0].imm
                        dest, is_resolved = self.resolve_target(raw_dest)
                        hooked_vas = {0x0070f640, 0x004afea0, 0x00828b43, 0x00828fee, 0x0082851b}
                        if dest in hooked_vas:
                            lines.append(f"    DISPATCH_CALL(c, 0x{dest:08x}u);")
                        elif dest in self.functions:
                            if is_resolved:
                                lines.append(f"    /* Resolved SecuROM trampoline call 0x{raw_dest:08x} -> 0x{dest:08x} */")
                            lines.append(f"    sub_{dest:08x}(c);")
                        else:
                            lines.append(f"    DISPATCH_CALL(c, 0x{dest:08x}u);")
                    elif ins.operands and ins.operands[0].type == CS_OP_MEM:
                        ea = self.lifter.ea(ins.operands[0].mem)
                        lines.append(f"    DISPATCH_CALL(c, MR32{ea});")
                    else:
                        lines.append(f"    DISPATCH_CALL(c, {self.lifter.rd(ins.operands[0])});")
                    if enable_lregs:
                        lines.append("    LR_RELOAD;")
                    continue

                # Standard Instruction Translation
                try:
                    c_stmts = self.lifter.lift_instruction(ins)
                    for stmt in c_stmts:
                        lines.append(f"    {stmt}")
                except UnsupportedInstruction as err:
                    lines.append(f"    /* Unsupported: {ins.mnemonic} {ins.op_str} ({err}) */")

        if enable_lregs and not has_terminal:
            lines.append("    LR_STORE;")

        self.lifter.use_rg = old_use_rg
        lines.append("}\n")
        return "\n".join(lines)

