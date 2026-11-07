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

from tools.clean_drm import EXPECTED_NFS_EXE_SHA256, parse_text_section, patch_all_countdown_stubs
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
    raw_m = ins.mnemonic
    m = raw_m[5:].strip() if raw_m.startswith("lock ") else raw_m

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

    # General arithmetic, logic & atomic exchange-add / compare-exchange
    if m in ("add", "sub", "cmp", "neg", "and", "or", "xor", "test", "xadd", "cmpxchg"):
        return (F_ALL, 0)
    if m == "cmpxchg8b":
        return (F_ZF, 0)

    if m in ("adc", "sbb"):
        return (F_ALL, F_CF)

    if m in ("inc", "dec"):
        return (F_ALL & ~F_CF, 0)

    if m in ("imul", "mul"):
        return (F_CF | F_OF, 0)

    if m in ("div", "idiv"):
        return (F_ALL, 0)

    # Shifts and rotates
    if m in ("shl", "sal", "shr", "sar", "shld", "shrd"):
        if m in ("shl", "sal", "shr", "sar") and hasattr(ins, "operands") and len(ins.operands) > 1 and ins.operands[1].type == CS_OP_IMM and ins.operands[1].imm == 0:
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

    # String comparisons (exclude SSE2 scalar cmpsd)
    base_str = m.split()[-1]
    if base_str in ("cmpsb", "cmpsw", "cmpsd", "scasb", "scasw", "scasd"):
        if not (hasattr(ins, "operands") and ins.operands and any(op.type == CS_OP_REG and op.reg in XM for op in ins.operands)):
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

    # CPUID / RDTSC / Returns
    if m in ("cpuid", "rdtsc", "ret", "retf"):
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
    call_like_addrs: set[int] | None = None,
) -> dict[int, int]:
    """Computes backward CFG flag liveness for a function.

    Returns:
        Mapping of instruction address -> live_after flag mask (F_CF..F_OF).
    """
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
                else:
                    out_mask |= F_ALL
            # Preserve flags across external / tail jumps (non-exit blocks with no local successors)
            if not is_exit and not succs:
                out_mask |= F_ALL
            if is_exit and returns_flags:
                out_mask |= F_ALL

            if out_mask != live_out[b_start]:
                live_out[b_start] = out_mask
                changed = True

            cur = out_mask
            insns = insns_by_block.get(b_start, [])
            for ins in reversed(insns):
                if call_like_addrs and ins.address in call_like_addrs:
                    d, u = F_ALL, 0
                else:
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
            if call_like_addrs and ins.address in call_like_addrs:
                d, u = F_ALL, 0
            else:
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
                if is_xm(1):
                    si = XM[o[1].reg]
                    return [
                        f"#if defined(__wasm_simd128__)\n"
                        f"WASM_SIMD_SQRTPS(c->xmm[{di}], c->xmm[{si}]);\n"
                        f"#else\n"
                        f"for (int _k = 0; _k < 4; _k++) {{ float _x = c->xmm[{si}].f[_k]; c->xmm[{di}].f[_k] = sqrtf(_x); }}\n"
                        f"#endif"
                    ]
                ea = self.ea(o[1].mem)
                return [f"for (int _k = 0; _k < 4; _k++) {{ float _x = MRF32(({ea}) + 4u * (uint32_t)_k); c->xmm[{di}].f[_k] = sqrtf(_x); }}"]
            fn = "(1.0f / _x)" if m == "rcpps" else "(1.0f / sqrtf(_x))"
            src = f"c->xmm[{XM[o[1].reg]}].f[_k]" if is_xm(1) else f"MRF32(({self.ea(o[1].mem)}) + 4u * (uint32_t)_k)"
            return [f"for (int _k = 0; _k < 4; _k++) {{ float _x = {src}; c->xmm[{di}].f[_k] = {fn}; }}"]

        # ------------------------------------------------------------------
        # SSE Scalar Single & SSE2 Scalar/Packed Double Arithmetic
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

        SD_OPS = {"addsd": "+", "subsd": "-", "mulsd": "*", "divsd": "/"}
        if m in SD_OPS and is_xm(0):
            di = XM[o[0].reg]
            op_c = SD_OPS[m]
            src = f"c->xmm[{XM[o[1].reg]}].d[0]" if is_xm(1) else f"MRF64{self.ea(o[1].mem)}"
            return [f"{{ double _a = c->xmm[{di}].d[0], _b = {src}; c->xmm[{di}].d[0] = sse_r2d(_a, _b, _a {op_c} _b); }}"]

        if m in ("maxsd", "minsd") and is_xm(0):
            di = XM[o[0].reg]
            cmp_op = ">" if m == "maxsd" else "<"
            src = f"c->xmm[{XM[o[1].reg]}].d[0]" if is_xm(1) else f"MRF64{self.ea(o[1].mem)}"
            return [f"{{ double _a = c->xmm[{di}].d[0], _b = {src}; c->xmm[{di}].d[0] = (_a {cmp_op} _b) ? _a : _b; }}"]

        if m == "sqrtsd" and is_xm(0):
            di = XM[o[0].reg]
            src = f"c->xmm[{XM[o[1].reg]}].d[0]" if is_xm(1) else f"MRF64{self.ea(o[1].mem)}"
            return [f"c->xmm[{di}].d[0] = sqrt({src});"]

        PD_OPS = {"addpd": "+", "subpd": "-", "mulpd": "*", "divpd": "/"}
        if m in PD_OPS and is_xm(0):
            di = XM[o[0].reg]
            op_c = PD_OPS[m]
            src = f"c->xmm[{XM[o[1].reg]}].d[_k]" if is_xm(1) else f"MRF64(({self.ea(o[1].mem)}) + 8u * (uint32_t)_k)"
            return [f"for (int _k = 0; _k < 2; _k++) {{ double _a = c->xmm[{di}].d[_k], _b = {src}; c->xmm[{di}].d[_k] = sse_r2d(_a, _b, _a {op_c} _b); }}"]

        if m in ("maxpd", "minpd") and is_xm(0):
            di = XM[o[0].reg]
            cmp_op = ">" if m == "maxpd" else "<"
            src = f"c->xmm[{XM[o[1].reg]}].d[_k]" if is_xm(1) else f"MRF64(({self.ea(o[1].mem)}) + 8u * (uint32_t)_k)"
            return [f"for (int _k = 0; _k < 2; _k++) {{ double _a = c->xmm[{di}].d[_k], _b = {src}; c->xmm[{di}].d[_k] = (_a {cmp_op} _b) ? _a : _b; }}"]

        if m == "sqrtpd" and is_xm(0):
            di = XM[o[0].reg]
            src = f"c->xmm[{XM[o[1].reg]}].d[_k]" if is_xm(1) else f"MRF64(({self.ea(o[1].mem)}) + 8u * (uint32_t)_k)"
            return [f"for (int _k = 0; _k < 2; _k++) {{ double _x = {src}; c->xmm[{di}].d[_k] = sqrt(_x); }}"]

        if m in ("haddps", "hsubps", "addsubps") and is_xm(0):
            di = XM[o[0].reg]
            pre = "" if is_xm(1) else f"float _ms[4]; memcpy(_ms, g_mem + (uint32_t){self.ea(o[1].mem)}, 16); "
            sv = f"c->xmm[{XM[o[1].reg]}].f" if is_xm(1) else "_ms"
            if m in ("haddps", "hsubps"):
                op_c = "+" if m == "haddps" else "-"
                return [
                    f"{{ {pre}float _t0 = c->xmm[{di}].f[0] {op_c} c->xmm[{di}].f[1], _t1 = c->xmm[{di}].f[2] {op_c} c->xmm[{di}].f[3]; "
                    f"float _t2 = {sv}[0] {op_c} {sv}[1], _t3 = {sv}[2] {op_c} {sv}[3]; "
                    f"c->xmm[{di}].f[0] = _t0; c->xmm[{di}].f[1] = _t1; c->xmm[{di}].f[2] = _t2; c->xmm[{di}].f[3] = _t3; }}"
                ]
            return [
                f"{{ {pre}c->xmm[{di}].f[0] -= {sv}[0]; c->xmm[{di}].f[1] += {sv}[1]; "
                f"c->xmm[{di}].f[2] -= {sv}[2]; c->xmm[{di}].f[3] += {sv}[3]; }}"
            ]

        # ------------------------------------------------------------------
        # SSE / SSE2 Comparisons (comiss, ucomiss, comisd, ucomisd, cmp*{ps,ss,pd,sd})
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

        CMP_PRED_MAP = {"eq": 0, "lt": 1, "le": 2, "unord": 3, "neq": 4, "nlt": 5, "nle": 6, "ord": 7}
        if is_xm(0) and (
            m in ("cmpps", "cmpss", "cmppd", "cmpsd")
            or (m.startswith("cmp") and len(m) >= 7 and m[-2:] in ("ps", "ss", "pd", "sd") and m[3:-2] in CMP_PRED_MAP)
        ):
            di = XM[o[0].reg]
            suf = m[-2:]
            pred = (o[2].imm & 7) if m in ("cmpps", "cmpss", "cmppd", "cmpsd") else CMP_PRED_MAP[m[3:-2]]
            p_expr = {
                0: "(_x == _y)",
                1: "(_x < _y)",
                2: "(_x <= _y)",
                3: "(_x != _x || _y != _y)",
                4: "(!(_x == _y))",
                5: "(!(_x < _y))",
                6: "(!(_x <= _y))",
                7: "(_x == _x && _y == _y)",
            }[pred]
            if suf == "ss":
                src = f"c->xmm[{XM[o[1].reg]}].f[0]" if is_xm(1) else f"MRF32{self.ea(o[1].mem)}"
                return [f"{{ float _x = c->xmm[{di}].f[0], _y = {src}; c->xmm[{di}].u32[0] = {p_expr} ? 0xffffffffu : 0u; }}"]
            if suf == "ps":
                src = f"c->xmm[{XM[o[1].reg]}].f[_k]" if is_xm(1) else f"MRF32(({self.ea(o[1].mem)}) + 4u * (uint32_t)_k)"
                return [f"for (int _k = 0; _k < 4; _k++) {{ float _x = c->xmm[{di}].f[_k], _y = {src}; c->xmm[{di}].u32[_k] = {p_expr} ? 0xffffffffu : 0u; }}"]
            if suf == "sd":
                src = f"c->xmm[{XM[o[1].reg]}].d[0]" if is_xm(1) else f"MRF64{self.ea(o[1].mem)}"
                return [f"{{ double _x = c->xmm[{di}].d[0], _y = {src}; c->xmm[{di}].u64[0] = {p_expr} ? 0xffffffffffffffffULL : 0ULL; }}"]
            src = f"c->xmm[{XM[o[1].reg]}].d[_k]" if is_xm(1) else f"MRF64(({self.ea(o[1].mem)}) + 8u * (uint32_t)_k)"
            return [f"for (int _k = 0; _k < 2; _k++) {{ double _x = c->xmm[{di}].d[_k], _y = {src}; c->xmm[{di}].u64[_k] = {p_expr} ? 0xffffffffffffffffULL : 0ULL; }}"]

        # ------------------------------------------------------------------
        # SSE / SSE2 / MMX Conversions & Extra Moves
        # ------------------------------------------------------------------
        if m == "cvtsi2ss" and is_xm(0):
            return [f"c->xmm[{XM[o[0].reg]}].f[0] = (float)(int32_t)({E(1)});"]
        if m == "cvtsi2sd" and is_xm(0):
            return [f"c->xmm[{XM[o[0].reg]}].d[0] = (double)(int32_t)({E(1)});"]

        if m in ("cvttss2si", "cvtss2si"):
            src = f"c->xmm[{XM[o[1].reg]}].f[0]" if is_xm(1) else f"MRF32{self.ea(o[1].mem)}"
            expr = f"trunc((double)({src}))" if m == "cvttss2si" else f"nearbyint((double)({src}))"
            return [W(0, f"x86_cvt_i32({expr})")]

        if m in ("cvttsd2si", "cvtsd2si"):
            src = f"c->xmm[{XM[o[1].reg]}].d[0]" if is_xm(1) else f"MRF64{self.ea(o[1].mem)}"
            expr = f"trunc({src})" if m == "cvttsd2si" else f"nearbyint({src})"
            return [W(0, f"x86_cvt_i32({expr})")]

        if m == "cvtss2sd" and is_xm(0):
            src = f"c->xmm[{XM[o[1].reg]}].f[0]" if is_xm(1) else f"MRF32{self.ea(o[1].mem)}"
            return [f"c->xmm[{XM[o[0].reg]}].d[0] = (double)({src});"]

        if m == "cvtsd2ss" and is_xm(0):
            src = f"c->xmm[{XM[o[1].reg]}].d[0]" if is_xm(1) else f"MRF64{self.ea(o[1].mem)}"
            return [f"c->xmm[{XM[o[0].reg]}].f[0] = (float)({src});"]

        if m == "cvtdq2ps" and is_xm(0):
            di = XM[o[0].reg]
            src = f"c->xmm[{XM[o[1].reg]}].u32[_k]" if is_xm(1) else f"MR32(({self.ea(o[1].mem)}) + 4u * (uint32_t)_k)"
            return [f"for (int _k = 0; _k < 4; _k++) c->xmm[{di}].f[_k] = (float)(int32_t)({src});"]

        if m in ("cvtps2dq", "cvttps2dq") and is_xm(0):
            di = XM[o[0].reg]
            src = f"c->xmm[{XM[o[1].reg]}].f[_k]" if is_xm(1) else f"MRF32(({self.ea(o[1].mem)}) + 4u * (uint32_t)_k)"
            fn = "trunc" if m == "cvttps2dq" else "nearbyint"
            return [f"for (int _k = 0; _k < 4; _k++) c->xmm[{di}].u32[_k] = x86_cvt_i32({fn}((double)({src})));"]

        if m == "cvtdq2pd" and is_xm(0):
            di = XM[o[0].reg]
            s0 = f"c->xmm[{XM[o[1].reg]}].u32[0]" if is_xm(1) else f"MR32({self.ea(o[1].mem)})"
            s1 = f"c->xmm[{XM[o[1].reg]}].u32[1]" if is_xm(1) else f"MR32(({self.ea(o[1].mem)}) + 4u)"
            return [f"{{ int32_t _i0 = (int32_t)({s0}), _i1 = (int32_t)({s1}); c->xmm[{di}].d[0] = (double)_i0; c->xmm[{di}].d[1] = (double)_i1; }}"]

        if m in ("cvtpd2dq", "cvttpd2dq") and is_xm(0):
            di = XM[o[0].reg]
            s0 = f"c->xmm[{XM[o[1].reg]}].d[0]" if is_xm(1) else f"MRF64({self.ea(o[1].mem)})"
            s1 = f"c->xmm[{XM[o[1].reg]}].d[1]" if is_xm(1) else f"MRF64(({self.ea(o[1].mem)}) + 8u)"
            fn = "trunc" if m == "cvttpd2dq" else "nearbyint"
            return [f"{{ double _d0 = ({s0}), _d1 = ({s1}); c->xmm[{di}].u32[0] = x86_cvt_i32({fn}(_d0)); c->xmm[{di}].u32[1] = x86_cvt_i32({fn}(_d1)); c->xmm[{di}].u64[1] = 0; }}"]

        if m == "cvtps2pd" and is_xm(0):
            di = XM[o[0].reg]
            s0 = f"c->xmm[{XM[o[1].reg]}].f[0]" if is_xm(1) else f"MRF32({self.ea(o[1].mem)})"
            s1 = f"c->xmm[{XM[o[1].reg]}].f[1]" if is_xm(1) else f"MRF32(({self.ea(o[1].mem)}) + 4u)"
            return [f"{{ float _f0 = ({s0}), _f1 = ({s1}); c->xmm[{di}].d[0] = (double)_f0; c->xmm[{di}].d[1] = (double)_f1; }}"]

        if m == "cvtpd2ps" and is_xm(0):
            di = XM[o[0].reg]
            s0 = f"c->xmm[{XM[o[1].reg]}].d[0]" if is_xm(1) else f"MRF64({self.ea(o[1].mem)})"
            s1 = f"c->xmm[{XM[o[1].reg]}].d[1]" if is_xm(1) else f"MRF64(({self.ea(o[1].mem)}) + 8u)"
            return [f"{{ double _d0 = ({s0}), _d1 = ({s1}); c->xmm[{di}].f[0] = (float)_d0; c->xmm[{di}].f[1] = (float)_d1; c->xmm[{di}].u64[1] = 0; }}"]

        if m == "cvtpi2ps" and is_xm(0):
            di = XM[o[0].reg]
            src = f"c->mm[{MM[o[1].reg]}]" if is_mm(1) else f"MR64{self.ea(o[1].mem)}"
            return [f"{{ uint64_t _q = ({src}); c->xmm[{di}].f[0] = (float)(int32_t)(uint32_t)_q; c->xmm[{di}].f[1] = (float)(int32_t)(uint32_t)(_q >> 32); }}"]

        if m in ("cvtps2pi", "cvttps2pi") and is_mm(0):
            di = MM[o[0].reg]
            s0 = f"c->xmm[{XM[o[1].reg]}].f[0]" if is_xm(1) else f"MRF32({self.ea(o[1].mem)})"
            s1 = f"c->xmm[{XM[o[1].reg]}].f[1]" if is_xm(1) else f"MRF32(({self.ea(o[1].mem)}) + 4u)"
            fn = "trunc" if m == "cvttps2pi" else "nearbyint"
            return [f"{{ uint32_t _l = x86_cvt_i32({fn}((double)({s0}))), _h = x86_cvt_i32({fn}((double)({s1}))); c->mm[{di}] = ((uint64_t)_h << 32) | _l; }}"]

        if m == "cvtpi2pd" and is_xm(0):
            di = XM[o[0].reg]
            src = f"c->mm[{MM[o[1].reg]}]" if is_mm(1) else f"MR64{self.ea(o[1].mem)}"
            return [f"{{ uint64_t _q = ({src}); c->xmm[{di}].d[0] = (double)(int32_t)(uint32_t)_q; c->xmm[{di}].d[1] = (double)(int32_t)(uint32_t)(_q >> 32); }}"]

        if m in ("cvtpd2pi", "cvttpd2pi") and is_mm(0):
            di = MM[o[0].reg]
            s0 = f"c->xmm[{XM[o[1].reg]}].d[0]" if is_xm(1) else f"MRF64({self.ea(o[1].mem)})"
            s1 = f"c->xmm[{XM[o[1].reg]}].d[1]" if is_xm(1) else f"MRF64(({self.ea(o[1].mem)}) + 8u)"
            fn = "trunc" if m == "cvttpd2pi" else "nearbyint"
            return [f"{{ uint32_t _l = x86_cvt_i32({fn}({s0})), _h = x86_cvt_i32({fn}({s1})); c->mm[{di}] = ((uint64_t)_h << 32) | _l; }}"]

        if m in ("movntps", "movntpd", "movntdq") and is_mem(0) and is_xm(1):
            return [f"memcpy(g_mem + (uint32_t){self.ea(o[0].mem)}, &c->xmm[{XM[o[1].reg]}], 16);"]
        if m == "lddqu" and is_xm(0) and is_mem(1):
            return [f"memcpy(&c->xmm[{XM[o[0].reg]}], g_mem + (uint32_t){self.ea(o[1].mem)}, 16);"]
        if m == "movntq" and is_mem(0) and is_mm(1):
            return [f"MR64{self.ea(o[0].mem)} = c->mm[{MM[o[1].reg]}];"]
        if m == "movnti" and is_mem(0):
            return [f"MR32{self.ea(o[0].mem)} = {E(1)};"]
        if m == "movq2dq" and is_xm(0) and is_mm(1):
            return [f"c->xmm[{XM[o[0].reg]}].u64[0] = c->mm[{MM[o[1].reg]}]; c->xmm[{XM[o[0].reg]}].u64[1] = 0;"]
        if m == "movdq2q" and is_mm(0) and is_xm(1):
            return [f"c->mm[{MM[o[0].reg]}] = c->xmm[{XM[o[1].reg]}].u64[0];"]
        if m in ("movlpd", "movhpd"):
            idx_d = 0 if m == "movlpd" else 1
            if is_xm(0) and is_mem(1):
                return [f"c->xmm[{XM[o[0].reg]}].u64[{idx_d}] = MR64{self.ea(o[1].mem)};"]
            if is_mem(0) and is_xm(1):
                return [f"MR64{self.ea(o[0].mem)} = c->xmm[{XM[o[1].reg]}].u64[{idx_d}];"]
        if m in ("movsldup", "movshdup") and is_xm(0):
            di = XM[o[0].reg]
            off_s = 0 if m == "movsldup" else 1
            if is_xm(1):
                si = XM[o[1].reg]
                return [f"{{ uint32_t _a = c->xmm[{si}].u32[{off_s}], _b = c->xmm[{si}].u32[{2+off_s}]; c->xmm[{di}].u32[0] = c->xmm[{di}].u32[1] = _a; c->xmm[{di}].u32[2] = c->xmm[{di}].u32[3] = _b; }}"]
            ea = self.ea(o[1].mem)
            return [f"{{ uint32_t _a = MR32(({ea}) + {4*off_s}u), _b = MR32(({ea}) + {4*(2+off_s)}u); c->xmm[{di}].u32[0] = c->xmm[{di}].u32[1] = _a; c->xmm[{di}].u32[2] = c->xmm[{di}].u32[3] = _b; }}"]
        if m == "movddup" and is_xm(0):
            di = XM[o[0].reg]
            src = f"c->xmm[{XM[o[1].reg]}].u64[0]" if is_xm(1) else f"MR64{self.ea(o[1].mem)}"
            return [f"{{ uint64_t _q = ({src}); c->xmm[{di}].u64[0] = c->xmm[{di}].u64[1] = _q; }}"]

        # ------------------------------------------------------------------
        # Shuffles, Permutations, Unpacks, Packs, Masks & Extracts
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

        if m == "shufpd" and is_xm(0) and len(o) > 2 and o[2].type == CS_OP_IMM:
            di = XM[o[0].reg]
            imm = o[2].imm & 0x03
            pre = "" if is_xm(1) else f"uint64_t _m[2]; memcpy(_m, g_mem + (uint32_t){self.ea(o[1].mem)}, 16); "
            src = f"c->xmm[{XM[o[1].reg]}].u64" if is_xm(1) else "_m"
            return [f"{{ {pre}uint64_t _t0 = c->xmm[{di}].u64[{imm & 1}], _t1 = {src}[{(imm >> 1) & 1}]; c->xmm[{di}].u64[0] = _t0; c->xmm[{di}].u64[1] = _t1; }}"]

        if m == "pshufd" and is_xm(0) and len(o) > 2 and o[2].type == CS_OP_IMM:
            di = XM[o[0].reg]
            imm = o[2].imm & 0xFF
            sel = [(imm >> 0) & 3, (imm >> 2) & 3, (imm >> 4) & 3, (imm >> 6) & 3]
            pre = "" if is_xm(1) else f"uint32_t _m[4]; memcpy(_m, g_mem + (uint32_t){self.ea(o[1].mem)}, 16); "
            src = f"c->xmm[{XM[o[1].reg]}].u32" if is_xm(1) else "_m"
            return [
                f"{{ {pre}uint32_t _t0 = {src}[{sel[0]}], _t1 = {src}[{sel[1]}], _t2 = {src}[{sel[2]}], _t3 = {src}[{sel[3]}]; "
                f"c->xmm[{di}].u32[0] = _t0; c->xmm[{di}].u32[1] = _t1; c->xmm[{di}].u32[2] = _t2; c->xmm[{di}].u32[3] = _t3; }}"
            ]

        if m in ("pshuflw", "pshufhw") and is_xm(0) and len(o) > 2 and o[2].type == CS_OP_IMM:
            di = XM[o[0].reg]
            imm = o[2].imm & 0xFF
            sel = [(imm >> 0) & 3, (imm >> 2) & 3, (imm >> 4) & 3, (imm >> 6) & 3]
            pre = f"xmm_reg_t _s = c->xmm[{XM[o[1].reg]}]; " if is_xm(1) else f"xmm_reg_t _s; memcpy(&_s, g_mem + (uint32_t){self.ea(o[1].mem)}, 16); "
            base_w = 0 if m == "pshuflw" else 4
            other_q = 1 if m == "pshuflw" else 0
            return [
                f"{{ {pre}uint16_t _sw[8]; memcpy(_sw, &_s, 16); uint16_t _dw[8]; memcpy(_dw, &_s, 16); "
                f"_dw[{base_w+0}] = _sw[{base_w+sel[0]}]; _dw[{base_w+1}] = _sw[{base_w+sel[1]}]; "
                f"_dw[{base_w+2}] = _sw[{base_w+sel[2]}]; _dw[{base_w+3}] = _sw[{base_w+sel[3]}]; "
                f"memcpy(&c->xmm[{di}], _dw, 16); c->xmm[{di}].u64[{other_q}] = _s.u64[{other_q}]; }}"
            ]

        if m == "pshufw" and is_mm(0) and len(o) > 2 and o[2].type == CS_OP_IMM:
            di = MM[o[0].reg]
            imm = o[2].imm & 0xFF
            sel = [(imm >> 0) & 3, (imm >> 2) & 3, (imm >> 4) & 3, (imm >> 6) & 3]
            src = f"c->mm[{MM[o[1].reg]}]" if is_mm(1) else f"MR64{self.ea(o[1].mem)}"
            return [
                f"{{ uint64_t _s = ({src}); "
                f"uint64_t _r = (((_s >> ({16*sel[0]})) & 0xffffULL) << 0) | (((_s >> ({16*sel[1]})) & 0xffffULL) << 16) | "
                f"(((_s >> ({16*sel[2]})) & 0xffffULL) << 32) | (((_s >> ({16*sel[3]})) & 0xffffULL) << 48); "
                f"c->mm[{di}] = _r; }}"
            ]

        if m in ("unpcklps", "unpckhps") and is_xm(0):
            di = XM[o[0].reg]
            o0 = 2 if m == "unpckhps" else 0
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

        if m in ("unpcklpd", "unpckhpd", "punpcklqdq", "punpckhqdq") and is_xm(0):
            di = XM[o[0].reg]
            hi = 1 if m in ("unpckhpd", "punpckhqdq") else 0
            src_q = f"c->xmm[{XM[o[1].reg]}].u64[{hi}]" if is_xm(1) else f"MR64(({self.ea(o[1].mem)}) + {8*hi}u)"
            return [f"{{ uint64_t _t0 = c->xmm[{di}].u64[{hi}], _t1 = ({src_q}); c->xmm[{di}].u64[0] = _t0; c->xmm[{di}].u64[1] = _t1; }}"]

        if m in ("punpcklbw", "punpckhbw", "punpcklwd", "punpckhwd", "punpckldq", "punpckhdq"):
            elem_sz = 1 if m.endswith("bw") else (2 if m.endswith("wd") else 4)
            is_hi = "punpckh" in m
            if is_xm(0):
                di = XM[o[0].reg]
                cnt_e = 8 // elem_sz
                off_b = 8 if is_hi else 0
                pre = f"xmm_reg_t _s = c->xmm[{XM[o[1].reg]}]; " if is_xm(1) else f"xmm_reg_t _s; memcpy(&_s, g_mem + (uint32_t){self.ea(o[1].mem)}, 16); "
                return [
                    f"{{ {pre}uint8_t _d[16], _r[16]; memcpy(_d, &c->xmm[{di}], 16); "
                    f"for (int _k = 0; _k < {cnt_e}; _k++) {{ "
                    f"memcpy(_r + _k * {2*elem_sz}, _d + {off_b} + _k * {elem_sz}, {elem_sz}); "
                    f"memcpy(_r + _k * {2*elem_sz} + {elem_sz}, _s.b + {off_b} + _k * {elem_sz}, {elem_sz}); }} "
                    f"memcpy(&c->xmm[{di}], _r, 16); }}"
                ]
            if is_mm(0):
                di = MM[o[0].reg]
                cnt_e = 4 // elem_sz
                off_b = 4 if is_hi else 0
                src = f"c->mm[{MM[o[1].reg]}]" if is_mm(1) else (f"MR32{self.ea(o[1].mem)}" if (not is_hi and o[1].size == 4) else f"MR64{self.ea(o[1].mem)}")
                return [
                    f"{{ uint64_t _sv = (uint64_t)({src}); uint8_t _d[8], _s[8], _r[8]; "
                    f"memcpy(_d, &c->mm[{di}], 8); memcpy(_s, &_sv, 8); "
                    f"for (int _k = 0; _k < {cnt_e}; _k++) {{ "
                    f"memcpy(_r + _k * {2*elem_sz}, _d + {off_b} + _k * {elem_sz}, {elem_sz}); "
                    f"memcpy(_r + _k * {2*elem_sz} + {elem_sz}, _s + {off_b} + _k * {elem_sz}, {elem_sz}); }} "
                    f"memcpy(&c->mm[{di}], _r, 8); }}"
                ]

        if m in ("packssdw", "packsswb", "packuswb") and (is_xm(0) or is_mm(0)):
            if is_xm(0):
                di = XM[o[0].reg]
                pre = f"xmm_reg_t _s = c->xmm[{XM[o[1].reg]}]; " if is_xm(1) else f"xmm_reg_t _s; memcpy(&_s, g_mem + (uint32_t){self.ea(o[1].mem)}, 16); "
                if m == "packssdw":
                    return [
                        f"{{ {pre}int16_t _r[8]; int32_t _in[8]; memcpy(_in, &c->xmm[{di}], 16); memcpy(_in + 4, &_s, 16); "
                        f"for (int _k = 0; _k < 8; _k++) {{ int32_t _v = _in[_k]; _r[_k] = _v > 32767 ? 32767 : (_v < -32768 ? -32768 : (int16_t)_v); }} "
                        f"memcpy(&c->xmm[{di}], _r, 16); }}"
                    ]
                if m == "packsswb":
                    return [
                        f"{{ {pre}int8_t _r[16]; int16_t _in[16]; memcpy(_in, &c->xmm[{di}], 16); memcpy(_in + 8, &_s, 16); "
                        f"for (int _k = 0; _k < 16; _k++) {{ int16_t _v = _in[_k]; _r[_k] = _v > 127 ? 127 : (_v < -128 ? -128 : (int8_t)_v); }} "
                        f"memcpy(&c->xmm[{di}], _r, 16); }}"
                    ]
                return [
                    f"{{ {pre}uint8_t _r[16]; int16_t _in[16]; memcpy(_in, &c->xmm[{di}], 16); memcpy(_in + 8, &_s, 16); "
                    f"for (int _k = 0; _k < 16; _k++) {{ int16_t _v = _in[_k]; _r[_k] = _v > 255 ? 255u : (_v < 0 ? 0u : (uint8_t)_v); }} "
                    f"memcpy(&c->xmm[{di}], _r, 16); }}"
                ]
            di = MM[o[0].reg]
            src = f"c->mm[{MM[o[1].reg]}]" if is_mm(1) else f"MR64{self.ea(o[1].mem)}"
            if m == "packssdw":
                return [
                    f"{{ uint64_t _sv = ({src}); int16_t _r[4]; int32_t _in[4]; memcpy(_in, &c->mm[{di}], 8); memcpy(_in + 2, &_sv, 8); "
                    f"for (int _k = 0; _k < 4; _k++) {{ int32_t _v = _in[_k]; _r[_k] = _v > 32767 ? 32767 : (_v < -32768 ? -32768 : (int16_t)_v); }} "
                    f"memcpy(&c->mm[{di}], _r, 8); }}"
                ]
            if m == "packsswb":
                return [
                    f"{{ uint64_t _sv = ({src}); int8_t _r[8]; int16_t _in[8]; memcpy(_in, &c->mm[{di}], 8); memcpy(_in + 4, &_sv, 8); "
                    f"for (int _k = 0; _k < 8; _k++) {{ int16_t _v = _in[_k]; _r[_k] = _v > 127 ? 127 : (_v < -128 ? -128 : (int8_t)_v); }} "
                    f"memcpy(&c->mm[{di}], _r, 8); }}"
                ]
            return [
                f"{{ uint64_t _sv = ({src}); uint8_t _r[8]; int16_t _in[8]; memcpy(_in, &c->mm[{di}], 8); memcpy(_in + 4, &_sv, 8); "
                f"for (int _k = 0; _k < 8; _k++) {{ int16_t _v = _in[_k]; _r[_k] = _v > 255 ? 255u : (_v < 0 ? 0u : (uint8_t)_v); }} "
                f"memcpy(&c->mm[{di}], _r, 8); }}"
            ]

        if m == "movmskps" and is_gp(0) and is_xm(1):
            si = XM[o[1].reg]
            return [f"{self._reg_name(R32[o[0].reg])} = ((c->xmm[{si}].u32[0] >> 31) & 1u) | (((c->xmm[{si}].u32[1] >> 31) & 1u) << 1) | (((c->xmm[{si}].u32[2] >> 31) & 1u) << 2) | (((c->xmm[{si}].u32[3] >> 31) & 1u) << 3);"]
        if m == "movmskpd" and is_gp(0) and is_xm(1):
            si = XM[o[1].reg]
            return [f"{self._reg_name(R32[o[0].reg])} = (uint32_t)(((c->xmm[{si}].u64[0] >> 63) & 1u) | (((c->xmm[{si}].u64[1] >> 63) & 1u) << 1));"]
        if m == "pmovmskb" and is_gp(0):
            rn = self._reg_name(R32[o[0].reg])
            if is_xm(1):
                si = XM[o[1].reg]
                return [f"{{ uint32_t _m = 0; for (int _k = 0; _k < 16; _k++) _m |= ((uint32_t)(c->xmm[{si}].b[_k] >> 7) << _k); {rn} = _m; }}"]
            if is_mm(1):
                si = MM[o[1].reg]
                return [f"{{ uint64_t _q = c->mm[{si}]; uint32_t _m = 0; for (int _k = 0; _k < 8; _k++) _m |= ((uint32_t)((_q >> (_k * 8 + 7)) & 1u) << _k); {rn} = _m; }}"]

        if m == "pextrw" and is_gp(0) and len(o) > 2 and o[2].type == CS_OP_IMM:
            rn = self._reg_name(R32[o[0].reg])
            if is_xm(1):
                idx_w = o[2].imm & 7
                return [f"{{ uint16_t _w[8]; memcpy(_w, &c->xmm[{XM[o[1].reg]}], 16); {rn} = (uint32_t)_w[{idx_w}]; }}"]
            if is_mm(1):
                idx_w = o[2].imm & 3
                return [f"{rn} = (uint32_t)((c->mm[{MM[o[1].reg]}] >> {16 * idx_w}) & 0xffffu);"]

        if m == "pinsrw" and len(o) > 2 and o[2].type == CS_OP_IMM:
            val_expr = f"(uint16_t)({self._reg_name(R32[o[1].reg])})" if is_gp(1) else f"MR16{self.ea(o[1].mem)}"
            if is_xm(0):
                di = XM[o[0].reg]
                idx_w = o[2].imm & 7
                return [f"{{ uint16_t _w[8]; memcpy(_w, &c->xmm[{di}], 16); _w[{idx_w}] = {val_expr}; memcpy(&c->xmm[{di}], _w, 16); }}"]
            if is_mm(0):
                di = MM[o[0].reg]
                idx_w = o[2].imm & 3
                sh = 16 * idx_w
                return [f"c->mm[{di}] = (c->mm[{di}] & ~(0xffffULL << {sh})) | ((uint64_t)({val_expr}) << {sh});"]

        if m == "maskmovdqu" and is_xm(0) and is_xm(1):
            edi = self._reg_name("edi")
            return [f"for (int _k = 0; _k < 16; _k++) if (c->xmm[{XM[o[1].reg]}].b[_k] & 0x80u) MR8({edi} + (uint32_t)_k) = c->xmm[{XM[o[0].reg]}].b[_k];"]
        if m == "maskmovq" and is_mm(0) and is_mm(1):
            edi = self._reg_name("edi")
            return [f"for (int _k = 0; _k < 8; _k++) if ((c->mm[{MM[o[1].reg]}] >> (_k * 8 + 7)) & 1u) MR8({edi} + (uint32_t)_k) = (uint8_t)(c->mm[{MM[o[0].reg]}] >> (_k * 8));"]

        if m in ("emms", "femms", "sfence", "lfence", "mfence", "pause", "clflush") or m.startswith("prefetch"):
            return [f"/* {m} */"]
        if m == "ldmxcsr" and is_mem(0):
            return [f"(void)MR32{self.ea(o[0].mem)}; /* ldmxcsr */"]
        if m == "stmxcsr" and is_mem(0):
            return [f"MR32{self.ea(o[0].mem)} = 0x1f80u; /* stmxcsr */"]
        if m in ("fnstenv", "fstenv") and is_mem(0):
            ea = self.ea(o[0].mem)
            return [f"MR32({ea}) = c->fcw; MR32(({ea}) + 4u) = fsw_get(c);"]
        if m == "fldenv" and is_mem(0):
            ea = self.ea(o[0].mem)
            return [f"c->fcw = (uint16_t)MR32({ea}); c->fsw = (uint16_t)MR32(({ea}) + 4u); c->top = (c->fsw >> 11) & 7;"]

        # ------------------------------------------------------------------
        # Integer SIMD (Arithmetic, Shifts, Compares, Min/Max/Avg)
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
            di = MM[o[0].reg]
            src = f"c->mm[{MM[o[1].reg]}]" if is_mm(1) else f"MR64{self.ea(o[1].mem)}"
            return [
                f"{{ uint64_t _s = ({src}); "
                f"c->mm[{di}] = ((uint64_t)((uint32_t)(c->mm[{di}] >> 32) {op_c} (uint32_t)(_s >> 32)) << 32) | "
                f"((uint32_t)c->mm[{di}] {op_c} (uint32_t)_s); }}"
            ]

        if m in ("paddb", "psubb", "paddw", "psubw", "paddq", "psubq") and (is_xm(0) or is_mm(0)):
            op_c = "+" if m.startswith("padd") else "-"
            elem = m[-1]
            if is_xm(0):
                di = XM[o[0].reg]
                pre = f"xmm_reg_t _s = c->xmm[{XM[o[1].reg]}]; " if is_xm(1) else f"xmm_reg_t _s; memcpy(&_s, g_mem + (uint32_t){self.ea(o[1].mem)}, 16); "
                if elem == "b":
                    return [f"{{ {pre}for (int _k = 0; _k < 16; _k++) c->xmm[{di}].b[_k] = (uint8_t)(c->xmm[{di}].b[_k] {op_c} _s.b[_k]); }}"]
                if elem == "w":
                    return [f"{{ {pre}uint16_t _d[8], _sw[8]; memcpy(_d, &c->xmm[{di}], 16); memcpy(_sw, &_s, 16); for (int _k = 0; _k < 8; _k++) _d[_k] = (uint16_t)(_d[_k] {op_c} _sw[_k]); memcpy(&c->xmm[{di}], _d, 16); }}"]
                return [f"{{ {pre}c->xmm[{di}].u64[0] {op_c}= _s.u64[0]; c->xmm[{di}].u64[1] {op_c}= _s.u64[1]; }}"]
            di = MM[o[0].reg]
            src = f"c->mm[{MM[o[1].reg]}]" if is_mm(1) else f"MR64{self.ea(o[1].mem)}"
            if elem == "q":
                return [f"c->mm[{di}] {op_c}= ({src});"]
            cnt_e = 8 if elem == "b" else 4
            tp = "uint8_t" if elem == "b" else "uint16_t"
            return [f"{{ uint64_t _sv = ({src}); {tp} _d[{cnt_e}], _s[{cnt_e}]; memcpy(_d, &c->mm[{di}], 8); memcpy(_s, &_sv, 8); for (int _k = 0; _k < {cnt_e}; _k++) _d[_k] = ({tp})(_d[_k] {op_c} _s[_k]); memcpy(&c->mm[{di}], _d, 8); }}"]

        if m in ("paddsb", "psubsb", "paddusb", "psubusb", "paddsw", "psubsw", "paddusw", "psubusw") and (is_xm(0) or is_mm(0)):
            op_c = "+" if m.startswith("padd") else "-"
            unsigned = "us" in m
            is_w = m.endswith("w")
            tp = ("uint16_t" if unsigned else "int16_t") if is_w else ("uint8_t" if unsigned else "int8_t")
            lo = 0 if unsigned else (-32768 if is_w else -128)
            hi = (65535 if unsigned else 32767) if is_w else (255 if unsigned else 127)
            if is_xm(0):
                di = XM[o[0].reg]
                cnt_e = 8 if is_w else 16
                pre = f"xmm_reg_t _s = c->xmm[{XM[o[1].reg]}]; " if is_xm(1) else f"xmm_reg_t _s; memcpy(&_s, g_mem + (uint32_t){self.ea(o[1].mem)}, 16); "
                return [f"{{ {pre}{tp} _d[{cnt_e}], _sv[{cnt_e}]; memcpy(_d, &c->xmm[{di}], 16); memcpy(_sv, &_s, 16); for (int _k = 0; _k < {cnt_e}; _k++) {{ int32_t _v = (int32_t)_d[_k] {op_c} (int32_t)_sv[_k]; _d[_k] = ({tp})(_v > {hi} ? {hi} : (_v < {lo} ? {lo} : _v)); }} memcpy(&c->xmm[{di}], _d, 16); }}"]
            di = MM[o[0].reg]
            cnt_e = 4 if is_w else 8
            src = f"c->mm[{MM[o[1].reg]}]" if is_mm(1) else f"MR64{self.ea(o[1].mem)}"
            return [f"{{ uint64_t _sq = ({src}); {tp} _d[{cnt_e}], _sv[{cnt_e}]; memcpy(_d, &c->mm[{di}], 8); memcpy(_sv, &_sq, 8); for (int _k = 0; _k < {cnt_e}; _k++) {{ int32_t _v = (int32_t)_d[_k] {op_c} (int32_t)_sv[_k]; _d[_k] = ({tp})(_v > {hi} ? {hi} : (_v < {lo} ? {lo} : _v)); }} memcpy(&c->mm[{di}], _d, 8); }}"]

        if m in ("pmullw", "pmulhw", "pmulhuw") and (is_xm(0) or is_mm(0)):
            cast_t = "uint32_t" if m == "pmulhuw" else "int32_t"
            in_t = "uint16_t" if m == "pmulhuw" else "int16_t"
            sh_expr = "(_p >> 16)" if m != "pmullw" else "_p"
            if is_xm(0):
                di = XM[o[0].reg]
                pre = f"xmm_reg_t _s = c->xmm[{XM[o[1].reg]}]; " if is_xm(1) else f"xmm_reg_t _s; memcpy(&_s, g_mem + (uint32_t){self.ea(o[1].mem)}, 16); "
                return [f"{{ {pre}{in_t} _d[8], _sv[8]; memcpy(_d, &c->xmm[{di}], 16); memcpy(_sv, &_s, 16); for (int _k = 0; _k < 8; _k++) {{ {cast_t} _p = ({cast_t})_d[_k] * ({cast_t})_sv[_k]; _d[_k] = ({in_t}){sh_expr}; }} memcpy(&c->xmm[{di}], _d, 16); }}"]
            di = MM[o[0].reg]
            src = f"c->mm[{MM[o[1].reg]}]" if is_mm(1) else f"MR64{self.ea(o[1].mem)}"
            return [f"{{ uint64_t _sq = ({src}); {in_t} _d[4], _sv[4]; memcpy(_d, &c->mm[{di}], 8); memcpy(_sv, &_sq, 8); for (int _k = 0; _k < 4; _k++) {{ {cast_t} _p = ({cast_t})_d[_k] * ({cast_t})_sv[_k]; _d[_k] = ({in_t}){sh_expr}; }} memcpy(&c->mm[{di}], _d, 8); }}"]

        if m == "pmuludq" and (is_xm(0) or is_mm(0)):
            if is_xm(0):
                di = XM[o[0].reg]
                pre = f"xmm_reg_t _s = c->xmm[{XM[o[1].reg]}]; " if is_xm(1) else f"xmm_reg_t _s; memcpy(&_s, g_mem + (uint32_t){self.ea(o[1].mem)}, 16); "
                return [f"{{ {pre}uint64_t _p0 = (uint64_t)c->xmm[{di}].u32[0] * (uint64_t)_s.u32[0]; uint64_t _p1 = (uint64_t)c->xmm[{di}].u32[2] * (uint64_t)_s.u32[2]; c->xmm[{di}].u64[0] = _p0; c->xmm[{di}].u64[1] = _p1; }}"]
            di = MM[o[0].reg]
            src = f"c->mm[{MM[o[1].reg]}]" if is_mm(1) else f"MR64{self.ea(o[1].mem)}"
            return [f"c->mm[{di}] = (uint64_t)(uint32_t)c->mm[{di}] * (uint64_t)(uint32_t)({src});"]

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

        if m in ("psllw", "psrlw", "psraw", "pslld", "psrld", "psrad", "psllq", "psrlq") and (is_xm(0) or is_mm(0)):
            if len(o) > 1:
                if is_xm(1):
                    cnt_q = f"c->xmm[{XM[o[1].reg]}].u64[0]"
                elif is_mm(1):
                    cnt_q = f"c->mm[{MM[o[1].reg]}]"
                elif is_mem(1):
                    cnt_q = f"MR64{self.ea(o[1].mem)}"
                else:
                    cnt_q = f"(uint64_t)({E(1)})"
            else:
                cnt_q = "1ULL"
            if is_xm(0):
                di = XM[o[0].reg]
                if m in ("psllq", "psrlq"):
                    op_s = "<<" if m == "psllq" else ">>"
                    return [f"{{ uint64_t _cnt = ({cnt_q}); if (_cnt < 64ULL) {{ c->xmm[{di}].u64[0] {op_s}= _cnt; c->xmm[{di}].u64[1] {op_s}= _cnt; }} else {{ c->xmm[{di}].u64[0] = c->xmm[{di}].u64[1] = 0; }} }}"]
                if m in ("pslld", "psrld"):
                    op_s = "<<" if m == "pslld" else ">>"
                    return [f"{{ uint64_t _cnt = ({cnt_q}); if (_cnt < 32ULL) {{ for (int _k=0;_k<4;_k++) c->xmm[{di}].u32[_k] {op_s}= (uint32_t)_cnt; }} else {{ memset(&c->xmm[{di}], 0, 16); }} }}"]
                if m == "psrad":
                    return [f"{{ uint64_t _cnt = ({cnt_q}); uint32_t _s = _cnt > 31ULL ? 31u : (uint32_t)_cnt; for (int _k=0;_k<4;_k++) c->xmm[{di}].u32[_k] = (uint32_t)((int32_t)c->xmm[{di}].u32[_k] >> _s); }}"]
                if m in ("psllw", "psrlw"):
                    op_s = "<<" if m == "psllw" else ">>"
                    return [f"{{ uint64_t _cnt = ({cnt_q}); if (_cnt < 16ULL) {{ uint16_t _w[8]; memcpy(_w, &c->xmm[{di}], 16); for (int _k=0;_k<8;_k++) _w[_k] = (uint16_t)(_w[_k] {op_s} (uint32_t)_cnt); memcpy(&c->xmm[{di}], _w, 16); }} else {{ memset(&c->xmm[{di}], 0, 16); }} }}"]
                return [f"{{ uint64_t _cnt = ({cnt_q}); uint32_t _s = _cnt > 15ULL ? 15u : (uint32_t)_cnt; int16_t _w[8]; memcpy(_w, &c->xmm[{di}], 16); for (int _k=0;_k<8;_k++) _w[_k] = (int16_t)(_w[_k] >> _s); memcpy(&c->xmm[{di}], _w, 16); }}"]
            di = MM[o[0].reg]
            if m in ("psllq", "psrlq"):
                op_s = "<<" if m == "psllq" else ">>"
                return [f"{{ uint64_t _cnt = ({cnt_q}); c->mm[{di}] = (_cnt < 64ULL) ? (c->mm[{di}] {op_s} _cnt) : 0ULL; }}"]
            if m in ("pslld", "psrld"):
                op_s = "<<" if m == "pslld" else ">>"
                return [f"{{ uint64_t _cnt = ({cnt_q}); if (_cnt < 32ULL) {{ uint32_t _s = (uint32_t)_cnt, _l = (uint32_t)c->mm[{di}] {op_s} _s, _h = (uint32_t)(c->mm[{di}] >> 32) {op_s} _s; c->mm[{di}] = ((uint64_t)_h << 32) | _l; }} else {{ c->mm[{di}] = 0ULL; }} }}"]
            if m == "psrad":
                return [f"{{ uint64_t _cnt = ({cnt_q}); uint32_t _s = _cnt > 31ULL ? 31u : (uint32_t)_cnt; uint32_t _l = (uint32_t)((int32_t)(uint32_t)c->mm[{di}] >> _s), _h = (uint32_t)((int32_t)(uint32_t)(c->mm[{di}] >> 32) >> _s); c->mm[{di}] = ((uint64_t)_h << 32) | _l; }}"]
            if m in ("psllw", "psrlw"):
                op_s = "<<" if m == "psllw" else ">>"
                return [f"{{ uint64_t _cnt = ({cnt_q}); if (_cnt < 16ULL) {{ uint16_t _w[4]; memcpy(_w, &c->mm[{di}], 8); for (int _k=0;_k<4;_k++) _w[_k] = (uint16_t)(_w[_k] {op_s} (uint32_t)_cnt); memcpy(&c->mm[{di}], _w, 8); }} else {{ c->mm[{di}] = 0ULL; }} }}"]
            return [f"{{ uint64_t _cnt = ({cnt_q}); uint32_t _s = _cnt > 15ULL ? 15u : (uint32_t)_cnt; int16_t _w[4]; memcpy(_w, &c->mm[{di}], 8); for (int _k=0;_k<4;_k++) _w[_k] = (int16_t)(_w[_k] >> _s); memcpy(&c->mm[{di}], _w, 8); }}"]

        if m in ("pslldq", "psrldq") and is_xm(0) and len(o) > 1 and o[1].type == CS_OP_IMM:
            di = XM[o[0].reg]
            sh_b = o[1].imm & 0xFF
            if sh_b >= 16:
                return [f"memset(&c->xmm[{di}], 0, 16);"]
            if sh_b == 0:
                return ["/* pslldq/psrldq 0 */"]
            if m == "pslldq":
                return [f"{{ uint8_t _t[16] = {{0}}; memcpy(_t + {sh_b}, c->xmm[{di}].b, {16 - sh_b}); memcpy(&c->xmm[{di}], _t, 16); }}"]
            return [f"{{ uint8_t _t[16] = {{0}}; memcpy(_t, c->xmm[{di}].b + {sh_b}, {16 - sh_b}); memcpy(&c->xmm[{di}], _t, 16); }}"]

        if m in ("pcmpeqb", "pcmpeqw", "pcmpeqd", "pcmpgtb", "pcmpgtw", "pcmpgtd") and (is_xm(0) or is_mm(0)):
            is_eq = "eq" in m
            elem = m[-1]
            tp = {"b": "int8_t", "w": "int16_t", "d": "int32_t"}[elem]
            utp = {"b": "uint8_t", "w": "uint16_t", "d": "uint32_t"}[elem]
            ones = {"b": "0xffu", "w": "0xffffu", "d": "0xffffffffu"}[elem]
            op_c = "==" if is_eq else ">"
            if is_xm(0):
                di = XM[o[0].reg]
                cnt_e = {"b": 16, "w": 8, "d": 4}[elem]
                pre = f"xmm_reg_t _s = c->xmm[{XM[o[1].reg]}]; " if is_xm(1) else f"xmm_reg_t _s; memcpy(&_s, g_mem + (uint32_t){self.ea(o[1].mem)}, 16); "
                return [f"{{ {pre}{tp} _d[{cnt_e}], _sv[{cnt_e}]; {utp} _r[{cnt_e}]; memcpy(_d, &c->xmm[{di}], 16); memcpy(_sv, &_s, 16); for (int _k=0;_k<{cnt_e};_k++) _r[_k] = (_d[_k] {op_c} _sv[_k]) ? {ones} : 0u; memcpy(&c->xmm[{di}], _r, 16); }}"]
            di = MM[o[0].reg]
            cnt_e = {"b": 8, "w": 4, "d": 2}[elem]
            src = f"c->mm[{MM[o[1].reg]}]" if is_mm(1) else f"MR64{self.ea(o[1].mem)}"
            return [f"{{ uint64_t _sq = ({src}); {tp} _d[{cnt_e}], _sv[{cnt_e}]; {utp} _r[{cnt_e}]; memcpy(_d, &c->mm[{di}], 8); memcpy(_sv, &_sq, 8); for (int _k=0;_k<{cnt_e};_k++) _r[_k] = (_d[_k] {op_c} _sv[_k]) ? {ones} : 0u; memcpy(&c->mm[{di}], _r, 8); }}"]

        if m in ("pmaxub", "pminub", "pmaxsw", "pminsw", "pavgb", "pavgw") and (is_xm(0) or is_mm(0)):
            is_w = m.endswith("w")
            tp = "int16_t" if m in ("pmaxsw", "pminsw") else ("uint16_t" if m == "pavgw" else "uint8_t")
            expr = "((uint32_t)_a + (uint32_t)_b + 1u) >> 1" if "avg" in m else ("(_a > _b ? _a : _b)" if "max" in m else "(_a < _b ? _a : _b)")
            if is_xm(0):
                di = XM[o[0].reg]
                cnt_e = 8 if is_w else 16
                pre = f"xmm_reg_t _s = c->xmm[{XM[o[1].reg]}]; " if is_xm(1) else f"xmm_reg_t _s; memcpy(&_s, g_mem + (uint32_t){self.ea(o[1].mem)}, 16); "
                return [f"{{ {pre}{tp} _d[{cnt_e}], _sv[{cnt_e}]; memcpy(_d, &c->xmm[{di}], 16); memcpy(_sv, &_s, 16); for (int _k=0;_k<{cnt_e};_k++) {{ {tp} _a = _d[_k], _b = _sv[_k]; _d[_k] = ({tp})({expr}); }} memcpy(&c->xmm[{di}], _d, 16); }}"]
            di = MM[o[0].reg]
            cnt_e = 4 if is_w else 8
            src = f"c->mm[{MM[o[1].reg]}]" if is_mm(1) else f"MR64{self.ea(o[1].mem)}"
            return [f"{{ uint64_t _sq = ({src}); {tp} _d[{cnt_e}], _sv[{cnt_e}]; memcpy(_d, &c->mm[{di}], 8); memcpy(_sv, &_sq, 8); for (int _k=0;_k<{cnt_e};_k++) {{ {tp} _a = _d[_k], _b = _sv[_k]; _d[_k] = ({tp})({expr}); }} memcpy(&c->mm[{di}], _d, 8); }}"]

        if m == "psadbw" and (is_xm(0) or is_mm(0)):
            if is_xm(0):
                di = XM[o[0].reg]
                pre = f"xmm_reg_t _s = c->xmm[{XM[o[1].reg]}]; " if is_xm(1) else f"xmm_reg_t _s; memcpy(&_s, g_mem + (uint32_t){self.ea(o[1].mem)}, 16); "
                return [f"{{ {pre}uint32_t _s0 = 0, _s1 = 0; for (int _k=0;_k<8;_k++) {{ int _d0 = (int)c->xmm[{di}].b[_k] - (int)_s.b[_k]; _s0 += (uint32_t)(_d0 < 0 ? -_d0 : _d0); int _d1 = (int)c->xmm[{di}].b[8+_k] - (int)_s.b[8+_k]; _s1 += (uint32_t)(_d1 < 0 ? -_d1 : _d1); }} c->xmm[{di}].u64[0] = _s0; c->xmm[{di}].u64[1] = _s1; }}"]
            di = MM[o[0].reg]
            src = f"c->mm[{MM[o[1].reg]}]" if is_mm(1) else f"MR64{self.ea(o[1].mem)}"
            return [f"{{ uint64_t _sq = ({src}); uint8_t _a[8], _b[8]; memcpy(_a, &c->mm[{di}], 8); memcpy(_b, &_sq, 8); uint32_t _sum = 0; for (int _k=0;_k<8;_k++) {{ int _d = (int)_a[_k] - (int)_b[_k]; _sum += (uint32_t)(_d < 0 ? -_d : _d); }} c->mm[{di}] = _sum; }}"]

        # ------------------------------------------------------------------
        # General Purpose Integer & Shared-Memory Atomic Instructions
        # ------------------------------------------------------------------
        is_lock = m.startswith("lock ") or (hasattr(ins, "prefix") and len(ins.prefix) > 0 and ins.prefix[0] == 0xF0)
        if m.startswith("lock "):
            m = m[5:].strip()

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
        if m == "enter":
            alloc_sz = o[0].imm & 0xFFFF if o else 0
            esp, ebp = self._reg_name("esp"), self._reg_name("ebp")
            return [f"PUSH32({ebp});", f"{ebp} = {esp};", f"{esp} -= 0x{alloc_sz:x}u;"]
        if m in ("pushal", "pushad"):
            eax, ecx, edx, ebx = self._reg_name("eax"), self._reg_name("ecx"), self._reg_name("edx"), self._reg_name("ebx")
            esp, ebp, esi, edi = self._reg_name("esp"), self._reg_name("ebp"), self._reg_name("esi"), self._reg_name("edi")
            return [f"{{ uint32_t _osp = {esp}; PUSH32({eax}); PUSH32({ecx}); PUSH32({edx}); PUSH32({ebx}); PUSH32(_osp); PUSH32({ebp}); PUSH32({esi}); PUSH32({edi}); }}"]
        if m in ("popal", "popad"):
            eax, ecx, edx, ebx = self._reg_name("eax"), self._reg_name("ecx"), self._reg_name("edx"), self._reg_name("ebx")
            esp, ebp, esi, edi = self._reg_name("esp"), self._reg_name("ebp"), self._reg_name("esi"), self._reg_name("edi")
            return [f"{{ uint32_t _ign; POP32({edi}); POP32({esi}); POP32({ebp}); POP32(_ign); (void)_ign; POP32({ebx}); POP32({edx}); POP32({ecx}); POP32({eax}); }}"]
        if m == "cdq":
            eax, edx = self._reg_name("eax"), self._reg_name("edx")
            return [f"{edx} = (uint32_t)((int32_t){eax} >> 31);"]
        if m == "cwd":
            eax, edx = self._reg_name("eax"), self._reg_name("edx")
            return [f"{edx} = ({edx} & 0xffff0000u) | ((uint32_t)((int32_t)(int16_t)(uint16_t){eax} >> 15) & 0xffffu);"]
        if m == "cwde":
            eax = self._reg_name("eax")
            return [f"{eax} = (uint32_t)(int32_t)(int16_t)(uint16_t){eax};"]
        if m == "cbw":
            eax = self._reg_name("eax")
            return [f"{eax} = ({eax} & 0xffff0000u) | ((uint32_t)(int16_t)(int8_t)(uint8_t){eax} & 0xffffu);"]
        if m == "bswap" and len(o) == 1:
            return [f"{{ uint32_t _v = {E(0)}; _v = ((_v & 0xffu) << 24) | ((_v & 0xff00u) << 8) | ((_v >> 8) & 0xff00u) | ((_v >> 24) & 0xffu); {W(0, '_v')} }}"]
        if m in ("xlatb", "xlat"):
            eax, ebx = self._reg_name("eax"), self._reg_name("ebx")
            return [f"{eax} = ({eax} & 0xffffff00u) | (uint32_t)MR8({ebx} + ({eax} & 0xffu));"]
        if m == "cpuid":
            eax, ecx, edx, ebx = self._reg_name("eax"), self._reg_name("ecx"), self._reg_name("edx"), self._reg_name("ebx")
            return [
                f"{{ uint32_t _leaf = {eax}; "
                f"if (_leaf == 0u) {{ {eax} = 1u; {ebx} = 0x756e6547u; {edx} = 0x49656e69u; {ecx} = 0x6c65746eu; }} "
                f"else if (_leaf == 1u) {{ {eax} = 0x00000f41u; {ebx} = 0x00010800u; {ecx} = 0x00000001u; {edx} = 0x078bfbffu; }} "
                f"else if (_leaf == 0x80000000u) {{ {eax} = 0x80000004u; {ebx} = {ecx} = {edx} = 0u; }} "
                f"else {{ {eax} = {ebx} = {ecx} = {edx} = 0u; }} }}"
            ]
        if m == "rdtsc":
            eax, edx = self._reg_name("eax"), self._reg_name("edx")
            return [
                f"{{ static uint32_t _ps_tsc = 0x10000u; "
                f"uint32_t _t = PS_HOST_ATOMIC_FETCH_ADD32(&_ps_tsc, 1000u); "
                f"{eax} = _t; {edx} = 0u; }}"
            ]

        if m in ("add", "sub", "adc", "sbb"):
            if is_lock and bits == 32 and is_mem(0) and m in ("add", "sub"):
                ea_s = self.ea(o[0].mem)
                b = E(1)
                if m == "add":
                    return [f"{{ uint32_t _ea = {ea_s}, _b = {b}, _a = PS_ATOMIC_FETCH_ADD32(_ea, _b), _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, {self._fm()}); }}"]
                return [f"{{ uint32_t _ea = {ea_s}, _b = {b}, _a = PS_ATOMIC_FETCH_ADD32(_ea, 0u - _b), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, {self._fm()}); }}"]
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
            if is_lock and bits == 32 and is_mem(0):
                ea_s = self.ea(o[0].mem)
                b = E(1)
                at_m = {"and": "PS_ATOMIC_FETCH_AND32", "or": "PS_ATOMIC_FETCH_OR32", "xor": "PS_ATOMIC_FETCH_XOR32"}[m]
                c_op = {"and": "&", "or": "|", "xor": "^"}[m]
                return [f"{{ uint32_t _ea = {ea_s}, _b = {b}, _a = {at_m}(_ea, _b), _r = _a {c_op} _b; FLAGS_LOG_M(_r, 32, {self._fm()}); }}"]
            c_op = {"and": "&", "or": "|", "xor": "^"}[m]
            return [f"{{ uint32_t _r = ({E(0)}) {c_op} ({E(1)}); FLAGS_LOG_M(_r, {bits}, {self._fm()}); {W(0, '_r')} }}"]
        if m == "not":
            return [W(0, f"~({E(0)})")]
        if m == "neg":
            return [f"{{ uint32_t _a = {E(0)}, _r = (uint32_t)0 - _a; FLAGS_SUB_M((uint32_t)0, _a, _r, {bits}, {self._fm()}); {W(0, '_r')} }}"]
        if m == "inc":
            if is_lock and bits == 32 and is_mem(0):
                ea_s = self.ea(o[0].mem)
                return [f"{{ uint32_t _ea = {ea_s}, _a = PS_ATOMIC_FETCH_ADD32(_ea, 1u), _r = _a + 1u; FLAGS_ADD_M(_a, 1u, _r, 32, ({self._fm()} & ~F_CF)); }}"]
            return [f"{{ uint32_t _a = {E(0)}, _r = _a + 1u; FLAGS_ADD_M(_a, 1u, _r, {bits}, ({self._fm()} & ~F_CF)); {W(0, '_r')} }}"]
        if m == "dec":
            if is_lock and bits == 32 and is_mem(0):
                ea_s = self.ea(o[0].mem)
                return [f"{{ uint32_t _ea = {ea_s}, _a = PS_ATOMIC_FETCH_ADD32(_ea, 0xffffffffu), _r = _a - 1u; FLAGS_SUB_M(_a, 1u, _r, 32, ({self._fm()} & ~F_CF)); }}"]
            return [f"{{ uint32_t _a = {E(0)}, _r = _a - 1u; FLAGS_SUB_M(_a, 1u, _r, {bits}, ({self._fm()} & ~F_CF)); {W(0, '_r')} }}"]

        if m == "xchg" and len(o) == 2:
            if bits == 32 and is_mem(0):
                ea_s = self.ea(o[0].mem)
                return [f"{{ uint32_t _ea = {ea_s}, _old = PS_ATOMIC_XCHG32(_ea, {E(1)}); {W(1, '_old')} }}"]
            if bits == 32 and is_mem(1):
                ea_s = self.ea(o[1].mem)
                return [f"{{ uint32_t _ea = {ea_s}, _old = PS_ATOMIC_XCHG32(_ea, {E(0)}); {W(0, '_old')} }}"]
            st0 = f"uint{bits}_t"
            return [f"{{ {st0} _t0 = ({E(0)}), _t1 = ({E(1)}); {W(0, '_t1')} {W(1, '_t0')} }}"]

        if m == "xadd" and len(o) == 2:
            if bits == 32 and is_mem(0):
                ea_s = self.ea(o[0].mem)
                return [f"{{ uint32_t _ea = {ea_s}, _b = {E(1)}, _a = PS_ATOMIC_FETCH_ADD32(_ea, _b), _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, {self._fm()}); {W(1, '_a')} }}"]
            return [f"{{ uint32_t _a = {E(0)}, _b = {E(1)}, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, {bits}, {self._fm()}); {W(0, '_r')} {W(1, '_a')} }}"]

        if m == "cmpxchg" and len(o) == 2:
            eax = self._reg_name("eax")
            if bits == 32 and is_mem(0):
                ea_s = self.ea(o[0].mem)
                return [
                    f"{{ uint32_t _ea = {ea_s}, _acc = {eax}, _exp = _acc, _src = {E(1)}; "
                    f"int _ok = PS_ATOMIC_CAS32(_ea, &_exp, _src); "
                    f"uint32_t _r = _acc - _exp; FLAGS_SUB_M(_acc, _exp, _r, 32, {self._fm()}); "
                    f"if (!_ok) {eax} = _exp; }}"
                ]
            mask_c = 0xFFFFFFFF if bits == 32 else (0xFFFF if bits == 16 else 0xFF)
            acc_rd = eax if bits == 32 else (f"({eax} & 0xffffu)" if bits == 16 else f"({eax} & 0xffu)")
            acc_wr = (f"{eax} = _dst;" if bits == 32 else (f"{eax} = ({eax} & 0xffff0000u) | (_dst & 0xffffu);" if bits == 16 else f"{eax} = ({eax} & 0xffffff00u) | (_dst & 0xffu);"))
            return [
                f"{{ uint32_t _acc = {acc_rd}, _dst = {E(0)}, _src = {E(1)}, _r = _acc - _dst; "
                f"FLAGS_SUB_M(_acc, _dst, _r, {bits}, {self._fm()}); "
                f"if ((_r & 0x{mask_c:x}u) == 0u) {{ {W(0, '_src')} }} else {{ {acc_wr} }} }}"
            ]

        if m == "cmpxchg8b" and len(o) == 1 and is_mem(0):
            eax, edx = self._reg_name("eax"), self._reg_name("edx")
            ebx, ecx = self._reg_name("ebx"), self._reg_name("ecx")
            zf = self._reg_name("zf")
            ea_s = self.ea(o[0].mem)
            return [
                f"{{ uint32_t _ea = {ea_s}; "
                f"uint64_t _exp = ((uint64_t){edx} << 32) | (uint64_t){eax}; "
                f"uint64_t _des = ((uint64_t){ecx} << 32) | (uint64_t){ebx}; "
                f"int _ok = PS_HOST_ATOMIC_CAS64(g_mem + _ea, &_exp, _des); "
                f"{zf} = _ok ? 1u : 0u; "
                f"if (!_ok) {{ {eax} = (uint32_t)_exp; {edx} = (uint32_t)(_exp >> 32); }} }}"
            ]

        if m in ("bsf", "bsr") and len(o) == 2:
            zf = self._reg_name("zf")
            mask_b = 0xFFFF if bits == 16 else 0xFFFFFFFF
            hi_bit = 15 if bits == 16 else 31
            if m == "bsf":
                return [
                    f"{{ uint32_t _v = ({E(1)}) & 0x{mask_b:x}u; "
                    f"if (_v == 0u) {{ {zf} = 1u; }} else {{ {zf} = 0u; uint32_t _i = 0u; while (((_v >> _i) & 1u) == 0u) _i++; {W(0, '_i')} }} }}"
                ]
            return [
                f"{{ uint32_t _v = ({E(1)}) & 0x{mask_b:x}u; "
                f"if (_v == 0u) {{ {zf} = 1u; }} else {{ {zf} = 0u; uint32_t _i = {hi_bit}u; while (((_v >> _i) & 1u) == 0u) _i--; {W(0, '_i')} }} }}"
            ]

        if m in ("bt", "bts", "btr", "btc") and len(o) == 2:
            cf = self._reg_name("cf")
            if is_mem(0) and o[1].type != CS_OP_IMM:
                ea_s = self.ea(o[0].mem)
                if bits == 16:
                    mut = "" if m == "bt" else ("_w |= (uint16_t)(1u << _bo); MR16(_maddr) = _w;" if m == "bts" else ("_w &= (uint16_t)~(1u << _bo); MR16(_maddr) = _w;" if m == "btr" else "_w ^= (uint16_t)(1u << _bo); MR16(_maddr) = _w;"))
                    return [
                        f"{{ int32_t _bi = (int16_t)({E(1)}); uint32_t _maddr = (uint32_t)((int32_t)({ea_s}) + ((_bi >> 4) * 2)); "
                        f"uint32_t _bo = (uint32_t)_bi & 15u; uint16_t _w = MR16(_maddr); {cf} = (_w >> _bo) & 1u; {mut} }}"
                    ]
                mut = "" if m == "bt" else ("_d |= (1u << _bo); MR32(_maddr) = _d;" if m == "bts" else ("_d &= ~(1u << _bo); MR32(_maddr) = _d;" if m == "btr" else "_d ^= (1u << _bo); MR32(_maddr) = _d;"))
                return [
                    f"{{ int32_t _bi = (int32_t)({E(1)}); uint32_t _maddr = (uint32_t)((int32_t)({ea_s}) + ((_bi >> 5) * 4)); "
                    f"uint32_t _bo = (uint32_t)_bi & 31u; uint32_t _d = MR32(_maddr); {cf} = (_d >> _bo) & 1u; {mut} }}"
                ]
            mod_m = 15 if bits == 16 else (7 if bits == 8 else 31)
            mut_r = "" if m == "bt" else (f"{W(0, '_v | (1u << _bo)')}" if m == "bts" else (f"{W(0, '_v & ~(1u << _bo)')}" if m == "btr" else f"{W(0, '_v ^ (1u << _bo)')}"))
            return [f"{{ uint32_t _v = {E(0)}, _bo = ({E(1)}) & {mod_m}u; {cf} = (_v >> _bo) & 1u; {mut_r} }}"]

        if m in ("imul", "mul"):
            cf, of = self._reg_name("cf"), self._reg_name("of")
            eax, edx = self._reg_name("eax"), self._reg_name("edx")
            if m == "imul":
                if len(o) == 1:
                    if bits == 32:
                        return [f"{{ int64_t _p = (int64_t)(int32_t){eax} * (int64_t)(int32_t)({E(0)}); {eax} = (uint32_t)_p; {edx} = (uint32_t)(_p >> 32); {cf} = {of} = ((int64_t)(int32_t)_p != _p); }}"]
                    if bits == 16:
                        return [f"{{ int32_t _p = (int32_t)(int16_t){eax} * (int32_t)(int16_t)({E(0)}); {eax} = ({eax} & 0xffff0000u) | ((uint32_t)_p & 0xffffu); {edx} = ({edx} & 0xffff0000u) | (((uint32_t)_p >> 16) & 0xffffu); {cf} = {of} = ((int32_t)(int16_t)_p != _p); }}"]
                    return [f"{{ int16_t _p = (int16_t)(int8_t){eax} * (int16_t)(int8_t)({E(0)}); {eax} = ({eax} & 0xffff0000u) | ((uint16_t)_p); {cf} = {of} = ((int16_t)(int8_t)_p != _p); }}"]
                if len(o) == 2:
                    cast_s = f"int{bits}_t"
                    return [f"{{ int64_t _p = (int64_t)({cast_s})({E(0)}) * (int64_t)({cast_s})({E(1)}); {cf} = {of} = ((int64_t)({cast_s})_p != _p); {W(0, '(uint32_t)_p')} }}"]
                cast_s = f"int{bits}_t"
                return [f"{{ int64_t _p = (int64_t)({cast_s})({E(1)}) * (int64_t)({cast_s})({E(2)}); {cf} = {of} = ((int64_t)({cast_s})_p != _p); {W(0, '(uint32_t)_p')} }}"]
            if bits == 32:
                return [f"{{ uint64_t _p = (uint64_t){eax} * (uint64_t)({E(0)}); {eax} = (uint32_t)_p; {edx} = (uint32_t)(_p >> 32); {cf} = {of} = ({edx} != 0); }}"]
            if bits == 16:
                return [f"{{ uint32_t _p = ({eax} & 0xffffu) * ({E(0)} & 0xffffu); {eax} = ({eax} & 0xffff0000u) | (_p & 0xffffu); {edx} = ({edx} & 0xffff0000u) | ((_p >> 16) & 0xffffu); {cf} = {of} = ((_p >> 16) != 0); }}"]
            return [f"{{ uint32_t _p = ({eax} & 0xffu) * ({E(0)} & 0xffu); {eax} = ({eax} & 0xffff0000u) | (_p & 0xffffu); {cf} = {of} = ((_p >> 8) != 0); }}"]

        if m in ("shl", "sal", "shr", "sar"):
            cnt = E(1) if len(o) > 1 else "1u"
            mask = 0xFFFFFFFF if bits == 32 else (0xFFFF if bits == 16 else 0xFF)
            cf = self._reg_name("cf")
            if m in ("shl", "sal"):
                return [f"{{ uint32_t _s = ({cnt}) & 31u; if (_s) {{ uint32_t _v = {E(0)}; uint32_t _r = (_v << _s) & 0x{mask:x}u; {cf} = (_v >> ({bits} - _s)) & 1u; FLAGS_LOG_M(_r, {bits}, {self._fm()}); {W(0, '_r')} }} }}"]
            if m == "shr":
                return [f"{{ uint32_t _s = ({cnt}) & 31u; if (_s) {{ uint32_t _v = {E(0)}; uint32_t _r = (_v >> _s) & 0x{mask:x}u; {cf} = (_v >> (_s - 1)) & 1u; FLAGS_LOG_M(_r, {bits}, {self._fm()}); {W(0, '_r')} }} }}"]
            st = {8: "int8_t", 16: "int16_t", 32: "int32_t"}[bits]
            return [f"{{ uint32_t _s = ({cnt}) & 31u; if (_s) {{ {st} _v = ({st}){E(0)}; uint32_t _r = (uint32_t)(_v >> _s) & 0x{mask:x}u; {cf} = ((uint32_t)_v >> (_s - 1)) & 1u; FLAGS_LOG_M(_r, {bits}, {self._fm()}); {W(0, '_r')} }} }}"]

        if m in ("shld", "shrd") and len(o) == 3:
            cnt = E(2)
            cf = self._reg_name("cf")
            if bits == 32:
                if m == "shld":
                    return [f"{{ uint32_t _s = ({cnt}) & 31u; if (_s) {{ uint32_t _d = {E(0)}, _in = {E(1)}, _r = (_d << _s) | (_in >> (32u - _s)); {cf} = (_d >> (32u - _s)) & 1u; FLAGS_LOG_M(_r, 32, {self._fm()}); {W(0, '_r')} }} }}"]
                return [f"{{ uint32_t _s = ({cnt}) & 31u; if (_s) {{ uint32_t _d = {E(0)}, _in = {E(1)}, _r = (_d >> _s) | (_in << (32u - _s)); {cf} = (_d >> (_s - 1u)) & 1u; FLAGS_LOG_M(_r, 32, {self._fm()}); {W(0, '_r')} }} }}"]
            if m == "shld":
                return [f"{{ uint32_t _s = ({cnt}) & 31u; if (_s && _s <= 16u) {{ uint32_t _d = ({E(0)}) & 0xffffu, _in = ({E(1)}) & 0xffffu, _r = ((_d << _s) | (_in >> (16u - _s))) & 0xffffu; {cf} = (_d >> (16u - _s)) & 1u; FLAGS_LOG_M(_r, 16, {self._fm()}); {W(0, '_r')} }} }}"]
            return [f"{{ uint32_t _s = ({cnt}) & 31u; if (_s && _s <= 16u) {{ uint32_t _d = ({E(0)}) & 0xffffu, _in = ({E(1)}) & 0xffffu, _r = ((_d >> _s) | (_in << (16u - _s))) & 0xffffu; {cf} = (_d >> (_s - 1u)) & 1u; FLAGS_LOG_M(_r, 16, {self._fm()}); {W(0, '_r')} }} }}"]

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
        if m == "cmc":
            cf_reg = "RG_(cf)" if self.use_rg else "c->cf"
            return [f"{cf_reg} = ({cf_reg} & 1u) ^ 1u;"]

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

        # Rotations
        if m in ("rol", "ror", "rcl", "rcr"):
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
            if m == "ror":
                return [
                    f"{{ uint32_t _c = ({cnt}) & 31u; if (_c) {{ "
                    f"uint32_t _v = ({E(0)}) & 0x{mask:x}u; "
                    f"uint32_t _s = _c % {bits}u; "
                    f"uint32_t _r = _s ? (((_v >> _s) | (_v << ({bits}u - _s))) & 0x{mask:x}u) : _v; "
                    f"{cf} = (_r >> ({bits-1}u)) & 1u; "
                    f"if (_c == 1u) {of} = ((_r >> ({bits-1}u)) & 1u) ^ ((_r >> ({bits-2 if bits > 1 else 0}u)) & 1u); "
                    f"{W(0, '_r')} }} }}"
                ]
            if m == "rcl":
                return [
                    f"{{ uint32_t _c = (({cnt}) & 31u) % {bits+1}u; if (_c) {{ "
                    f"uint64_t _v = ((uint64_t)({E(0)}) & 0x{mask:x}ULL) | ((uint64_t)({cf} & 1u) << {bits}); "
                    f"uint64_t _r = ((_v << _c) | (_v >> ({bits+1}u - _c))) & 0x{(1 << (bits + 1)) - 1:x}ULL; "
                    f"{cf} = (uint32_t)((_r >> {bits}) & 1ULL); "
                    f"uint32_t _res = (uint32_t)(_r & 0x{mask:x}ULL); "
                    f"if (_c == 1u) {of} = ((_res >> {bits-1}u) & 1u) ^ {cf}; "
                    f"{W(0, '_res')} }} }}"
                ]
            return [
                f"{{ uint32_t _c = (({cnt}) & 31u) % {bits+1}u; if (_c) {{ "
                f"uint64_t _v = ((uint64_t)({E(0)}) & 0x{mask:x}ULL) | ((uint64_t)({cf} & 1u) << {bits}); "
                f"uint64_t _r = ((_v >> _c) | (_v << ({bits+1}u - _c))) & 0x{(1 << (bits + 1)) - 1:x}ULL; "
                f"{cf} = (uint32_t)((_r >> {bits}) & 1ULL); "
                f"uint32_t _res = (uint32_t)(_r & 0x{mask:x}ULL); "
                f"if (_c == 1u) {of} = ((_res >> {bits-1}u) & 1u) ^ ((_res >> {bits-2 if bits > 1 else 0}u) & 1u); "
                f"{W(0, '_res')} }} }}"
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

        # String instructions (movsb/w/d, stosb/w/d, lodsb/w/d, cmpsb/w/d, scasb/w/d)
        base_m = m.split()[-1]
        is_repe = m.startswith("rep ") or m.startswith("repe ") or m.startswith("repz ")
        is_repne = m.startswith("repne ") or m.startswith("repnz ")
        is_any_rep = is_repe or is_repne
        if base_m in (
            "movsb", "movsw", "movsd",
            "stosb", "stosw", "stosd",
            "lodsb", "lodsw", "lodsd",
            "cmpsb", "cmpsw", "cmpsd",
            "scasb", "scasw", "scasd",
        ):
            if o and any(op.type == CS_OP_REG and op.reg in XM for op in o):
                pass
            else:
                esi = self._reg_name("esi")
                edi = self._reg_name("edi")
                ecx = self._reg_name("ecx")
                eax = self._reg_name("eax")
                step = 4 if base_m.endswith("d") else (2 if base_m.endswith("w") else 1)
                MR_OP = {1: "MR8", 2: "MR16", 4: "MR32"}[step]
                bits_s = step * 8
                mask_s = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF}[step]

                if base_m.startswith("movs"):
                    if is_any_rep:
                        return [
                            f"if (c->df) {{ while ({ecx} > 0u) {{ {MR_OP}({edi}) = {MR_OP}({esi}); {esi} -= {step}u; {edi} -= {step}u; {ecx}--; }} }} "
                            f"else {{ while ({ecx} > 0u) {{ {MR_OP}({edi}) = {MR_OP}({esi}); {esi} += {step}u; {edi} += {step}u; {ecx}--; }} }}"
                        ]
                    return [
                        f"{MR_OP}({edi}) = {MR_OP}({esi}); "
                        f"if (c->df) {{ {esi} -= {step}u; {edi} -= {step}u; }} else {{ {esi} += {step}u; {edi} += {step}u; }}"
                    ]

                if base_m.startswith("stos"):
                    val = eax if step == 4 else (f"(uint16_t)({eax} & 0xffffu)" if step == 2 else f"(uint8_t)({eax} & 0xffu)")
                    if is_any_rep:
                        return [
                            f"if (c->df) {{ while ({ecx} > 0u) {{ {MR_OP}({edi}) = {val}; {edi} -= {step}u; {ecx}--; }} }} "
                            f"else {{ while ({ecx} > 0u) {{ {MR_OP}({edi}) = {val}; {edi} += {step}u; {ecx}--; }} }}"
                        ]
                    return [
                        f"{MR_OP}({edi}) = {val}; "
                        f"if (c->df) {{ {edi} -= {step}u; }} else {{ {edi} += {step}u; }}"
                    ]

                if base_m.startswith("lods"):
                    wr_ax = (
                        f"{eax} = {MR_OP}({esi});"
                        if step == 4
                        else (
                            f"{eax} = ({eax} & 0xffff0000u) | (uint32_t){MR_OP}({esi});"
                            if step == 2
                            else f"{eax} = ({eax} & 0xffffff00u) | (uint32_t){MR_OP}({esi});"
                        )
                    )
                    if is_any_rep:
                        return [
                            f"while ({ecx} > 0u) {{ {wr_ax} if (c->df) {esi} -= {step}u; else {esi} += {step}u; {ecx}--; }}"
                        ]
                    return [f"{wr_ax} if (c->df) {esi} -= {step}u; else {esi} += {step}u;"]

                if base_m.startswith("cmps"):
                    brk = "(_r == 0u)" if is_repne else "(_r != 0u)"
                    if is_any_rep:
                        return [
                            f"while ({ecx} > 0u) {{ "
                            f"uint32_t _a = (uint32_t){MR_OP}({esi}), _b = (uint32_t){MR_OP}({edi}); "
                            f"uint32_t _r = (_a - _b) & 0x{mask_s:x}u; "
                            f"FLAGS_SUB_M(_a, _b, _r, {bits_s}, 0x3fu); "
                            f"if (c->df) {{ {esi} -= {step}u; {edi} -= {step}u; }} else {{ {esi} += {step}u; {edi} += {step}u; }} "
                            f"{ecx}--; if {brk} break; }}"
                        ]
                    return [
                        f"{{ uint32_t _a = (uint32_t){MR_OP}({esi}), _b = (uint32_t){MR_OP}({edi}); "
                        f"uint32_t _r = (_a - _b) & 0x{mask_s:x}u; "
                        f"FLAGS_SUB_M(_a, _b, _r, {bits_s}, 0x3fu); "
                        f"if (c->df) {{ {esi} -= {step}u; {edi} -= {step}u; }} else {{ {esi} += {step}u; {edi} += {step}u; }} }}"
                    ]

                if base_m.startswith("scas"):
                    acc_a = eax if step == 4 else f"({eax} & 0x{mask_s:x}u)"
                    brk = "(_r == 0u)" if is_repne else "(_r != 0u)"
                    if is_any_rep:
                        return [
                            f"while ({ecx} > 0u) {{ "
                            f"uint32_t _a = {acc_a}, _b = (uint32_t){MR_OP}({edi}); "
                            f"uint32_t _r = (_a - _b) & 0x{mask_s:x}u; "
                            f"FLAGS_SUB_M(_a, _b, _r, {bits_s}, 0x3fu); "
                            f"if (c->df) {edi} -= {step}u; else {edi} += {step}u; "
                            f"{ecx}--; if {brk} break; }}"
                        ]
                    return [
                        f"{{ uint32_t _a = {acc_a}, _b = (uint32_t){MR_OP}({edi}); "
                        f"uint32_t _r = (_a - _b) & 0x{mask_s:x}u; "
                        f"FLAGS_SUB_M(_a, _b, _r, {bits_s}, 0x3fu); "
                        f"if (c->df) {edi} -= {step}u; else {edi} += {step}u; }}"
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
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        self.cs.detail = True
        self.raw_exe = patch_all_countdown_stubs(raw_exe, cs=self.cs)
        self.catalog = catalog
        self.functions = {int(f["address"]): f for f in catalog["functions"]}
        self.image_base = int(catalog["image_base"])
        self.code_start = int(catalog["code_start"])
        self.code_end = int(catalog["code_end"])
        self.enable_lregs = enable_lregs
        self.enable_flagabi = enable_flagabi

        # SecuROM Trampoline & Bridge Mapping (site_va / stub_va -> target_va)
        self.trampoline_map: dict[int, int] = {}
        if trampoline_data is None:
            t_path = WORKSPACE / "research" / "local" / "phase1" / "securom_trampolines.json"
            if t_path.is_file():
                try:
                    trampoline_data = json.loads(t_path.read_text(encoding="utf-8"))
                except Exception:
                    trampoline_data = None

        if trampoline_data:
            raw_map: dict[int, int] = {}
            for key in ("trampolines", "securom_bridges"):
                for t in trampoline_data.get(key, []):
                    if "site_va" in t and "target_va" in t:
                        raw_map[int(t["site_va"])] = int(t["target_va"])
                    if "stub_va" in t and "target_va" in t:
                        s_va = int(t["stub_va"])
                        t_va = int(t["target_va"])
                        if s_va != t_va and s_va not in raw_map:
                            raw_map[s_va] = t_va
            # Resolve chained trampolines iteratively
            for s_va in raw_map:
                visited = set()
                cur = s_va
                while cur in raw_map and cur not in visited:
                    visited.add(cur)
                    cur = raw_map[cur]
                self.trampoline_map[s_va] = cur

        self.lifter = InstructionLifter(self.cs, use_rg=enable_lregs)

    def resolve_target(
        self, dest: int, block_starts: set[int] | None = None
    ) -> tuple[int, bool]:
        """Resolve a destination VA through SecuROM trampoline mappings.

        Returns (target_va, is_resolved).
        Only redirects if the resolved target is confirmed in self.functions or block_starts.
        """
        if dest in self.trampoline_map:
            target = self.trampoline_map[dest]
            if target in self.functions or (
                block_starts is not None and target in block_starts
            ):
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
                        "loopz",
                        "loopnz",
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

    def _emit_callee_dispatch(self, lines: list[str], raw_dest: int) -> None:
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

        if blocks and blocks[0][0] != func_entry and func_entry in block_starts:
            lines.append(f"    goto L_{func_entry:08x};")

        # Disassemble all blocks for CFG dataflow analysis & SecuROM obfuscation detection
        block_insns: dict[int, list[Any]] = {}
        obf_skip_addrs: set[int] = set()
        obf_p12_calls: dict[int, tuple[int, int]] = {}  # term_va -> (raw_callee, cont_va)
        obf_p3_jmps: dict[int, int] = {}                # ret_va  -> raw_target
        call_like_addrs: set[int] = set()

        def _push_imm_val(ins_obj: Any) -> int | None:
            if (
                ins_obj is not None
                and ins_obj.mnemonic == "push"
                and ins_obj.operands
                and ins_obj.operands[0].type == CS_OP_IMM
            ):
                return ins_obj.operands[0].imm & 0xFFFFFFFF
            return None

        for b_start, b_end, succs, is_exit in blocks:
            code = self.read_bytes(b_start, b_end - b_start)
            ins_list = list(self.cs.disasm(code, b_start)) if code else []
            block_insns[b_start] = ins_list
            if len(ins_list) >= 2:
                last = ins_list[-1]
                prev1 = ins_list[-2]
                next_pc = last.address + last.size
                if last.mnemonic == "ret" and not last.operands and last.address != b_start:
                    cal_imm = _push_imm_val(prev1)
                    prev2 = ins_list[-3] if (len(ins_list) >= 3 and prev1.address != b_start) else None
                    ret_imm = _push_imm_val(prev2)
                    if (
                        cal_imm is not None
                        and ret_imm is not None
                        and ret_imm in block_starts
                        and 0 <= (ret_imm - next_pc) <= 64
                    ):
                        # P2: push imm_ret; push imm_callee; ret
                        obf_skip_addrs.add(prev1.address)
                        obf_p12_calls[last.address] = (cal_imm, ret_imm)
                        call_like_addrs.add(last.address)
                    elif cal_imm is not None and (
                        cal_imm in block_starts
                        or cal_imm in self.trampoline_map
                        or (self.code_start <= cal_imm < self.code_end)
                    ):
                        # P3: push imm_target; ret
                        obf_skip_addrs.add(prev1.address)
                        obf_p3_jmps[last.address] = cal_imm
                elif last.mnemonic == "jmp" and last.address != b_start:
                    ret_imm = _push_imm_val(prev1)
                    if (
                        ret_imm is not None
                        and ret_imm in block_starts
                        and 0 <= (ret_imm - next_pc) <= 64
                    ):
                        # P1: push imm_ret; jmp <callee>
                        raw_cal: int | None = None
                        if last.address in self.trampoline_map:
                            raw_cal = self.trampoline_map[last.address]
                        elif last.operands and last.operands[0].type == CS_OP_IMM:
                            raw_cal = last.operands[0].imm & 0xFFFFFFFF
                        if raw_cal is not None:
                            obf_p12_calls[last.address] = (raw_cal, ret_imm)
                            call_like_addrs.add(last.address)

        if enable_flagabi:
            live_after = compute_flag_liveness(blocks, block_insns, call_like_addrs=call_like_addrs)
        else:
            live_after = {}

        has_terminal = False
        for b_idx, (b_start, b_end, succs, is_exit) in enumerate(blocks):
            lines.append(f"L_{b_start:08x}:")
            disasm_insns = block_insns.get(b_start, [])
            if not disasm_insns:
                lines.append(f"    /* Warning: could not read bytes at 0x{b_start:08x} */")
                continue

            blk_terminated = False
            for idx, ins in enumerate(disasm_insns):
                if ins.address in obf_skip_addrs:
                    continue

                m = ins.mnemonic
                if enable_flagabi:
                    self.lifter.cur_fmask = live_after.get(ins.address, F_ALL)
                else:
                    self.lifter.cur_fmask = F_ALL

                # SecuROM P1 / P2 obfuscated call (push imm_ret already pushed on stack)
                if ins.address in obf_p12_calls:
                    raw_cal, cont_va = obf_p12_calls[ins.address]
                    lines.append(f"    /* SecuROM obfuscated call -> 0x{raw_cal:08x}, cont 0x{cont_va:08x} */")
                    if enable_lregs:
                        lines.append("    LR_STORE;")
                    self._emit_callee_dispatch(lines, raw_cal)
                    if enable_lregs:
                        lines.append("    LR_RELOAD;")
                    lines.append(f"    goto L_{cont_va:08x};")
                    blk_terminated = True
                    continue

                # SecuROM P3 obfuscated jump (push imm_tgt skipped, net ESP change 0)
                if ins.address in obf_p3_jmps:
                    raw_dest = obf_p3_jmps[ins.address]
                    dest, is_resolved = self.resolve_target(raw_dest, block_starts)
                    if dest in block_starts:
                        lines.append(f"    goto L_{dest:08x};")
                    else:
                        if is_resolved:
                            lines.append(f"    /* Resolved SecuROM P3 jmp 0x{raw_dest:08x} -> 0x{dest:08x} */")
                        if enable_lregs:
                            lines.append("    LR_STORE;")
                        lines.append(f"    DISPATCH_TAIL(c, 0x{dest:08x}u);")
                        has_terminal = True
                    blk_terminated = True
                    continue

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
                    blk_terminated = True
                    continue

                # Unconditional Jumps
                if m == "jmp":
                    if ins.address in self.trampoline_map:
                        raw_dest = self.trampoline_map[ins.address]
                        dest, _ = self.resolve_target(raw_dest, block_starts)
                        if dest in block_starts:
                            lines.append(f"    /* Resolved SecuROM intra-function bridge -> 0x{dest:08x} */")
                            lines.append(f"    goto L_{dest:08x};")
                        else:
                            lines.append(f"    /* Resolved SecuROM tail bridge -> 0x{dest:08x} */")
                            if enable_lregs:
                                lines.append("    LR_STORE;")
                            lines.append(f"    DISPATCH_TAIL(c, 0x{dest:08x}u);")
                            has_terminal = True
                    elif ins.operands and ins.operands[0].type == CS_OP_IMM:
                        raw_dest = ins.operands[0].imm & 0xFFFFFFFF
                        if raw_dest in block_starts:
                            lines.append(f"    goto L_{raw_dest:08x};")
                        else:
                            dest, is_resolved = self.resolve_target(raw_dest, block_starts)
                            if dest in block_starts:
                                lines.append(f"    goto L_{dest:08x};")
                            else:
                                if is_resolved:
                                    lines.append(f"    /* Resolved SecuROM trampoline jmp 0x{raw_dest:08x} -> 0x{dest:08x} */")
                                if enable_lregs:
                                    lines.append("    LR_STORE;")
                                lines.append(f"    DISPATCH_TAIL(c, 0x{dest:08x}u);")
                                has_terminal = True
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
                            has_terminal = True
                    else:
                        rd_expr = self.lifter.rd(ins.operands[0])
                        if enable_lregs:
                            lines.append("    LR_STORE;")
                        lines.append(f"    DISPATCH_TAIL(c, {rd_expr});")
                        has_terminal = True
                    blk_terminated = True
                    continue

                # Conditional Jumps & Loop Branches
                if (m.startswith("j") and m[1:] in CC) or m in ("jecxz", "jcxz", "loop", "loope", "loopz", "loopne", "loopnz"):
                    ecx_r = self.lifter._reg_name("ecx")
                    if m in ("jecxz", "jcxz", "loop", "loope", "loopz", "loopne", "loopnz"):
                        if m == "jecxz":
                            cond = f"({ecx_r} == 0u)"
                        elif m == "jcxz":
                            cond = f"(({ecx_r} & 0xffffu) == 0u)"
                        elif m == "loop":
                            lines.append(f"    {ecx_r} -= 1u;")
                            cond = f"({ecx_r} != 0u)"
                        elif m in ("loope", "loopz"):
                            lines.append(f"    {ecx_r} -= 1u;")
                            cond = f"({ecx_r} != 0u && CC_E)"
                        else:
                            lines.append(f"    {ecx_r} -= 1u;")
                            cond = f"({ecx_r} != 0u && CC_NE)"
                    else:
                        cond = CC.get(m[1:], None)
                    if ins.operands and ins.operands[0].type == CS_OP_IMM and cond:
                        raw_dest = ins.operands[0].imm & 0xFFFFFFFF
                        dest, _ = self.resolve_target(raw_dest, block_starts) if raw_dest not in block_starts else (raw_dest, False)
                        if dest in block_starts:
                            lines.append(f"    if ({cond}) goto L_{dest:08x};")
                        else:
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
                    if ins.address in self.trampoline_map:
                        self._emit_callee_dispatch(lines, self.trampoline_map[ins.address])
                    elif ins.operands and ins.operands[0].type == CS_OP_IMM:
                        self._emit_callee_dispatch(lines, ins.operands[0].imm & 0xFFFFFFFF)
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

            # Explicit fallthrough goto when the next emitted block is not contiguous
            if not blk_terminated and disasm_insns:
                ft_va = disasm_insns[-1].address + disasm_insns[-1].size
                next_b_start = blocks[b_idx + 1][0] if (b_idx + 1) < len(blocks) else None
                if ft_va in block_starts and next_b_start != ft_va:
                    lines.append(f"    goto L_{ft_va:08x};")

        if enable_lregs and not has_terminal:
            lines.append("    LR_STORE;")

        self.lifter.use_rg = old_use_rg
        lines.append("}\n")
        return "\n".join(lines)

