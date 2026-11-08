/* Need for Speed ProStreet - x86-32 CPU and SIMD execution state.
 *
 * Implements 32-bit x86 execution context with full SSE, SSE2, MMX, and x87 FPU,
 * mapped 1:1 into WebAssembly linear memory with optional WebAssembly SIMD128 intrinsics.
 */
#ifndef PROSTREET_CPU_H
#define PROSTREET_CPU_H

#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#if defined(__wasm_simd128__)
#include <wasm_simd128.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef GUEST_END
#define GUEST_END 0x28000000u
#endif

/* --------------------------------------------------------------------------
 * Guest Memory Access Layer
 * -------------------------------------------------------------------------- */
#if defined(__GNUC__) || defined(__clang__)
typedef uint16_t __attribute__((may_alias)) gm_u16;
typedef volatile uint32_t __attribute__((may_alias)) gm_u32;
typedef uint64_t __attribute__((may_alias)) gm_u64;
typedef float    __attribute__((may_alias)) gm_f32;
typedef double   __attribute__((may_alias)) gm_f64;
#else
typedef uint16_t gm_u16;
typedef volatile uint32_t gm_u32;
typedef uint64_t gm_u64;
typedef float    gm_f32;
typedef double   gm_f64;
#endif

#ifdef __wasm__
#define g_mem ((uint8_t *)0)
#define GUEST_MEM_READY 1
#define GSZ ((uint64_t)GUEST_END)
#define MR8(a)   (*(uint8_t *)(g_mem + (uint32_t)(a)))
#define MR16(a)  (*(gm_u16  *)(g_mem + (uint32_t)(a)))
#define MR32(a)  (*(gm_u32  *)(g_mem + (uint32_t)(a)))
#define MR64(a)  (*(gm_u64  *)(g_mem + (uint32_t)(a)))
#define MRF32(a) (*(gm_f32  *)(g_mem + (uint32_t)(a)))
#define MRF64(a) (*(gm_f64  *)(g_mem + (uint32_t)(a)))
#else
extern uint8_t *g_mem;
#define GUEST_MEM_READY (g_mem != NULL)
#define GSZ 0x100000000ull
#define MR8(a)   (*(uint8_t  *)(g_mem + (uint32_t)(a)))
#define MR16(a)  (*(gm_u16  *)(g_mem + (uint32_t)(a)))
#define MR32(a)  (*(gm_u32  *)(g_mem + (uint32_t)(a)))
#define MR64(a)  (*(gm_u64  *)(g_mem + (uint32_t)(a)))
#define MRF32(a) (*(gm_f32  *)(g_mem + (uint32_t)(a)))
#define MRF64(a) (*(gm_f64  *)(g_mem + (uint32_t)(a)))
#endif

/* --------------------------------------------------------------------------
 * Portable Shared-Memory Atomic & Futex Helpers (WASM Atomics + Host C99)
 * -------------------------------------------------------------------------- */
#if defined(__GNUC__) || defined(__clang__)
#define PS_HOST_ATOMIC_LOAD32(p)             __atomic_load_n((uint32_t *)(p), __ATOMIC_ACQUIRE)
#define PS_HOST_ATOMIC_STORE32(p, v)         __atomic_store_n((uint32_t *)(p), (uint32_t)(v), __ATOMIC_RELEASE)
#define PS_HOST_ATOMIC_XCHG32(p, v)          __atomic_exchange_n((uint32_t *)(p), (uint32_t)(v), __ATOMIC_ACQ_REL)
#define PS_HOST_ATOMIC_FETCH_ADD32(p, v)     __atomic_fetch_add((uint32_t *)(p), (uint32_t)(v), __ATOMIC_ACQ_REL)
#define PS_HOST_ATOMIC_FETCH_OR32(p, v)      __atomic_fetch_or((uint32_t *)(p), (uint32_t)(v), __ATOMIC_ACQ_REL)
#define PS_HOST_ATOMIC_FETCH_AND32(p, v)     __atomic_fetch_and((uint32_t *)(p), (uint32_t)(v), __ATOMIC_ACQ_REL)
#define PS_HOST_ATOMIC_FETCH_XOR32(p, v)     __atomic_fetch_xor((uint32_t *)(p), (uint32_t)(v), __ATOMIC_ACQ_REL)
#define PS_HOST_ATOMIC_CAS32(p, exp_p, des)  __atomic_compare_exchange_n((uint32_t *)(p), (uint32_t *)(exp_p), (uint32_t)(des), 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)
#define PS_HOST_ATOMIC_LOAD64(p)             __atomic_load_n((uint64_t *)(p), __ATOMIC_ACQUIRE)
#define PS_HOST_ATOMIC_CAS64(p, exp_p, des)  __atomic_compare_exchange_n((uint64_t *)(p), (uint64_t *)(exp_p), (uint64_t)(des), 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)
#else
static inline uint32_t ps_fallback_xchg32(volatile uint32_t *p, uint32_t v) { uint32_t o = *p; *p = v; return o; }
static inline uint32_t ps_fallback_fadd32(volatile uint32_t *p, uint32_t v) { uint32_t o = *p; *p = o + v; return o; }
static inline uint32_t ps_fallback_for32(volatile uint32_t *p, uint32_t v)  { uint32_t o = *p; *p = o | v; return o; }
static inline uint32_t ps_fallback_fand32(volatile uint32_t *p, uint32_t v) { uint32_t o = *p; *p = o & v; return o; }
static inline uint32_t ps_fallback_fxor32(volatile uint32_t *p, uint32_t v) { uint32_t o = *p; *p = o ^ v; return o; }
static inline int ps_fallback_cas32(volatile uint32_t *p, uint32_t *e, uint32_t d) { uint32_t o = *p; if (o == *e) { *p = d; return 1; } *e = o; return 0; }
static inline int ps_fallback_cas64(volatile uint64_t *p, uint64_t *e, uint64_t d) { uint64_t o = *p; if (o == *e) { *p = d; return 1; } *e = o; return 0; }
#define PS_HOST_ATOMIC_LOAD32(p)             (*(volatile const uint32_t *)(p))
#define PS_HOST_ATOMIC_STORE32(p, v)         (*(volatile uint32_t *)(p) = (uint32_t)(v))
#define PS_HOST_ATOMIC_XCHG32(p, v)          ps_fallback_xchg32((volatile uint32_t *)(p), (uint32_t)(v))
#define PS_HOST_ATOMIC_FETCH_ADD32(p, v)     ps_fallback_fadd32((volatile uint32_t *)(p), (uint32_t)(v))
#define PS_HOST_ATOMIC_FETCH_OR32(p, v)      ps_fallback_for32((volatile uint32_t *)(p), (uint32_t)(v))
#define PS_HOST_ATOMIC_FETCH_AND32(p, v)     ps_fallback_fand32((volatile uint32_t *)(p), (uint32_t)(v))
#define PS_HOST_ATOMIC_FETCH_XOR32(p, v)     ps_fallback_fxor32((volatile uint32_t *)(p), (uint32_t)(v))
#define PS_HOST_ATOMIC_CAS32(p, exp_p, des)  ps_fallback_cas32((volatile uint32_t *)(p), (uint32_t *)(exp_p), (uint32_t)(des))
#define PS_HOST_ATOMIC_LOAD64(p)             (*(volatile const uint64_t *)(p))
#define PS_HOST_ATOMIC_CAS64(p, exp_p, des)  ps_fallback_cas64((volatile uint64_t *)(p), (uint64_t *)(exp_p), (uint64_t)(des))
#endif

#define PS_ATOMIC_LOAD32(va)                 PS_HOST_ATOMIC_LOAD32(g_mem + (uint32_t)(va))
#define PS_ATOMIC_STORE32(va, v)             PS_HOST_ATOMIC_STORE32(g_mem + (uint32_t)(va), (v))
#define PS_ATOMIC_XCHG32(va, v)              PS_HOST_ATOMIC_XCHG32(g_mem + (uint32_t)(va), (v))
#define PS_ATOMIC_FETCH_ADD32(va, v)         PS_HOST_ATOMIC_FETCH_ADD32(g_mem + (uint32_t)(va), (v))
#define PS_ATOMIC_FETCH_OR32(va, v)          PS_HOST_ATOMIC_FETCH_OR32(g_mem + (uint32_t)(va), (v))
#define PS_ATOMIC_FETCH_AND32(va, v)         PS_HOST_ATOMIC_FETCH_AND32(g_mem + (uint32_t)(va), (v))
#define PS_ATOMIC_FETCH_XOR32(va, v)         PS_HOST_ATOMIC_FETCH_XOR32(g_mem + (uint32_t)(va), (v))
#define PS_ATOMIC_CAS32(va, exp_p, des)      PS_HOST_ATOMIC_CAS32(g_mem + (uint32_t)(va), (exp_p), (des))

#if defined(__wasm__) && defined(__wasm_atomics__)
#define PS_WASM_HOST_WAIT32(p, exp, ns)      __builtin_wasm_memory_atomic_wait32((int *)(p), (int)(exp), (long long)(ns))
#define PS_WASM_HOST_NOTIFY(p, cnt)          __builtin_wasm_memory_atomic_notify((int *)(p), (unsigned int)(cnt))
#else
#define PS_WASM_HOST_WAIT32(p, exp, ns)      ((void)(p), (void)(exp), (void)(ns), 2)
#define PS_WASM_HOST_NOTIFY(p, cnt)          ((void)(p), (void)(cnt), 0)
#endif
#define PS_WASM_WAIT32(va, exp, ns)          PS_WASM_HOST_WAIT32(g_mem + (uint32_t)(va), (exp), (ns))
#define PS_WASM_NOTIFY(va, cnt)              PS_WASM_HOST_NOTIFY(g_mem + (uint32_t)(va), (cnt))

/* --------------------------------------------------------------------------
 * CPU Register Enumeration & State Structure
 * -------------------------------------------------------------------------- */
enum { R_EAX=0, R_ECX, R_EDX, R_EBX, R_ESP, R_EBP, R_ESI, R_EDI };

typedef union xmm_reg {
    uint8_t  b[16];
    float    f[4];
    double   d[2];
    uint32_t u32[4];
    uint64_t u64[2];
#if defined(__wasm_simd128__)
    v128_t   v;
#endif
} xmm_reg_t;

typedef struct CPU {
    union {
        uint32_t r[8];
        struct { uint32_t eax, ecx, edx, ebx, esp, ebp, esi, edi; };
    };
    uint32_t eip;
    uint32_t fs_base, gs_base;

    /* Flags: CF, PF, AF, ZF, SF, OF, DF (each 0 or 1) */
    uint32_t cf, pf, af, zf, sf, of, df;
    uint32_t sysfl; /* EFLAGS system bits: ID (21), AC (18) */

    /* x87 FPU stack */
    double   st[8];
    int32_t  top;
    uint16_t fcw, fsw;

    /* MMX registers (64-bit) */
    uint64_t mm[8];

    /* SSE / SSE2 registers (128-bit) */
    xmm_reg_t xmm[8];

    /* Per-CPU diagnostic dispatch ring buffer (appended to preserve offsets 0..295) */
    uint32_t trace_idx;
    uint32_t trace_va[16];
    uint32_t trace_esp[16];
} CPU;

static inline void cpu_trace_record(struct CPU *c, uint32_t addr) {
    uint32_t slot = c->trace_idx & 15u;
    c->trace_va[slot] = addr;
    c->trace_esp[slot] = c->esp;
    c->trace_idx = c->trace_idx + 1u;
    c->eip = addr;
}

/* --------------------------------------------------------------------------
 * Dispatch Layer
 * -------------------------------------------------------------------------- */
struct CPU;
typedef void (*guest_fn_t)(struct CPU *);
void dispatch_indirect(struct CPU *c, uint32_t addr);
void dispatch_tail(struct CPU *c);

#define DISPATCH_TEXT_BASE 0x00401000u
#define DISPATCH_TEXT_SIZE 0x00567000u

extern guest_fn_t g_dtab[DISPATCH_TEXT_SIZE];

static inline guest_fn_t dispatch_fast(uint32_t a) {
    uint32_t o = a - DISPATCH_TEXT_BASE;
    return o < DISPATCH_TEXT_SIZE ? g_dtab[o] : (guest_fn_t)0;
}

#define DISPATCH_CALL(c_, t_) do { \
    uint32_t _dc = (uint32_t)(t_); \
    if (_dc >= 0x00967000u && _dc <= 0x00967650u) { (c_)->esp += 4u; } \
    guest_fn_t _df = dispatch_fast(_dc); \
    if (_df) { cpu_trace_record((c_), _dc); _df(c_); } else dispatch_indirect((c_), _dc); \
} while (0)

#ifdef __wasm__
#define DISPATCH_TAIL(c_, t_) { \
    uint32_t _dc = (uint32_t)(t_); \
    if (_dc >= 0x00967000u && _dc <= 0x00967650u) { (c_)->esp += 4u; } \
    guest_fn_t _df = dispatch_fast(_dc); \
    if (_df) { cpu_trace_record((c_), _dc); __attribute__((musttail)) return _df(c_); } \
    (c_)->eip = _dc; __attribute__((musttail)) return dispatch_tail(c_); \
}
#else
#define DISPATCH_TAIL(c_, t_) { \
    uint32_t _dc = (uint32_t)(t_); \
    if (_dc >= 0x00967000u && _dc <= 0x00967650u) { (c_)->esp += 4u; } \
    dispatch_indirect((c_), _dc); return; \
}
#endif

/* --------------------------------------------------------------------------
 * Local Register Promotion (LREGS) & Arithmetic Flag Helpers
 * -------------------------------------------------------------------------- */
#ifdef PROSTREET_LREGS
#define RG_(x) _r_##x
#else
#define RG_(x) c->x
#endif

#define LR_ENTER \
    uint32_t _r_eax = c->eax, _r_ecx = c->ecx, _r_edx = c->edx, _r_ebx = c->ebx, \
             _r_esp = c->esp, _r_ebp = c->ebp, _r_esi = c->esi, _r_edi = c->edi; \
    uint32_t _r_cf = c->cf, _r_pf = c->pf, _r_af = c->af, _r_zf = c->zf, _r_sf = c->sf, _r_of = c->of

#define LR_STORE do { \
    c->eax = _r_eax; c->ecx = _r_ecx; c->edx = _r_edx; c->ebx = _r_ebx; \
    c->esp = _r_esp; c->ebp = _r_ebp; c->esi = _r_esi; c->edi = _r_edi; \
    c->cf = _r_cf; c->pf = _r_pf; c->af = _r_af; c->zf = _r_zf; c->sf = _r_sf; c->of = _r_of; \
} while (0)

#define LR_RELOAD do { \
    _r_eax = c->eax; _r_ecx = c->ecx; _r_edx = c->edx; _r_ebx = c->ebx; \
    _r_esp = c->esp; _r_ebp = c->ebp; _r_esi = c->esi; _r_edi = c->edi; \
    _r_cf = c->cf; _r_pf = c->pf; _r_af = c->af; _r_zf = c->zf; _r_sf = c->sf; _r_of = c->of; \
} while (0)

#define LR_RELOAD_FLAGS do { \
    _r_cf = c->cf; _r_pf = c->pf; _r_af = c->af; _r_zf = c->zf; _r_sf = c->sf; _r_of = c->of; \
} while (0)

static inline uint32_t parity8(uint32_t v) {
    v &= 0xff; v ^= v >> 4; v ^= v >> 2; v ^= v >> 1;
    return (~v) & 1;
}

#define F_CF  0x01u
#define F_PF  0x02u
#define F_AF  0x04u
#define F_ZF  0x08u
#define F_SF  0x10u
#define F_OF  0x20u
#define F_ALL 0x3Fu

#define SETZSP_M(res, bits, M) do { \
    if ((M) & F_ZF) RG_(zf) = ((uint##bits##_t)(res) == 0); \
    if ((M) & F_SF) RG_(sf) = (((uint##bits##_t)(res)) >> ((bits) - 1)) & 1; \
    if ((M) & F_PF) RG_(pf) = parity8((uint32_t)(res)); \
} while (0)

#define FLAGS_ADD_M(a, b, res, bits, M) do { \
    SETZSP_M(res, bits, M); \
    if ((M) & F_CF) RG_(cf) = ((uint##bits##_t)(res) < (uint##bits##_t)(a)); \
    if ((M) & F_AF) RG_(af) = ((((a) ^ (b) ^ (res)) >> 4) & 1); \
    if ((M) & F_OF) RG_(of) = ((~((a) ^ (b)) & ((a) ^ (res))) >> ((bits) - 1)) & 1; \
} while (0)

#define FLAGS_SUB_M(a, b, res, bits, M) do { \
    SETZSP_M(res, bits, M); \
    if ((M) & F_CF) RG_(cf) = ((uint##bits##_t)(a) < (uint##bits##_t)(b)); \
    if ((M) & F_AF) RG_(af) = ((((a) ^ (b) ^ (res)) >> 4) & 1); \
    if ((M) & F_OF) RG_(of) = ((((a) ^ (b)) & ((a) ^ (res))) >> ((bits) - 1)) & 1; \
} while (0)

#define FLAGS_ADC_M(a, b, cin, res, bits, M) do { \
    SETZSP_M(res, bits, M); \
    if ((M) & F_CF) RG_(cf) = (cin) ? ((uint##bits##_t)(res) <= (uint##bits##_t)(a)) \
                                 : ((uint##bits##_t)(res) <  (uint##bits##_t)(a)); \
    if ((M) & F_AF) RG_(af) = ((((a) ^ (b) ^ (res)) >> 4) & 1); \
    if ((M) & F_OF) RG_(of) = ((~((a) ^ (b)) & ((a) ^ (res))) >> ((bits) - 1)) & 1; \
} while (0)

#define FLAGS_SBB_M(a, b, cin, res, bits, M) do { \
    SETZSP_M(res, bits, M); \
    if ((M) & F_CF) RG_(cf) = (cin) ? ((uint##bits##_t)(a) <= (uint##bits##_t)(b)) \
                                 : ((uint##bits##_t)(a) <  (uint##bits##_t)(b)); \
    if ((M) & F_AF) RG_(af) = ((((a) ^ (b) ^ (res)) >> 4) & 1); \
    if ((M) & F_OF) RG_(of) = ((((a) ^ (b)) & ((a) ^ (res))) >> ((bits) - 1)) & 1; \
} while (0)

#define FLAGS_LOG_M(res, bits, M) do { \
    SETZSP_M(res, bits, M); \
    if ((M) & F_CF) RG_(cf) = 0; \
    if ((M) & F_OF) RG_(of) = 0; \
    if ((M) & F_AF) RG_(af) = 0; \
} while (0)

/* --------------------------------------------------------------------------
 * Stack Operations
 * -------------------------------------------------------------------------- */
#define GUEST_PUSH32(c, v) do { (c)->esp -= 4; MR32((c)->esp) = (uint32_t)(v); } while (0)
#define GUEST_POP32(c, d)  do { (d) = MR32((c)->esp); (c)->esp += 4; } while (0)

#define PUSH32(v) do { uint32_t _pv = (uint32_t)(v); RG_(esp) -= 4; MR32(RG_(esp)) = _pv; } while (0)
#define POP32(d)  do { uint32_t _qv = MR32(RG_(esp)); RG_(esp) += 4; (d) = _qv; } while (0)

/* --------------------------------------------------------------------------
 * Condition Codes
 * -------------------------------------------------------------------------- */
#define CC_O   (RG_(of) != 0)
#define CC_NO  (RG_(of) == 0)
#define CC_B   (RG_(cf) != 0)
#define CC_AE  (RG_(cf) == 0)
#define CC_E   (RG_(zf) != 0)
#define CC_NE  (RG_(zf) == 0)
#define CC_BE  (RG_(cf) != 0 || RG_(zf) != 0)
#define CC_A   (RG_(cf) == 0 && RG_(zf) == 0)
#define CC_S   (RG_(sf) != 0)
#define CC_NS  (RG_(sf) == 0)
#define CC_P   (RG_(pf) != 0)
#define CC_NP  (RG_(pf) == 0)
#define CC_L   (RG_(sf) != RG_(of))
#define CC_GE  (RG_(sf) == RG_(of))
#define CC_LE  (RG_(zf) != 0 || RG_(sf) != RG_(of))
#define CC_G   (RG_(zf) == 0 && RG_(sf) == RG_(of))

/* --------------------------------------------------------------------------
 * EFLAGS Pack / Unpack
 * -------------------------------------------------------------------------- */
static inline uint32_t eflags_get(const struct CPU *c) {
    return 0x00000202u | (c->cf & 1u) | ((c->pf & 1u) << 2) | ((c->af & 1u) << 4)
         | ((c->zf & 1u) << 6) | ((c->sf & 1u) << 7) | ((c->df & 1u) << 10) | ((c->of & 1u) << 11)
         | (c->sysfl & 0x00240000u);
}

static inline void eflags_set(struct CPU *c, uint32_t f) {
    c->cf = f & 1u; c->pf = (f >> 2) & 1u; c->af = (f >> 4) & 1u;
    c->zf = (f >> 6) & 1u; c->sf = (f >> 7) & 1u; c->df = (f >> 10) & 1u; c->of = (f >> 11) & 1u;
    c->sysfl = f & 0x00240000u;
}

/* --------------------------------------------------------------------------
 * x87 FPU Stack Operations & Precision Emulation
 * -------------------------------------------------------------------------- */
#define ST(n)    (c->st[(c->top + (n)) & 7])
#define FPUSH(v) do { double _fpv = (double)(v); \
    c->top = (c->top - 1) & 7; c->st[c->top] = _fpv; } while (0)
#define FPOP()   do { c->top = (c->top + 1) & 7; } while (0)

#define FSW_C0 (1u << 8)
#define FSW_C1 (1u << 9)
#define FSW_C2 (1u << 10)
#define FSW_C3 (1u << 14)

static inline uint16_t fsw_get(const struct CPU *c) {
    return (uint16_t)((c->fsw & (uint16_t)~0x3800u) | (uint16_t)((c->top & 7u) << 11));
}

static inline void fcompare(struct CPU *c, double a, double b) {
    c->fsw &= (uint16_t)~(FSW_C0 | FSW_C2 | FSW_C3);
    if (a != a || b != b)      c->fsw |= FSW_C0 | FSW_C2 | FSW_C3;
    else if (a > b)            ;
    else if (a < b)            c->fsw |= FSW_C0;
    else                       c->fsw |= FSW_C3;
}

#define FCOMI(a, b) do { double _x = (a), _y = (b); \
    if (_x != _x || _y != _y) { RG_(zf) = 1; RG_(pf) = 1; RG_(cf) = 1; } \
    else { RG_(pf) = 0; RG_(zf) = (_x == _y); RG_(cf) = (_x < _y); } \
    RG_(of) = RG_(sf) = RG_(af) = 0; } while (0)

static inline double x87_round(uint16_t fcw, double v) {
    switch ((fcw >> 10) & 3u) {
    case 0:  return nearbyint(v);
    case 1:  return floor(v);
    case 2:  return ceil(v);
    default: return trunc(v);
    }
}

static inline double x87_round24(double v, uint32_t rc) {
    uint64_t b; memcpy(&b, &v, 8);
    uint64_t low = b & 0x1FFFFFFFull;
    if (!low || ((b >> 52) & 0x7FFu) == 0x7FFu) return v;
    uint64_t t = b - low;
    int up;
    if (rc == 0) up = low > 0x10000000ull || (low == 0x10000000ull && (t & 0x20000000ull));
    else if (rc == 3) up = 0;
    else up = (int)(b >> 63) == (rc == 1);
    if (up) t += 0x20000000ull;
    memcpy(&v, &t, 8);
    return v;
}

static inline double x87_pcround(uint16_t fcw, double v) {
    if ((fcw & 0x0F00u) == 0u) {
        float f = (float)v, a = fabsf(f);
        if (a > 0x1p-126f && a <= 0x1.fffffep127f) return (double)f;
        if (v == 0.0) return v;
        return x87_round24(v, 0);
    }
    if (fcw & 0x0300u) return v;
    return x87_round24(v, (fcw >> 10) & 3u);
}
#define X87R(v) x87_pcround(c->fcw, (v))

#if defined(__GNUC__) || defined(__clang__)
#define X87_INDEF (-__builtin_nan(""))
#elif defined(NAN)
#define X87_INDEF (-(double)NAN)
#else
#define X87_INDEF (-0.0/0.0)
#endif

static inline double x87_r1(double a, double r) {
    if (r == r) return r;
    if (a != a) return a;
    return X87_INDEF;
}

static inline double x87_r2(double a, double b, double r) {
    if (r == r) return r;
    if (a != a) return a;
    if (b != b) return b;
    return X87_INDEF;
}

static inline double x87_r2pc(uint16_t fcw, double a, double b, double r) {
    return x87_pcround(fcw, x87_r2(a, b, r));
}
#define X87R2(a, b, r) x87_r2pc(c->fcw, (a), (b), (r))

static inline void f80_store(uint8_t *p, double v) {
    uint64_t bits; memcpy(&bits, &v, 8);
    uint32_t sign = (uint32_t)(bits >> 63);
    int32_t  exp  = (int32_t)((bits >> 52) & 0x7FF);
    uint64_t man  = bits & 0xFFFFFFFFFFFFFull;
    uint16_t e80; uint64_t m80;
    if (exp == 0x7FF) { e80 = 0x7FFF; m80 = man ? (0xC000000000000000ull | (man << 11)) : 0x8000000000000000ull; }
    else if (exp == 0) {
        if (!man) { e80 = 0; m80 = 0; }
        else { int sh = 0; while (!(man & 0x10000000000000ull)) { man <<= 1; sh++; }
               e80 = (uint16_t)(16383 - 1022 - sh); m80 = (man << 11) | 0x8000000000000000ull; }
    } else { e80 = (uint16_t)(exp - 1023 + 16383); m80 = 0x8000000000000000ull | (man << 11); }
    memcpy(p, &m80, 8);
    uint16_t se = (uint16_t)((sign << 15) | e80);
    memcpy(p + 8, &se, 2);
}

static inline double f80_load(const uint8_t *p) {
    uint64_t m80; uint16_t se;
    memcpy(&m80, p, 8); memcpy(&se, p + 8, 2);
    uint32_t sign = (uint32_t)(se >> 15);
    int32_t  e80  = (int32_t)(se & 0x7FFF);
    if (e80 == 0 && m80 == 0) return sign ? -0.0 : 0.0;
    if (e80 == 0x7FFF) {
        double inf = sign ? -1.0/0.0 : 1.0/0.0;
        return (m80 << 1) ? (0.0/0.0) : inf;
    }
    int32_t exp = e80 - 16383 + 1023;
    uint64_t man = (m80 & 0x7FFFFFFFFFFFFFFFull) >> 11;
    if (exp <= 0) return sign ? -0.0 : 0.0;
    if (exp >= 0x7FF) { double inf = sign ? -1.0/0.0 : 1.0/0.0; return inf; }
    uint64_t bits = ((uint64_t)sign << 63) | ((uint64_t)(uint32_t)exp << 52) | man;
    double d; memcpy(&d, &bits, 8); return d;
}

#define FTOL2_BODY(c) do { \
    uint32_t _fT = (uint32_t)(c)->top & 7u; \
    double _fv = (c)->st[_fT]; \
    uint64_t _fq = x86_cvt_i64(x87_round((c)->fcw, _fv)); \
    double _frq = (double)(int64_t)_fq; \
    (c)->st[(_fT - 1u) & 7u] = _frq; \
    uint32_t _flo = (uint32_t)_fq, _fhi = (uint32_t)(_fq >> 32); \
    float _ffv = (float)_fv; uint32_t _fedx; memcpy(&_fedx, &_ffv, 4); \
    (c)->eax = _flo; \
    if (_flo == 0u) _fedx = _fhi; \
    if (_flo == 0u && (_fhi & 0x7fffffffu) == 0u) { \
        (c)->edx = _fhi; FLAGS_LOG_M(0u, 32, 0x3fu); (c)->top = (int32_t)((_fT + 1u) & 7u); \
    } else { \
        double _fd = X87R(x87_r2(_fv, _frq, _fv - _frq)); \
        (c)->st[_fT] = _fd; \
        float _ffd = (float)_fd; uint32_t _fecx; memcpy(&_fecx, &_ffd, 4); \
        (c)->top = (int32_t)((_fT + 1u) & 7u); \
        if (_fedx >> 31) _fecx ^= 0x80000000u; \
        uint32_t _fe2 = _fecx + 0x7fffffffu, _fcf = _fe2 < _fecx; \
        (c)->ecx = _fe2; \
        if (_fedx >> 31) { \
            uint32_t _fa = _flo + _fcf, _fc2 = _fcf ? _fa <= _flo : _fa < _flo; (c)->eax = _fa; \
            uint32_t _fr = _fhi + _fc2; FLAGS_ADC_M(_fhi, 0u, _fc2, _fr, 32, 0x3fu); (c)->edx = _fr; \
        } else { \
            uint32_t _fa = _flo - _fcf, _fc2 = _fcf ? _flo <= 0u : 0u; (c)->eax = _fa; \
            uint32_t _fr = _fhi - _fc2; FLAGS_SBB_M(_fhi, 0u, _fc2, _fr, 32, 0x3fu); (c)->edx = _fr; \
        } \
    } } while (0)
#define FTOL2_INL(c) do { FTOL2_BODY(c); POP32((c)->eip); } while (0)

/* --------------------------------------------------------------------------
 * SSE / SSE2 / Math Helper Functions
 * -------------------------------------------------------------------------- */

static inline float sse_r2f(float a, float b, float r) {
    if (r == r) return r;
    if (a != a) return a;
    if (b != b) return b;
    return (float)X87_INDEF;
}

static inline float sse_r1f(float a, float r) {
    if (r == r) return r;
    if (a != a) return a;
    return (float)X87_INDEF;
}

static inline double sse_r2d(double a, double b, double r) {
    if (r == r) return r;
    if (a != a) return a;
    if (b != b) return b;
    return X87_INDEF;
}

static inline double sse_r1d(double a, double r) {
    if (r == r) return r;
    if (a != a) return a;
    return X87_INDEF;
}

static inline uint32_t x86_cvt_i32(double v) {
    if (!(v >= -2147483648.0 && v <= 2147483647.0)) return 0x80000000u;
    return (uint32_t)(int32_t)v;
}

static inline uint16_t x86_cvt_i16(double v) {
    if (!(v >= -32768.0 && v <= 32767.0)) return 0x8000u;
    return (uint16_t)(int16_t)v;
}

static inline uint64_t x86_cvt_i64(double v) {
    if (!(v >= -9223372036854775808.0 && v < 9223372036854775808.0))
        return 0x8000000000000000ull;
    return (uint64_t)(int64_t)v;
}

/* --------------------------------------------------------------------------
 * WebAssembly SIMD128 Accelerators
 * -------------------------------------------------------------------------- */
#if defined(__wasm_simd128__)
#define WASM_SIMD_ADDPS(d, s)  ((d).v = wasm_f32x4_add((d).v, (s).v))
#define WASM_SIMD_SUBPS(d, s)  ((d).v = wasm_f32x4_sub((d).v, (s).v))
#define WASM_SIMD_MULPS(d, s)  ((d).v = wasm_f32x4_mul((d).v, (s).v))
#define WASM_SIMD_DIVPS(d, s)  ((d).v = wasm_f32x4_div((d).v, (s).v))
#define WASM_SIMD_XORPS(d, s)  ((d).v = wasm_v128_xor((d).v, (s).v))
#define WASM_SIMD_XORPD(d, s)  ((d).v = wasm_v128_xor((d).v, (s).v))
#define WASM_SIMD_PXOR(d, s)   ((d).v = wasm_v128_xor((d).v, (s).v))
#define WASM_SIMD_ANDPS(d, s)  ((d).v = wasm_v128_and((d).v, (s).v))
#define WASM_SIMD_ANDPD(d, s)  ((d).v = wasm_v128_and((d).v, (s).v))
#define WASM_SIMD_PAND(d, s)   ((d).v = wasm_v128_and((d).v, (s).v))
#define WASM_SIMD_ORPS(d, s)   ((d).v = wasm_v128_or((d).v, (s).v))
#define WASM_SIMD_ORPD(d, s)   ((d).v = wasm_v128_or((d).v, (s).v))
#define WASM_SIMD_POR(d, s)    ((d).v = wasm_v128_or((d).v, (s).v))
#define WASM_SIMD_ANDNPS(d, s) ((d).v = wasm_v128_andnot((s).v, (d).v))
#define WASM_SIMD_MINPS(d, s)  ((d).v = wasm_f32x4_pmin((s).v, (d).v))
#define WASM_SIMD_MAXPS(d, s)  ((d).v = wasm_f32x4_pmax((s).v, (d).v))
#define WASM_SIMD_SQRTPS(d, s) ((d).v = wasm_f32x4_sqrt((s).v))
#define WASM_SIMD_PADDD(d, s)  ((d).v = wasm_i32x4_add((d).v, (s).v))
#define WASM_SIMD_PSUBD(d, s)  ((d).v = wasm_i32x4_sub((d).v, (s).v))
#endif

#ifdef __cplusplus
}
#endif

#endif /* PROSTREET_CPU_H */

