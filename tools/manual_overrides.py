"""Manually Recovered Functions and Shard Patches for NFS ProStreet.

Preserves authentic implementations across shard regenerations:
- Fastmem bChunk alloc/free/realloc (sub_00463e90, sub_00435eb0, etc.)
- bString::reserve (sub_004dd540) and bString::Hash (sub_0052a7f0, sub_0052b8d0)
- MSVC C++ runtime helpers (__ehvec_ctor, __EH_prolog, __EH_epilog)
- Disc check bypass (sub_0070f600), Multi-instance check bypass (sub_0070f640)
- WASM non-blocking timer setup (sub_008975c3)
- Static ctor helpers missing from raw disassembly
"""
from __future__ import annotations

ADDITIONAL_FUNCTIONS = [
    0x00463d70,
    0x004e03d0,
    0x004f9db0,
    0x004fed90,
    0x00634490,
    0x007223b0,
    0x00783de0,
    0x00783e30,
    0x009006c0,
]

MANUAL_RECOVERIES: dict[int, str] = {
    0x01c04000: r"""void sub_01c04000(CPU *c) {
    LR_ENTER;
L_01c04000:
    PUSH32(RG_(ecx));
    { uint32_t _a = MR32(RG_(esi)+0x108u), _b = 0x0u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x09u); }
    if (CC_BE) goto L_01c0400e;
L_01c0400a:
    { uint32_t _r = ((uint8_t)RG_(eax)) ^ ((uint8_t)RG_(eax)); FLAGS_LOG_M(_r, 8, 0x00u); RG_(eax) = (RG_(eax) & 0xffffff00u) | (uint32_t)((_r) & 0xffu); }
    { uint32_t _t; POP32(_t); RG_(ecx) = (uint32_t)(_t); }
    RG_(esp) += 4u;
    LR_STORE;
    return;
L_01c0400e:
    RG_(eax) = (uint32_t)(MR32(RG_(esi)+0x100u));
    RG_(edx) = (uint32_t)(MR32(RG_(esi)+0x104u));
    PUSH32(RG_(eax));
    RG_(eax) = (uint32_t)(RG_(esi));
    PUSH32(0x1c04033u);
    LR_STORE;
    sub_00463f70(c);
    LR_RELOAD;
    { uint32_t _r = (RG_(eax)) & (RG_(eax)); FLAGS_LOG_M(_r, 32, 0x08u); }
    if (CC_E) goto L_01c0400a;
L_01c04037:
    RG_(ecx) = (uint32_t)(MR32(RG_(esi)+0x110u));
    MR32(RG_(eax)) = (RG_(ecx));
    RG_(edx) = (uint32_t)(MR32(RG_(esi)+0x104u));
    MR32(RG_(eax)+4u) = (RG_(edx));
    MR32(RG_(esi)+0x110u) = (RG_(eax));
    RG_(eax) = (uint32_t)(MR32(RG_(esi)+0x104u));
    MR32(RG_(esi)+0x114u) = (RG_(eax));
    RG_(eax) = (RG_(eax) & 0xffffff00u) | 1u;
    { uint32_t _t; POP32(_t); RG_(ecx) = (uint32_t)(_t); }
    RG_(esp) += 4u;
    LR_STORE;
    return;
}
""",
    0x00828460: r"""void sub_00828460(CPU *c) {
    LR_ENTER;
L_00828460:
    { uint32_t _a = RG_(ecx), _b = MR32(0xa8be00u), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    if (CC_NE) goto L_0082846a;
L_00828468:
    RG_(esp) += 4u;
    LR_STORE;
    return;
L_0082846a:
    goto L_00828da4;
L_00828da4:
    PUSH32(RG_(ebp));
    RG_(ebp) = (uint32_t)(RG_(esp));
    { uint32_t _a = RG_(esp), _b = 0x328u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x3fu); RG_(esp) = (uint32_t)(_r); }
    MR32(0xb33b90u) = (RG_(eax));
    MR32(0xb33b8cu) = (RG_(ecx));
    MR32(0xb33b88u) = (RG_(edx));
    MR32(0xb33b84u) = (RG_(ebx));
    MR32(0xb33b80u) = (RG_(esi));
    MR32(0xb33b7cu) = (RG_(edi));
    MR16(0xb33ba8u) = (0x23u);
    MR16(0xb33b9cu) = (0x1bu);
    MR16(0xb33b78u) = (0x23u);
    MR16(0xb33b74u) = (0x23u);
    MR16(0xb33b70u) = (0x3bu);
    MR16(0xb33b6cu) = (0x0u);
    { uint32_t _t; POP32(_t); MR32(0xb33ba0u) = (_t); }
    RG_(eax) = (uint32_t)(MR32(RG_(ebp)));
    MR32(0xb33b94u) = (RG_(eax));
    RG_(eax) = (uint32_t)(MR32(RG_(ebp)+0x4u));
    MR32(0xb33b98u) = (RG_(eax));
    RG_(eax) = (uint32_t)((RG_(ebp)+0x8u));
    MR32(0xb33ba4u) = (RG_(eax));
    RG_(eax) = (uint32_t)(MR32(RG_(ebp)+0xfffffce0u));
    MR32(0xb33ae0u) = (0x10001u);
    RG_(eax) = (uint32_t)(MR32(0xb33b98u));
    MR32(0xb33a94u) = (RG_(eax));
    MR32(0xb33a88u) = (0xc0000409u);
    MR32(0xb33a8cu) = (0x1u);
    RG_(eax) = (uint32_t)(MR32(0xa8be00u));
    MR32(RG_(ebp)+0xfffffcd8u) = (RG_(eax));
    RG_(eax) = (uint32_t)(MR32(0xa8be04u));
    MR32(RG_(ebp)+0xfffffcdcu) = (RG_(eax));
    PUSH32(0x00828e63u);
    LR_STORE;
    DISPATCH_CALL(c, MR32(0x96716cu));
    LR_RELOAD;
    MR32(0xb33ad8u) = (RG_(eax));
    PUSH32(0x1u);
    PUSH32(0x00828e6fu);
    LR_STORE;
    sub_008291fe(c);
    LR_RELOAD;
    { uint32_t _t; POP32(_t); RG_(ecx) = (uint32_t)(_t); }
    PUSH32(0x0u);
    PUSH32(0x00828e78u);
    LR_STORE;
    DISPATCH_CALL(c, MR32(0x9670a0u));
    LR_RELOAD;
    PUSH32(0x9a86c8u);
    PUSH32(0x00828e83u);
    LR_STORE;
    DISPATCH_CALL(c, MR32(0x9670a4u));
    LR_RELOAD;
    { uint32_t _a = MR32(0xb33ad8u), _b = 0x0u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    if (CC_NE) goto L_00828e94;
L_00828e8c:
    PUSH32(0x1u);
    PUSH32(0x00828e93u);
    LR_STORE;
    sub_008291fe(c);
    LR_RELOAD;
    { uint32_t _t; POP32(_t); RG_(ecx) = (uint32_t)(_t); }
L_00828e94:
    PUSH32(0xc0000409u);
    PUSH32(0x00828e9fu);
    LR_STORE;
    DISPATCH_CALL(c, MR32(0x9670a8u));
    LR_RELOAD;
    PUSH32(RG_(eax));
    PUSH32(0x00828ea6u);
    LR_STORE;
    DISPATCH_CALL(c, MR32(0x9670acu));
    LR_RELOAD;
    RG_(esp) = RG_(ebp);
    { uint32_t _t; POP32(_t); RG_(ebp) = _t; }
    RG_(esp) += 4u;
    LR_STORE;
    return;
}""",
    0x00435390: r"""void sub_00435390(CPU *c) {
    LR_ENTER;
L_00435390:
    PUSH32(RG_(ebp));
    RG_(ebp) = (uint32_t)(RG_(esp));
    { uint32_t _r = (RG_(esp)) & (0xfffffff8u); FLAGS_LOG_M(_r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    { uint32_t _a = RG_(esp), _b = 0x14u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    PUSH32(RG_(ebx));
    PUSH32(RG_(esi));
    PUSH32(RG_(edi));
    RG_(edi) = (uint32_t)(RG_(ecx));
    RG_(ecx) = (uint32_t)(MR32(RG_(edi)+0x78u));
    PUSH32(0x9ef5c4u);
    PUSH32(0x004353abu);
    LR_STORE;
    sub_00904970(c);
    LR_RELOAD;
    RG_(ebx) = (uint32_t)(MR32(RG_(ebp)+0x8u));
    { uint32_t _a = RG_(ebx), _b = 0x3u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(ebx) = (uint32_t)(_r); }
    { uint32_t _r = (RG_(ebx)) & (0xfffffffcu); FLAGS_LOG_M(_r, 32, 0x00u); RG_(ebx) = (uint32_t)(_r); }
    { uint32_t _a = RG_(ebx), _b = 0x10u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x30u); }
    if (CC_GE) goto L_004353be;
L_004353b9:
    RG_(ebx) = (uint32_t)(0x10u);
L_004353be:
    { uint32_t _r = (RG_(ecx)) ^ (RG_(ecx)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(ecx) = (uint32_t)(_r); }
    { uint32_t _a = MR32(RG_(ebp)+0x14u), _b = RG_(ecx), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    MR32(RG_(esp)+0x18u) = (RG_(ecx));
    MR32(RG_(esp)+0x14u) = (RG_(ecx));
    MR32(RG_(esp)+0xcu) = (0x7fffffffu);
    RG_(eax) = (uint32_t)((RG_(edi)+0x4u));
    if (CC_E) goto L_00435435;
L_004353d8:
    RG_(esi) = (uint32_t)(MR32(RG_(eax)));
    { uint32_t _a = RG_(esi), _b = RG_(eax), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    if (CC_E) goto L_004354a0;
L_004353e2:
    RG_(eax) = (uint32_t)(MR32(RG_(ebp)+0xcu));
    { uint32_t _a = RG_(eax), _b = 0xffffffffu, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    MR32(RG_(esp)+0x18u) = (RG_(eax));
L_004353ec:
    RG_(edx) = (uint32_t)(MR32(RG_(ebp)+0x10u));
    RG_(eax) = (uint32_t)(MR32(RG_(ebp)+0xcu));
    { uint32_t _a = RG_(edx), _b = RG_(esi), _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(edx) = (uint32_t)(_r); }
    { uint32_t _r = (RG_(edx)) & (MR32(RG_(esp)+0x18u)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(edx) = (uint32_t)(_r); }
    { uint32_t _a = RG_(eax), _b = RG_(edx), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    RG_(edx) = (uint32_t)((int32_t)RG_(eax) >> 31);
    {
        int32_t _den = (int32_t)(MR32(RG_(ebp)+0xcu));
        if (_den != 0) {
            int64_t _num = (int64_t)(((uint64_t)RG_(edx) << 32) | (uint64_t)(uint32_t)RG_(eax));
            if (!(_num == (-9223372036854775807LL - 1LL) && _den == -1)) {
                int64_t _q = _num / _den;
                int64_t _rem = _num % _den;
                if (_q >= -2147483648LL && _q <= 2147483647LL) {
                    RG_(eax) = (uint32_t)(int32_t)_q;
                    RG_(edx) = (uint32_t)(int32_t)_rem;
                }
            }
        }
    }
    RG_(eax) = (uint32_t)(MR32(RG_(esi)+0x8u));
    { uint32_t _a = RG_(eax), _b = RG_(edx), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    { uint32_t _a = RG_(eax), _b = RG_(ebx), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); RG_(eax) = (uint32_t)(_r); }
    MR32(RG_(esp)+0x10u) = (RG_(edx));
    if (CC_E) goto L_00435410;
L_0043540b:
    { uint32_t _a = RG_(eax), _b = 0x10u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x30u); }
    if (CC_L) goto L_0043542a;
L_00435410:
    { uint32_t _a = RG_(eax), _b = MR32(RG_(esp)+0xcu), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x30u); }
    if (CC_GE) goto L_0043542a;
L_00435416:
    { uint32_t _a = MR32(RG_(ebp)+0x18u), _b = 0x0u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    MR32(RG_(esp)+0xcu) = (RG_(eax));
    RG_(eax) = (uint32_t)(MR32(RG_(esp)+0x10u));
    RG_(ecx) = (uint32_t)(RG_(esi));
    MR32(RG_(esp)+0x14u) = (RG_(eax));
    if (CC_E) goto L_00435498;
L_0043542a:
    RG_(esi) = (uint32_t)(MR32(RG_(esi)));
    RG_(eax) = (uint32_t)((RG_(edi)+0x4u));
    { uint32_t _a = RG_(esi), _b = RG_(eax), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    if (CC_NE) goto L_004353ec;
L_00435433:
    goto L_00435498;
L_00435435:
    RG_(edx) = (uint32_t)(MR32(RG_(edi)+0x8u));
    { uint32_t _a = RG_(edx), _b = RG_(eax), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    MR32(RG_(esp)+0x10u) = (RG_(edx));
    if (CC_E) goto L_004354a0;
L_00435440:
    RG_(ecx) = (uint32_t)(MR32(RG_(edx)+0x8u));
    RG_(esi) = (uint32_t)(MR32(RG_(ebp)+0xcu));
    RG_(eax) = (uint32_t)(RG_(ecx));
    { uint32_t _a = RG_(eax), _b = RG_(ebx), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    { uint32_t _a = RG_(eax), _b = RG_(edx), _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    { uint32_t _a = RG_(eax), _b = MR32(RG_(ebp)+0x10u), _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    RG_(edx) = (uint32_t)((RG_(esi)+0xffffffffu));
    { uint32_t _r = (RG_(eax)) & (RG_(edx)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    RG_(edx) = (uint32_t)((int32_t)RG_(eax) >> 31);
    {
        int32_t _den = (int32_t)(RG_(esi));
        if (_den != 0) {
            int64_t _num = (int64_t)(((uint64_t)RG_(edx) << 32) | (uint64_t)(uint32_t)RG_(eax));
            if (!(_num == (-9223372036854775807LL - 1LL) && _den == -1)) {
                int64_t _q = _num / _den;
                int64_t _rem = _num % _den;
                if (_q >= -2147483648LL && _q <= 2147483647LL) {
                    RG_(eax) = (uint32_t)(int32_t)_q;
                    RG_(edx) = (uint32_t)(int32_t)_rem;
                }
            }
        }
    }
    { uint32_t _a = RG_(ecx), _b = RG_(edx), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x00u); RG_(ecx) = (uint32_t)(_r); }
    { uint32_t _a = RG_(ecx), _b = RG_(ebx), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); RG_(ecx) = (uint32_t)(_r); }
    RG_(eax) = (uint32_t)(RG_(ecx));
    if (CC_E) goto L_00435464;
L_0043545f:
    { uint32_t _a = RG_(eax), _b = 0x10u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x30u); }
    if (CC_L) goto L_00435482;
L_00435464:
    { uint32_t _a = RG_(eax), _b = MR32(RG_(esp)+0xcu), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x30u); }
    if (CC_GE) goto L_00435482;
L_0043546a:
    { uint32_t _a = MR32(RG_(ebp)+0x18u), _b = 0x0u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    RG_(ecx) = (uint32_t)(MR32(RG_(esp)+0x10u));
    MR32(RG_(esp)+0x18u) = (RG_(ecx));
    MR32(RG_(esp)+0xcu) = (RG_(eax));
    MR32(RG_(esp)+0x14u) = (RG_(edx));
    if (CC_E) goto L_00435498;
L_00435480:
    goto L_00435486;
L_00435482:
    RG_(ecx) = (uint32_t)(MR32(RG_(esp)+0x18u));
L_00435486:
    RG_(edx) = (uint32_t)(MR32(RG_(esp)+0x10u));
    RG_(edx) = (uint32_t)(MR32(RG_(edx)+0x4u));
    RG_(eax) = (uint32_t)((RG_(edi)+0x4u));
    { uint32_t _a = RG_(edx), _b = RG_(eax), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    MR32(RG_(esp)+0x10u) = (RG_(edx));
    if (CC_NE) goto L_00435440;
L_00435498:
    { uint32_t _r = (RG_(ecx)) & (RG_(ecx)); FLAGS_LOG_M(_r, 32, 0x08u); }
    if (CC_NE) goto L_00435561;
L_004354a0:
    RG_(ecx) = (uint32_t)(MR32(RG_(edi)+0x78u));
    PUSH32(0x004354a8u);
    LR_STORE;
    sub_00904a30(c);
    LR_RELOAD;
    RG_(eax) = (uint32_t)(MR32(RG_(ebp)+0xcu));
    RG_(eax) = (uint32_t)((RG_(ebx)+RG_(eax)+0x10u));
    { uint32_t _a = RG_(eax), _b = 0x19000u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x30u); }
    MR32(RG_(esp)+0x18u) = (RG_(eax));
    if (CC_GE) goto L_004354c2;
L_004354ba:
    MR32(RG_(esp)+0x18u) = (0x19000u);
L_004354c2:
    PUSH32(0x10u);
    PUSH32(0x004354cau);
    LR_STORE;
    DISPATCH_CALL(c, MR32(0x967218u));
    LR_RELOAD;
    RG_(esi) = (uint32_t)(RG_(eax));
    { uint32_t _a = RG_(esp), _b = 0x4u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    { uint32_t _r = (RG_(esi)) & (RG_(esi)); FLAGS_LOG_M(_r, 32, 0x08u); }
    if (CC_E) goto L_004354e9;
L_004354d3:
    RG_(eax) = (uint32_t)(MR32(RG_(esp)+0x18u));
    PUSH32(RG_(eax));
    MR32(RG_(esi)+0xcu) = (RG_(eax));
    PUSH32(0x004354e1u);
    LR_STORE;
    DISPATCH_CALL(c, MR32(0x967218u));
    LR_RELOAD;
    { uint32_t _a = RG_(esp), _b = 0x4u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    MR32(RG_(esi)+0x8u) = (RG_(eax));
    goto L_004354eb;
L_004354e9:
    { uint32_t _r = (RG_(esi)) ^ (RG_(esi)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(esi) = (uint32_t)(_r); }
L_004354eb:
    RG_(eax) = (uint32_t)(MR32(RG_(esi)+0x8u));
    { uint32_t _r = (RG_(eax)) & (RG_(eax)); FLAGS_LOG_M(_r, 32, 0x08u); }
    if (CC_NE) goto L_00435511;
L_004354f2:
    RG_(edi) = (uint32_t)(MR32(0x967214u));
    RG_(ecx) = (uint32_t)(RG_(eax));
    PUSH32(RG_(ecx));
    PUSH32(0x004354fdu);
    LR_STORE;
    DISPATCH_CALL(c, RG_(edi));
    LR_RELOAD;
    { uint32_t _a = RG_(esp), _b = 0x4u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    PUSH32(RG_(esi));
    PUSH32(0x00435503u);
    LR_STORE;
    DISPATCH_CALL(c, RG_(edi));
    LR_RELOAD;
    { uint32_t _a = RG_(esp), _b = 0x4u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    { uint32_t _r = (RG_(eax)) ^ (RG_(eax)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    { uint32_t _t; POP32(_t); RG_(edi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ebx) = (uint32_t)(_t); }
    RG_(esp) = (uint32_t)(RG_(ebp));
    { uint32_t _t; POP32(_t); RG_(ebp) = (uint32_t)(_t); }
    RG_(esp) += 28u;
    LR_STORE;
    return;
L_00435511:
    RG_(ecx) = (uint32_t)(MR32(RG_(esi)+0xcu));
    { uint32_t _a = MR32(RG_(edi)+0x2cu), _b = RG_(ecx), _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); MR32(RG_(edi)+0x2cu) = (_r); }
    PUSH32(RG_(ecx));
    PUSH32(RG_(edi));
    PUSH32(0x0043551eu);
    LR_STORE;
    sub_00435230(c);
    LR_RELOAD;
    RG_(ecx) = (uint32_t)(MR32(RG_(edi)+0x18u));
    RG_(edx) = (uint32_t)(MR32(RG_(ebp)+0x1cu));
    RG_(eax) = (uint32_t)((RG_(edi)+0x14u));
    MR32(RG_(ecx)) = (RG_(esi));
    MR32(RG_(eax)+0x4u) = (RG_(esi));
    PUSH32(RG_(edx));
    RG_(edx) = (uint32_t)(MR32(RG_(ebp)+0x10u));
    MR32(RG_(esi)) = (RG_(eax));
    RG_(eax) = (uint32_t)(MR32(RG_(ebp)+0x18u));
    PUSH32(RG_(eax));
    RG_(eax) = (uint32_t)(MR32(RG_(ebp)+0xcu));
    MR32(RG_(esi)+0x4u) = (RG_(ecx));
    RG_(ecx) = (uint32_t)(MR32(RG_(ebp)+0x14u));
    PUSH32(RG_(ecx));
    PUSH32(RG_(edx));
    PUSH32(RG_(eax));
    PUSH32(RG_(ebx));
    RG_(ecx) = (uint32_t)(RG_(edi));
    MR8(0xffd210u) = (0x1u);
    PUSH32(0x00435551u);
    LR_STORE;
    sub_00435390(c);
    LR_RELOAD;
    MR8(0xffd210u) = (0x0u);
    { uint32_t _t; POP32(_t); RG_(edi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ebx) = (uint32_t)(_t); }
    RG_(esp) = (uint32_t)(RG_(ebp));
    { uint32_t _t; POP32(_t); RG_(ebp) = (uint32_t)(_t); }
    RG_(esp) += 28u;
    LR_STORE;
    return;
L_00435561:
    { uint32_t _a = RG_(ebx), _b = MR32(RG_(esp)+0x14u), _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(ebx) = (uint32_t)(_r); }
    { uint32_t _a = MR32(RG_(ebp)+0x14u), _b = 0x0u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    if (CC_NE) goto L_0043557a;
L_0043556b:
    RG_(eax) = (uint32_t)(MR32(RG_(ecx)+0x8u));
    { uint32_t _a = RG_(eax), _b = RG_(ebx), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); RG_(eax) = (uint32_t)(_r); }
    RG_(esi) = (uint32_t)((RG_(eax)+RG_(ecx)));
    MR32(RG_(ecx)+0x8u) = (RG_(eax));
    if (CC_NE) goto L_004355a6;
L_00435578:
    goto L_0043559c;
L_0043557a:
    RG_(edx) = (uint32_t)(MR32(RG_(ecx)+0x8u));
    { uint32_t _a = RG_(edx), _b = RG_(ebx), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); RG_(edx) = (uint32_t)(_r); }
    RG_(esi) = (uint32_t)(RG_(ecx));
    if (CC_E) goto L_0043559c;
L_00435583:
    RG_(eax) = (uint32_t)((RG_(ecx)+RG_(ebx)));
    MR32(RG_(eax)+0x8u) = (RG_(edx));
    MR32(RG_(eax)+0xcu) = (0x44443333u);
    RG_(edx) = (uint32_t)(MR32(RG_(ecx)));
    MR32(RG_(ecx)) = (RG_(eax));
    MR32(RG_(edx)+0x4u) = (RG_(eax));
    MR32(RG_(eax)+0x4u) = (RG_(ecx));
    MR32(RG_(eax)) = (RG_(edx));
L_0043559c:
    RG_(eax) = (uint32_t)(MR32(RG_(ecx)));
    RG_(ecx) = (uint32_t)(MR32(RG_(ecx)+0x4u));
    MR32(RG_(ecx)) = (RG_(eax));
    MR32(RG_(eax)+0x4u) = (RG_(ecx));
L_004355a6:
    { uint32_t _a = MR8(RG_(edi)+0x44u), _b = 0x0u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 8, 0x08u); }
    if (CC_E) goto L_004355e6;
L_004355ac:
    { uint32_t _a = MR32(0xbfbcc8u), _b = 0x0u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    if (CC_E) goto L_004355d7;
L_004355b5:
    RG_(ecx) = (uint32_t)((RG_(esp)+0x18u));
    PUSH32(RG_(ecx));
    PUSH32(0x004355c0u);
    LR_STORE;
    DISPATCH_CALL(c, MR32(0x967178u));
    LR_RELOAD;
    RG_(eax) = (uint32_t)(MR32(RG_(esp)+0x18u));
    RG_(edx) = (uint32_t)(MR32(RG_(esp)+0x1cu));
    RG_(ecx) = (uint32_t)(MR32(0xbfbc98u));
    PUSH32(RG_(ebx));
    PUSH32(0x004355d4u);
    LR_STORE;
    sub_0092f380(c);
    LR_RELOAD;
    PUSH32(RG_(eax));
    goto L_004355dd;
L_004355d7:
    PUSH32(RG_(ebx));
    PUSH32(0xaau);
L_004355dd:
    PUSH32(RG_(esi));
    PUSH32(0x004355e3u);
    LR_STORE;
    sub_008287c8(c);
    LR_RELOAD;
    { uint32_t _a = RG_(esp), _b = 0xcu, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
L_004355e6:
    { uint32_t _a = MR32(RG_(edi)+0x30u), _b = RG_(ebx), _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); MR32(RG_(edi)+0x30u) = (_r); }
    RG_(ecx) = (uint32_t)(MR32(RG_(edi)+0x30u));
    RG_(eax) = (uint32_t)(0x1u);
    { uint32_t _a = MR32(RG_(edi)+0x24u), _b = RG_(eax), _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); MR32(RG_(edi)+0x24u) = (_r); }
    { uint32_t _a = MR32(RG_(edi)+0x28u), _b = RG_(eax), _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); MR32(RG_(edi)+0x28u) = (_r); }
    { uint32_t _a = RG_(ecx), _b = MR32(RG_(edi)+0x34u), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x38u); }
    if (CC_LE) goto L_004355ff;
L_004355fc:
    MR32(RG_(edi)+0x34u) = (RG_(ecx));
L_004355ff:
    RG_(eax) = (uint32_t)(MR32(RG_(edi)+0x2cu));
    RG_(edx) = (uint32_t)(RG_(eax));
    { uint32_t _a = RG_(eax), _b = MR32(RG_(edi)+0x34u), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    { uint32_t _a = RG_(edx), _b = RG_(ecx), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x00u); RG_(edx) = (uint32_t)(_r); }
    RG_(ecx) = (uint32_t)(MR32(RG_(edi)+0x78u));
    MR32(RG_(edi)+0x38u) = (RG_(edx));
    MR32(RG_(edi)+0x3cu) = (RG_(eax));
    PUSH32(0x00435617u);
    LR_STORE;
    sub_00904a30(c);
    LR_RELOAD;
    RG_(eax) = (uint32_t)(MR32(RG_(ebp)+0x1cu));
    MR32(RG_(eax)) = (RG_(ebx));
    { uint32_t _t; POP32(_t); RG_(edi) = (uint32_t)(_t); }
    RG_(eax) = (uint32_t)(RG_(esi));
    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ebx) = (uint32_t)(_t); }
    RG_(esp) = (uint32_t)(RG_(ebp));
    { uint32_t _t; POP32(_t); RG_(ebp) = (uint32_t)(_t); }
    RG_(esp) += 28u;
    LR_STORE;
    return;
}
""",
    0x00430cb0: r"""void sub_00430cb0(CPU *c) {
    LR_ENTER;
L_00430cb0:
    { uint32_t _a = RG_(ecx), _b = 0x30u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x00u); RG_(ecx) = (uint32_t)(_r); }
    LR_STORE;
    DISPATCH_TAIL(c, 0x004291e0u);
}
""",
    0x00435eb0: r"""void sub_00435eb0(CPU *c) {
    LR_ENTER;
L_00435eb0:
    { uint32_t _a = RG_(esp), _b = 0x14u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    RG_(eax) = (uint32_t)(MR32(0xa8be00u));

L_00435eb8:
    { uint32_t _r = (RG_(eax)) ^ (RG_(esp)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    MR32(RG_(esp)+0x10u) = (RG_(eax));
    PUSH32(RG_(ebx));
    RG_(ebx) = (uint32_t)(MR32(RG_(esp)+0x20u));
    PUSH32(RG_(ebp));
    PUSH32(RG_(esi));
    PUSH32(RG_(edi));
    RG_(edi) = (uint32_t)(RG_(ebx));
    { uint32_t _r = (RG_(edi)) & (0x1fu); FLAGS_LOG_M(_r, 32, 0x00u); RG_(edi) = (uint32_t)(_r); }
    MR32(RG_(esp)+0x14u) = (RG_(edi));
    { uint32_t _s = (0x4u) & 31u; if (_s) { uint32_t _v = RG_(edi); uint32_t _r = (_v << _s) & 0xffffffffu; RG_(cf) = (_v >> (32 - _s)) & 1u; FLAGS_LOG_M(_r, 32, 0x00u); RG_(edi) = (uint32_t)(_r); } }
    { uint32_t _a = RG_(edi), _b = 0xb4d9f0u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(edi) = (uint32_t)(_r); }
    RG_(eax) = (uint32_t)(MR32(RG_(edi)+0x4u));
    { uint32_t _a = RG_(eax), _b = 0xffffffffu, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    if (CC_E) goto L_00435f0a;
L_00435ee0:
    { uint32_t _r = (RG_(eax)) ^ (RG_(ebx)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    { uint32_t _r = (RG_(eax)) & (0x1fu); FLAGS_LOG_M(_r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    { uint32_t _r = (RG_(eax)) ^ (RG_(ebx)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    RG_(esi) = (uint32_t)(RG_(eax));
    PUSH32(RG_(esi));
    PUSH32(0x00435eefu);
    LR_STORE;
    DISPATCH_CALL(c, 0x00436360u);
    LR_RELOAD;
    { uint32_t _a = RG_(esp), _b = 0x4u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    { uint32_t _a = RG_(eax), _b = MR32(RG_(esp)+0x28u), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x38u); }
    if (CC_LE) goto L_00435f0a;
L_00435ef8:
    RG_(edi) = (uint32_t)(MR32(RG_(edi)+0x4u));
    MR32(RG_(esp)+0x14u) = (RG_(edi));
    { uint32_t _s = (0x4u) & 31u; if (_s) { uint32_t _v = RG_(edi); uint32_t _r = (_v << _s) & 0xffffffffu; RG_(cf) = (_v >> (32 - _s)) & 1u; FLAGS_LOG_M(_r, 32, 0x00u); RG_(edi) = (uint32_t)(_r); } }
    { uint32_t _a = RG_(edi), _b = 0xb4d9f0u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(edi) = (uint32_t)(_r); }
    RG_(ebx) = (uint32_t)(RG_(esi));
L_00435f0a:
    { uint32_t _a = MR8(RG_(edi)+0x1u), _b = 0x0u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 8, 0x08u); }
    if (CC_E) goto L_00435f13;
L_00435f10:
    { uint32_t _r = (RG_(ebx)) ^ (0x40u); FLAGS_LOG_M(_r, 32, 0x00u); RG_(ebx) = (uint32_t)(_r); }
L_00435f13:
    RG_(eax) = (uint32_t)(MR32(RG_(edi)+0xcu));
    { uint32_t _r = (RG_(ebp)) ^ (RG_(ebp)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(ebp) = (uint32_t)(_r); }
    { uint32_t _a = RG_(eax), _b = RG_(ebp), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    if (CC_E) goto L_00435f43;
L_00435f1c:
    RG_(ecx) = (uint32_t)(MR32(RG_(esp)+0x28u));
    RG_(edx) = (uint32_t)(MR32(RG_(eax)+0x4u));
    RG_(eax) = (uint32_t)(MR32(RG_(eax)+0x10u));
    PUSH32(RG_(ebx));
    PUSH32(RG_(ebp));
    PUSH32(RG_(ebp));
    PUSH32(RG_(ecx));
    PUSH32(RG_(edx));
    PUSH32(0x00435f2du);
    LR_STORE;
    DISPATCH_CALL(c, RG_(eax));
    LR_RELOAD;
    { uint32_t _a = RG_(esp), _b = 0x14u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    { uint32_t _t; POP32(_t); RG_(edi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ebp) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ebx) = (uint32_t)(_t); }
    RG_(ecx) = (uint32_t)(MR32(RG_(esp)+0x10u));
    { uint32_t _r = (RG_(ecx)) ^ (RG_(esp)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(ecx) = (uint32_t)(_r); }
    PUSH32(0x00435f3fu);
    LR_STORE;
    DISPATCH_CALL(c, 0x00828460u);
    LR_RELOAD;
    { uint32_t _a = RG_(esp), _b = 0x14u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    RG_(esp) += 4u;
    LR_STORE;
    return;
L_00435f43:
    { uint32_t _a = MR32(0xbfbcdcu), _b = RG_(ebp), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    MR32(0xbfbcd0u) = (RG_(ebp));
    MR32(0xbfbcd4u) = (RG_(ebp));
    if (CC_NE) goto L_00435f93;
L_00435f57:
    PUSH32(0x9f3598u);
    PUSH32(RG_(ebp));
    RG_(esi) = (uint32_t)(0xb4dd10u);
    PUSH32(RG_(ebp));
    MR8(0xb4d9f1u) = (0x0u);
    MR32(0xb4d9f4u) = (0xffffffffu);
    MR32(0xb4d9f8u) = (0x10u);
    MR32(0xb4dbf0u) = (RG_(esi));
    PUSH32(0x00435f89u);
    LR_STORE;
    DISPATCH_CALL(c, 0x00435140u);
    LR_RELOAD;
    MR32(0xbfbcdcu) = (0x1u);
L_00435f93:
    RG_(ecx) = (uint32_t)(MR32(0xbfbcc0u));
    { uint32_t _a = RG_(ecx), _b = RG_(ebp), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    if (CC_E) goto L_00435fbf;
L_00435f9d:
    RG_(eax) = (uint32_t)(MR32(0xbfbcd8u));
    RG_(edx) = (uint32_t)((int32_t)RG_(eax) >> 31);
    if ((int32_t)RG_(ecx) != 0) {
        int64_t _num = (int64_t)(((uint64_t)RG_(edx) << 32) | (uint64_t)(uint32_t)RG_(eax));
        int32_t _den = (int32_t)RG_(ecx);
        RG_(eax) = (uint32_t)(_num / _den);
        RG_(edx) = (uint32_t)(_num % _den);
    }
    { uint32_t _r = (RG_(edx)) & (RG_(edx)); FLAGS_LOG_M(_r, 32, 0x08u); }
    if (CC_NE) goto L_00435fbf;
L_00435fa9:
    RG_(eax) = (uint32_t)(RG_(ebx));
    { uint32_t _r = (RG_(eax)) & (0x1fu); FLAGS_LOG_M(_r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    RG_(eax) = (uint32_t)(MR32(RG_(eax)*4+0xb4dbf0u));
    { uint32_t _a = RG_(eax), _b = RG_(ebp), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    if (CC_E) goto L_00435fbf;
L_00435fb9:
    PUSH32(RG_(eax));
    PUSH32(0x00435fbfu);
    LR_STORE;
    DISPATCH_CALL(c, 0x00435670u);
    LR_RELOAD;
L_00435fbf:
    RG_(eax) = (uint32_t)(RG_(ebx));
    { uint32_t _s = (0x6u) & 31u; if (_s) { int32_t _v = (int32_t)RG_(eax); uint32_t _r = (uint32_t)(_v >> _s) & 0xffffffffu; RG_(cf) = ((uint32_t)_v >> (_s - 1)) & 1u; FLAGS_LOG_M(_r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); } }
    { uint32_t _r = (RG_(eax)) & (0x1ffcu); FLAGS_LOG_M(_r, 32, 0x08u); RG_(eax) = (uint32_t)(_r); }
    MR32(RG_(esp)+0x10u) = (RG_(eax));
    if (CC_NE) goto L_00435fd6;
L_00435fcf:
    RG_(ecx) = (uint32_t)(MR32(RG_(edi)+0x8u));
    MR32(RG_(esp)+0x10u) = (RG_(ecx));
L_00435fd6:
    RG_(ebp) = (uint32_t)(RG_(ebx));
    RG_(esi) = (uint32_t)(RG_(ebx));
    { uint32_t _s = (0x11u) & 31u; if (_s) { int32_t _v = (int32_t)RG_(esi); uint32_t _r = (uint32_t)(_v >> _s) & 0xffffffffu; RG_(cf) = ((uint32_t)_v >> (_s - 1)) & 1u; FLAGS_LOG_M(_r, 32, 0x00u); RG_(esi) = (uint32_t)(_r); } }
    { uint32_t _r = (RG_(ebp)) & (0x1fu); FLAGS_LOG_M(_r, 32, 0x00u); RG_(ebp) = (uint32_t)(_r); }
    RG_(edi) = (uint32_t)(MR32(RG_(ebp)*4+0xb4dbf0u));
    RG_(ecx) = (uint32_t)(MR32(RG_(edi)+0x78u));
    { uint32_t _r = (RG_(esi)) & (0x1ffcu); FLAGS_LOG_M(_r, 32, 0x00u); RG_(esi) = (uint32_t)(_r); }
    PUSH32(0x9ef5c4u);
    { uint32_t _a = RG_(esi), _b = 0x14u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esi) = (uint32_t)(_r); }
    PUSH32(0x00435ffdu);
    LR_STORE;
    DISPATCH_CALL(c, 0x00904970u);
    LR_RELOAD;
    RG_(edx) = (uint32_t)((RG_(esp)+0x1cu));
    PUSH32(RG_(edx));
    RG_(edx) = (uint32_t)(MR32(RG_(esp)+0x14u));
    RG_(ecx) = (uint32_t)(RG_(ebx));
    { uint32_t _r = (RG_(ecx)) & (0x80u); FLAGS_LOG_M(_r, 32, 0x00u); RG_(ecx) = (uint32_t)(_r); }
    PUSH32(RG_(ecx));
    RG_(eax) = (uint32_t)(RG_(ebx));
    { uint32_t _r = (RG_(eax)) & (0x40u); FLAGS_LOG_M(_r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    PUSH32(RG_(eax));
    MR32(RG_(esp)+0x24u) = (RG_(eax));
    RG_(eax) = (uint32_t)(MR32(RG_(esp)+0x34u));
    PUSH32(RG_(esi));
    PUSH32(RG_(edx));
    { uint32_t _a = RG_(eax), _b = 0x14u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    PUSH32(RG_(eax));
    RG_(ecx) = (uint32_t)(RG_(edi));
    PUSH32(0x0043602au);
    LR_STORE;
    DISPATCH_CALL(c, 0x00435390u);
    LR_RELOAD;
    RG_(ecx) = (uint32_t)(RG_(eax));
    { uint32_t _r = (RG_(ecx)) & (RG_(ecx)); FLAGS_LOG_M(_r, 32, 0x08u); }
    if (CC_E) goto L_004360b6;
L_00436034:
    { uint32_t _r = (RG_(edx)) ^ (RG_(edx)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(edx) = (uint32_t)(_r); }
    { uint32_t _a = MR32(RG_(esp)+0x18u), _b = RG_(edx), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    if (CC_E) goto L_0043604f;
L_0043603c:
    RG_(edx) = (uint32_t)((RG_(ecx)+RG_(esi)));
    RG_(esi) = (uint32_t)(MR32(RG_(esp)+0x10u));
    RG_(eax) = (uint32_t)((RG_(esi)+0xffffffffu));
    { uint32_t _r = (RG_(edx)) & (RG_(eax)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(edx) = (uint32_t)(_r); }
    RG_(eax) = (uint32_t)(RG_(esi));
    { uint32_t _a = RG_(eax), _b = RG_(edx), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    RG_(edx) = (uint32_t)((int32_t)RG_(eax) >> 31);
    if ((int32_t)RG_(esi) != 0) {
        int64_t _num = (int64_t)(((uint64_t)RG_(edx) << 32) | (uint64_t)(uint32_t)RG_(eax));
        int32_t _den = (int32_t)RG_(esi);
        RG_(eax) = (uint32_t)(_num / _den);
        RG_(edx) = (uint32_t)(_num % _den);
    }
L_0043604f:
    RG_(esi) = (uint32_t)((RG_(edx)+RG_(ecx)));
    RG_(ecx) = (uint32_t)(MR32(RG_(edi)+0x10u));
    MR32(RG_(ecx)) = (RG_(esi));
    RG_(eax) = (uint32_t)((RG_(edi)+0xcu));
    MR32(RG_(eax)+0x4u) = (RG_(esi));
    { uint32_t _r = ((uint8_t)RG_(ebx)) & (0x1fu); FLAGS_LOG_M(_r, 8, 0x00u); RG_(ebx) = (RG_(ebx) & 0xffffff00u) | (uint32_t)((_r) & 0xffu); }
    { uint32_t _a = MR32(0xbfbcd8u), _b = 0xffffffffu, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    MR16(RG_(esi)+0xau) = ((uint16_t)RG_(edx));
    RG_(edx) = (uint32_t)(MR32(RG_(esp)+0x28u));
    MR32(RG_(esi)+0x4u) = (RG_(ecx));
    MR32(RG_(esi)) = (RG_(eax));
    MR8(RG_(esi)+0x8u) = ((uint8_t)RG_(ebx));
    MR8(RG_(esi)+0x9u) = (0x22u);
    RG_(ecx) = (uint32_t)(MR32(RG_(esp)+0x1cu));
    MR32(RG_(esi)+0xcu) = (RG_(ecx));
    MR32(RG_(esi)+0x10u) = (RG_(edx));
    if (CC_NE) goto L_00436091;
L_00436087:
    MR32(0x0u) = (0x0u);
L_00436091:
    RG_(ecx) = (uint32_t)(MR32(RG_(edi)+0x78u));
    { uint32_t _a = MR32(0xbfbcd8u), _b = 0x1u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); MR32(0xbfbcd8u) = (_r); }
    PUSH32(0x004360a0u);
    LR_STORE;
    DISPATCH_CALL(c, 0x00904a30u);
    LR_RELOAD;
    RG_(eax) = (uint32_t)((RG_(esi)+0x14u));
    { uint32_t _t; POP32(_t); RG_(edi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ebp) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ebx) = (uint32_t)(_t); }
    RG_(ecx) = (uint32_t)(MR32(RG_(esp)+0x10u));
    { uint32_t _r = (RG_(ecx)) ^ (RG_(esp)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(ecx) = (uint32_t)(_r); }
    PUSH32(0x004360b2u);
    LR_STORE;
    DISPATCH_CALL(c, 0x00828460u);
    LR_RELOAD;
    { uint32_t _a = RG_(esp), _b = 0x14u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    RG_(esp) += 4u;
    LR_STORE;
    return;
L_004360b6:
    RG_(ecx) = (uint32_t)(MR32(RG_(edi)+0x78u));
    PUSH32(0x004360beu);
    LR_STORE;
    DISPATCH_CALL(c, 0x00904a30u);
    LR_RELOAD;
    RG_(eax) = (uint32_t)(MR32(RG_(esp)+0x14u));
    RG_(ecx) = (uint32_t)(MR32(RG_(eax)*4+0xb4dbf0u));
    { uint32_t _r = (RG_(ecx)) & (RG_(ecx)); FLAGS_LOG_M(_r, 32, 0x08u); }
    if (CC_E) goto L_004360d9;
L_004360cd:
    PUSH32(0x7fffffffu);
    PUSH32(0x0u);
    PUSH32(0x004360d9u);
    LR_STORE;
    DISPATCH_CALL(c, 0x00435850u);
    LR_RELOAD;
L_004360d9:
    RG_(edi) = (uint32_t)(MR32(RG_(edi)));
    PUSH32(RG_(ebp));
    PUSH32(0x004360e1u);
    LR_STORE;
    DISPATCH_CALL(c, 0x00436300u);
    LR_RELOAD;
    { uint32_t _a = RG_(esp), _b = 0x4u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    PUSH32(RG_(eax));
    PUSH32(RG_(ebx));
    PUSH32(0x004360ebu);
    LR_STORE;
    DISPATCH_CALL(c, 0x00436360u);
    LR_RELOAD;
    RG_(ecx) = (uint32_t)(MR32(RG_(esp)+0x30u));
    { uint32_t _a = RG_(esp), _b = 0x4u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    PUSH32(RG_(eax));
    PUSH32(RG_(ecx));
    PUSH32(0x0u);
    PUSH32(RG_(edi));
    PUSH32(0x9f35a8u);
    PUSH32(0x00436101u);
    LR_STORE;
    DISPATCH_CALL(c, 0x004324e0u);
    LR_RELOAD;
    RG_(ecx) = (uint32_t)(MR32(RG_(esp)+0x38u));
    { uint32_t _a = RG_(esp), _b = 0x18u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    { uint32_t _t; POP32(_t); RG_(edi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ebp) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ebx) = (uint32_t)(_t); }
    { uint32_t _r = (RG_(ecx)) ^ (RG_(esp)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(ecx) = (uint32_t)(_r); }
    MR32(0x0u) = (0x0u);
    { uint32_t _r = (RG_(eax)) ^ (RG_(eax)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    PUSH32(0x0043611fu);
    LR_STORE;
    DISPATCH_CALL(c, 0x00828460u);
    LR_RELOAD;
    { uint32_t _a = RG_(esp), _b = 0x14u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    RG_(esp) += 4u;
    LR_STORE;
    return;
L_00436123:
    /* int3 */
    /* int3 */
    /* int3 */
}
""",
    0x00436130: r"""void sub_00436130(CPU *c) {
    LR_ENTER;
L_00436130:
    { uint32_t _a = RG_(esp), _b = 0x28u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    RG_(eax) = (uint32_t)(MR32(0xa8be00u));
    { uint32_t _r = (RG_(eax)) ^ (RG_(esp)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    MR32(RG_(esp)+0x24u) = (RG_(eax));
    PUSH32(RG_(ebx));
    PUSH32(RG_(ebp));
    PUSH32(RG_(esi));
    RG_(esi) = (uint32_t)(MR32(RG_(esp)+0x38u));
    { uint32_t _r = (RG_(ebx)) ^ (RG_(ebx)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(ebx) = (uint32_t)(_r); }
    { uint32_t _a = RG_(esi), _b = RG_(ebx), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    PUSH32(RG_(edi));
    if (CC_E) goto L_004362c4;
L_00436150:
    RG_(ebp) = (uint32_t)(0xb4d9fcu);
L_00436155:
    RG_(edi) = (uint32_t)(MR32(RG_(ebp)));
    { uint32_t _a = RG_(edi), _b = RG_(ebx), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    if (CC_E) goto L_00436199;
L_0043615c:
    RG_(eax) = (uint32_t)(MR32(RG_(edi)+0x8u));
    { uint32_t _a = RG_(esi), _b = RG_(eax), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x30u); }
    if (CC_L) goto L_00436199;
L_00436163:
    RG_(ecx) = (uint32_t)(MR32(RG_(edi)+0xcu));
    { uint32_t _a = RG_(ecx), _b = RG_(eax), _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(ecx) = (uint32_t)(_r); }
    { uint32_t _a = RG_(esi), _b = RG_(ecx), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x30u); }
    if (CC_GE) goto L_00436199;
L_0043616c:
    RG_(edx) = (uint32_t)(0x1u);
L_00436171:
    RG_(eax) = (uint32_t)(MR32(RG_(edx)*4+0xb4dbf0u));
    { uint32_t _a = RG_(eax), _b = RG_(ebx), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    if (CC_E) goto L_0043618c;
L_0043617c:
    RG_(ecx) = (uint32_t)(MR32(RG_(eax)+0x1cu));
    { uint32_t _a = RG_(esi), _b = RG_(ecx), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x30u); }
    if (CC_L) goto L_0043618c;
L_00436183:
    RG_(eax) = (uint32_t)(MR32(RG_(eax)+0x20u));
    { uint32_t _a = RG_(eax), _b = RG_(ecx), _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    { uint32_t _a = RG_(esi), _b = RG_(eax), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x30u); }
    if (CC_L) goto L_00436194;
L_0043618c:
    { uint32_t _a = RG_(edx), _b = 0x1u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(edx) = (uint32_t)(_r); }
    { uint32_t _a = RG_(edx), _b = 0x20u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x30u); }
    if (CC_L) goto L_00436171;
L_00436194:
    { uint32_t _a = RG_(edx), _b = 0x20u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    if (CC_E) goto L_004361d1;
L_00436199:
    { uint32_t _a = RG_(ebp), _b = 0x10u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(ebp) = (uint32_t)(_r); }
    { uint32_t _a = RG_(ebp), _b = 0xb4dbfcu, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x30u); }
    if (CC_L) goto L_00436155;
L_004361a4:
    { uint32_t _a = MR8(RG_(esi)+0xfffffff5u), _b = 0x22u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 8, 0x08u); }
    RG_(ebp) = (uint32_t)((uint32_t)(MR8(RG_(esi)+0xfffffff4u)));
    RG_(edi) = (uint32_t)((RG_(esi)+0xffffffecu));
    RG_(esi) = (uint32_t)(MR32(RG_(ebp)*4+0xb4dbf0u));
    if (CC_E) goto L_004361f1;
L_004361b8:
    MR32(0x0u) = (RG_(ebx));
    { uint32_t _t; POP32(_t); RG_(edi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ebp) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ebx) = (uint32_t)(_t); }
    RG_(ecx) = (uint32_t)(MR32(RG_(esp)+0x24u));
    { uint32_t _r = (RG_(ecx)) ^ (RG_(esp)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(ecx) = (uint32_t)(_r); }
    PUSH32(0x004361cdu);
    LR_STORE;
    sub_00828460(c);
    LR_RELOAD;
    { uint32_t _a = RG_(esp), _b = 0x28u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    RG_(esp) += 4u;
    LR_STORE;
    return;
L_004361d1:
    RG_(ecx) = (uint32_t)(MR32(RG_(edi)+0x4u));
    RG_(edx) = (uint32_t)(MR32(RG_(edi)+0x14u));
    PUSH32(RG_(esi));
    PUSH32(RG_(ecx));
    PUSH32(0x004361dbu);
    LR_STORE;
    DISPATCH_CALL(c, RG_(edx));
    LR_RELOAD;
    { uint32_t _a = RG_(esp), _b = 0x8u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    { uint32_t _t; POP32(_t); RG_(edi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ebp) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ebx) = (uint32_t)(_t); }
    RG_(ecx) = (uint32_t)(MR32(RG_(esp)+0x24u));
    { uint32_t _r = (RG_(ecx)) ^ (RG_(esp)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(ecx) = (uint32_t)(_r); }
    PUSH32(0x004361edu);
    LR_STORE;
    sub_00828460(c);
    LR_RELOAD;
    { uint32_t _a = RG_(esp), _b = 0x28u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    RG_(esp) += 4u;
    LR_STORE;
    return;
L_004361f1:
    RG_(ecx) = (uint32_t)(MR32(RG_(esi)+0x78u));
    PUSH32(0x9ef5c4u);
    PUSH32(0x004361feu);
    LR_STORE;
    sub_00904970(c);
    LR_RELOAD;
    RG_(ecx) = (uint32_t)(MR32(0xbfbcc0u));
    { uint32_t _r = (RG_(eax)) ^ (RG_(eax)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    { uint32_t _a = RG_(ecx), _b = RG_(ebx), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    MR8(RG_(esp)+0x14u) = ((uint8_t)RG_(ebx));
    MR32(RG_(esp)+0x15u) = (RG_(eax));
    MR32(RG_(esp)+0x19u) = (RG_(eax));
    MR32(RG_(esp)+0x1du) = (RG_(eax));
    MR32(RG_(esp)+0x21u) = (RG_(eax));
    MR32(RG_(esp)+0x25u) = (RG_(eax));
    MR32(RG_(esp)+0x29u) = (RG_(eax));
    MR32(RG_(esp)+0x2du) = (RG_(eax));
    MR16(RG_(esp)+0x31u) = ((uint16_t)RG_(eax));
    MR8(RG_(esp)+0x33u) = ((uint8_t)RG_(eax));
    if (CC_E) goto L_00436250;
L_00436233:
    RG_(eax) = (uint32_t)(MR32(0xbfbcd8u));
    RG_(edx) = (uint32_t)((int32_t)RG_(eax) >> 31);
    if ((int32_t)RG_(ecx) != 0) {
        int64_t _num = (int64_t)(((uint64_t)RG_(edx) << 32) | (uint64_t)(uint32_t)RG_(eax));
        int32_t _den = (int32_t)RG_(ecx);
        RG_(eax) = (uint32_t)(_num / _den);
        RG_(edx) = (uint32_t)(_num % _den);
    }
    { uint32_t _r = (RG_(edx)) & (RG_(edx)); FLAGS_LOG_M(_r, 32, 0x08u); }
    if (CC_NE) goto L_00436250;
L_0043623f:
    RG_(ebp) = (uint32_t)(MR32(RG_(ebp)*4+0xb4dbf0u));
    { uint32_t _a = RG_(ebp), _b = RG_(ebx), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    if (CC_E) goto L_00436250;
L_0043624a:
    PUSH32(RG_(ebp));
    PUSH32(0x00436250u);
    LR_STORE;
    sub_00435670(c);
    LR_RELOAD;
L_00436250:
    RG_(eax) = (uint32_t)((uint32_t)(MR16(RG_(edi)+0xau)));
    RG_(ecx) = (uint32_t)(MR32(RG_(edi)+0x4u));
    RG_(ebp) = (uint32_t)(RG_(edi));
    MR8(RG_(edi)+0x9u) = ((uint8_t)RG_(ebx));
    { uint32_t _a = RG_(ebp), _b = RG_(eax), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x00u); RG_(ebp) = (uint32_t)(_r); }
    RG_(eax) = (uint32_t)(MR32(RG_(edi)));
    MR32(RG_(ecx)) = (RG_(eax));
    MR32(RG_(eax)+0x4u) = (RG_(ecx));
    RG_(ecx) = (uint32_t)(MR32(RG_(esi)+0x78u));
    RG_(edi) = (uint32_t)(MR32(RG_(edi)+0xcu));
    PUSH32(0x9ef5c4u);
    PUSH32(0x00436275u);
    LR_STORE;
    sub_00904970(c);
    LR_RELOAD;
    PUSH32(RG_(edi));
    PUSH32(RG_(esi));
    RG_(eax) = (uint32_t)(RG_(ebp));
    PUSH32(0x0043627eu);
    LR_STORE;
    sub_00435230(c);
    LR_RELOAD;
    { uint32_t _a = MR32(RG_(esi)+0x30u), _b = RG_(edi), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x00u); MR32(RG_(esi)+0x30u) = (_r); }
    RG_(eax) = (uint32_t)(MR32(RG_(esi)+0x30u));
    RG_(ecx) = (uint32_t)(MR32(RG_(esi)+0x2cu));
    { uint32_t _a = MR32(RG_(esi)+0x24u), _b = 0xffffffffu, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); MR32(RG_(esi)+0x24u) = (_r); }
    { uint32_t _a = RG_(ecx), _b = RG_(eax), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x00u); RG_(ecx) = (uint32_t)(_r); }
    MR32(RG_(esi)+0x38u) = (RG_(ecx));
    RG_(ecx) = (uint32_t)(MR32(RG_(esi)+0x78u));
    PUSH32(0x00436298u);
    LR_STORE;
    sub_00904a30(c);
    LR_RELOAD;
    RG_(ecx) = (uint32_t)(MR32(RG_(esi)+0x78u));
    PUSH32(0x004362a0u);
    LR_STORE;
    sub_00904a30(c);
    LR_RELOAD;
    { uint32_t _a = MR32(0xbfbcdcu), _b = RG_(ebx), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    if (CC_E) goto L_004362c4;
L_004362a8:
    RG_(eax) = (uint32_t)(MR32(0xb4dbf0u));
    { uint32_t _a = MR32(RG_(eax)+0x24u), _b = RG_(ebx), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    if (CC_NE) goto L_004362c4;
L_004362b2:
    PUSH32(RG_(eax));
    PUSH32(0x004362b8u);
    LR_STORE;
    sub_004351c0(c);
    LR_RELOAD;
    MR32(0xb4dbf0u) = (RG_(ebx));
    MR32(0xbfbcdcu) = (RG_(ebx));
L_004362c4:
    RG_(ecx) = (uint32_t)(MR32(RG_(esp)+0x34u));
    { uint32_t _t; POP32(_t); RG_(edi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ebp) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ebx) = (uint32_t)(_t); }
    { uint32_t _r = (RG_(ecx)) ^ (RG_(esp)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(ecx) = (uint32_t)(_r); }
    PUSH32(0x004362d3u);
    LR_STORE;
    sub_00828460(c);
    LR_RELOAD;
    { uint32_t _a = RG_(esp), _b = 0x28u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    RG_(esp) += 4u;
    LR_STORE;
    return;
}
""",
    0x004363e6: r"""void sub_004363e6(CPU *c) {
    LR_ENTER;
L_004363e6:
    RG_(edi) = (uint32_t)(MR32(RG_(ecx)+0x2ce0u));
    LR_STORE;
    DISPATCH_TAIL(c, 0x0065ddc9u);
}
""",
    0x0045a920: r"""void sub_0045a920(CPU *c) {
    LR_ENTER;
L_0045a920:
    PUSH32(RG_(esi));
    RG_(esi) = (uint32_t)(RG_(ecx));
    if (RG_(esi) == 0u) {
        { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }
        RG_(esp) += 4u;
        LR_STORE;
        return;
    }
    RG_(eax) = (uint32_t)(MR32(RG_(esi)+0x14u));
    { uint32_t _r = (RG_(eax)) & (RG_(eax)); FLAGS_LOG_M(_r, 32, 0x30u); }
    if (CC_L) goto L_0045a93e;
L_0045a92a:
    RG_(ecx) = (uint32_t)(MR32(RG_(eax)*4+0xb53a78u));
    PUSH32(0x0045a936u);
    LR_STORE;
    sub_0045a920(c);
    LR_RELOAD;
    { uint32_t _r = ((uint8_t)RG_(eax)) & ((uint8_t)RG_(eax)); FLAGS_LOG_M(_r, 8, 0x08u); }
    if (CC_E) goto L_0045a93e;
L_0045a93a:
    RG_(eax) = (RG_(eax) & 0xffffff00u) | (uint32_t)((0x1u) & 0xffu);
    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }
    RG_(esp) += 4u;
    LR_STORE;
    return;
L_0045a93e:
    PUSH32(RG_(edi));
    RG_(edi) = (uint32_t)(MR32(RG_(esi)+0x8u));
    { uint32_t _a = RG_(edi), _b = MR32(RG_(esi)+0x4u), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x01u); }
    if (CC_AE) goto L_0045a987;
L_0045a947:
    MR32(RG_(esi)+0x10u) = (RG_(edi));
    RG_(eax) = (uint32_t)(MR32(RG_(edi)));
    RG_(edx) = (uint32_t)(MR32(RG_(eax)));
    PUSH32(0x0u);
    RG_(ecx) = (uint32_t)(RG_(edi));
    PUSH32(0x0045a954u);
    LR_STORE;
    DISPATCH_CALL(c, RG_(edx));
    LR_RELOAD;
    RG_(eax) = (uint32_t)(MR32(RG_(edi)+0x4u));
    { uint32_t _a = MR32(RG_(esi)+0x8u), _b = RG_(eax), _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); MR32(RG_(esi)+0x8u) = (_r); }
    RG_(ecx) = (uint32_t)(MR32(RG_(esi)+0x8u));
    { uint32_t _a = MR32(RG_(esi)+0x18u), _b = 0xffffffffu, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); MR32(RG_(esi)+0x18u) = (_r); }
    { uint32_t _a = RG_(ecx), _b = MR32(RG_(esi)+0x4u), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    MR32(RG_(esi)+0x10u) = (0x0u);
    if (CC_NE) goto L_0045a982;
L_0045a96d:
    RG_(eax) = (uint32_t)(MR32(RG_(esi)));
    { uint32_t _a = RG_(eax), _b = 0xfu, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    { uint32_t _r = (RG_(eax)) & (0xfffffff0u); FLAGS_LOG_M(_r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    MR32(RG_(esi)+0x4u) = (RG_(eax));
    MR32(RG_(esi)+0x8u) = (RG_(eax));
    MR32(RG_(esi)+0x18u) = (0x0u);
L_0045a982:
    { uint32_t _t; POP32(_t); RG_(edi) = (uint32_t)(_t); }
    RG_(eax) = (RG_(eax) & 0xffffff00u) | (uint32_t)((0x1u) & 0xffu);
    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }
    RG_(esp) += 4u;
    LR_STORE;
    return;
L_0045a987:
    { uint32_t _t; POP32(_t); RG_(edi) = (uint32_t)(_t); }
    { uint32_t _r = ((uint8_t)RG_(eax)) ^ ((uint8_t)RG_(eax)); FLAGS_LOG_M(_r, 8, 0x00u); RG_(eax) = (RG_(eax) & 0xffffff00u) | (uint32_t)((_r) & 0xffu); }
    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }
    RG_(esp) += 4u;
    LR_STORE;
    return;
}
""",
    0x00463d70: r"""void sub_00463d70(CPU *c) {
    sub_01a11e20(c);
}
""",
    0x00463e90: r"""void sub_00463e90(CPU *c) {
    LR_ENTER;
L_00463e90:
    PUSH32(RG_(ecx));
    PUSH32(RG_(ebx));
    PUSH32(RG_(ebp));
    RG_(ebp) = (uint32_t)(MR32(RG_(esp)+0x10u));
    /* Unspliced SecuROM bridge: cmp ebp, 0x400 (bChunk small-block threshold); jmp 0x463e9d */
    { uint32_t _a = RG_(ebp), _b = 0x400u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x09u); }
L_00463e9d:
    PUSH32(RG_(esi));
    PUSH32(RG_(edi));
    RG_(ebx) = (uint32_t)(RG_(ecx));
    if (CC_BE) goto L_00463eb5;
L_00463ea3:
    RG_(eax) = (uint32_t)(MR32(RG_(esp)+0x1cu));
    PUSH32(RG_(eax));
    RG_(edx) = (uint32_t)(RG_(ebp));
    RG_(eax) = (uint32_t)(RG_(ebx));
    PUSH32(0x00463eacu);
    LR_STORE;
    DISPATCH_CALL(c, 0x00463f70u);
    LR_RELOAD;
    RG_(edi) = (uint32_t)(RG_(eax));
    goto L_00463ef6;
L_00463eb5:
    RG_(esi) = (uint32_t)(RG_(ebp) - 1u);
    RG_(esi) >>= 4;
    { uint32_t _a = MR32(RG_(ebx)+RG_(esi)*4u), _b = 0u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    if (CC_NE) goto L_00463eee;
L_00463ec1:
    PUSH32(RG_(esi));
    RG_(eax) = (uint32_t)(RG_(ebx));
    PUSH32(0x00463ec9u);
    LR_STORE;
    DISPATCH_CALL(c, 0x00464100u);
    LR_RELOAD;
    { uint32_t _r = ((uint8_t)RG_(eax)) & ((uint8_t)RG_(eax)); FLAGS_LOG_M(_r, 8, 0x08u); }
    if (CC_NE) goto L_00463eee;
L_00463ecd:
    PUSH32(0x9f4258u);
    PUSH32(0x00463ed7u);
    LR_STORE;
    DISPATCH_CALL(c, 0x004324e0u);
    LR_RELOAD;
    RG_(esp) += 4u;
    MR32(0x0u) = 0u; /* Assert failure in bChunk */
    RG_(eax) = 0u;
    { uint32_t _t; POP32(_t); RG_(edi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ebp) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ebx) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ecx) = (uint32_t)(_t); }
    RG_(esp) += 12u;
    LR_STORE;
    return;
L_00463eee:
    RG_(edi) = (uint32_t)(MR32(RG_(ebx)+RG_(esi)*4u));
    RG_(ecx) = (uint32_t)(MR32(RG_(edi)));
    MR32(RG_(ebx)+RG_(esi)*4u) = (RG_(ecx));
L_00463ef6:
    PUSH32(RG_(ebp));
    PUSH32(0u);
    PUSH32(RG_(edi));
    PUSH32(0x00463effu);
    LR_STORE;
    DISPATCH_CALL(c, 0x008287c8u);
    LR_RELOAD;
    RG_(esp) += 12u;
    RG_(eax) = (uint32_t)(RG_(edi));
    { uint32_t _t; POP32(_t); RG_(edi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ebp) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ebx) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ecx) = (uint32_t)(_t); }
    RG_(esp) += 12u;
    LR_STORE;
    return;
}
""",
    0x00463f10: r"""void sub_00463f10(CPU *c) {
    LR_ENTER;
L_00463f10:
    PUSH32(RG_(ecx));
    RG_(eax) = (uint32_t)(MR32(RG_(esp)+0xcu));
    { uint32_t _a = RG_(eax), _b = 0x400u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x09u); }
    PUSH32(RG_(esi));
    if (CC_BE) goto L_00463f51;
L_00463f1d:
    { uint32_t _a = MR32(RG_(ecx)+0x324u), _b = 0x0u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    if (CC_E) goto L_00463f3f;
L_00463f26:
    RG_(ecx) = (uint32_t)(MR32(RG_(ecx)+0x324u));
    RG_(eax) = (uint32_t)(MR32(RG_(ecx)));
    RG_(edx) = (uint32_t)(MR32(RG_(esp)+0xcu));
    RG_(eax) = (uint32_t)(MR32(RG_(eax)+0x4u));
    PUSH32(0x0u);
    PUSH32(RG_(edx));
    PUSH32(0x00463f3au);
    LR_STORE;
    DISPATCH_CALL(c, RG_(eax));
    LR_RELOAD;
    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ecx) = (uint32_t)(_t); }
    RG_(esp) += 16u;
    LR_STORE;
    return;
L_00463f3f:
    RG_(ecx) = (uint32_t)(MR32(RG_(esp)+0xcu));
    PUSH32(RG_(ecx));
    PUSH32(0x00463f49u);
    LR_STORE;
    sub_00436130(c);
    LR_RELOAD;
    { uint32_t _a = RG_(esp), _b = 0x4u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ecx) = (uint32_t)(_t); }
    RG_(esp) += 16u;
    LR_STORE;
    return;
L_00463f51:
    RG_(edx) = (uint32_t)(MR32(RG_(esp)+0xcu));
    { uint32_t _a = RG_(eax), _b = 0xffffffffu, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    { uint32_t _s = (0x4u) & 31u; if (_s) { uint32_t _v = RG_(eax); uint32_t _r = (_v >> _s) & 0xffffffffu; RG_(cf) = (_v >> (_s - 1)) & 1u; FLAGS_LOG_M(_r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); } }
    RG_(esi) = (uint32_t)(MR32(RG_(ecx)+RG_(eax)*4));
    MR32(RG_(edx)) = (RG_(esi));
    MR32(RG_(ecx)+RG_(eax)*4) = (RG_(edx));
    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ecx) = (uint32_t)(_t); }
    RG_(esp) += 16u;
    LR_STORE;
    return;
}
""",
    0x00464e70: r"""void sub_00464e70(CPU *c) {
    uint32_t k_va = MR32(c->esp + 4u);
    uint32_t len = MR32(c->esp + 8u);
    uint32_t initval = MR32(c->esp + 12u);
    if (!k_va || len == 0 || !guest_is_valid_va(k_va, len)) {
        c->eax = 0u;
    } else {
        c->eax = bstring_hash((const uint8_t*)(g_mem + k_va), len, initval);
    }
    c->esp += 4u;
}
""",
    0x00465020: r"""void sub_00465020(CPU *c) {
    LR_ENTER;
L_00465020:
    RG_(edx) = (uint32_t)(MR32(RG_(esp)+0x4u));
    { uint32_t _r = (RG_(edx)) & (RG_(edx)); FLAGS_LOG_M(_r, 32, 0x08u); }
    if (CC_E) goto L_0046504a;
L_00465028:
    { uint32_t _a = MR8(RG_(edx)), _b = 0x0u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 8, 0x08u); }
    if (CC_E) goto L_0046504a;
L_0046502d:
    RG_(eax) = (uint32_t)(RG_(edx));
    PUSH32(RG_(esi));
    RG_(esi) = (uint32_t)((RG_(eax)+0x1u));
L_00465033:
    RG_(ecx) = (RG_(ecx) & 0xffffff00u) | (uint32_t)((MR8(RG_(eax))) & 0xffu);
    { uint32_t _a = RG_(eax), _b = 0x1u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    { uint32_t _r = ((uint8_t)RG_(ecx)) & ((uint8_t)RG_(ecx)); FLAGS_LOG_M(_r, 8, 0x08u); }
    if (CC_NE) goto L_00465033;
L_0046503c:
    { uint32_t _a = RG_(eax), _b = RG_(esi), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    PUSH32(RG_(eax));
    PUSH32(RG_(edx));
    PUSH32(0x00465045u);
    LR_STORE;
    sub_00464e70(c);
    LR_RELOAD;
    { uint32_t _a = RG_(esp), _b = 0x8u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }
    RG_(esp) += 4u;
    LR_STORE;
    return;
L_0046504a:
    { uint32_t _r = (RG_(eax)) ^ (RG_(eax)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    RG_(esp) += 4u;
    LR_STORE;
    return;
}
""",
    0x004afee0: r"""#include <stdio.h>
void sub_004afee0(CPU *c) {
    LR_ENTER;
L_004afee0:
    printf("[MAIN] Entered sub_004afee0 (EIP=0x004afee0)\n"); fflush(stdout);
    PUSH32(0xffffffffu);
    PUSH32(0x952884u);
    RG_(eax) = (uint32_t)(MR32(c->fs_base));
    PUSH32(RG_(eax));
    PUSH32(RG_(ecx));
    PUSH32(RG_(esi));
    PUSH32(RG_(edi));
    RG_(eax) = (uint32_t)(MR32(0xa8be00u));
    { uint32_t _r = (RG_(eax)) ^ (RG_(esp)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    PUSH32(RG_(eax));
    RG_(eax) = (uint32_t)((RG_(esp)+0x10u));
    MR32(c->fs_base) = (RG_(eax));
    RG_(eax) = (uint32_t)(MR32(RG_(esp)+0x24u));
    RG_(edi) = (uint32_t)(MR32(RG_(esp)+0x20u));
    PUSH32(RG_(eax));
    PUSH32(0x004aff11u);
    LR_STORE;
    DISPATCH_CALL(c, 0x004afea0u);
    LR_RELOAD;
    { uint32_t _a = RG_(esp), _b = 0x4u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    { uint32_t _r = ((uint8_t)RG_(eax)) & ((uint8_t)RG_(eax)); FLAGS_LOG_M(_r, 8, 0x08u); }
    if (CC_E) goto L_004aff22;
L_004aff18:
    MR32(0xac7378u) = (0x1u);
printf("[MAIN] Safemode checked (eax=0x%x)\n", RG_(eax)); fflush(stdout);
L_004aff22:
    RG_(edi) = (uint32_t)(MR32(0x9670e0u));
    RG_(esi) = (uint32_t)(0xbbad1cu);
    RG_(ecx) = (uint32_t)((RG_(ecx)));
L_004aff30:
    PUSH32(0x0u);
    PUSH32(0x0u);
    PUSH32(0x1u);
    PUSH32(0x0u);
    PUSH32(0x004aff3au);
    LR_STORE;
    DISPATCH_CALL(c, RG_(edi));
    LR_RELOAD;
    { uint32_t _r = (RG_(eax)) & (RG_(eax)); FLAGS_LOG_M(_r, 32, 0x08u); }
    MR32(RG_(esi)) = (RG_(eax));
    if (CC_E) goto L_004aff6e;
L_004aff40:
    { uint32_t _a = RG_(esi), _b = 0x4u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esi) = (uint32_t)(_r); }
    { uint32_t _a = RG_(esi), _b = 0xbbad2cu, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x30u); }
    if (CC_L) goto L_004aff30;
printf("[MAIN] Events created, calling sub_006d0ae0 (alloc 4 bytes)\n"); fflush(stdout);
L_004aff4b:
    PUSH32(0x4u);
    PUSH32(0x004aff52u);
    LR_STORE;
    sub_006d0ae0(c);
    LR_RELOAD;
    { uint32_t _a = RG_(esp), _b = 0x4u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    MR32(RG_(esp)+0xcu) = (RG_(eax));
    { uint32_t _r = (RG_(eax)) & (RG_(eax)); FLAGS_LOG_M(_r, 32, 0x08u); }
    MR32(RG_(esp)+0x18u) = (0x0u);
    if (CC_E) goto L_004aff82;
L_004aff65:
    RG_(ecx) = (uint32_t)(RG_(eax));
    PUSH32(0x004aff6cu);
    LR_STORE;
    printf("[MAIN] Calling engine root ctor sub_0090c8d0 (obj=0x%x)\n", RG_(eax)); fflush(stdout);
    sub_0090c8d0(c);
    printf("[MAIN] sub_0090c8d0 finished\n"); fflush(stdout);
    LR_RELOAD;
    goto L_004aff84;
L_004aff6e:
    { uint32_t _r = (RG_(eax)) ^ (RG_(eax)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    RG_(ecx) = (uint32_t)(MR32(RG_(esp)+0x10u));
    MR32(c->fs_base) = (RG_(ecx));
    { uint32_t _t; POP32(_t); RG_(ecx) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(edi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }
    { uint32_t _a = RG_(esp), _b = 0x10u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    RG_(esp) += 4u;
    LR_STORE;
    return;
L_004aff82:
    { uint32_t _r = (RG_(eax)) ^ (RG_(eax)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
L_004aff84:
    MR32(RG_(esp)+0x18u) = (0xffffffffu);
    MR32(0xbfc024u) = (RG_(eax));
    PUSH32(0x004aff96u);
    LR_STORE;
    printf("[MAIN] Calling sub_00904ce0\n"); fflush(stdout);
    sub_00904ce0(c);
    printf("[MAIN] sub_00904ce0 finished\n"); fflush(stdout);
    LR_RELOAD;
    RG_(ecx) = (uint32_t)(MR32(0xbfc024u));
    PUSH32(RG_(eax));
    PUSH32(0x0u);
    PUSH32(0x0u);
    PUSH32(0x4b0100u);
    PUSH32(0x004affabu);
    LR_STORE;
    printf("[MAIN] Calling sub_00905760\n"); fflush(stdout);
    sub_00905760(c);
    printf("[MAIN] sub_00905760 finished\n"); fflush(stdout);
    LR_RELOAD;
    RG_(ecx) = (uint32_t)(MR32(0xbfc024u));
    PUSH32(0x2u);
    PUSH32(0x004affb8u);
    LR_STORE;
    printf("[MAIN] Calling sub_009053a0\n"); fflush(stdout);
    sub_009053a0(c);
    printf("[MAIN] sub_009053a0 finished\n"); fflush(stdout);
    LR_RELOAD;
    RG_(ecx) = (uint32_t)(MR32(0xbfc024u));
    PUSH32(0x9f7fd4u);
    PUSH32(0x004affc8u);
    LR_STORE;
    printf("[MAIN] Calling sub_00904ec0\n"); fflush(stdout);
    sub_00904ec0(c);
    printf("[MAIN] sub_00904ec0 finished\n"); fflush(stdout);
    LR_RELOAD;
    PUSH32(0x004affcdu);
    LR_STORE;
    printf("[MAIN] Calling sub_009047e0\n"); fflush(stdout);
    sub_009047e0(c);
    printf("[MAIN] sub_009047e0 finished\n"); fflush(stdout);
    LR_RELOAD;
    RG_(ecx) = (uint32_t)(MR32(c->fs_base+0x2cu));
    RG_(edx) = (uint32_t)(MR32(RG_(ecx)));
    MR32(0xbfc02cu) = (RG_(eax));
    MR32(RG_(edx)+0x4u) = (RG_(eax));
    PUSH32(0x004affe3u);
    LR_STORE;
    printf("[MAIN] Calling engine main loop sub_006dba80\n"); fflush(stdout);
    sub_006dba80(c);
    printf("[MAIN] sub_006dba80 exited!\n"); fflush(stdout);
    LR_RELOAD;
    RG_(edi) = (uint32_t)(MR32(0x9670b0u));
    RG_(esi) = (uint32_t)(0xbbad1cu);
    RG_(edi) = (uint32_t)(RG_(edi));
L_004afff0:
    RG_(eax) = (uint32_t)(MR32(RG_(esi)));
    PUSH32(RG_(eax));
    PUSH32(0x004afff5u);
    LR_STORE;
    DISPATCH_CALL(c, RG_(edi));
    LR_RELOAD;
    { uint32_t _a = RG_(esi), _b = 0x4u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esi) = (uint32_t)(_r); }
    { uint32_t _a = RG_(esi), _b = 0xbbad2cu, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x30u); }
    if (CC_L) goto L_004afff0;
L_004b0000:
    PUSH32(0x0u);
    PUSH32(0x004b0008u);
    LR_STORE;
    DISPATCH_CALL(c, MR32(0x967260u));
    LR_RELOAD;
    /* int3 */
}
""",
    0x004dd540: r"""void sub_004dd540(CPU *c) {
    /* Authentic bString::reserve(size_t size) lifted from SecuROM trampoline 0x01a0d570 */
    uint32_t size = MR32(c->esp + 4u);
    uint32_t this_ptr = c->ecx;
    if (size <= 1u) {
        MR32(this_ptr) = 0x00b4c9e4u;
        MR32(this_ptr + 4u) = 0x00b4c9e4u;
        MR32(this_ptr + 8u) = 0x00b4c9e5u;
    } else {
        uint32_t buf = guest_heap_alloc(size, 4u);
        MR32(this_ptr) = buf;
        MR32(this_ptr + 4u) = buf;
        MR32(this_ptr + 8u) = buf + size;
    }
    c->esp += 8u; /* pop return address (4) + arg size (4) */
}
""",
    0x004e03c0: r"""void sub_004e03c0(CPU *c) {
    /* Authentic sub_004e03c0 (thiscall default ctor):
     * Zeroes an 8-byte structure at c->ecx.
     * Returns this in c->eax.
     * Pops return address (c->esp += 4).
     */
    uint32_t this_ptr = c->ecx;
    MR32(this_ptr + 0u) = 0u;
    MR32(this_ptr + 4u) = 0u;
    c->eax = this_ptr;
    c->esp += 4u;
}
""",
    0x004e03d0: r"""void sub_004e03d0(CPU *c) {
    /* Authentic sub_004e03d0 (thiscall dtor):
     * If obj at c->ecx + 4 is non-null, calls deleting dtor with flag 1.
     */
    uint32_t obj = MR32(c->ecx + 4u);
    if (obj != 0u) {
        uint32_t vtbl = MR32(obj);
        uint32_t dtor = MR32(vtbl);
        c->ecx = obj;
        GUEST_PUSH32(c, 1u);
        GUEST_PUSH32(c, 0x004e03dfu);
        DISPATCH_CALL(c, dtor);
    }
    c->esp += 4u;
}
""",
    0x004f9db0: r"""void sub_004f9db0(CPU *c) {
    LR_ENTER;
L_004f9db0:
    PUSH32(0xffffffffu);
    PUSH32(0x93248bu);
    RG_(eax) = (uint32_t)(MR32(c->fs_base));
    PUSH32(RG_(eax));
    PUSH32(RG_(ecx));
    PUSH32(RG_(esi));
    RG_(eax) = (uint32_t)(MR32(0xa8be00u));
    { uint32_t _r = (RG_(eax)) ^ (RG_(esp)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    PUSH32(RG_(eax));
    RG_(eax) = (uint32_t)((RG_(esp)+0xcu));
    MR32(c->fs_base) = (RG_(eax));
    RG_(esi) = (uint32_t)(RG_(ecx));
    MR32(RG_(esp)+0x8u) = (RG_(esi));
    RG_(ecx) = (uint32_t)(MR32(RG_(esi)+0x40u));
    { uint32_t _r = (RG_(ecx)) & (RG_(ecx)); FLAGS_LOG_M(_r, 32, 0x08u); }
    MR32(RG_(esp)+0x14u) = (0x0u);
    if (CC_E) goto L_004f9e01;
L_004f9de7:
    RG_(eax) = (uint32_t)(MR32(RG_(esi)+0x48u));
    { uint32_t _a = RG_(eax), _b = RG_(ecx), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    { uint32_t _s = (0x2u) & 31u; if (_s) { int32_t _v = (int32_t)RG_(eax); uint32_t _r = (uint32_t)(_v >> _s) & 0xffffffffu; RG_(cf) = ((uint32_t)_v >> (_s - 1)) & 1u; FLAGS_LOG_M(_r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); } }
    { uint32_t _a = RG_(eax), _b = RG_(eax), _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    PUSH32(0x0u);
    { uint32_t _a = RG_(eax), _b = RG_(eax), _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    PUSH32(RG_(eax));
    PUSH32(RG_(ecx));
    RG_(ecx) = (uint32_t)(0xabb060u);
    PUSH32(0x004f9e01u);
    LR_STORE;
    DISPATCH_CALL(c, 0x00463f10u);
    LR_RELOAD;
L_004f9e01:
    RG_(eax) = (uint32_t)(MR32(RG_(esi)+0x30u));
    { uint32_t _r = (RG_(eax)) & (RG_(eax)); FLAGS_LOG_M(_r, 32, 0x08u); }
    MR32(RG_(esp)+0x14u) = (0xffffffffu);
    if (CC_E) goto L_004f9e2a;
L_004f9e10:
    RG_(ecx) = (uint32_t)(MR32(RG_(esi)+0x38u));
    { uint32_t _a = RG_(ecx), _b = RG_(eax), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x00u); RG_(ecx) = (uint32_t)(_r); }
    { uint32_t _s = (0x2u) & 31u; if (_s) { int32_t _v = (int32_t)RG_(ecx); uint32_t _r = (uint32_t)(_v >> _s) & 0xffffffffu; RG_(cf) = ((uint32_t)_v >> (_s - 1)) & 1u; FLAGS_LOG_M(_r, 32, 0x00u); RG_(ecx) = (uint32_t)(_r); } }
    { uint32_t _a = RG_(ecx), _b = RG_(ecx), _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(ecx) = (uint32_t)(_r); }
    PUSH32(0x0u);
    { uint32_t _a = RG_(ecx), _b = RG_(ecx), _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(ecx) = (uint32_t)(_r); }
    PUSH32(RG_(ecx));
    PUSH32(RG_(eax));
    RG_(ecx) = (uint32_t)(0xabb060u);
    PUSH32(0x004f9e2au);
    LR_STORE;
    DISPATCH_CALL(c, 0x00463f10u);
    LR_RELOAD;
L_004f9e2a:
    RG_(ecx) = (uint32_t)(MR32(RG_(esp)+0xcu));
    MR32(c->fs_base) = (RG_(ecx));
    { uint32_t _t; POP32(_t); RG_(ecx) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }
    { uint32_t _a = RG_(esp), _b = 0x10u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    LR_STORE;
    return;
}
""",
    0x004fed90: r"""void sub_004fed90(CPU *c) {
    LR_ENTER;
L_004fed90:
    PUSH32(0xffffffffu);
    PUSH32(0x932bc6u);
    RG_(eax) = (uint32_t)(MR32(c->fs_base));
    PUSH32(RG_(eax));
    PUSH32(RG_(ecx));
    PUSH32(RG_(esi));
    PUSH32(RG_(edi));
    RG_(eax) = (uint32_t)(MR32(0xa8be00u));
    { uint32_t _r = (RG_(eax)) ^ (RG_(esp)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    PUSH32(RG_(eax));
    RG_(eax) = (uint32_t)((RG_(esp)+0x10u));
    MR32(c->fs_base) = (RG_(eax));
    RG_(esi) = (uint32_t)(RG_(ecx));
    MR32(RG_(esp)+0xcu) = (RG_(esi));
    { uint32_t _r = (RG_(edi)) ^ (RG_(edi)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(edi) = (uint32_t)(_r); }
    MR32(RG_(esi)+0x4u) = (RG_(edi));
    MR32(RG_(esi)+0x8u) = (0x9ee914u);
    PUSH32(0x9ee914u);
    MR32(RG_(esi)) = (0xffffffffu);
    PUSH32(0x004fedd5u);
    LR_STORE;
    DISPATCH_CALL(c, 0x0052b8d0u);
    LR_RELOAD;
    MR32(RG_(esi)+0x8u) = (0x9ee914u);
    MR32(RG_(esi)+0x4u) = (RG_(eax));
    MR32(RG_(esi)+0xcu) = (RG_(edi));
    { uint32_t _a = RG_(esp), _b = 0x4u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    MR32(RG_(esi)+0x30u) = (RG_(edi));
    MR32(RG_(esi)+0x34u) = (RG_(edi));
    MR32(RG_(esi)+0x38u) = (RG_(edi));
    MR32(RG_(esp)+0x18u) = (RG_(edi));
    MR32(RG_(esi)+0x40u) = (RG_(edi));
    MR32(RG_(esi)+0x44u) = (RG_(edi));
    MR32(RG_(esi)+0x48u) = (RG_(edi));
    MR32(RG_(esi)+0x50u) = (RG_(edi));
    RG_(ecx) = (uint32_t)(RG_(esi));
    MR8(RG_(esp)+0x18u) = (0x1u);
    MR32(RG_(esi)+0x54u) = (RG_(edi));
    PUSH32(0x004fee0du);
    LR_STORE;
    DISPATCH_CALL(c, 0x004fe670u);
    LR_RELOAD;
    RG_(eax) = (uint32_t)(RG_(esi));
    RG_(ecx) = (uint32_t)(MR32(RG_(esp)+0x10u));
    MR32(c->fs_base) = (RG_(ecx));
    { uint32_t _t; POP32(_t); RG_(ecx) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(edi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }
    { uint32_t _a = RG_(esp), _b = 0x10u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    LR_STORE;
    return;
}
""",
    0x0052a7f0: r"""void sub_0052a7f0(CPU *c) {
    uint32_t k_va = MR32(c->esp + 4u);
    uint32_t len = MR32(c->esp + 8u);
    uint32_t initval = c->eax;
    if (!k_va || !guest_is_valid_va(k_va, len)) {
        c->eax = 0u;
    } else {
        c->eax = bstring_hash((const uint8_t*)(g_mem + k_va), len, initval);
    }
    c->esp += 4u;
}
""",
    0x0052b8d0: r"""void sub_0052b8d0(CPU *c) {
    uint32_t str_va = MR32(c->esp + 4u);
    if (!str_va || !guest_is_valid_va(str_va, 1) || MR8(str_va) == 0) {
        c->eax = 0u;
    } else {
        uint32_t len = 0;
        while (guest_is_valid_va(str_va + len, 1) && MR8(str_va + len) != 0) len++;
        c->eax = bstring_hash((const uint8_t*)(g_mem + str_va), len, 0xabcdef00u);
    }
    c->esp += 4u;
}
""",
    0x0052ea80: r"""void sub_0052ea80(CPU *c) {
    LR_ENTER;
L_0052ea80:
    RG_(edx) = (uint32_t)(MR32(RG_(esp)+0x8u));
    RG_(eax) = (uint32_t)(RG_(ecx));
    RG_(ecx) = (uint32_t)(MR32(RG_(esp)+0x4u));
    MR32(RG_(eax)+0x8u) = (RG_(edx));
    RG_(edx) = (uint32_t)((0x1a6fd9eu));
    { uint32_t _a = RG_(edx), _b = 0x5858u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x00u); RG_(edx) = (uint32_t)(_r); }
    { uint32_t _a = MR32(RG_(edx)), _r = _a - 1u; FLAGS_SUB_M(_a, 1u, _r, 32, (0x08u & ~F_CF)); MR32(RG_(edx)) = (_r); }
    if (CC_E) goto L_00555696;
L_0052eaa1:
    RG_(edx) = (uint32_t)(MR32(RG_(esp)+0xcu));
    { uint32_t _r = (RG_(ecx)) & (0x7fffffffu); FLAGS_LOG_M(_r, 32, 0x00u); RG_(ecx) = (uint32_t)(_r); }
    MR32(RG_(eax)+0x4u) = (RG_(ecx));
    MR32(RG_(eax)+0xcu) = (RG_(edx));
    { uint32_t _r = (RG_(ecx)) & (0x7fffffffu); FLAGS_LOG_M(_r, 32, 0x00u); RG_(ecx) = (uint32_t)(_r); }
    PUSH32(RG_(esi));
    RG_(esi) = (uint32_t)(RG_(ecx));
    { uint32_t _s = (0xcu) & 31u; if (_s) { uint32_t _v = RG_(esi); uint32_t _r = (_v >> _s) & 0xffffffffu; RG_(cf) = (_v >> (_s - 1)) & 1u; FLAGS_LOG_M(_r, 32, 0x00u); RG_(esi) = (uint32_t)(_r); } }
    { uint32_t _a = MR32(0x1a6a54cu), _r = _a - 1u; FLAGS_SUB_M(_a, 1u, _r, 32, (0x08u & ~F_CF)); MR32(0x1a6a54cu) = (_r); }
    if (CC_E) { MR32(0x1a6a54cu) = 0x1f8u; }
    RG_(edx) = (uint32_t)(RG_(ecx));
    { uint32_t _a = RG_(esi), _b = RG_(ecx), _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esi) = (uint32_t)(_r); }
    { uint32_t _s = (0x6u) & 31u; if (_s) { uint32_t _v = RG_(edx); uint32_t _r = (_v >> _s) & 0xffffffffu; RG_(cf) = (_v >> (_s - 1)) & 1u; FLAGS_LOG_M(_r, 32, 0x00u); RG_(edx) = (uint32_t)(_r); } }
    { uint32_t _a = RG_(edx), _b = RG_(esi), _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(edx) = (uint32_t)(_r); }
    { uint32_t _r = (RG_(edx)) & (0x3fu); FLAGS_LOG_M(_r, 32, 0x00u); RG_(edx) = (uint32_t)(_r); }
    RG_(ecx) = (uint32_t)(MR32(RG_(edx)*4+0xb4d8f0u));
    MR32(RG_(eax)) = (RG_(ecx));
    { uint32_t _a = MR8(RG_(edx)+0xb4d8a8u), _b = 0x1u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 8, 0x00u); MR8(RG_(edx)+0xb4d8a8u) = (_r); }
    MR32(RG_(edx)*4+0xb4d8f0u) = (RG_(eax));
    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }
    RG_(esp) += 16u;
    LR_STORE;
    return;
L_00555696:
    MR32(0x1a6a546u) = (0x251u);
    goto L_0052eaa1;
}
""",
    0x00634490: r"""void sub_00634490(CPU *c) {
    LR_ENTER;
L_00634490:
    RG_(eax) = RG_(ecx);
    MR32(RG_(eax)) = 0xffffu;
    MR32(RG_(eax) + 4u) = 0u;
    MR8(RG_(eax) + 8u) = 1u;
    RG_(esp) += 4u;
    LR_STORE;
    return;
}
""",
    0x006f8d60: r"""void sub_006f8d60(CPU *c) {
    LR_ENTER;
L_006f8d60:
    RG_(eax) = (uint32_t)(RG_(ecx));
    { uint32_t _r = (RG_(ecx)) ^ (RG_(ecx)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(ecx) = (uint32_t)(_r); }
    MR32(RG_(eax)+0x40u) = (RG_(ecx));
    MR32(RG_(eax)+0x44u) = (RG_(ecx));
    MR32(RG_(eax)+0x48u) = (RG_(ecx));
    RG_(esp) += 4u;
    LR_STORE;
    return;
}
""",
    0x0070f5d0: r"""void sub_0070f5d0(CPU *c) {
    /* Deobfuscated SecuROM trampoline 0x52eb4e -> 0x70f5d5 */
    uint32_t val = MR32(0x00a64a94u);
    c->eax = (val == 0xffffffffu) ? 0u : MR32(0x00acdcb4u);
    c->esp += 4u;
}
""",
    0x0070f600: r"""void sub_0070f600(CPU *c) {
    /* Authentic ProStreet CD/DVD disc presence check bypass for browser port */
    c->eax = 1u;
    c->esp += 4u;
}
""",
    0x0070f640: r"""void sub_0070f640(CPU *c) {
    /* Multi-instance check bypass (Toolhelp32 process snapshot) */
    c->eax = 0u;
    c->esp += 4u;
}
""",
    0x007223b0: r"""void sub_007223b0(CPU *c) {
    LR_ENTER;
L_007223b0:
    RG_(eax) = RG_(ecx);
    MR32(RG_(eax) + 4u) = 0u;
    MR32(RG_(eax) + 8u) = 0u;
    MR32(RG_(eax) + 0xcu) = 0u;
    MR32(RG_(eax)) = 0x9932f0u;
    RG_(esp) += 4u;
    LR_STORE;
    return;
}
""",
    0x007567b0: r"""void sub_007567b0(CPU *c) {
    /* Authentic sub_007567b0 (stdcall, ret 0x10):
     * [c->esp + 0] = return address
     * [c->esp + 4] = array pointer
     * [c->esp + 8] = count
     * [c->esp + 12] = arg3 (type / id value)
     * [c->esp + 16] = name string pointer (e.g. "DUMMY_SKIN")
     */
    uint32_t arr_va   = MR32(c->esp + 4u);
    uint32_t count    = MR32(c->esp + 8u);
    uint32_t arg3_val = MR32(c->esp + 12u);
    uint32_t name_va  = MR32(c->esp + 16u);

    const char *prefix = (const char *)(g_mem + name_va);
    size_t plen = strlen(prefix);

    for (uint32_t i = 0; i < count; ++i) {
        char name_buf[64];
        size_t cp_len = plen;
        if (cp_len >= sizeof(name_buf) - 16) cp_len = sizeof(name_buf) - 16;
        memcpy(name_buf, prefix, cp_len);
        char *p = name_buf + cp_len;
        uint32_t num = i + 1u;
        char tmp[16];
        int tlen = 0;
        do {
            tmp[tlen++] = (char)('0' + (num % 10u));
            num /= 10u;
        } while (num > 0u);
        while (tlen > 0) {
            *p++ = tmp[--tlen];
        }
        *p = '\0';

        uint32_t h = 0xffffffffu;
        for (const char *s = name_buf; *s; ++s) {
            h = (h << 5) + h + (uint8_t)*s;
        }

        uint32_t elem_va = arr_va + i * 16u;
        MR32(elem_va + 0u)  = h;
        MR32(elem_va + 4u)  = 0u;
        MR32(elem_va + 8u)  = arg3_val;
        MR32(elem_va + 12u) = 0u;
    }

    c->esp += 20u; /* pop return address (4) + 16 bytes args (ret 0x10) */
}
""",
    0x00783de0: r"""void sub_00783de0(CPU *c) {
    LR_ENTER;
L_00783de0:
    RG_(eax) = (uint32_t)(RG_(ecx));
    { uint32_t _r = (RG_(ecx)) ^ (RG_(ecx)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(ecx) = (uint32_t)(_r); }
    MR32(RG_(eax)+0x4u) = (RG_(ecx));
    MR32(RG_(eax)+0x8u) = (RG_(ecx));
    MR32(RG_(eax)+0xcu) = (RG_(ecx));
    MR32(RG_(eax)) = (0x998068u);
    RG_(esp) += 4u;
    LR_STORE;
    return;
}
""",
    0x00783e30: r"""void sub_00783e30(CPU *c) {
    LR_ENTER;
L_00783e30:
    LR_STORE;
    DISPATCH_TAIL(c, 0x00783d20u);
}
""",
    0x007c9a50: r"""void sub_007c9a50(CPU *c) {
    LR_ENTER;
    goto L_007c9a50;
L_007c58f0:
    PUSH32(RG_(ecx));
    PUSH32(RG_(esi));
    RG_(esi) = (uint32_t)(RG_(ecx));
    { uint32_t _a = MR8(RG_(esi)+0x1du), _b = 0x1u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 8, 0x08u); }
    if (CC_NE) goto L_007c5975;
L_007c58fa:
    MR8(RG_(esi)+0x1du) = (0x0u);
    PUSH32(0x007c5903u);
    LR_STORE;
    sub_0081c230(c);
    LR_RELOAD;
    { uint32_t _r = (RG_(eax)) & (RG_(eax)); FLAGS_LOG_M(_r, 32, 0x08u); }
    if (CC_E) goto L_007c5930;
L_007c5907:
    PUSH32(0x007c590cu);
    LR_STORE;
    sub_0081c230(c);
    LR_RELOAD;
    RG_(edx) = (uint32_t)(MR32(RG_(eax)));
    RG_(ecx) = (uint32_t)(RG_(eax));
    RG_(eax) = (uint32_t)(MR32(RG_(edx)+0x1cu));
    PUSH32(0x007c5915u);
    LR_STORE;
    DISPATCH_CALL(c, RG_(eax));
    LR_RELOAD;
    { uint32_t _r = (RG_(eax)) & (RG_(eax)); FLAGS_LOG_M(_r, 32, 0x08u); }
    if (CC_E) goto L_007c5930;
L_007c5919:
    PUSH32(0x007c591eu);
    LR_STORE;
    sub_0081c230(c);
    LR_RELOAD;
    RG_(edx) = (uint32_t)(MR32(RG_(eax)));
    RG_(ecx) = (uint32_t)(RG_(eax));
    RG_(eax) = (uint32_t)(MR32(RG_(edx)+0x1cu));
    PUSH32(0x007c5927u);
    LR_STORE;
    DISPATCH_CALL(c, RG_(eax));
    LR_RELOAD;
    RG_(edx) = (uint32_t)(MR32(RG_(eax)));
    RG_(ecx) = (uint32_t)(RG_(eax));
    RG_(eax) = (uint32_t)(MR32(RG_(edx)+0x28u));
    PUSH32(0x007c5930u);
    LR_STORE;
    DISPATCH_CALL(c, RG_(eax));
    LR_RELOAD;
L_007c5930:
    RG_(eax) = (uint32_t)(MR32(0xb30834u));
    { uint32_t _r = (RG_(eax)) & (RG_(eax)); FLAGS_LOG_M(_r, 32, 0x08u); }
    if (CC_E) goto L_007c5946;
L_007c5939:
    RG_(edx) = (uint32_t)(MR32(RG_(eax)+0x4u));
    RG_(ecx) = (uint32_t)((RG_(eax)+0x4u));
    RG_(eax) = (uint32_t)(MR32(RG_(edx)+0x28u));
    PUSH32(0xffffffffu);
    PUSH32(0x007c5946u);
    LR_STORE;
    DISPATCH_CALL(c, RG_(eax));
    LR_RELOAD;
L_007c5946:
    { uint32_t _a = MR8(0xb307ffu), _b = 0x0u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 8, 0x08u); }
    if (CC_E) goto L_007c5975;
L_007c594f:
    PUSH32(0x007c5954u);
    LR_STORE;
    sub_007c0b00(c);
    LR_RELOAD;
    PUSH32(0x007c5959u);
    LR_STORE;
    sub_0081c1d0(c);
    LR_RELOAD;
    RG_(ecx) = (uint32_t)(MR32(0xb309d8u));
    { uint32_t _r = (RG_(ecx)) & (RG_(ecx)); FLAGS_LOG_M(_r, 32, 0x08u); }
    if (CC_E) goto L_007c5975;
L_007c5963:
    RG_(edx) = (uint32_t)(MR32(RG_(ecx)));
    RG_(eax) = (uint32_t)(MR32(RG_(edx)));
    PUSH32(0x1u);
    PUSH32(0x007c596bu);
    LR_STORE;
    DISPATCH_CALL(c, RG_(eax));
    LR_RELOAD;
    MR32(0xb309d8u) = (0x0u);
L_007c5975:
    { uint32_t _a = MR8(RG_(esi)+0x24u), _b = 0x0u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 8, 0x08u); }
    if (CC_E) goto L_007c5a63;
L_007c597f:
    { uint32_t _a = MR8(0xb307feu), _b = 0x0u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 8, 0x08u); }
    if (CC_E) goto L_007c5993;
L_007c5988:
    PUSH32(0x007c598du);
    LR_STORE;
    sub_007b2b40(c);
    LR_RELOAD;
    MRF32(RG_(esp)+0x4u) = (float)ST(0);
    FPOP();
    goto L_007c599c;
L_007c5993:
    #if defined(__wasm_simd128__)
WASM_SIMD_XORPS(c->xmm[0], c->xmm[0]);
#else
c->xmm[0].u64[0] ^= c->xmm[0].u64[0]; c->xmm[0].u64[1] ^= c->xmm[0].u64[1];
#endif
    memcpy(g_mem + (uint32_t)(RG_(esp)+0x4u), &c->xmm[0], 4);
L_007c599c:
    FPUSH((double)MRF32(RG_(esp)+0x4u));
    { double _d = ST(0), _s = ((double)MRF32(RG_(esi)+0x20u)); ST(0) = X87R2(_d, _s, _d - _s); }
    FPUSH(MRF64(0x9faf28u));
    { double _t = ST(0); ST(0) = ST(1); ST(1) = _t; }
    FCOMI(ST(0), ST(1));
    FPOP();
    ST(0) = ST(0);
    FPOP();
    if (CC_BE) goto L_007c5a63;
L_007c59b5:
    { uint32_t _a = MR32(0xb30830u), _b = 0x0u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    if (CC_E) goto L_007c5a63;
L_007c59c2:
    MR8(RG_(esi)+0x25u) = (0x1u);
    PUSH32(0x007c59cbu);
    LR_STORE;
    sub_0081c230(c);
    LR_RELOAD;
    { uint32_t _r = (RG_(eax)) & (RG_(eax)); FLAGS_LOG_M(_r, 32, 0x08u); }
    if (CC_E) goto L_007c59fd;
L_007c59cf:
    PUSH32(0x007c59d4u);
    LR_STORE;
    sub_0081c230(c);
    LR_RELOAD;
    RG_(edx) = (uint32_t)(MR32(RG_(eax)));
    RG_(ecx) = (uint32_t)(RG_(eax));
    RG_(eax) = (uint32_t)(MR32(RG_(edx)+0x1cu));
    PUSH32(0x007c59ddu);
    LR_STORE;
    DISPATCH_CALL(c, RG_(eax));
    LR_RELOAD;
    { uint32_t _r = (RG_(eax)) & (RG_(eax)); FLAGS_LOG_M(_r, 32, 0x08u); }
    if (CC_E) goto L_007c59f8;
L_007c59e1:
    PUSH32(0x007c59e6u);
    LR_STORE;
    sub_0081c230(c);
    LR_RELOAD;
    RG_(edx) = (uint32_t)(MR32(RG_(eax)));
    RG_(ecx) = (uint32_t)(RG_(eax));
    RG_(eax) = (uint32_t)(MR32(RG_(edx)+0x1cu));
    PUSH32(0x007c59efu);
    LR_STORE;
    DISPATCH_CALL(c, RG_(eax));
    LR_RELOAD;
    RG_(edx) = (uint32_t)(MR32(RG_(eax)));
    RG_(ecx) = (uint32_t)(RG_(eax));
    RG_(eax) = (uint32_t)(MR32(RG_(edx)+0x28u));
    PUSH32(0x007c59f8u);
    LR_STORE;
    DISPATCH_CALL(c, RG_(eax));
    LR_RELOAD;
L_007c59f8:
    PUSH32(0x007c59fdu);
    LR_STORE;
    sub_007c54d0(c);
    LR_RELOAD;
L_007c59fd:
    PUSH32(0x007c5a02u);
    LR_STORE;
    sub_0082f4d0(c);
    LR_RELOAD;
    { uint32_t _r = (RG_(eax)) & (RG_(eax)); FLAGS_LOG_M(_r, 32, 0x08u); }
    if (CC_E) goto L_007c5a56;
L_007c5a06:
    PUSH32(0x007c5a0bu);
    LR_STORE;
    sub_0082f4d0(c);
    LR_RELOAD;
    RG_(edx) = (uint32_t)(MR32(RG_(eax)));
    RG_(ecx) = (uint32_t)(RG_(eax));
    RG_(eax) = (uint32_t)(MR32(RG_(edx)+0x40u));
    PUSH32(0x007c5a14u);
    LR_STORE;
    DISPATCH_CALL(c, RG_(eax));
    LR_RELOAD;
    { uint32_t _r = (RG_(eax)) & (RG_(eax)); FLAGS_LOG_M(_r, 32, 0x08u); }
    if (CC_E) goto L_007c5a56;
L_007c5a18:
    PUSH32(0x007c5a1du);
    LR_STORE;
    sub_0082f4d0(c);
    LR_RELOAD;
    RG_(edx) = (uint32_t)(MR32(RG_(eax)));
    RG_(ecx) = (uint32_t)(RG_(eax));
    RG_(eax) = (uint32_t)(MR32(RG_(edx)+0x40u));
    PUSH32(0x007c5a26u);
    LR_STORE;
    DISPATCH_CALL(c, RG_(eax));
    LR_RELOAD;
    RG_(edx) = (uint32_t)(MR32(RG_(eax)));
    RG_(ecx) = (uint32_t)(RG_(eax));
    RG_(eax) = (uint32_t)(MR32(RG_(edx)+0x40u));
    PUSH32(0x007c5a2fu);
    LR_STORE;
    DISPATCH_CALL(c, RG_(eax));
    LR_RELOAD;
    { uint32_t _r = (RG_(eax)) & (RG_(eax)); FLAGS_LOG_M(_r, 32, 0x08u); }
    if (CC_E) goto L_007c5a56;
L_007c5a33:
    PUSH32(0x007c5a38u);
    LR_STORE;
    sub_0082f4d0(c);
    LR_RELOAD;
    RG_(edx) = (uint32_t)(MR32(RG_(eax)));
    RG_(ecx) = (uint32_t)(RG_(eax));
    RG_(eax) = (uint32_t)(MR32(RG_(edx)+0x40u));
    PUSH32(0x007c5a41u);
    LR_STORE;
    DISPATCH_CALL(c, RG_(eax));
    LR_RELOAD;
    RG_(edx) = (uint32_t)(MR32(RG_(eax)));
    RG_(ecx) = (uint32_t)(RG_(eax));
    RG_(eax) = (uint32_t)(MR32(RG_(edx)+0x40u));
    PUSH32(0x007c5a4au);
    LR_STORE;
    DISPATCH_CALL(c, RG_(eax));
    LR_RELOAD;
    RG_(edx) = (uint32_t)(MR32(RG_(eax)));
    RG_(ecx) = (uint32_t)(RG_(eax));
    RG_(eax) = (uint32_t)(MR32(RG_(edx)+0x90u));
    PUSH32(0x007c5a56u);
    LR_STORE;
    DISPATCH_CALL(c, RG_(eax));
    LR_RELOAD;
L_007c5a56:
    RG_(edx) = (uint32_t)(MR32(RG_(esi)+0x4u));
    RG_(eax) = (uint32_t)(MR32(RG_(edx)+0x28u));
    RG_(ecx) = (uint32_t)((RG_(esi)+0x4u));
    PUSH32(0xffffffffu);
    PUSH32(0x007c5a63u);
    LR_STORE;
    DISPATCH_CALL(c, RG_(eax));
    LR_RELOAD;
L_007c5a63:
    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ecx) = (uint32_t)(_t); }
    RG_(esp) += 4u;
    LR_STORE;
    return;
L_007c9a50:
    { uint32_t _a = MR8(0xb307fau), _b = 0x0u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 8, 0x08u); }
    if (CC_E) goto L_007c9a75;
L_007c9a59:
    RG_(eax) = (uint32_t)(MR32(0xb3082cu));
    { uint32_t _r = (RG_(eax)) & (RG_(eax)); FLAGS_LOG_M(_r, 32, 0x08u); }
    if (CC_E) goto L_007c9a75;
L_007c9a62:
    RG_(ecx) = (uint32_t)(MR32(RG_(eax)+0x8u));
    { uint32_t _r = (RG_(eax)) ^ (RG_(eax)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    { uint32_t _r = (RG_(ecx)) & (RG_(ecx)); FLAGS_LOG_M(_r, 32, 0x08u); }
    RG_(eax) = (RG_(eax) & 0xffffff00u) | (uint32_t)(((CC_NE) ? 1u : 0u) & 0xffu);
    { uint32_t _r = ((uint8_t)RG_(eax)) & ((uint8_t)RG_(eax)); FLAGS_LOG_M(_r, 8, 0x08u); }
    if (CC_E) goto L_007c9a75;
L_007c9a70:
    PUSH32(0x007c9a75u);
    LR_STORE;
    sub_007ba7b0(c);
    LR_RELOAD;
L_007c9a75:
    { uint32_t _a = MR8(0xb307ffu), _b = 0x0u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 8, 0x08u); }
    if (CC_E) goto L_007c9a83;
L_007c9a7e:
    PUSH32(0x007c9a83u);
    LR_STORE;
    sub_0081c1c0(c);
    LR_RELOAD;
L_007c9a83:
    RG_(ecx) = (uint32_t)(MR32(0xb3082cu));
    { uint32_t _r = (RG_(ecx)) & (RG_(ecx)); FLAGS_LOG_M(_r, 32, 0x08u); }
    if (CC_E) goto L_007c9a92;
L_007c9a8d:
    PUSH32(0x007c9a92u);
    LR_STORE;
    sub_007c8290(c);
    LR_RELOAD;
L_007c9a92:
    PUSH32(0x1u);
    RG_(ecx) = (uint32_t)(0xaeb870u);
    PUSH32(0x007c9a9eu);
    LR_STORE;
    sub_00772e60(c);
    LR_RELOAD;
    PUSH32(0x007c9aa3u);
    LR_STORE;
    sub_0084c4f0(c);
    LR_RELOAD;
    RG_(eax) = (uint32_t)(MR32(0xb30814u));
    { uint32_t _r = (RG_(eax)) & (RG_(eax)); FLAGS_LOG_M(_r, 32, 0x08u); }
    if (CC_E) goto L_007c9ac4;
L_007c9aac:
    { uint32_t _a = MR32(RG_(eax)+0xcu), _b = 0xau, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    if (CC_NE) goto L_007c9ac4;
L_007c9ab2:
    MR32(RG_(eax)+0xcu) = (0xbu);
    RG_(ecx) = (uint32_t)(MR32(0xb30814u));
    PUSH32(0x007c9ac4u);
    LR_STORE;
    sub_007b3170(c);
    LR_RELOAD;
L_007c9ac4:
    PUSH32(0x007c9ac9u);
    LR_STORE;
    sub_007c6e60(c);
    LR_RELOAD;
    RG_(ecx) = (uint32_t)(MR32(0xb30834u));
    { uint32_t _r = (RG_(ecx)) & (RG_(ecx)); FLAGS_LOG_M(_r, 32, 0x08u); }
    if (CC_E) goto L_007c9ad8;
L_007c9ad3:
    goto L_007c58f0;
L_007c9ad8:
    RG_(esp) += 4u;
    LR_STORE;
    return;
}
""",
    0x00828652: r"""void sub_00828652(CPU *c) {
    /* Authentic MSVC __ehvec_ctor array constructor iterator */
    uint32_t ptr   = MR32(c->esp + 4);
    uint32_t size  = MR32(c->esp + 8);
    uint32_t count = MR32(c->esp + 12);
    uint32_t ctor  = MR32(c->esp + 16);

    for (uint32_t i = 0; i < count; ++i) {
        c->ecx = ptr + i * size;
        c->esp -= 4u;
        MR32(c->esp) = 0x00828679u;
        DISPATCH_CALL(c, ctor);
    }

    c->esp += 24u;
}
""",
    0x00828ebc: r"""void sub_00828ebc(CPU *c) {
    /* Authentic MSVC __EH_prolog runtime helper */
    uint32_t scope_table = MR32(c->esp);
    uint32_t alloc_size  = MR32(c->esp + 4);
    uint32_t frame_base  = c->esp + 4u;
    uint32_t old_ebp     = c->ebp;

    c->ebp = frame_base;
    MR32(c->ebp) = old_ebp;

    MR32(c->ebp - 4)  = 0xfffffffeu;
    MR32(c->ebp - 8)  = scope_table;
    MR32(c->ebp - 12) = 0x00828f15u;
    MR32(c->ebp - 16) = MR32(c->fs_base);
    MR32(c->fs_base)  = c->ebp - 16;

    c->esp = c->ebp - 16 - alloc_size - 16;
}
""",
    0x00828f01: r"""void sub_00828f01(CPU *c) {
    /* Authentic MSVC __EH_epilog runtime helper */
    MR32(c->fs_base) = MR32(c->ebp - 16);
    uint32_t old_ebp = MR32(c->ebp);
    c->esp = c->ebp + 8;
    c->ebp = old_ebp;
}
""",
    0x008975c3: r"""void sub_008975c3(CPU *c) {
    LR_ENTER;
    /* WebAssembly non-blocking timer setup */
    MR32(0xb34278u) = 1u;
    MR32(0xb342a8u) = 1u;
    MR32(0xa8d038u) = 1u;
    c->eax = 1u;
    c->esp += 4u;
    LR_STORE;
    return;
}
""",
    0x009006c0: r"""void sub_009006c0(CPU *c) {
    LR_ENTER;
L_009006c0:
    RG_(eax) = RG_(ecx);
    MR32(RG_(eax) + 4u) = 0xfffffffd;
    RG_(esp) += 4u;
    LR_STORE;
    return;
}
""",
    0x01a11e20: r"""void sub_01a11e20(CPU *c) {
    LR_ENTER;
L_01a11e20:
    PUSH32(RG_(edi));
    RG_(eax) = (uint32_t)((RG_(esi)+0x220u));
L_01a11e33:
    RG_(ecx) = (uint32_t)(0x40u);
    { uint32_t _r = (RG_(edi)) ^ (RG_(edi)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(edi) = (uint32_t)(_r); }
L_01a11e3c:
    MR32(RG_(eax)+0xfffffde0u) = (RG_(edi));
    MR32(RG_(eax)+0xffffff00u) = (RG_(edi));
    MR32(RG_(eax)) = (RG_(edi));
    { uint32_t _a = RG_(eax), _b = 0x4u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    { uint32_t _a = RG_(ecx), _b = 0x1u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); RG_(ecx) = (uint32_t)(_r); }
    if (CC_NE) goto L_01a11e3c;
L_01a11e52:
    RG_(eax) = (uint32_t)(MR32(RG_(esi)+0x100u));
    RG_(edx) = (uint32_t)(MR32(RG_(esi)+0x114u));
    PUSH32(RG_(eax));
    RG_(eax) = (uint32_t)(RG_(esi));
    PUSH32(0x01a11e78u);
    LR_STORE;
    DISPATCH_CALL(c, 0x00463f70u);
    LR_RELOAD;
L_01a11e78:
    MR32(RG_(esi)+0x110u) = (RG_(eax));
    { uint32_t _a = MR32(RG_(esi)+0x104u), _b = RG_(edi), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x09u); }
    if (CC_BE) goto L_01a11eab;
L_01a11e86:
    if (RG_(eax) != 0u) {
        MR32(RG_(eax)) = (RG_(edi));
        RG_(ecx) = (uint32_t)(MR32(RG_(esi)+0x110u));
        RG_(edx) = (uint32_t)(MR32(RG_(esi)+0x114u));
        MR32(RG_(ecx)+4u) = (RG_(edx));
    }
L_01a11eab:
    MR8(RG_(esi)+0x10cu) = 1u;
    { uint32_t _t; POP32(_t); RG_(edi) = (uint32_t)(_t); }
    RG_(esp) += 4u;
    LR_STORE;
    return;
}
""",
    0x00436360: r"""void sub_00436360(CPU *c) {
    LR_ENTER;
L_00436360:
    PUSH32(RG_(ebx));
    RG_(ebx) = (uint32_t)(MR32(RG_(esp)+0x8u));
    PUSH32(RG_(esi));
    RG_(esi) = (uint32_t)(RG_(ebx));
    { uint32_t _r = (RG_(esi)) & (0x1fu); FLAGS_LOG_M(_r, 32, 0x00u); RG_(esi) = (uint32_t)(_r); }
    PUSH32(RG_(edi));
    RG_(edi) = (uint32_t)(MR32(RG_(esi)*4u + 0xb4dbf0u));
L_00436373:
    { uint32_t _r = (RG_(edi)) & (RG_(edi)); FLAGS_LOG_M(_r, 32, 0x08u); }
    if (CC_NE) goto L_00436394;
L_00436377:
    { uint32_t _s = (0x4u) & 31u; if (_s) { uint32_t _v = RG_(esi); uint32_t _r = (_v << _s) & 0xffffffffu; RG_(cf) = (_v >> (32 - _s)) & 1u; FLAGS_LOG_M(_r, 32, 0x00u); RG_(esi) = (uint32_t)(_r); } }
    RG_(esi) = (uint32_t)(MR32(RG_(esi)+0xb4d9fcu));
    { uint32_t _r = (RG_(esi)) & (RG_(esi)); FLAGS_LOG_M(_r, 32, 0x08u); }
    if (CC_E) goto L_004363ce;
L_00436384:
    RG_(eax) = (uint32_t)(MR32(RG_(esi)+0x4u));
    RG_(ecx) = (uint32_t)(MR32(RG_(esi)+0x1cu));
    PUSH32(RG_(eax));
    PUSH32(0x0043638du);
    LR_STORE;
    DISPATCH_CALL(c, RG_(ecx));
    LR_RELOAD;
    { uint32_t _a = RG_(esp), _b = 0x4u, _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); RG_(esp) = (uint32_t)(_r); }
    { uint32_t _t; POP32(_t); RG_(edi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ebx) = (uint32_t)(_t); }
    RG_(esp) += 4u;
    LR_STORE;
    return;
L_00436394:
    { uint32_t _r = (RG_(esi)) & (RG_(esi)); FLAGS_LOG_M(_r, 32, 0x08u); }
    if (CC_NE) goto L_004363a1;
L_00436398:
    { uint32_t _t; POP32(_t); RG_(edi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }
    RG_(eax) = (uint32_t)(0x6300000u);
    { uint32_t _t; POP32(_t); RG_(ebx) = (uint32_t)(_t); }
    RG_(esp) += 4u;
    LR_STORE;
    return;
L_004363a1:
    PUSH32(0x004363a6u);
    LR_STORE;
    DISPATCH_CALL(c, 0x00435630u);
    LR_RELOAD;
    { uint32_t _s = (0x6u) & 31u; if (_s) { int32_t _v = (int32_t)RG_(ebx); uint32_t _r = (uint32_t)(_v >> _s) & 0xffffffffu; RG_(cf) = ((uint32_t)_v >> (_s - 1)) & 1u; FLAGS_LOG_M(_r, 32, 0x00u); RG_(ebx) = (uint32_t)(_r); } }
    { uint32_t _a = RG_(eax), _b = 0x5cu, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
    { uint32_t _r = (RG_(ebx)) & (0x1ffcu); FLAGS_LOG_M(_r, 32, 0x08u); RG_(ebx) = (uint32_t)(_r); }
    if (CC_NE) goto L_004363bd;
L_004363b4:
    { uint32_t _s = (0x4u) & 31u; if (_s) { uint32_t _v = RG_(esi); uint32_t _r = (_v << _s) & 0xffffffffu; RG_(cf) = (_v >> (32 - _s)) & 1u; FLAGS_LOG_M(_r, 32, 0x00u); RG_(esi) = (uint32_t)(_r); } }
    RG_(ebx) = (uint32_t)(MR32(RG_(esi)+0xb4d9f8u));
L_004363bd:
    { uint32_t _a = RG_(ebx), _b = 0x80u, _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x30u); }
    if (CC_GE) goto L_004363ca;
L_004363c5:
    RG_(ebx) = (uint32_t)(0x80u);
L_004363ca:
    { uint32_t _a = RG_(eax), _b = RG_(ebx), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x10u); RG_(eax) = (uint32_t)(_r); }
    if (CC_NS) goto L_004363d0;
L_004363ce:
    { uint32_t _r = (RG_(eax)) ^ (RG_(eax)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(eax) = (uint32_t)(_r); }
L_004363d0:
    { uint32_t _t; POP32(_t); RG_(edi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(esi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ebx) = (uint32_t)(_t); }
    RG_(esp) += 4u;
    LR_STORE;
    return;
}
""",
    0x01a19100: r"""void sub_01a19100(CPU *c) {
    LR_ENTER;
L_01a19100:
    RG_(eax) = (uint32_t)((RG_(esi)+0x4u));
    MR32(RG_(eax)) = (RG_(eax));
    MR32(RG_(eax)+0x4u) = (RG_(eax));
    PUSH32(RG_(ebx));
    RG_(ebx) = (uint32_t)(MR32(RG_(esp)+0xcu));
    RG_(eax) = (uint32_t)((RG_(esi)+0xcu));
    MR32(RG_(eax)) = (RG_(eax));
    MR32(RG_(eax)+0x4u) = (RG_(eax));
    PUSH32(RG_(ebp));
    RG_(ebp) = (uint32_t)(MR32(RG_(esp)+0xcu));
    RG_(eax) = (uint32_t)((RG_(esi)+0x14u));
    MR32(RG_(eax)) = (RG_(eax));
    MR32(RG_(eax)+0x4u) = (RG_(eax));
    PUSH32(RG_(edi));
    { uint32_t _r = (RG_(edi)) ^ (RG_(edi)); FLAGS_LOG_M(_r, 32, 0x00u); RG_(edi) = (uint32_t)(_r); }
    RG_(ecx) = (uint32_t)((RG_(esi)+0x48u));
    MR32(RG_(esi)+0x1cu) = (RG_(ebp));
    MR32(RG_(esi)+0x20u) = (RG_(ebx));
    MR32(RG_(esi)+0x24u) = (RG_(edi));
    MR32(RG_(esi)+0x28u) = (RG_(edi));
    MR32(RG_(esi)+0x2cu) = (RG_(edi));
    MR32(RG_(esi)+0x30u) = (RG_(edi));
    MR32(RG_(esi)+0x34u) = (RG_(edi));
    MR32(RG_(esi)+0x38u) = (RG_(edi));
    MR32(RG_(esi)+0x3cu) = (RG_(edi));
    MR32(RG_(esi)+0x40u) = (0xffffffffu);
    MR32(RG_(ecx)+0x00u) = 0u;
    MR32(RG_(ecx)+0x04u) = 0u;
    MR32(RG_(ecx)+0x08u) = 0u;
    MR32(RG_(ecx)+0x0cu) = 0u;
    MR32(RG_(ecx)+0x10u) = 0u;
    MR32(RG_(ecx)+0x14u) = 0u;
    MR8(RG_(esi)+0x44u) = 1u;
    MR8(RG_(esi)+0x45u) = 1u;
    RG_(eax) = (uint32_t)(MR32(RG_(esp)+0x18u));
    MR32(RG_(esi)) = (RG_(eax));
    { uint32_t _a = MR32(0xbfbcccu), _b = RG_(edi), _r = _a - _b; FLAGS_SUB_M(_a, _b, _r, 32, 0x08u); }
    if (CC_E) goto L_01a191ae;
L_01a191ae:
    { uint32_t _a = MR32(RG_(esi)+0x2cu), _b = RG_(ebx), _r = _a + _b; FLAGS_ADD_M(_a, _b, _r, 32, 0x00u); MR32(RG_(esi)+0x2cu) = (_r); }
    PUSH32(RG_(ebx));
    PUSH32(RG_(esi));
    RG_(eax) = (uint32_t)(RG_(ebp));
    PUSH32(0x01a191c3u);
    LR_STORE;
    DISPATCH_CALL(c, 0x00435230u);
    LR_RELOAD;
    { uint32_t _t; POP32(_t); RG_(edi) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ebp) = (uint32_t)(_t); }
    { uint32_t _t; POP32(_t); RG_(ebx) = (uint32_t)(_t); }
    RG_(esp) += 16u;
    LR_STORE;
    return;
}
""",
}
