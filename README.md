# M32R processor module (Aisin 09G927750, 1 MB)

Based on github.com/ripnet/ghidra-m32r, corrected for the Aisin 09G M32R/ECU code:

- removed the "fp(0x80c000)" hack (hard-coded FP base of the original author's ECU; here FP/R13 is a normal callee-saved register)
- LDH @(disp,Rs): load from Rs+disp (was *(Rs)+disp)
- MVTC restricted to op3=10 (was a catch-all for every unassigned 0x1xxx opcode)
- CMPUI: sign-extended immediate, unsigned compare
- ADDV/ADDV3 set C = signed overflow; ADDX/SUBX use and produce the carry
- added DSP/accumulator instructions (MULHI/LO, MULWHI/LO, MACHI/LO, MACWHI/LO, RAC/RACH, MVFAC*, MVTAC*)
- cspec: args R4-R7 then stack, return R0 (R0:R1), callee-saved R8-R14/SP (measured on 3300 functions)

Install: copy this folder to `<ghidra>/Ghidra/Processors/M32R` and run
`support/sleigh Ghidra/Processors/M32R/data/languages/m32r.slaspec`; restart Ghidra.
Language id `m32r:2:default`, raw binary at base 0.

Import recipe: M32RSetup.java (SFR/RAM block 0x800000-0x81FFFF, R12 = 0x80C000 set by boot
`ld24 r12,#0x80c000` @0x2b0), then M32RSeed.java (vector table 0x20080, function starts after
`jmp r14`, BL targets; skips BRA stubs / addresses < 0x2000 to avoid thunk recursion into 0xFF fill).
