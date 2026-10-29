#!/usr/bin/env python3
"""Apply the narrowly scoped MPC5121E experimental rfi restore correction."""
from pathlib import Path
import argparse

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("qemu_source", type=Path)
args = parser.parse_args()
path = args.qemu_source.resolve() / "target/ppc/excp_helper.c"
before = '''void helper_rfi(CPUPPCState *env)
{
    do_rfi(env, env->spr[SPR_SRR0], env->spr[SPR_SRR1] & 0xfffffffful);
}'''
after = '''void helper_rfi(CPUPPCState *env)
{
    target_ulong restored_msr = env->spr[SPR_SRR1] & 0xfffffffful;

    /* Experimental MPC5121E correction, deliberately limited to its PVR.
     * NXP e300coreRM: SRR1 bits 1-4 and 10-15 contain interrupt-specific
     * information; saved MSR fields occupy bits 5-9 and 16-31. In particular,
     * a DSTLB store syndrome must not become MSR[ILE] after rfi. Retain the
     * live MSR in the syndrome positions, rather than restoring SRR1 there.
     * do_rfi() below still clears POW and TGPR as required.
     * Reference: https://www.nxp.com/docs/en/reference-manual/e300coreRM.pdf
     */
    if (env->spr[SPR_PVR] == 0x80860010) {
        const target_ulong syndrome_mask = 0x783f0000;
        restored_msr = (restored_msr & ~syndrome_mask) |
                       (env->msr & syndrome_mask);
    }
    do_rfi(env, env->spr[SPR_SRR0], restored_msr);
}'''
text = path.read_text()
if after in text:
    print(f"MPC5121E rfi correction already present in {path}")
elif text.count(before) == 1:
    path.write_text(text.replace(before, after, 1))
    print(f"Applied experimental MPC5121E rfi correction to {path}")
else:
    parser.error("Expected QEMU 9.2 helper_rfi body not found; manual review required")
