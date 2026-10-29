#!/usr/bin/env python3
"""Install optional CPU-scoped native API interception into QEMU 9.2.

No guest image is edited. No GLES/EGL behavior is implemented here. The board
must explicitly register its software backend before CPU translation starts.
"""
from pathlib import Path
import argparse
import shutil

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('qemu_source', type=Path)
args = parser.parse_args()
root = args.qemu_source.resolve()

def replace_once(path, before, after, marker):
    text = path.read_text()
    if marker in text:
        return
    if text.count(before) != 1:
        parser.error(f'QEMU9.2 patch anchor not unique in {path}; review required')
    path.write_text(text.replace(before, after, 1))

hook_source = Path(__file__).with_name('smeg_api_hook.h')
hook_target = root / 'include/hw/ppc/smeg_api_hook.h'
# Retouching this unchanged header forces a full PowerPC translator rebuild.
if not hook_target.exists() or hook_target.read_bytes() != hook_source.read_bytes():
    shutil.copyfile(hook_source, hook_target)
replace_once(root / 'target/ppc/helper.h',
             'DEF_HELPER_1(tbegin, void, env)',
             'DEF_HELPER_2(smeg_soft_gles, i32, env, tl)\n\n'
             'DEF_HELPER_1(tbegin, void, env)',
             'DEF_HELPER_2(smeg_soft_gles,')

registry = '''
/* Optional SMEG software API boundary; no renderer or guest API semantics.
 * An immutable process-lifetime registration is published before CPU start.
 * Atomic publication also makes translation-time reads MTTCG-safe. */
#include "hw/ppc/smeg_api_hook.h"
#include "qemu/atomic.h"

typedef struct SmegApiRegistration {
    CPUPPCState *env;
    SmegSoftGlesMatch match;
    SmegSoftGlesCall call;
    void *opaque;
} SmegApiRegistration;

static SmegApiRegistration *smeg_api_registration;

void smeg_soft_gles_register(CPUPPCState *env, SmegSoftGlesMatch match,
                             SmegSoftGlesCall call, void *opaque)
{
    SmegApiRegistration *registration;
    g_assert(env && match && call);
    g_assert(!qatomic_load_acquire(&smeg_api_registration));
    registration = g_new(SmegApiRegistration, 1);
    *registration = (SmegApiRegistration){env, match, call, opaque};
    qatomic_store_release(&smeg_api_registration, registration);
}

bool smeg_soft_gles_matches(CPUPPCState *env, uint32_t pc)
{
    SmegApiRegistration *r = qatomic_load_acquire(&smeg_api_registration);
    return r && r->env == env && r->match(r->opaque, pc);
}

uint32_t helper_smeg_soft_gles(CPUPPCState *env, target_ulong pc)
{
    SmegApiRegistration *r = qatomic_load_acquire(&smeg_api_registration);
    return r && r->env == env && r->match(r->opaque, pc) &&
           r->call(r->opaque, env, pc);
}
'''
replace_once(root / 'target/ppc/misc_helper.c',
             '#include "helper_regs.h"',
             '#include "helper_regs.h"\n' + registry,
             'static SmegApiRegistration *smeg_api_registration;')
replace_once(root / 'target/ppc/translate.c',
             '#include "power8-pmu.h"',
             '#include "power8-pmu.h"\n#include "hw/ppc/smeg_api_hook.h"',
             '#include "hw/ppc/smeg_api_hook.h"')
before = '''    ctx->cia = pc = ctx->base.pc_next;
    insn = translator_ldl_swap(env, dcbase, pc, need_byteswap(ctx));'''
after = '''    ctx->cia = pc = ctx->base.pc_next;
    /* Optional CPU-scoped API hook. The helper is emitted only for immutable
     * registered PCs. A declined runtime call falls through the original
     * guest instruction. A handled call supplies its own ABI return nip. */
    if (smeg_soft_gles_matches(env, pc)) {
        TCGLabel *native = gen_new_label();
        TCGv_i32 handled = tcg_temp_new_i32();
        gen_update_nip(ctx, pc);
        gen_helper_smeg_soft_gles(handled, tcg_env, tcg_constant_tl(pc));
        tcg_gen_brcondi_i32(TCG_COND_EQ, handled, 0, native);
        tcg_gen_lookup_and_goto_ptr();
        gen_set_label(native);
    }
    insn = translator_ldl_swap(env, dcbase, pc, need_byteswap(ctx));'''
replace_once(root / 'target/ppc/translate.c', before, after,
             'if (smeg_soft_gles_matches(env, pc))')
print(f'Installed optional CPU-scoped SMEG API hook into {root}')
