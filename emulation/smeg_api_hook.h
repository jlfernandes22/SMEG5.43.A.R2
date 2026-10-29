/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HW_PPC_SMEG_API_HOOK_H
#define HW_PPC_SMEG_API_HOOK_H

#include "qemu/osdep.h"
typedef struct CPUArchState CPUPPCState;

/* Register once, before any vCPU starts. Match must be immutable/thread-safe:
 * translation can run on a different thread. Call executes on the vCPU thread
 * and may update GPR/FPR/memory state. On handled=true it must set env->nip to
 * the ABI return address (normally env->lr). False executes native code.
 * Registration is scoped to exactly this CPU; absent registration costs only
 * a null check during translation and never changes guest instructions.
 * The board, not this generic hook, controls explicit SMEG_SOFT_GLES opt-in.
 */
typedef bool (*SmegSoftGlesMatch)(void *opaque, uint32_t pc);
typedef bool (*SmegSoftGlesCall)(void *opaque, CPUPPCState *env, uint32_t pc);
void smeg_soft_gles_register(CPUPPCState *env, SmegSoftGlesMatch match,
                             SmegSoftGlesCall call, void *opaque);
bool smeg_soft_gles_matches(CPUPPCState *env, uint32_t pc);

#endif
