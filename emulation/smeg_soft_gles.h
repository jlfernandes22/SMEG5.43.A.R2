#ifndef SMEG_SOFT_GLES_H
#define SMEG_SOFT_GLES_H
#include "cpu.h"
/* Opt-in guest GL API emulation using host compatibility OpenGL.
 * SMEG_GL_RENDERER=auto (default) preserves host renderer preferences;
 * software explicitly requests Mesa software rendering. No guest image edits. */
void smeg_soft_gles_install(CPUPPCState *env,
                           uint32_t (*framebuffer)(void *opaque),
                           void (*present)(void *opaque), void *opaque);
/* Host-only API routing for an observed, relocated native updater module.
 * Caller must pause the guest. No guest instruction or data bytes are changed. */
bool smeg_soft_gles_set_upgrade_base(uint32_t base);
uint32_t smeg_soft_gles_get_upgrade_base(void);
#endif
