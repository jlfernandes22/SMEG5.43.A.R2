#ifndef SMEG_DMA_COPY_H
#define SMEG_DMA_COPY_H
#include <stdint.h>
typedef int (*SmegDmaRead)(void *, uint32_t, uint8_t *, unsigned);
typedef int (*SmegDmaWrite)(void *, uint32_t, const uint8_t *, unsigned);

/* eDMA independently sizes source and destination bus accesses. Stage one
 * minor loop before writing it, e.g. SD FIFO4-byte reads -> RAM32-byte bursts.
 * Memory bytes are preserved; peripheral/guest code owns any byte swapping. */
static inline int smeg_dma_copy_minor(void *opaque, uint32_t *source,
                                      uint32_t *dest, unsigned ssize,
                                      unsigned dsize, int16_t soff,
                                      int16_t doff, unsigned nbytes,
                                      uint8_t *buffer, SmegDmaRead read,
                                      SmegDmaWrite write)
{
    if (!ssize || !dsize || !nbytes || nbytes % ssize || nbytes % dsize) {
        return -1;
    }
    for (unsigned i = 0; i < nbytes; i += ssize) {
        if (read(opaque, *source, buffer + i, ssize)) { return -1; }
        *source += soff;
    }
    for (unsigned i = 0; i < nbytes; i += dsize) {
        if (write(opaque, *dest, buffer + i, dsize)) { return -1; }
        *dest += doff;
    }
    return 0;
}
#endif
