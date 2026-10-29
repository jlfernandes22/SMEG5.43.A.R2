#ifndef SMEG_PVRTC_H
#define SMEG_PVRTC_H
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Input: PVRTC1 RGBA4bpp Morton/twiddled blocks in standard little-endian
 * word byte order. Buffer must contain max(width,8)*max(height,8)/2 bytes.
 * Output: width*height*4 RGBA bytes. Dimensions must be powers of two. */
bool smeg_decode_pvrtc4(const uint8_t *compressed, unsigned width,
                       unsigned height, uint8_t *rgba);
#ifdef __cplusplus
}
#endif
#endif
