/* Adapter for the unmodified official Imagination PowerVR Native SDK decoder.
 * Upstream MIT license and exact commit/hashes are alongside this file. */
#include "smeg_pvrtc.h"
#include "PVRTDecompress.h"
#include <algorithm>
#include <cstddef>
#include <vector>

extern "C" bool smeg_decode_pvrtc4(const uint8_t *compressed, unsigned width,
                                   unsigned height, uint8_t *rgba)
{
    if (!compressed || !rgba || !width || !height || width > 4096 || height > 4096 ||
        (width & (width - 1)) || (height & (height - 1))) {
        return false;
    }
    const size_t bytes = size_t(std::max(width, 8u)) * std::max(height, 8u) / 2;
    // Upstream reads uint32_t words directly. Supply aligned native words,
    // explicitly interpreting the standard PVRTC stream as little endian.
    std::vector<uint32_t> aligned(bytes / 4);
    for (size_t i = 0; i < aligned.size(); ++i) {
        const uint8_t *p = compressed + 4 * i;
        aligned[i] = uint32_t(p[0]) | uint32_t(p[1]) << 8 |
                     uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
    }
    return pvr::PVRTDecompressPVRTC(aligned.data(), 0, width, height, rgba) != 0;
}
