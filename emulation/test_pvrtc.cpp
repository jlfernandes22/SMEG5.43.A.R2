#include "emulation/powervr/smeg_pvrtc.h"
#include <cassert>
#include <cstdio>
#include <cstdint>
int main(){
 uint8_t input[32]={},out[8*8*4];
 // Four identical 64-bit blocks: modulation0, endpointsA/B opaque white.
 for(unsigned i=0;i<4;i++){input[i*8+4]=0xfe;input[i*8+5]=0xff;input[i*8+6]=0xff;input[i*8+7]=0xff;}
 assert(smeg_decode_pvrtc4(input,8,8,out));
 for(unsigned i=0;i<sizeof(out);i++)assert(out[i]==255);
 // Identical opaque-red endpoints A/B, zero modulation: RGBA red.
 for(unsigned i=0;i<4;i++){input[i*8+4]=0x00;input[i*8+5]=0xfc;input[i*8+6]=0x00;input[i*8+7]=0xfc;}
 assert(smeg_decode_pvrtc4(input,8,8,out));
 for(unsigned i=0;i<64;i++){assert(out[4*i]==255);assert(out[4*i+1]==0);assert(out[4*i+2]==0);assert(out[4*i+3]==255);}
 // Transparent endpoints produce an actual transparent image, not opaque black.
 for(unsigned i=0;i<32;i++)input[i]=0;
 assert(smeg_decode_pvrtc4(input,8,8,out));
 for(unsigned i=0;i<sizeof(out);i++)assert(out[i]==0);
 assert(!smeg_decode_pvrtc4(input,7,8,out));
 assert(!smeg_decode_pvrtc4(nullptr,8,8,out));
 puts("Official PowerVR decoder: opaque-white/red/transparent PVRTC4 fixtures and invalid-dimension checks pass");
}
