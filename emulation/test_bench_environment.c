#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "emulation/smeg_bench_environment.h"
#include "emulation/smeg_mcu_peer.h"
int main(void)
{
    uint8_t date[5]={0x80,0xf0,0xc0,0xe0,0xc0}, before[5];
    struct tm tm={.tm_year=126,.tm_mon=9,.tm_mday=26,.tm_hour=23,.tm_min=59};
    assert(smeg_bench_date(date,&tm));
    const uint8_t expected[5]={0x9a,0xfa,0xda,0xf7,0xfb};
    assert(!memcmp(date,expected,5));
    tm.tm_year=124;tm.tm_mon=1;tm.tm_mday=29;assert(smeg_bench_date(date,&tm));
    memcpy(before,date,5);tm.tm_year=200;assert(!smeg_bench_date(date,&tm));
    assert(!memcmp(before,date,5)); /* 2100 is not a leap year. */
    tm.tm_year=126;tm.tm_mon=11;tm.tm_mday=31;assert(smeg_bench_date(date,&tm));
    tm.tm_year=127;tm.tm_mon=0;tm.tm_mday=1;tm.tm_hour=0;tm.tm_min=0;
    assert(smeg_bench_date(date,&tm));assert((date[0]&127)==27&&(date[4]&63)==0);
    uint8_t service[8]={8,1,2,3,4,5,255,7};
    assert(smeg_bench_temperature(service,120)&&service[6]==120);
    assert(service[0]==8&&service[5]==5&&service[7]==7);
    assert(!smeg_bench_temperature(service,251)&&service[6]==120);
    assert(smeg_bench_temperature(service,255));
    const uint8_t ids[10]={0x1a,5,0xc,0x15,0xf,0xe,0xb,0x22,2,0x13};
    const unsigned lens[10]={5,8,6,8,7,5,8,5,8,5};
    const uint8_t identity[4]={5,3,9,1};SmegMcuPeer peer;
    smeg_mcu_peer_init(&peer,identity);
    for(unsigned n=0;n<100;n++) {
        for(unsigned i=0;i<10;i++)assert(smeg_mcu_peer_net(&peer,ids[i],service,lens[i]));
        assert(peer.net_count==10);
        assert(smeg_mcu_peer_net(&peer,0x13,date,5));
        assert(!smeg_mcu_peer_net(&peer,0x13,date,4));
        for(unsigned i=0;i<10;i++) {
            uint8_t rx[92];memset(rx,255,92);rx[0]=0x99;rx[1]=0;smeg_mcu_seal(rx,90);
            assert(smeg_mcu_peer_net_pending(&peer,rx));
            assert(rx[3]==ids[i]&&rx[4]==lens[i]&&smeg_mcu_crc_valid(rx,90));
            assert(smeg_mcu_crc_valid(rx+2,lens[i]+3));
            if(i==9)assert(!memcmp(rx+5,date,5));
        }
    }
    puts("Native BSI date validation, leap years, rollover, flags, temperature preservation and ten-ID queue passed");
}
