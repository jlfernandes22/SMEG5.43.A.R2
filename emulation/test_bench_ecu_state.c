#include <assert.h>
#include <stdio.h>
#include "emulation/smeg_bench_ecu.h"
static const uint8_t original[3][8]={
    {0x12,0x34,0x56,0x5d,0x78,0x9a,0xbc,0xde},
    {0xb7,0xb0,0x15,0xfc,0xfc,0xae,0xc2,0x87},
    {0x11,0x22,0x33,0x44,0x06,0x66,0x77,0x88}
};
static void seed(SmegMcuPeer *peer,uint8_t payload[3][8])
{const uint8_t identity[4]={5,3,9,1};smeg_mcu_peer_init(peer,identity);memcpy(payload,original,sizeof original);}
static void only_eco_byte_changed(const uint8_t p[3][8],unsigned expected)
{
    uint8_t want[3][8];memcpy(want,original,sizeof want);want[0][3]=expected;
    assert(!memcmp(p,want,sizeof want));
}
static void only_parking_fields_changed(const uint8_t before[3][8],const uint8_t after[3][8])
{
    uint8_t want[3][8];memcpy(want,before,sizeof want);want[1][0]=after[1][0];want[1][5]=after[1][5];
    assert(!memcmp(want,after,sizeof want));
    assert((before[1][0]&3)==(after[1][0]&3));
    assert((before[1][5]&~2)==(after[1][5]&~2));
}
int main(void)
{
    SmegMcuPeer peer;uint8_t p[3][8],before[3][8];seed(&peer,p);
    /* ECO1(enabled)->2(disabled)->1; preserve every unrelated bit and row. */
    peer.ecu_toggle_count[0]=1;assert(smeg_bench_ecu_apply(&peer,p,1)==1);
    only_eco_byte_changed(p,0x9d);assert(peer.ecu_toggle_count[0]==0);
    peer.ecu_toggle_count[0]=1;assert(smeg_bench_ecu_apply(&peer,p,1)==1);
    only_eco_byte_changed(p,0x5d);
    peer.ecu_toggle_count[0]=2;assert(smeg_bench_ecu_apply(&peer,p,1)==0);
    assert(!memcmp(p,original,sizeof p)&&!peer.ecu_toggle_count[0]);
    /* Unknown ECOraw0/3 are retained, without fabricating a valid status. */
    for(unsigned raw=0;raw<=3;raw+=3){
        seed(&peer,p);p[0][3]=(p[0][3]&0x3f)|(raw<<6);memcpy(before,p,sizeof p);
        peer.ecu_toggle_count[0]=1;assert(smeg_bench_ecu_apply(&peer,p,1)==0);
        assert(!memcmp(p,before,sizeof p)&&!peer.ecu_toggle_count[0]);
    }
    /* Parking standby5/5 -> disabled2/2 -> active4/4. */
    seed(&peer,p);memcpy(before,p,sizeof p);peer.ecu_toggle_count[1]=1;
    assert(smeg_bench_ecu_apply(&peer,p,2)==2);
    assert(p[1][0]==0x4b&&!(p[1][5]&2));only_parking_fields_changed(before,p);
    memcpy(before,p,sizeof p);peer.ecu_toggle_count[1]=1;
    assert(smeg_bench_ecu_apply(&peer,p,2)==2);
    assert(p[1][0]==0x93&&(p[1][5]&2));only_parking_fields_changed(before,p);
    memcpy(before,p,sizeof p);peer.ecu_toggle_count[1]=2;
    assert(smeg_bench_ecu_apply(&peer,p,2)==2); /* Processed, identical finalstate. */
    assert(!memcmp(p,before,sizeof p));
    /* Batched count is equivalent to sequential requests, including special
     * initial standby transition; no dropped first request or off-by-one. */
    for(unsigned status=2;status<=5;status++){
        if(status==3)continue;
        for(unsigned n=1;n<=8;n++){
            SmegMcuPeer sequential,batched;uint8_t q[3][8],r[3][8];
            seed(&sequential,q);seed(&batched,r);
            q[1][0]=r[1][0]=(q[1][0]&3)|(status<<5)|(status<<2);
            q[1][5]=r[1][5]=(q[1][5]&~2)|(status==4?2:0);
            for(unsigned i=0;i<n;i++){sequential.ecu_toggle_count[1]=1;smeg_bench_ecu_apply(&sequential,q,2);}
            batched.ecu_toggle_count[1]=n;smeg_bench_ecu_apply(&batched,r,2);
            assert(!memcmp(q,r,sizeof q));
        }
    }
    /* Missing fixture bits prevent any state edits and drain stale requests. */
    seed(&peer,p);peer.ecu_toggle_count[0]=peer.ecu_toggle_count[1]=1;
    assert(!smeg_bench_ecu_apply(&peer,p,0));assert(!memcmp(p,original,sizeof p));
    assert(!peer.ecu_toggle_count[0]&&!peer.ecu_toggle_count[1]);
    seed(&peer,p);peer.ecu_toggle_count[0]=peer.ecu_toggle_count[1]=1;
    assert(smeg_bench_ecu_apply(&peer,p,1)==1);only_eco_byte_changed(p,0x9d);
    /* Unsupported/mismatched parking states are untouched. */
    const uint8_t invalid[]={0x03,0x27,0x6f,0xdb,0xff,0x8b};
    for(unsigned i=0;i<sizeof invalid;i++){
        seed(&peer,p);p[1][0]=invalid[i];memcpy(before,p,sizeof p);peer.ecu_toggle_count[1]=1;
        assert(!smeg_bench_ecu_apply(&peer,p,2));assert(!memcmp(p,before,sizeof p));
        assert(!peer.ecu_toggle_count[1]);
    }
    /* Combined accepted events affect only their own fixture fields. */
    seed(&peer,p);peer.ecu_toggle_count[0]=peer.ecu_toggle_count[1]=1;
    assert(smeg_bench_ecu_apply(&peer,p,3)==3);
    assert(p[0][3]==0x9d&&p[1][0]==0x4b&&!(p[1][5]&2));
    assert(!memcmp(p[2],original[2],8));
    puts("Bench ECU state: ECO/preserved bits, parity, parking standby/disabled/active, visual request, batched equivalence and unsupported/missing fixtures passed");
}
