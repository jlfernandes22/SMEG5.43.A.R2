#include <assert.h>
#include <stdio.h>
#include "emulation/smeg_hci_uart.h"
int main(void)
{
    SmegHciUart u={0};uint8_t b[SMEG_HCI_FIFO];
    for(unsigned i=0;i<SMEG_HCI_FIFO;i++)b[i]=i;
    for(unsigned round=0;round<20;round++) {
        assert(smeg_hci_receive(&u,b,SMEG_HCI_FIFO)==SMEG_HCI_FIFO);
        assert(!smeg_hci_receive(&u,b,1));
        for(unsigned i=0;i<SMEG_HCI_FIFO;i++)assert(smeg_hci_read(&u)==(uint8_t)i);
        assert(!u.rn&&!smeg_hci_read(&u));
        for(unsigned i=0;i<64;i++)assert(smeg_hci_push_tx(&u,i,64));
        assert(!smeg_hci_push_tx(&u,0,64)&&u.overrun==round+1);
        assert(smeg_hci_tx_status(&u,64,32)&2);
        for(unsigned i=0;i<64;i++) {
            assert(u.tx[u.th]==i);smeg_hci_sent(&u,1);
        }
        assert(!u.tn&&(smeg_hci_tx_status(&u,64,32)&5)==5);
    }
    /* Partial socket writes must preserve unsent bytes and order. */
    for(unsigned i=0;i<100;i++)assert(smeg_hci_push_tx(&u,i,4096));
    smeg_hci_sent(&u,7);assert(u.tn==93&&u.tx[u.th]==7);
    smeg_hci_sent(&u,500);assert(!u.tn);
    puts("HCI UART bounded FIFOs, wrap, order, overruns, alarm state and partial-write preservation passed");
}
