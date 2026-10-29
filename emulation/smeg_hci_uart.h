/* Bounded PSC1 byte FIFOs. No Bluetooth responses or radio state live here. */
#ifndef SMEG_HCI_UART_H
#define SMEG_HCI_UART_H
#include <stdint.h>
#include <string.h>
#define SMEG_HCI_FIFO 4096

typedef struct SmegHciUart {
    uint8_t rx[SMEG_HCI_FIFO], tx[SMEG_HCI_FIFO];
    unsigned rh, rn, th, tn;
    uint32_t tx_isr;
    uint64_t received, transmitted, overrun;
} SmegHciUart;
static inline unsigned smeg_hci_tx_status(const SmegHciUart *u, unsigned cap, unsigned alarm)
{
    return (!cap ? 0x80 : 0) | (!u->tn ? 1 : 0x20) |
           (cap && u->tn >= cap ? 2 : 0) | (u->tn < alarm ? 4 : 0);
}
static inline int smeg_hci_push_tx(SmegHciUart *u, uint8_t b, unsigned cap)
{
    if (cap > SMEG_HCI_FIFO) cap = SMEG_HCI_FIFO;
    if (!cap || u->tn >= cap) { u->tx_isr |= 0x10;u->overrun++;return 0; }
    u->tx[(u->th + u->tn++) % SMEG_HCI_FIFO] = b;return 1;
}
static inline unsigned smeg_hci_receive(SmegHciUart *u, const uint8_t *b, unsigned n)
{
    unsigned i=0;
    while(i<n && u->rn<SMEG_HCI_FIFO)u->rx[(u->rh+u->rn++)%SMEG_HCI_FIFO]=b[i++];
    u->received+=i;return i;
}
static inline uint8_t smeg_hci_read(SmegHciUart *u)
{
    if(!u->rn)return 0;
    uint8_t b=u->rx[u->rh];u->rh=(u->rh+1)%SMEG_HCI_FIFO;u->rn--;return b;
}
static inline void smeg_hci_sent(SmegHciUart *u, unsigned n)
{
    if(n>u->tn)n=u->tn;
    u->th=(u->th+n)%SMEG_HCI_FIFO;u->tn-=n;u->transmitted+=n;
}
#endif
