/* Virtual bench front-panel peer. No claim about the installed vehicle identity.
 * Protocol recovered from unmodified SMEG5.43.A.R2 kernel:
 * sync 267d64, message/control 268870/268668, CRC 287634/287770,
 * EOL request 263aa0, EOL response 2630a0, board table 7288b8.
 * Hardware transport must call exchange once per complete 92-byte host frame.
 */
#ifndef SMEG_MCU_PEER_H
#define SMEG_MCU_PEER_H
#include <stdint.h>
#include <string.h>
#define SMEG_MCU_FRAME_SIZE 92
#define SMEG_MCU_TOUCH_QUEUE 64
#define SMEG_MCU_KEY_QUEUE 64
#define SMEG_MCU_NET_QUEUE 11

typedef struct SmegMcuPeer {
    uint8_t identity[4];
    uint8_t upg_sw_release[3]; /* Explicit virtual MCU firmware, not measured car state. */
    uint8_t upg_sw_release_enabled; /* Query-only model; disabled by default. */
    uint8_t upg_config[16], system_config[16];
    uint8_t upg_config_enabled, system_config_enabled; /* Explicit virtual NVRAM only. */
    uint8_t diag_flags; /* Virtual display bit2, alert bit1. Not measured coding. */
    uint8_t onoff_state; /* Explicit virtual bench KEY_ON=7; native enum26603c. */
    uint8_t libcom_power_sent;
    uint8_t fp_power_sent;
    uint8_t init_pending, init_sequence; /* 1 awaiting transport ACK, 2 ready for next poll. */
    uint8_t ack[29][3];
    unsigned ack_count;
    unsigned synced;
    uint8_t touch[SMEG_MCU_TOUCH_QUEUE][7];
    unsigned touch_head, touch_count;
    uint8_t key[SMEG_MCU_KEY_QUEUE][2];
    unsigned key_head, key_count;
    /* Whitelisted native NET state notifications, latest per local ID. */
    uint8_t net[SMEG_MCU_NET_QUEUE][10]; /* local ID, length, <=8 payload bytes */
    unsigned net_head, net_count;
    /* Opt-in status-only virtual ECU behavior. Board enables only for explicit
     * fixtures; it drains counters to update its persistent periodic payloads. */
    uint8_t bench_key_profile; /* Opt-in native FMUX profiles, no physicalcoding. */
    uint8_t key_variant; /* Native UPG profile byte1: 00 default, a1 MENU/SRC. */
    uint8_t key_profile_pending;
    uint8_t bench_ecu_mask; /* bit0 Stop/Start, bit1 parking, bit2 body; defaultdisabled */
    uint32_t ecu_toggle_count[2];
    uint8_t body_pending, body_level; /* Latest Welcome Lighting level, not a pulse. */
    uint8_t ecu_last_aa[90];
    uint8_t ecu_awaiting_ack;
} SmegMcuPeer;

static inline uint16_t smeg_mcu_crc(const uint8_t *p, unsigned n)
{
    uint16_t crc = 0;
    while (n--) {
        crc ^= *p++;
        for (unsigned bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ ((crc & 1) ? 0x8408 : 0);
        }
    }
    return crc;
}
static inline void smeg_mcu_seal(uint8_t *p, unsigned n)
{
    uint16_t crc = smeg_mcu_crc(p, n);
    p[n] = crc >> 8;
    p[n + 1] = crc;
}
static inline int smeg_mcu_crc_valid(const uint8_t *p, unsigned n)
{
    return smeg_mcu_crc(p, n) == (((unsigned)p[n] << 8) | p[n + 1]);
}
static inline void smeg_mcu_peer_init(SmegMcuPeer *s, const uint8_t identity[4])
{
    memset(s, 0, sizeof(*s));
    memcpy(s->identity, identity, 4);
    s->diag_flags = 4; /* Explicit bench: virtual LVDS present, early alert off. */
    s->onoff_state = 7;
}
/* Set an explicitly selected virtual MCU software release, or NULL to disable.
 * Native BSP256 Upg_Write262568 sets channel10. GetEolSwIdent26c08c
 * sends ID01/len1/5a; UpdateData table7244a4 index2 ->26b818 formats
 * response ID02's three bytes as %02x.%02x.%02x and signals event2.
 * This does not model loader entry, erase, programming, or update completion. */
static inline void smeg_mcu_peer_set_upg_sw_release(SmegMcuPeer *s,
                                                   const uint8_t release[3])
{
    s->upg_sw_release_enabled = release != NULL;
    if (release) {
        memcpy(s->upg_sw_release, release, 3);
    } else {
        memset(s->upg_sw_release, 0, 3);
    }
}
/* Virtual MCU NVRAM fixtures. These bytes are not inferred from the car's
 * SQLite settings. EC transport synchronization preserves them; peer_init
 * disables/clears them, so board-level warm-reset persistence is separate. */
static inline void smeg_mcu_peer_set_upg_config(SmegMcuPeer *s,
                                              const uint8_t config[16])
{
    s->upg_config_enabled = config != NULL;
    if (config) memcpy(s->upg_config, config, 16);
    else memset(s->upg_config, 0, 16);
}
static inline void smeg_mcu_peer_set_system_config(SmegMcuPeer *s,
                                                 const uint8_t config[16])
{
    s->system_config_enabled = config != NULL;
    if (config) memcpy(s->system_config, config, 16);
    else memset(s->system_config, 0, 16);
}
/* Native /DevKbd channel08 ID80: packed12-bit X/Y, pressure,
 * BE16 timestamp, flags. GetTactileData0128bc64 decodes these seven bytes.
 * KBDUpdateData0128c8f4 refreshes press-detect time when flags bit7 is set.
 * Raw begin filtering requires nonzero flags; native DeBounceEnd/timer
 * synthesizes final release flags downstream. Board samples use81 pressed
 * /01 released with pressure128/0. Unspecified hardware bits are not claimed.
 * Keep the first pending sample and the latest repeat in each contact phase.
 * This preserves native begin/end filtering samples and every down/up edge,
 * without a 50 Hz mouse producer building seconds of stale SPI input.
 * Return0 when a new phase cannot fit; caller may retry the edge. */
static inline int smeg_mcu_peer_touch(SmegMcuPeer *s, uint16_t x, uint16_t y,
                                      uint8_t pressure, uint16_t ms,
                                      uint8_t flags)
{
    unsigned slot = (s->touch_head + s->touch_count) % SMEG_MCU_TOUCH_QUEUE;
    int replace = 0;
    if (s->touch_count >= 2) {
        unsigned tail = (slot + SMEG_MCU_TOUCH_QUEUE - 1) % SMEG_MCU_TOUCH_QUEUE;
        unsigned previous = (tail + SMEG_MCU_TOUCH_QUEUE - 1) % SMEG_MCU_TOUCH_QUEUE;
        int pressed = pressure != 0;
        if ((s->touch[tail][3] != 0) == pressed &&
            (s->touch[previous][3] != 0) == pressed) {
            /* Only the newest repeat is replaceable, never a phase edge. */
            slot = tail;
            replace = 1;
        }
    }
    if (!replace && s->touch_count == SMEG_MCU_TOUCH_QUEUE) {
        return 0;
    }
    uint8_t *p = s->touch[slot];
    x &= 0x0fff;
    y &= 0x0fff;
    p[0] = x >> 4;
    p[1] = ((x & 15) << 4) | (y >> 8);
    p[2] = y;
    p[3] = pressure;
    p[4] = ms >> 8;
    p[5] = ms;
    p[6] = flags;
    if (!replace) {
        s->touch_count++;
    }
    return 1;
}
static inline unsigned smeg_mcu_append(uint8_t rx[92], unsigned out,
                                      uint8_t channel, uint8_t id,
                                      const uint8_t *payload, unsigned len)
{
    if (out + len + 5 > 90) {
        return out;
    }
    rx[out] = channel;
    rx[out + 1] = id;
    rx[out + 2] = len;
    memcpy(rx + out + 3, payload, len);
    smeg_mcu_seal(rx + out, len + 3);
    rx[1]++;
    return out + len + 5;
}
/* Original KBDUpdateData0128c680 accepts channel08 IDs00..44 and one
 * status byte. GetKeyOffsetCommand0128dd54 maps status01..0a to offsets0..9.
 * Preserve every front-panel event; unlike pointer motion none coalesce. */
static inline int smeg_mcu_peer_key(SmegMcuPeer *s, uint8_t id, uint8_t status)
{
    if (id > 0x44 || status < 1 || status > 0x0a ||
        s->key_count == SMEG_MCU_KEY_QUEUE) {
        return 0;
    }
    unsigned slot = (s->key_head + s->key_count) % SMEG_MCU_KEY_QUEUE;
    s->key[slot][0] = id;
    s->key[slot][1] = status;
    s->key_count++;
    return 1;
}
/* Original FPUpdateData01289454 accepts this17-byte configuration update.
 * Publish it before a key, so FMUX0128f648 selects the appropriate native
 * table. This changes only the virtual MCU profile, never guest instructions. */
static inline int smeg_mcu_peer_set_key_variant(SmegMcuPeer *s, unsigned variant)
{
    if (!s->bench_key_profile || (variant != 0 && variant != 0xa1)) return 0;
    if (s->key_variant != variant) {
        s->key_variant = variant;
        s->key_profile_pending = 1;
    }
    return 1;
}
static inline int smeg_mcu_peer_profile_pending(SmegMcuPeer *s, uint8_t rx[92])
{
    unsigned out = 2;
    if (!s->key_profile_pending || !s->bench_key_profile ||
        rx[0] != 0x99 || !smeg_mcu_crc_valid(rx, 90)) return 0;
    for (unsigned i = 0; i < rx[1]; i++) {
        if (out + 5 > 90 || out + rx[out + 2] + 5 > 90 ||
            !smeg_mcu_crc_valid(rx + out, rx[out + 2] + 3)) return 0;
        if (rx[out] == 1 && rx[out + 1] == 0x10) return 0;
        out += rx[out + 2] + 5;
    }
    uint8_t profile[17] = {0};
    profile[1] = s->key_variant;
    unsigned next = smeg_mcu_append(rx, out, 1, 0x10, profile, sizeof(profile));
    if (next == out) return 0;
    s->key_profile_pending = 0;
    smeg_mcu_seal(rx, 90);
    return 1;
}
/* Append only to a validated, not-yet-clocked data response. Native key
 * observers share cached state, so at most one key is delivered per frame. */
static inline int smeg_mcu_peer_key_pending(SmegMcuPeer *s, uint8_t rx[92])
{
    unsigned out = 2;
    if (!s->key_count || s->key_profile_pending || rx[0] != 0x99 || !smeg_mcu_crc_valid(rx, 90)) {
        return 0;
    }
    for (unsigned i = 0; i < rx[1]; i++) {
        if (out + 5 > 90 || out + rx[out + 2] + 5 > 90 ||
            !smeg_mcu_crc_valid(rx + out, rx[out + 2] + 3)) {
            return 0;
        }
        if ((rx[out] == 8 && rx[out + 1] <= 0x44) ||
            (rx[out] == 1 && rx[out + 1] == 0x10)) {
            return 0;
        }
        out += rx[out + 2] + 5;
    }
    const uint8_t *event = s->key[s->key_head];
    unsigned next = smeg_mcu_append(rx, out, 8, event[0], event + 1, 1);
    if (next == out) {
        return 0;
    }
    s->key_head = (s->key_head + 1) % SMEG_MCU_KEY_QUEUE;
    s->key_count--;
    smeg_mcu_seal(rx, 90);
    return 1;
}
/* Native NET receive path: channel02 -> FPSpiSendToApplMsg268458 ->
 * /DevNet ReadNetDevice268e04 -> ReadTask012c8aa0 -> action(local ID).
 * C_BCM_CAN_MSG_RECEPTION::Init012bad50 subscribes object+0xc local ID.
 * Payload is the exact CAN data bytes: no arbitration ID/timestamp prefix.
 * BSI_RAPIDES local15/len8 speed0b6: BE16D2:D3, validityD7bit7.
 * BSI_INF_PROFILS local0f/len7 CAN260: availabilityD1bit2.
 * BSI_INF_CFG local0e/len5 CAN361: InfoMenuD0bit7, option0D0bit5.
 * BSI_CDE_PTR_MESSAGE local0b/len8 CAN1a1: original alert pointer/status.
 * CDE_LED_PUSH local22/len5 CAN227: AAS D0bits7:6, STT D3bits3:2.
 * DONNEES_BSI_LENTES_3 local13/len5 CAN276: native civil date/time.
 * DONNEES_BSI_LENTES local02/len8 CAN0f6: temperature D6.
 * CAN_NET_STATUS local1d/len1: bit4 economy mode, bit3 network healthy (MCU local status).
 * These status-only fixtures never transmit to a physical CAN interface. */
static inline int smeg_mcu_peer_net(SmegMcuPeer *s, uint8_t local_id,
                                    const uint8_t *payload, unsigned len)
{
    unsigned expected=local_id==0x1a?5:local_id==5?8:local_id==0x0c?6:
                      local_id==0x15?8:local_id==0x0f?7:local_id==0x0e?5:
                      local_id==0x0b?8:local_id==0x22?5:local_id==0x02?8:local_id==0x13?5:local_id==0x1d?1:0;
    if(!expected||len!=expected||!payload)return 0;
    for(unsigned i=0;i<s->net_count;i++) {
        unsigned slot=(s->net_head+i)%SMEG_MCU_NET_QUEUE;
        if(s->net[slot][0]==local_id) {
            memcpy(s->net[slot]+2,payload,len);
            return 1;
        }
    }
    if(s->net_count==SMEG_MCU_NET_QUEUE)return 0;
    unsigned slot=(s->net_head+s->net_count)%SMEG_MCU_NET_QUEUE;
    s->net[slot][0]=local_id;s->net[slot][1]=len;
    memcpy(s->net[slot]+2,payload,len);s->net_count++;
    return 1;
}
/* One native NET observer cache is shared: retain different state IDs, but
 * publish at most one per complete validated data frame. */
static inline int smeg_mcu_peer_net_pending(SmegMcuPeer *s, uint8_t rx[92])
{
    unsigned out=2;
    if(!s->net_count||rx[0]!=0x99||!smeg_mcu_crc_valid(rx,90))return 0;
    for(unsigned i=0;i<rx[1];i++) {
        if(out+5>90||out+rx[out+2]+5>90||
           !smeg_mcu_crc_valid(rx+out,rx[out+2]+3))return 0;
        if(rx[out]==2)return 0;
        out+=rx[out+2]+5;
    }
    const uint8_t *event=s->net[s->net_head];
    unsigned next=smeg_mcu_append(rx,out,2,event[0],event+2,event[1]);
    if(next==out)return 0;
    s->net_head=(s->net_head+1)%SMEG_MCU_NET_QUEUE;s->net_count--;
    smeg_mcu_seal(rx,90);
    return 1;
}
/* Counter units are accepted native request messages, not sampled bit edges.
 * Native pulses may repeat without a zero frame. No arbitrary sequence number
 * exists: exact AA repeats before the valid0F ACK cycle are retries; the same
 * bytes after that cycle represent a new request on this reliable bench link.
 * This does not promise exactly-once delivery across arbitrary ACK loss. */
static inline uint32_t smeg_mcu_peer_take_ecu_toggles(SmegMcuPeer *s,
                                                     unsigned index)
{
    if(index>=2)return 0;
    uint32_t count=s->ecu_toggle_count[index];s->ecu_toggle_count[index]=0;
    return count;
}
static inline void smeg_mcu_peer_ecu_commands(SmegMcuPeer *s,
                                               const uint8_t tx[92])
{
    if(!s->bench_ecu_mask)return;
    if(s->ecu_awaiting_ack&&!memcmp(s->ecu_last_aa,tx,90))return;
    /* Called only after exchange validates complete frame/message bounds.
     * Malformed or CRC-invalid submessages never trigger a bench reaction. */
    unsigned pos=2;
    for(unsigned i=0;i<tx[1];i++) {
        unsigned len=tx[pos+2];
        if(tx[pos]==2&&tx[pos+1]==3&&len==8&&
           smeg_mcu_crc_valid(tx+pos,len+3)) {
            const uint8_t *data=tx+pos+3;
            if((s->bench_ecu_mask&1)&&(data[6]&0x80)&&
               s->ecu_toggle_count[0]!=UINT32_MAX)s->ecu_toggle_count[0]++;
            if((s->bench_ecu_mask&2)&&(data[3]&4)&&
               s->ecu_toggle_count[1]!=UINT32_MAX)s->ecu_toggle_count[1]++;
        }
        /* Original ECRAN_INFO_PROFILS12acf24: local09/len7, CAN15b.
         * SetConfigurableFunctionStatus12a3284..32a4 sets D1bit2 and clears
         * D0bit7; SetLanguage does the inverse. Option0 is D3bit3. */
        if((s->bench_ecu_mask&4)&&tx[pos]==2&&tx[pos+1]==9&&len==7&&
           smeg_mcu_crc_valid(tx+pos,len+3)) {
            const uint8_t *data=tx+pos+3;
            if((data[1]&4)&&!(data[0]&0x80)) {
                s->body_level=data[3]&8;
                s->body_pending=1;
            }
        }
        pos+=len+5;
    }
    memcpy(s->ecu_last_aa,tx,90);s->ecu_awaiting_ack=1;
}
/* A secondary MCU can receive an input edge after host TX but before the
 * matching master RX clocks. Update only an unclocked data response, with
 * at most one tactile notification; never replace an existing phase sample. */
static inline int smeg_mcu_peer_touch_pending(SmegMcuPeer *s, uint8_t rx[92])
{
    unsigned out = 2;
    if (!s->touch_count || rx[0] != 0x99 || !smeg_mcu_crc_valid(rx, 90)) {
        return 0;
    }
    for (unsigned i = 0; i < rx[1]; i++) {
        if (out + 5 > 90 || out + rx[out + 2] + 5 > 90) {
            return 0;
        }
        if (rx[out] == 8 && rx[out + 1] == 0x80) {
            return 0;
        }
        out += rx[out + 2] + 5;
    }
    unsigned next = smeg_mcu_append(rx, out, 8, 0x80,
                                     s->touch[s->touch_head], 7);
    if (next == out) {
        return 0;
    }
    s->touch_head = (s->touch_head + 1) % SMEG_MCU_TOUCH_QUEUE;
    s->touch_count--;
    smeg_mcu_seal(rx, 90);
    return 1;
}
/* Returns 1 for a recognized valid host frame, 0 for malformed/unknown input.
 * Unknown application messages are transport ACKed but receive no invented
 * application payload. Explicit supported operation: EOL HW identity query and diagnostic configuration query.
 */
static inline int smeg_mcu_peer_exchange(SmegMcuPeer *s,
                                        const uint8_t tx[92], uint8_t rx[92])
{
    static const uint8_t sync_host[9] = {0xec,0xaa,0x55,0xff,0,0xaa,0x55,0xfb,0x8d};
    static const uint8_t sync_peer[9] = {0xd9,0xff,0,0xaa,0x55,0xff,0,0x73,0xcc};
    memset(rx, 0xff, 92);
    if (!memcmp(tx, sync_host, 9)) {
        memcpy(rx, sync_peer, 9);
        s->synced = 1;
        s->ack_count = 0;
        s->init_pending = 0;
        s->libcom_power_sent = s->fp_power_sent = 0;
        s->touch_head = s->touch_count = 0;
        s->key_head = s->key_count = 0;
        s->net_head = s->net_count = 0;
        s->ecu_toggle_count[0] = s->ecu_toggle_count[1] = 0;
        s->body_pending = s->body_level = 0;
        s->ecu_awaiting_ack = 0;
        return 1;
    }
    /* A warm host can start with a valid empty AA frame without EC sync.
     * Accept normal CRC-valid frames immediately; EC still resets peer state. */
    if (!smeg_mcu_crc_valid(tx, 90)) {
        return 0;
    }
    if (tx[0] == 0x0f) {
        s->ecu_awaiting_ack = 0;
        rx[0] = 0x6b;
        rx[1] = s->ack_count;
        memcpy(rx + 2, s->ack, s->ack_count * 3);
        for (unsigned i = 0; i < s->ack_count; i++)
            if (s->init_pending == 1 && s->ack[i][0] == 0x40 &&
                s->ack[i][1] == 3 && s->ack[i][2] == 0xf9)
                s->init_pending = 2;
        smeg_mcu_seal(rx, 90);
        s->ack_count = 0;
        return 1;
    }
    if (tx[0] == 0xaa) {
        unsigned pos = 2, out = 2;
        s->ack_count = 0;
        rx[0] = 0x99;
        rx[1] = 0;
        if (s->init_pending == 2) {
            out = smeg_mcu_append(rx, out, 0x40, 3, &s->init_sequence, 1);
            s->init_pending = 0;
        }
        for (unsigned i = 0; i < tx[1]; i++) {
            if (pos + 5 > 90) {
                return 0;
            }
            unsigned len = tx[pos + 2];
            if (len > 83 || pos + len + 5 > 90) {
                return 0; /* Fragmented application messages unsupported. */
            }
            int valid = smeg_mcu_crc_valid(tx + pos, len + 3);
            if (s->ack_count < 29) {
                uint8_t *ack = s->ack[s->ack_count++];
                ack[0] = tx[pos];
                ack[1] = tx[pos + 1];
                ack[2] = valid ? 0xf9 : 0xfa;
            }
            if (valid && s->upg_sw_release_enabled && tx[pos] == 0x10 &&
                tx[pos + 1] == 1 && len == 1 && tx[pos + 3] == 0x5a) {
                out = smeg_mcu_append(rx, out, 0x10, 2,
                                      s->upg_sw_release, 3);
            }
            /* Native BSP256 UPG/System config queries and real virtual-state
             * writes only. GetUpg26ccd0 ->ID09/17/80+16bytes(event16);
             * SetUpg26cdd8 ->ID04/2/0020(event15). GetSystem26ce94
             * ->ID07/16bytes(event14); SetSystem26cfb8 ->ID08/1/80(event13).
             * GET request tails are uninitialized native stack bytes, not
             * selectors: require exactly17bytes and inspect only byte0.
             * SET success is emitted only after copying all16bytes into the
             * selected enabled virtual bank. No loader/erase/program support. */
            if (valid && tx[pos] == 0x10 && len == 17) {
                uint8_t id = tx[pos + 1], selector = tx[pos + 3];
                uint8_t *state = id == 9 && s->upg_config_enabled ? s->upg_config :
                                 id == 8 && s->system_config_enabled ? s->system_config : NULL;
                if (state && selector == 0x40) {
                    if (id == 9) {
                        uint8_t payload[17] = {0x80};
                        memcpy(payload + 1, state, 16);
                        out = smeg_mcu_append(rx, out, 0x10, 9, payload, 17);
                    } else {
                        out = smeg_mcu_append(rx, out, 0x10, 7, state, 16);
                    }
                } else if (state && selector == 0x80) {
                    memcpy(state, tx + pos + 4, 16);
                    if (id == 9) {
                        const uint8_t written[2] = {0, 0x20};
                        out = smeg_mcu_append(rx, out, 0x10, 4, written, 2);
                    } else {
                        const uint8_t written = 0x80;
                        out = smeg_mcu_append(rx, out, 0x10, 8, &written, 1);
                    }
                }
            }
            if (valid && tx[pos] == 0x40 && len == 1 && out + 9 <= 90) {
                uint8_t payload[4];
                uint8_t response_id = 0;
                if (tx[pos + 1] == 1 && tx[pos + 3] == 0x5a) {
                    response_id = 1;
                    memcpy(payload, s->identity, 4);
                } else if (tx[pos + 1] == 4 && tx[pos + 3] == 1) {
                    /* GetDiagConfig request263940; response ID5 handler263120.
                     * First3 bytes are opaque and logged only. Fourth byte:
                     * bit2 LVDS display present; bit1 early-alert active.
                     * This is explicit virtual bench configuration, not VIN,
                     * feature licensing, or a claim about physical coding. */
                    response_id = 5;
                    memset(payload, 0, 4);
                    payload[3] = s->diag_flags;
                }
                if (response_id) {
                    rx[1]++;
                    rx[out] = 0x40;
                    rx[out + 1] = response_id;
                    rx[out + 2] = 4;
                    memcpy(rx + out + 3, payload, 4);
                    smeg_mcu_seal(rx + out, 7);
                    out += 9;
                }
            }
            /* Native LIBCOM Init26431c sends40/03/<sequence>; UpdateData
             * 263190 requires40/03 with the same byte before setting event3.
             * Client sets its expected byte after Write completes; deliver the
             * application echo only on a poll after the transport ACK. */
            if (valid && tx[pos] == 0x40 && tx[pos + 1] == 3 &&
                len == 1 && tx[pos + 3] <= 1) {
                s->init_sequence = tx[pos + 3];
                s->init_pending = 1;
            }
            /* Explicit bench native-key-table profile. Native FPUpdateData
             * switch table02f42cc0 entry10 ->01289454 copies exactly17bytes;
             * FMUXGetEnumTabKey0128f648 uses byte1==a1 for alternate table,
             * otherwise the compiled default table. The other16bytes remain
             * zero; no physical coding or installed board identity is claimed. */
            if (s->bench_key_profile && valid && tx[pos] == 1 &&
                tx[pos + 1] == 0x10 && len == 2 &&
                tx[pos + 3] == 0x80 && tx[pos + 4] == 1) {
                uint8_t profile[17] = {0};
                profile[1] = s->key_variant;
                out = smeg_mcu_append(rx, out, 1, 0x10, profile,
                                      sizeof(profile));
            }
            /* Native input notifications, not guessed request replies.
             * LIBCOM ID4 handler263180 accepts low5bits as on/off state.
             * App FP channel1 ID1 dispatch1288bb4 ->1288704 accepts two
             * bytes and emits the real OnOffStateChanged event. Wait until
             * each channel transmits before announcing its bench state,
             * so that the native receive queue has been opened.
             * Evidence: artifacts/phase3/mcu-power-evidence.json. */
            if (valid && tx[pos] == 0x40 && !s->libcom_power_sent) {
                unsigned next = smeg_mcu_append(rx, out, 0x40, 4,
                                                &s->onoff_state, 1);
                if (next != out) {
                    out = next;
                    s->libcom_power_sent = 1;
                }
            }
            if (valid && tx[pos] == 1 && !s->fp_power_sent) {
                uint8_t state[2] = {s->onoff_state, 0};
                unsigned next = smeg_mcu_append(rx, out, 1, 1, state, 2);
                if (next != out) {
                    out = next;
                    s->fp_power_sent = 1;
                }
            }
            pos += len + 5;
        }
        /* Asynchronous native input notifications are valid even when the
         * host data frame has no messages. Deliver one sample per exchange:
         * native KBDUpdateData has one cached7byte object, and deferred
         * observers must get a chance to copy each sample before replacement.
         * Keep the FIFO ordered; never collapse press/release into one frame. */
        smeg_mcu_peer_ecu_commands(s, tx);
        smeg_mcu_seal(rx, 90);
        smeg_mcu_peer_touch_pending(s, rx);
        smeg_mcu_peer_profile_pending(s, rx);
        smeg_mcu_peer_key_pending(s, rx);
        smeg_mcu_peer_net_pending(s, rx);
        return 1;
    }
    return 0;
}
#endif
