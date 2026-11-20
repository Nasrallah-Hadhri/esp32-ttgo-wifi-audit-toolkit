#ifndef WIFI_ATTACKS_H
#define WIFI_ATTACKS_H

#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

void wifi_attacks_init(void);

// 1. Scan (Returns detailed scan results via Serial)
void wifi_cmd_scan(void);

// 1b. Sniffing (Promiscuous mode for EAPOL)
void wifi_cmd_sniff_start(uint8_t channel);
void wifi_cmd_sniff_stop(void);

// 2. Rogue AP / Evil Twin
void wifi_cmd_rogue_ap(const char* ssid);
void wifi_cmd_rogue_ap_stop(void);

// 3. Deauth Attack (Targeted burst)
void wifi_cmd_deauth(uint8_t *bssid, uint8_t channel);
// 3b. Continuous deauth (background FreeRTOS task — use CMD:DEAUTH_CONT / CMD:DEAUTH_STOP)
void wifi_cmd_deauth_continuous(uint8_t *bssid, uint8_t channel);
void wifi_cmd_deauth_stop(void);
// 3c. Targeted unicast deauth — aim at a specific client MAC (bypasses broadcast PMF filtering)
void wifi_cmd_deauth_targeted(uint8_t *bssid, uint8_t channel, uint8_t *client_mac);

// 4. Router Audit
//    do_sweep=false → FAST: port scan only  (~5s)
//    do_sweep=true  → DEEP: port scan + subnet host discovery (~10-40s)
void wifi_cmd_connect_and_audit(const char* ssid, const char* pass, bool do_sweep);

// 5. Device Port Scanner
void wifi_cmd_scan_device(const char* ip);

// 6. PMKID Hunt — passive EAPOL Message 1 capture (no client needed)
//    CMD:PMKID_HUNT:6  (channel number)
//    CMD:PMKID_STOP
void wifi_cmd_pmkid_hunt(uint8_t channel);
void wifi_cmd_pmkid_stop(void);

#endif // WIFI_ATTACKS_H

