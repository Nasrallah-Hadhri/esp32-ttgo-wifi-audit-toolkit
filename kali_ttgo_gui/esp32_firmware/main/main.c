#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/uart.h"
#include "esp_log.h"
#include "ssd1306.h"
#include "wifi_attacks.h"

#define EX_UART_NUM UART_NUM_0
#define BUF_SIZE (1024)



// Helper to parse hex string MAC address into uint8_t array
static void parse_mac(const char* mac_str, uint8_t* mac) {
    int values[6];
    if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) == 6) {
        for(int i = 0; i < 6; ++i) mac[i] = (uint8_t) values[i];
    }
}

void app_main(void)
{
    ssd1306_init();
    ssd1306_draw_string(10, 10, "[+] SYSTEM BOOT");
    ssd1306_draw_string(10, 30, "Init WiFi...");
    ssd1306_update();

    wifi_attacks_init();

    uart_config_t uart_config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE
    };
    uart_param_config(EX_UART_NUM, &uart_config);
    uart_driver_install(EX_UART_NUM, BUF_SIZE * 2, 0, 0, NULL, 0);

    ssd1306_clear();
    ssd1306_draw_string(0, 10, "TTGO SECURE NODE");
    ssd1306_draw_string(0, 30, "Awaiting uplink");
    ssd1306_draw_string(0, 40, "via Serial...");
    ssd1306_update();

    uint8_t *data = (uint8_t *) malloc(BUF_SIZE);
    
    printf("RES:READY\n");

    while (1) {
        int len = uart_read_bytes(EX_UART_NUM, data, BUF_SIZE - 1, 100 / portTICK_PERIOD_MS);
        if (len > 0) {
            data[len] = '\0';
            char* cmd = (char*)data;
            if (cmd[len-1] == '\n') cmd[len-1] = '\0';
            if (cmd[len-2] == '\r') cmd[len-2] = '\0';

            if (strncmp(cmd, "CMD:SCAN", 8) == 0) {
                ssd1306_clear();
                ssd1306_draw_string(0, 10, "[*] RECONNAISSANCE");
                ssd1306_draw_string(0, 30, "Scanning 802.11...");
                ssd1306_update();
                wifi_cmd_scan();
                ssd1306_draw_string(0, 50, "Scan Complete.");
                ssd1306_update();
            }
            else if (strncmp(cmd, "CMD:SNIFF_START:", 16) == 0) {
                int ch = atoi(cmd + 16);
                ssd1306_clear();
                ssd1306_draw_string(0, 10, "[*] PROMISCUOUS");
                char buf[32];
                sprintf(buf, "Channel %d locked.", ch);
                ssd1306_draw_string(0, 30, buf);
                ssd1306_draw_string(0, 50, "Hunting EAPOL...");
                ssd1306_update();
                wifi_cmd_sniff_start(ch);
            }
            else if (strncmp(cmd, "CMD:SNIFF_STOP", 14) == 0) {
                wifi_cmd_sniff_stop();
                ssd1306_clear();
                ssd1306_draw_string(0, 10, "Sniffer halted.");
                ssd1306_update();
            }
            else if (strncmp(cmd, "CMD:ROGUE:", 10) == 0) {
                char* ssid = cmd + 10;
                ssd1306_clear();
                ssd1306_draw_string(0, 10, "[*] EVIL TWIN");
                ssd1306_draw_string(0, 30, "Broadcasting:");
                ssd1306_draw_string(0, 40, ssid);
                ssd1306_update();
                wifi_cmd_rogue_ap(ssid);
            }
            else if (strncmp(cmd, "CMD:ROGUE_STOP", 14) == 0) {
                wifi_cmd_rogue_ap_stop();
                ssd1306_clear();
                ssd1306_draw_string(0, 10, "Rogue AP Stoped");
                ssd1306_update();
            }
            else if (strncmp(cmd, "CMD:DEAUTH:", 11) == 0) {
                // Parse BSSID and Channel: CMD:DEAUTH:AA:BB:CC:DD:EE:FF:6
                char* args = cmd + 11;
                char mac_str[18];
                strncpy(mac_str, args, 17);
                mac_str[17] = '\0';
                int channel = atoi(args + 18);
                
                uint8_t target_bssid[6];
                parse_mac(mac_str, target_bssid);

                ssd1306_clear();
                ssd1306_draw_string(0, 10, "[!] DEAUTH BURST");
                ssd1306_draw_string(0, 30, mac_str);
                ssd1306_draw_string(0, 50, "200 frames x2 dir");
                ssd1306_update();
                
                wifi_cmd_deauth(target_bssid, channel);
                
                ssd1306_clear();
                ssd1306_draw_string(0, 10, "[+] DEAUTH DONE");
                ssd1306_update();
            }
            else if (strncmp(cmd, "CMD:DEAUTH_CONT:", 16) == 0) {
                // Continuous deauth task: CMD:DEAUTH_CONT:AA:BB:CC:DD:EE:FF:6
                char* args = cmd + 16;
                char mac_str[18];
                strncpy(mac_str, args, 17);
                mac_str[17] = '\0';
                int channel = atoi(args + 18);

                uint8_t target_bssid[6];
                parse_mac(mac_str, target_bssid);

                ssd1306_clear();
                ssd1306_draw_string(0, 10, "[!] DEAUTH CONT");
                ssd1306_draw_string(0, 30, mac_str);
                ssd1306_draw_string(0, 50, "Running...");
                ssd1306_update();

                wifi_cmd_deauth_continuous(target_bssid, channel);
            }
            else if (strncmp(cmd, "CMD:DEAUTH_STOP", 15) == 0) {
                wifi_cmd_deauth_stop();
                ssd1306_clear();
                ssd1306_draw_string(0, 10, "[+] DEAUTH STOPPED");
                ssd1306_update();
            }
            /* CMD:DEAUTH_TARGETED:AA:BB:CC:DD:EE:FF:6:11:22:33:44:55:66
             * Layout: cmd+18 → AP BSSID (17 chars), +36 → channel, +38 → client MAC */
            else if (strncmp(cmd, "CMD:DEAUTH_TARGETED:", 20) == 0) {
                char* args = cmd + 20;
                // AP BSSID: first 17 chars
                char ap_mac_str[18];
                strncpy(ap_mac_str, args, 17);
                ap_mac_str[17] = '\0';
                // Channel: position 18 (after "AA:BB:CC:DD:EE:FF:")
                int channel = atoi(args + 18);
                // Client MAC: position 20 (after "AA:BB:CC:DD:EE:FF:6:" or ":12:")
                //   find second colon-separated number then skip to next colon
                char* ch_end = strchr(args + 18, ':');
                char client_mac_str[18] = {0};
                if (ch_end) {
                    strncpy(client_mac_str, ch_end + 1, 17);
                    client_mac_str[17] = '\0';
                }

                uint8_t ap_bssid[6]    = {0};
                uint8_t client_mac[6]  = {0};
                parse_mac(ap_mac_str,     ap_bssid);
                parse_mac(client_mac_str, client_mac);

                ssd1306_clear();
                ssd1306_draw_string(0, 10, "[!] TARGETED DEAUTH");
                ssd1306_draw_string(0, 30, client_mac_str);
                ssd1306_draw_string(0, 50, "Unicast frames...");
                ssd1306_update();

                wifi_cmd_deauth_targeted(ap_bssid, (uint8_t)channel, client_mac);

                ssd1306_clear();
                ssd1306_draw_string(0, 10, "[+] TARGET DONE");
                ssd1306_update();
            }
            else if (strncmp(cmd, "CMD:AUDIT:", 10) == 0) {
                // CMD:AUDIT:MySSID:MyPass:FAST  or  CMD:AUDIT:MySSID:MyPass:DEEP
                char* args = cmd + 10;
                char* sep  = strchr(args, ':');
                if (sep) {
                    *sep = '\0';
                    char* ssid      = args;
                    char* rest      = sep + 1;
                    // Find second colon separating pass from mode
                    char* sep2      = strrchr(rest, ':');
                    bool  do_sweep  = false;
                    if (sep2 && strcmp(sep2 + 1, "DEEP") == 0) {
                        *sep2     = '\0';
                        do_sweep  = true;
                    } else if (sep2 && strcmp(sep2 + 1, "FAST") == 0) {
                        *sep2 = '\0';
                    }
                    char* pass = rest;

                    ssd1306_clear();
                    ssd1306_draw_string(0, 10, do_sweep ? "[*] DEEP AUDIT" : "[*] FAST AUDIT");
                    ssd1306_draw_string(0, 30, "Connecting to:");
                    ssd1306_draw_string(0, 40, ssid);
                    ssd1306_update();

                    wifi_cmd_connect_and_audit(ssid, pass, do_sweep);
                }
            }
            else if (strncmp(cmd, "CMD:SCAN_DEVICE:", 16) == 0) {
                // CMD:SCAN_DEVICE:192.168.137.5
                char* ip = cmd + 16;
                ssd1306_clear();
                ssd1306_draw_string(0, 10, "[*] DEVICE SCAN");
                ssd1306_draw_string(0, 30, ip);
                ssd1306_update();
                wifi_cmd_scan_device(ip);
                ssd1306_clear();
                ssd1306_draw_string(0, 10, "[+] DEVICE DONE");
                ssd1306_update();
            }
            else if (strncmp(cmd, "CMD:PMKID_HUNT:", 15) == 0) {
                uint8_t ch = (uint8_t)atoi(cmd + 15);
                ssd1306_clear();
                ssd1306_draw_string(0, 10, "[*] PMKID HUNT");
                char ch_str[12]; snprintf(ch_str, sizeof(ch_str), "CH %d", ch);
                ssd1306_draw_string(0, 30, ch_str);
                ssd1306_update();
                wifi_cmd_pmkid_hunt(ch);
            }
            else if (strcmp(cmd, "CMD:PMKID_STOP") == 0) {
                wifi_cmd_pmkid_stop();
                ssd1306_clear();
                ssd1306_draw_string(0, 10, "[+] PMKID STOP");
                ssd1306_update();
            }

        }
    }
}
