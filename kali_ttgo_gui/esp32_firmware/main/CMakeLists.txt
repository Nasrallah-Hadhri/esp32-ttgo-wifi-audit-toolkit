idf_component_register(SRCS "main.c" "ssd1306.c" "wifi_attacks.c"
                    INCLUDE_DIRS "."
                    REQUIRES esp_wifi nvs_flash esp_event freertos esp_driver_uart esp_driver_gpio driver)
