#ifndef SSD1306_H
#define SSD1306_H

#include "driver/i2c.h"

#define OLED_I2C_ADDR 0x3C
#define OLED_WIDTH 128
#define OLED_HEIGHT 64

#define I2C_MASTER_SCL_IO 15
#define I2C_MASTER_SDA_IO 4
#define OLED_RST_IO 16
#define I2C_MASTER_NUM I2C_NUM_0
#define I2C_MASTER_FREQ_HZ 400000

void ssd1306_init(void);
void ssd1306_clear(void);
void ssd1306_draw_string(int x, int y, const char *str);
void ssd1306_update(void);

#endif // SSD1306_H
