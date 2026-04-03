# ESP32-S3-DevKitC-1 Assembly

**Note on the OV2640 Camera Module**

This build uses the STM32-compatible OV2640 red module (common on AliExpress). Unlike other OV2640 modules, this one has an **onboard 24 MHz oscillator**, so the XCLK pin is not connected. The pixel clock output on this module is labelled **DCLK** (not PCLK), connect it to GPIO 21.

## Power Pins
| Function | Pin Number (On ESP32-S3) |
| --- | --- |
| VCC (Display, Camera) | 3.3V |
| GND (Display, Camera, Buttons) | GND |

## Display Pins (ST7789 1.14" SPI)
| Function Pin (On Display) | Pin Number (On ESP32-S3) |
| --- | --- |
| SDA (MOSI) | 11 |
| SCL (CLK) | 12 |
| CS | 10 |
| DC | 13 |
| RES (RST) | 14 |
| BL (Backlight) | 15 |

## Camera Pins (OV2640)
| Function Pin (On Camera) | Pin Number (On ESP32-S3) |
| --- | --- |
| D0 | 4 |
| D1 | 5 |
| D2 | 6 |
| D3 | 7 |
| D4 | 8 |
| D5 | 9 |
| D6 | 16 |
| D7 | 17 |
| XCLK | Not Connected (onboard oscillator) |
| DCLK (PCLK) | 21 |
| VSYNC | 38 |
| HREF | 39 |
| SDA (SCCB) | 40 |
| SCL (SCCB) | 41 |
| PWDN | GND (tie directly) |
| RESET | 3.3V (tie directly) |

## Button Pins
Wire each button with one leg to the Pin Number (On ESP32-S3) and the other to GND. Internal pull-ups are enabled, no external resistors needed.

| Button | Pin Number (On ESP32-S3) | Function |
| --- | --- | --- |
| LEFT | 1 | Navigate left / back |
| SELECT | 2 | Confirm / select |
| RIGHT | 42 | Navigate right |
