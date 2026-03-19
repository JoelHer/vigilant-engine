#include <stdio.h>
#include "status_led.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "led_strip.h"
#include "sdkconfig.h"

/*
Choose mode depending on board or preference

BLINK mode:
- SLOW   (2s)    = Info
- MEDIUM (700ms) = Warning
- FAST   (100ms) = Error
RGB mode:
- GREEN = Info 
- BLUE  = Warning
- RED  = ERROR
*/

static const char *TAG = "status_led";
static TaskHandle_t s_blink_task = NULL;

//Only relevant if led_mode is set to RGB
static int led_gpio_red = 46;
static int led_gpio_green = 0;
static int led_gpio_blue = 45;

//Status led for BLINK mode
static int led_gpio_blink = 48;

static void blink_led(uint8_t led_gpio)
{
    // Set the GPIO level according to the state (LOW or HIGH)
    gpio_set_level(led_gpio, s_blink.state);
}

void configure_led(led_mode mode)
{
    if(mode == RGB) {
        gpio_reset_pin(led_gpio_red);
        gpio_reset_pin(led_gpio_green);
        gpio_reset_pin(led_gpio_blue);

        gpio_set_direction(led_gpio_red, GPIO_MODE_OUTPUT);
        gpio_set_direction(led_gpio_green, GPIO_MODE_OUTPUT);
        gpio_set_direction(led_gpio_blue, GPIO_MODE_OUTPUT);
    } else {
        gpio_reset_pin(led_gpio_blink);
        gpio_set_direction(led_gpio_blink, GPIO_MODE_OUTPUT);
    }
}

static void blink_task(void *arg)
{
    uint8_t led_gpio = (uint8_t)(intptr_t)arg;

    while (s_blink.running) {
        blink_led(led_gpio);
        s_blink.state = !s_blink.state;
        s_blink.state ? vTaskDelay(s_blink.on_ms / portTICK_PERIOD_MS) :  vTaskDelay(s_blink.off_ms / portTICK_PERIOD_MS);
    }
    s_blink_task = NULL;
    vTaskDelete(NULL);
}

esp_err_t status_led_blink_start(uint32_t on_ms, uint32_t off_ms, uint8_t led_gpio)
{
    status_led_blink_stop();

    s_blink.gpio = led_gpio;
    s_blink.on_ms = on_ms;
    s_blink.off_ms = off_ms;
    s_blink.state = 0;
    s_blink.running = true;

    BaseType_t ok = xTaskCreate(blink_task, "status_led_blink", 4096, (void *)(intptr_t)led_gpio, 15, &s_blink_task);
    ESP_LOGI(TAG, "Blink task created");
    return ok == pdPASS ? ESP_OK : ESP_ERR_NO_MEM;
}

esp_err_t status_led_blink_stop(void)
{
    if (s_blink_task) {
        s_blink.running = false;
        vTaskDelay(pdMS_TO_TICKS(20)); // Wait for task exit
    }
    return 0;
}

esp_err_t status_led_set_state(status_state_t state, led_mode mode) {
    switch (mode) {
        case RGB:
            switch (state) {
            case STATUS_STATE_INFO:
                gpio_set_level(led_gpio_red, 1);
                gpio_set_level(led_gpio_blue, 1);
                return status_led_blink_start(1000, 1000, led_gpio_green);
            case STATUS_STATE_WARNING:
                gpio_set_level(led_gpio_green, 1);
                gpio_set_level(led_gpio_red, 1);
                return status_led_blink_start(600, 600, led_gpio_blue);
            case STATUS_STATE_ERROR:
                gpio_set_level(led_gpio_green, 1);
                gpio_set_level(led_gpio_blue, 1);
                return status_led_blink_start(300, 300, led_gpio_red);
            default:
                return status_led_blink_stop();
        }
        case BLINK:
            switch (state) {
            case STATUS_STATE_INFO:
                return status_led_blink_start(2000, 2000, led_gpio_blink);
            case STATUS_STATE_WARNING:
                return status_led_blink_start(700, 700, led_gpio_blink);
            case STATUS_STATE_ERROR:
                return status_led_blink_start(100, 100, led_gpio_blink);
            default:
                return status_led_blink_stop();
        }
        default:
            return status_led_blink_stop();
    }
}