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

#if defined(VE_STATUS_LED_MODE_RGB)
    #define CURRENT_MODE 0
#else
    #define CURRENT_MODE 1
#endif

typedef enum {
    MODE_RGB,
    MODE_BLINK
} led_mode_t;

#if defined(CONFIG_VE_STATUS_LED_MODE_RGB)
    #define CURRENT_LED_MODE MODE_RGB
#else
    #define CURRENT_LED_MODE MODE_BLINK
#endif

static const char *TAG = "status_led";
static TaskHandle_t s_blink_task = NULL;

static void blink_led(uint8_t led_gpio)
{
    // Set the GPIO level according to the state (LOW or HIGH)
    gpio_set_level(led_gpio, s_blink.state);
}

void configure_led()
{
#if defined(CONFIG_VE_STATUS_LED_MODE_RGB)
    gpio_reset_pin(CONFIG_VE_STATUS_LED_GPIO_RED);
    gpio_reset_pin(CONFIG_VE_STATUS_LED_GPIO_GREEN);
    gpio_reset_pin(CONFIG_VE_STATUS_LED_GPIO_BLUE);

    gpio_set_direction(CONFIG_VE_STATUS_LED_GPIO_RED, GPIO_MODE_OUTPUT);
    gpio_set_direction(CONFIG_VE_STATUS_LED_GPIO_GREEN, GPIO_MODE_OUTPUT);
    gpio_set_direction(CONFIG_VE_STATUS_LED_GPIO_BLUE, GPIO_MODE_OUTPUT);

#elif defined(CONFIG_VE_STATUS_LED_MODE_BLINK)
    gpio_reset_pin(CONFIG_VE_STATUS_LED_GPIO_BLINK);
    gpio_set_direction(CONFIG_VE_STATUS_LED_GPIO_BLINK, GPIO_MODE_OUTPUT);
#endif
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

esp_err_t status_led_set_state(status_state_t state) {
#if defined(CONFIG_VE_STATUS_LED_MODE_RGB)
    switch (state) {
        case STATUS_STATE_INFO:
            gpio_set_level(CONFIG_VE_STATUS_LED_GPIO_RED, 1);
            gpio_set_level(CONFIG_VE_STATUS_LED_GPIO_BLUE, 1);
            return status_led_blink_start(1000, 1000, CONFIG_VE_STATUS_LED_GPIO_GREEN);
        case STATUS_STATE_WARNING:
            gpio_set_level(CONFIG_VE_STATUS_LED_GPIO_GREEN, 1);
            gpio_set_level(CONFIG_VE_STATUS_LED_GPIO_RED, 1);
            return status_led_blink_start(600, 600, CONFIG_VE_STATUS_LED_GPIO_BLUE);
        case STATUS_STATE_ERROR:
            gpio_set_level(CONFIG_VE_STATUS_LED_GPIO_GREEN, 1);
            gpio_set_level(CONFIG_VE_STATUS_LED_GPIO_BLUE, 1);
            return status_led_blink_start(300, 300, CONFIG_VE_STATUS_LED_GPIO_RED);
        default:
            return status_led_blink_stop();
        }
#elif defined(CONFIG_VE_STATUS_LED_MODE_BLINK)
    switch (state) {
        case STATUS_STATE_INFO:
            return status_led_blink_start(2000, 2000, CONFIG_VE_STATUS_LED_GPIO_BLINK);
        case STATUS_STATE_WARNING:
            return status_led_blink_start(700, 700, CONFIG_VE_STATUS_LED_GPIO_BLINK);
        case STATUS_STATE_ERROR:
            return status_led_blink_start(100, 100, CONFIG_VE_STATUS_LED_GPIO_BLINK);
        default:
            return status_led_blink_stop();
}
#else
    return status_led_blink_stop();
#endif
}