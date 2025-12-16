#include <unistd.h>
#include "esp_log.h"
#include "vigilant.h"

static const char *TAG = "app_main";

void app_main(void)
{
    NW_MODE mode = NW_MODE_STA;
    ESP_ERROR_CHECK(vigilant_init(mode));

    while (1) {
        sleep(1);
    }
}
