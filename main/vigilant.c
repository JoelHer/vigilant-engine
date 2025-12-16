#include "vigilant.h"

#include "esp_err.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_log.h"
#include "esp_event.h"
#include "protocol_examples_common.h"
#include "http_server.h"

static const char *TAG = "vigilant";

esp_err_t  vigilant_init(NW_MODE NETWORK_MODE) {
    ESP_LOGI(TAG, "Init NVS");
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_LOGI(TAG, "Init netif + event loop");
    ESP_ERROR_CHECK(esp_netif_init());

    ret = esp_event_loop_create_default();
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        ESP_ERROR_CHECK(ret);
    }

    ESP_LOGI(TAG, "Connecting... mode=%d", (int)NETWORK_MODE);
    ESP_ERROR_CHECK(example_connect());

    ESP_LOGI(TAG, "Registering HTTP server event handlers");
    ESP_ERROR_CHECK(http_server_register_event_handlers());

    ESP_LOGI(TAG, "Starting HTTP server");
    ESP_ERROR_CHECK(http_server_start());

    return ESP_OK;
}