set(requires esp-tls nvs_flash esp_netif esp_http_server)
idf_build_get_property(target IDF_TARGET)

if(${target} STREQUAL "linux")
    list(APPEND requires esp_stubs protocol_examples_common)
else()
    list(APPEND requires esp_wifi esp_eth)
endif()

idf_component_register(
    SRCS
        "main.c"
        "http_server.c"
        "websocket.c"
        "ota_http.c"
        "vigilant.c"
        "status_led.c"
    INCLUDE_DIRS
        "."
    EMBED_FILES 
        "static/vigilant.html"
    REQUIRES
        ${requires}
        app_update
        esp_partition
        led_strip
        cjson
)

# Ensure web UI is built before compiling the firmware
if(TARGET ve_web)
  add_dependencies(${COMPONENT_LIB} ve_web)
endif()
