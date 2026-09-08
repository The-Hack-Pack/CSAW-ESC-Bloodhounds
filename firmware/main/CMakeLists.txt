# `driver` is listed explicitly rather than relying on the common requirements:
# IDF v5.x split GPIO out into esp_driver_gpio, and depending on the implicit
# set makes the driver/gpio.h include in app_main.c version-fragile.
idf_component_register(SRCS "app_main.c"
                       INCLUDE_DIRS "."
                       REQUIRES driver)
