/*
 * ESP32 / FreeRTOS mirror of host_twin/target.c.
 *
 * Same bugs, same names, real dual-core + ISR context. Use the host twin for
 * fast iteration (TSan/ASan/AFL++/angr all work there) and this build to
 * confirm the finding survives on the actual architecture.
 *
 * NOT COMPILED OR RUN in the environment where this scaffold was produced --
 * treat it as a starting point and expect to fix includes for your ESP-IDF
 * version. Verified against the ESP-IDF v5.x API surface by inspection only.
 */
#include <string.h>

#include "driver/gpio.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define TAG        "esc26"
#define FRAME_MAX  64
#define LOCAL_MAX  16
#define IRQ_PIN    GPIO_NUM_4      /* MFRC522 IRQ line */

static uint8_t         g_frame[FRAME_MAX];
static volatile size_t g_len;      /* shared across cores, no lock -- BUG-001 */

/* ---- BUG-001: written from ISR context, read from a task on the other core */
static void IRAM_ATTR rfid_isr_handler(void *arg)
{
    /* In the real gateway this drains the MFRC522 FIFO over SPI. The shape
     * that matters is: invalidate, fill, publish -- with no critical section. */
    size_t n = (size_t)arg;
    if (n > FRAME_MAX) n = FRAME_MAX;
    g_len = 0;
    memset(g_frame, 0x41, n);
    g_len = n;
}

static int handle_frame(void)
{
    uint8_t local[LOCAL_MAX];
    size_t n = g_len;                       /* CHECK */
    if (n == 0 || n > LOCAL_MAX) return -1;
    memcpy(local, g_frame, g_len);          /* USE -- re-reads g_len */
    return (int)local[0];
}

/* ---- BUG-002: trusted length field from the wire */
static int parse_config(const uint8_t *in, size_t len)
{
    uint8_t name[32];
    if (len < 3 || in[0] != 0xC0) return -1;
    size_t nlen = ((size_t)in[1] << 8) | in[2];
    if (len < 3 + nlen) return -1;
    memcpy(name, in + 3, nlen);
    return (int)name[0];
}

static void consumer_task(void *arg)
{
    (void)arg;
    for (;;) {
        handle_frame();
        taskYIELD();
    }
}

static void net_task(void *arg)
{
    (void)arg;
    uint8_t buf[128];
    for (;;) {
        /* Replace with your UART/Wi-Fi read. Kept as a stub so the harness
         * entry point is obvious to both a fuzzer and an agent. */
        size_t n = 0;
        if (n) parse_config(buf, n);
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "esc26 testbed up");

    gpio_config_t io = {
        .pin_bit_mask = 1ULL << IRQ_PIN,
        .mode         = GPIO_MODE_INPUT,
        .intr_type    = GPIO_INTR_POSEDGE,
    };
    gpio_config(&io);
    gpio_install_isr_service(0);
    gpio_isr_handler_add(IRQ_PIN, rfid_isr_handler, (void *)(size_t)FRAME_MAX);

    /* Pin the two halves to different cores so the race is a true parallel
     * race, not just an interrupt-preemption race. */
    xTaskCreatePinnedToCore(consumer_task, "consumer", 4096, NULL, 5, NULL, 0);
    xTaskCreatePinnedToCore(net_task,      "net",      4096, NULL, 5, NULL, 1);
}
