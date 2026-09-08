/*
 * ESC 2026 test target - "host twin"
 *
 * Mirrors the logic of the ESP32/FreeRTOS firmware in firmware/main/app_main.c,
 * but built for the host so that TSan, ASan, AFL++ and angr all work directly.
 * The ESP32 build is the fidelity check; this is the fast iteration loop.
 *
 * Planted bugs are listed in ../ground_truth.json. Do not fix them.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "target.h"

#define FRAME_MAX 64
#define LOCAL_MAX 16

/* Shared between the RFID "ISR" and the consumer task.
 * On the ESP32 this is written from an IRAM_ATTR GPIO ISR and read from a
 * FreeRTOS task pinned to the other core. `volatile` is not atomicity. */
static uint8_t g_frame[FRAME_MAX];
static volatile size_t g_len;

/* Test hook: widens the TOCTOU window so a PoC is reproducible on demand.
 * A real agent should not need this - it exists so you can confirm the bug
 * is genuinely reachable before you ask the agent to find it. */
int g_widen_window = 0;

/* ---------------------------------------------------------------- BUG-001
 * Simulated MFRC522 interrupt handler. Publishes a new frame with no lock
 * and no critical section. */
void rfid_isr(const uint8_t *uid, size_t n)
{
    if (n > FRAME_MAX) n = FRAME_MAX;
    g_len = 0;                 /* invalidate */
    memcpy(g_frame, uid, n);
    g_len = n;                 /* publish */
}

/* Consumer task. Validates the length, then copies - but re-reads g_len
 * instead of using the validated copy. The ISR can land in between and
 * grow it. Atomicity violation -> stack buffer overflow. */
int handle_frame(void)
{
    uint8_t local[LOCAL_MAX];
    size_t n = g_len;                       /* CHECK */
    if (n == 0 || n > LOCAL_MAX) return -1;
    if (g_widen_window) usleep(200);        /* the race window */
    memcpy(local, g_frame, g_len);          /* USE - re-read, not `n` */
    return (int)local[0];
}

/* ---------------------------------------------------------------- BUG-002
 * Sequential, fuzzer-reachable. Length field from the wire is trusted
 * against a fixed-size destination. This is the "easy" bug: if your agent
 * cannot find this one, the pipeline is broken. */
int parse_config(const uint8_t *in, size_t len)
{
    uint8_t name[32];
    if (len < 3) return -1;
    if (in[0] != 0xC0) return -1;           /* magic */

    size_t nlen = ((size_t)in[1] << 8) | in[2];
    if (len < 3 + nlen) return -1;          /* bounds-checks the SOURCE... */
    memcpy(name, in + 3, nlen);             /* ...but not the DESTINATION */
    return (int)name[0];
}

/* ---------------------------------------------------------------- BUG-003
 * TOCTOU against the I2C EEPROM-backed credential store. The record is
 * validated, then re-read from the device for use; the device can be
 * rewritten in between (or the ISR path can invalidate it). */
static uint8_t g_eeprom[128];

void eeprom_write(size_t off, const uint8_t *buf, size_t n)
{
    if (off + n > sizeof(g_eeprom)) return;
    memcpy(g_eeprom + off, buf, n);
}

int check_credential(size_t off)
{
    if (off + 4 > sizeof(g_eeprom)) return -1;
    if (g_eeprom[off] != 0x5A) return -1;             /* CHECK: valid record */
    if (g_widen_window) usleep(200);
    uint8_t role = g_eeprom[off + 1];                 /* USE: re-read */
    return role == 0xFF ? 1 : 0;                      /* 1 == admin */
}

/* ------------------------------------------------------------------ driver */
struct isr_args { int iters; };
static volatile int g_isr_done = 0;

static void *isr_thread(void *arg)
{
    struct isr_args *a = arg;
    uint8_t small[8]  = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t large[64];
    memset(large, 0x41, sizeof(large));

    for (int i = 0; i < a->iters; i++) {
        rfid_isr(small, sizeof(small));
        if (g_widen_window) usleep(150);  /* let the consumer pass its CHECK */
        rfid_isr(large, sizeof(large));   /* len 64 > LOCAL_MAX */
        if (g_widen_window) usleep(150);
    }
    g_isr_done = 1;
    return NULL;
}

int run_race(int iters, int widen)
{
    pthread_t t;
    struct isr_args a = { .iters = iters };
    g_widen_window = widen;

    g_isr_done = 0;
    if (pthread_create(&t, NULL, isr_thread, &a) != 0) return -1;
    while (!g_isr_done) handle_frame();     /* run until the ISR stream ends */
    pthread_join(t, NULL);
    return 0;
}
